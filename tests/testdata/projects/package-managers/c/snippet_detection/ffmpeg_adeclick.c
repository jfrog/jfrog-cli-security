/*
 * Copyright (c) 2018 Paul B Mahol
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/audio_fifo.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/tx.h"
#include "avfilter.h"
#include "audio.h"
#include "filters.h"

typedef struct DeclickChannel {
    double *auxiliary;
    double *detection;
    double *acoefficients;
    double *acorrelation;
    double *tmp;
    double *interpolated;
    double *matrix;
    int matrix_size;
    double *vector;
    int vector_size;
    double *y;
    int y_size;
    uint8_t *click;
    int *index;
    unsigned *histogram;
    int histogram_size;
} DeclickChannel;

typedef struct AudioDeclickContext {
    const AVClass *class;

    double w;
    double overlap;
    double threshold;
    double ar;
    double burst;
    int method;
    int nb_hbins;

    int is_declip;
    int ar_order;
    int nb_burst_samples;
    int window_size;
    int hop_size;
    int overlap_skip;

    AVFrame *enabled;
    AVFrame *in;
    AVFrame *out;
    AVFrame *buffer;
    AVFrame *is;

    DeclickChannel *chan;

    int64_t pts;
    int nb_channels;
    uint64_t nb_samples;
    uint64_t detected_errors;
    int samples_left;
    int eof;

    AVAudioFifo *efifo;
    AVAudioFifo *fifo;
    double *window_func_lut;

    int (*detector)(struct AudioDeclickContext *s, DeclickChannel *c,
                    double sigmae, double *detection,
                    double *acoefficients, uint8_t *click, int *index,
                    const double *src, double *dst);
} AudioDeclickContext;

#define OFFSET(x) offsetof(AudioDeclickContext, x)
#define AF AV_OPT_FLAG_AUDIO_PARAM|AV_OPT_FLAG_FILTERING_PARAM

static const AVOption adeclick_options[] = {
    { "window", "set window size",     OFFSET(w),         AV_OPT_TYPE_DOUBLE, {.dbl=55}, 10,  100, AF },
    { "w", "set window size",          OFFSET(w),         AV_OPT_TYPE_DOUBLE, {.dbl=55}, 10,  100, AF },
    { "overlap", "set window overlap", OFFSET(overlap),   AV_OPT_TYPE_DOUBLE, {.dbl=75}, 50,   95, AF },
    { "o", "set window overlap",       OFFSET(overlap),   AV_OPT_TYPE_DOUBLE, {.dbl=75}, 50,   95, AF },
    { "arorder", "set autoregression order", OFFSET(ar),  AV_OPT_TYPE_DOUBLE, {.dbl=2},   0,   25, AF },
    { "a", "set autoregression order", OFFSET(ar),        AV_OPT_TYPE_DOUBLE, {.dbl=2},   0,   25, AF },
    { "threshold", "set threshold",    OFFSET(threshold), AV_OPT_TYPE_DOUBLE, {.dbl=2},   1,  100, AF },
    { "t", "set threshold",            OFFSET(threshold), AV_OPT_TYPE_DOUBLE, {.dbl=2},   1,  100, AF },
    { "burst", "set burst fusion",     OFFSET(burst),     AV_OPT_TYPE_DOUBLE, {.dbl=2},   0,   10, AF },
    { "b", "set burst fusion",         OFFSET(burst),     AV_OPT_TYPE_DOUBLE, {.dbl=2},   0,   10, AF },
    { "method", "set overlap method",  OFFSET(method),    AV_OPT_TYPE_INT,    {.i64=0},   0,    1, AF, .unit = "m" },
    { "m", "set overlap method",       OFFSET(method),    AV_OPT_TYPE_INT,    {.i64=0},   0,    1, AF, .unit = "m" },
    { "add", "overlap-add",            0,                 AV_OPT_TYPE_CONST,  {.i64=0},   0,    0, AF, .unit = "m" },
    { "a", "overlap-add",              0,                 AV_OPT_TYPE_CONST,  {.i64=0},   0,    0, AF, .unit = "m" },
    { "save", "overlap-save",          0,                 AV_OPT_TYPE_CONST,  {.i64=1},   0,    0, AF, .unit = "m" },
    { "s", "overlap-save",             0,                 AV_OPT_TYPE_CONST,  {.i64=1},   0,    0, AF, .unit = "m" },
    { NULL }
};

AVFILTER_DEFINE_CLASS(adeclick);

static int config_input(AVFilterLink *inlink)
{
    AVFilterContext *ctx = inlink->dst;
    AudioDeclickContext *s = ctx->priv;
    int i;

    s->pts = AV_NOPTS_VALUE;
    s->window_size = FFMAX(100, inlink->sample_rate * s->w / 1000.);
    s->ar_order = FFMAX(s->window_size * s->ar / 100., 1);
    s->nb_burst_samples = s->window_size * s->burst / 1000.;
    s->hop_size = FFMAX(1, s->window_size * (1. - (s->overlap / 100.)));

    s->window_func_lut = av_calloc(s->window_size, sizeof(*s->window_func_lut));
    if (!s->window_func_lut)
        return AVERROR(ENOMEM);

    {
        double *tx_in[2], *tx_out[2];
        AVTXContext *tx, *itx;
        av_tx_fn tx_fn, itx_fn;
        int ret, tx_size;
        double scale;

        tx_size = 1 << (32 - ff_clz(s->window_size));

        scale = 1.0;
        ret = av_tx_init(&tx, &tx_fn, AV_TX_DOUBLE_RDFT, 0, tx_size, &scale, 0);
        if (ret < 0)
            return ret;

        scale = 1.0 / tx_size;
        ret = av_tx_init(&itx, &itx_fn, AV_TX_DOUBLE_RDFT, 1, tx_size, &scale, 0);
        if (ret < 0)
            return ret;

        tx_in[0]  = av_calloc(tx_size + 2, sizeof(*tx_in[0]));
        tx_in[1]  = av_calloc(tx_size + 2, sizeof(*tx_in[1]));
        tx_out[0] = av_calloc(tx_size + 2, sizeof(*tx_out[0]));
        tx_out[1] = av_calloc(tx_size + 2, sizeof(*tx_out[1]));
        if (!tx_in[0] || !tx_in[1] || !tx_out[0] || !tx_out[1])
            return AVERROR(ENOMEM);

        for (int n = 0; n < s->window_size - s->hop_size; n++)
            tx_in[0][n] = 1.0;

        for (int n = 0; n < s->hop_size; n++)
            tx_in[1][n] = 1.0;

        tx_fn(tx, tx_out[0], tx_in[0], sizeof(double));
        tx_fn(tx, tx_out[1], tx_in[1], sizeof(double));

        for (int n = 0; n <= tx_size/2; n++) {
            double re0 = tx_out[0][2*n];
            double im0 = tx_out[0][2*n+1];
            double re1 = tx_out[1][2*n];
            double im1 = tx_out[1][2*n+1];

            tx_in[0][2*n]   = re0 * re1 - im0 * im1;
            tx_in[0][2*n+1] = re0 * im1 + re1 * im0;
        }

        itx_fn(itx, tx_out[0], tx_in[0], sizeof(AVComplexDouble));

        scale = 1.0 / (s->window_size - s->hop_size);
        for (int n = 0; n < s->window_size; n++)
            s->window_func_lut[n] = tx_out[0][n] * scale;

        av_tx_uninit(&tx);
        av_tx_uninit(&itx);

        av_freep(&tx_in[0]);
        av_freep(&tx_in[1]);
        av_freep(&tx_out[0]);
        av_freep(&tx_out[1]);
    }

    av_frame_free(&s->in);
    av_frame_free(&s->out);
    av_frame_free(&s->buffer);
    av_frame_free(&s->is);
    s->enabled = ff_get_audio_buffer(inlink, s->window_size);
    s->in = ff_get_audio_buffer(inlink, s->window_size);
    s->out = ff_get_audio_buffer(inlink, s->window_size);
    s->buffer = ff_get_audio_buffer(inlink, s->window_size * 2);
    s->is = ff_get_audio_buffer(inlink, s->window_size);
    if (!s->in || !s->out || !s->buffer || !s->is || !s->enabled)
        return AVERROR(ENOMEM);

    s->efifo = av_audio_fifo_alloc(inlink->format, 1, s->window_size);
    if (!s->efifo)
        return AVERROR(ENOMEM);
    s->fifo = av_audio_fifo_alloc(inlink->format, inlink->ch_layout.nb_channels, s->window_size);
    if (!s->fifo)
        return AVERROR(ENOMEM);
    s->overlap_skip = s->method ? (s->window_size - s->hop_size) / 2 : 0;
    if (s->overlap_skip > 0) {
        av_audio_fifo_write(s->fifo, (void **)s->in->extended_data,
                            s->overlap_skip);
    }

    s->nb_channels = inlink->ch_layout.nb_channels;
    s->chan = av_calloc(inlink->ch_layout.nb_channels, sizeof(*s->chan));
    if (!s->chan)
        return AVERROR(ENOMEM);

    for (i = 0; i < inlink->ch_layout.nb_channels; i++) {
        DeclickChannel *c = &s->chan[i];

        c->detection = av_calloc(s->window_size, sizeof(*c->detection));
        c->auxiliary = av_calloc(s->ar_order + 1, sizeof(*c->auxiliary));
        c->acoefficients = av_calloc(s->ar_order + 1, sizeof(*c->acoefficients));
        c->acorrelation = av_calloc(s->ar_order + 1, sizeof(*c->acorrelation));
        c->tmp = av_calloc(s->ar_order, sizeof(*c->tmp));
        c->click = av_calloc(s->window_size, sizeof(*c->click));
        c->index = av_calloc(s->window_size, sizeof(*c->index));
        c->interpolated = av_calloc(s->window_size, sizeof(*c->interpolated));
        if (!c->auxiliary || !c->acoefficients || !c->detection || !c->click ||
            !c->index || !c->interpolated || !c->acorrelation || !c->tmp)
            return AVERROR(ENOMEM);
    }

    return 0;
}

static int detect_clips(AudioDeclickContext *s, DeclickChannel *c,
                        double unused0,
                        double *unused1, double *unused2,
                        uint8_t *clip, int *index,
                        const double *src, double *dst)
{
    const double threshold = s->threshold;
    double max_amplitude = 0;
    unsigned *histogram;
    int i, nb_clips = 0;

    av_fast_malloc(&c->histogram, &c->histogram_size, s->nb_hbins * sizeof(*c->histogram));
    if (!c->histogram)
        return AVERROR(ENOMEM);
    histogram = c->histogram;
    memset(histogram, 0, sizeof(*histogram) * s->nb_hbins);

    for (i = 0; i < s->window_size; i++) {
        const unsigned index = fmin(fabs(src[i]), 1) * (s->nb_hbins - 1);

        histogram[index]++;
        dst[i] = src[i];
        clip[i] = 0;
    }

    for (i = s->nb_hbins - 1; i > 1; i--) {
        if (histogram[i]) {
            if (histogram[i] / (double)FFMAX(histogram[i - 1], 1) > threshold) {
                max_amplitude = i / (double)s->nb_hbins;
            }
            break;
        }
    }

    if (max_amplitude > 0.) {
        for (i = 0; i < s->window_size; i++) {
            clip[i] = fabs(src[i]) >= max_amplitude;
        }
    }

    memset(clip, 0, s->ar_order * sizeof(*clip));
    memset(clip + (s->window_size - s->ar_order), 0, s->ar_order * sizeof(*clip));

    for (i = s->ar_order; i < s->window_size - s->ar_order; i++)
        if (clip[i])
            index[nb_clips++] = i;

    return nb_clips;
}

static int detect_clicks(AudioDeclickContext *s, DeclickChannel *c,
                         double sigmae,
                         double *detection, double *acoefficients,
                         uint8_t *click, int *index,
                         const double *src, double *dst)
{
    const double threshold = s->threshold;
    int i, j, nb_clicks = 0, prev = -1;

    memset(detection, 0, s->window_size * sizeof(*detection));

    for (i = s->ar_order; i < s->window_size; i++) {
        for (j = 0; j <= s->ar_order; j++) {
            detection[i] += acoefficients[j] * src[i - j];
        }
    }

    for (i = 0; i < s->window_size; i++) {
        click[i] = fabs(detection[i]) > sigmae * threshold;
        dst[i] = src[i];
    }

    for (i = 0; i < s->window_size; i++) {
        if (!click[i])
            continue;

        if (prev >= 0 && (i > prev + 1) && (i <= s->nb_burst_samples + prev))
            for (j = prev + 1; j < i; j++)
                click[j] = 1;
        prev = i;
    }

    memset(click, 0, s->ar_order * sizeof(*click));
    memset(click + (s->window_size - s->ar_order), 0, s->ar_order * sizeof(*click));

    for (i = s->ar_order; i < s->window_size - s->ar_order; i++)
        if (click[i])
            index[nb_clicks++] = i;

    return nb_clicks;
}

typedef struct ThreadData {
    AVFrame *out;
} ThreadData;

static int filter_frame(AVFilterLink *inlink)
{
    AVFilterContext *ctx = inlink->dst;
    AVFilterLink *outlink = ctx->outputs[0];
    AudioDeclickContext *s = ctx->priv;
    AVFrame *out = NULL;
    int ret = 0, j, ch, detected_errors = 0;
    ThreadData td;

    out = ff_get_audio_buffer(outlink, s->hop_size);
    if (!out)
        return AVERROR(ENOMEM);

    ret = av_audio_fifo_peek(s->fifo, (void **)s->in->extended_data,
                             s->window_size);
    if (ret < 0)
        goto fail;

    td.out = out;
    ret = ff_filter_execute(ctx, filter_channel, &td, NULL, inlink->ch_layout.nb_channels);
    if (ret < 0)
        goto fail;

    for (ch = 0; ch < s->in->ch_layout.nb_channels; ch++) {
        double *is = (double *)s->is->extended_data[ch];

        for (j = 0; j < s->hop_size; j++) {
            if (is[j])
                detected_errors++;
        }
    }

    av_audio_fifo_drain(s->fifo, s->hop_size);
    av_audio_fifo_drain(s->efifo, s->hop_size);

    if (s->samples_left > 0)
        out->nb_samples = FFMIN(s->hop_size, s->samples_left);

    out->pts = s->pts;
    s->pts += av_rescale_q(s->hop_size, (AVRational){1, outlink->sample_rate}, outlink->time_base);

    s->detected_errors += detected_errors;
    s->nb_samples += out->nb_samples * inlink->ch_layout.nb_channels;

    ret = ff_filter_frame(outlink, out);
    if (ret < 0)
        return ret;

    if (s->samples_left > 0) {
        s->samples_left -= s->hop_size;
        if (s->samples_left <= 0)
            av_audio_fifo_drain(s->fifo, av_audio_fifo_size(s->fifo));
    }

fail:
    if (ret < 0)
        av_frame_free(&out);
    return ret;
}

static int activate(AVFilterContext *ctx)
{
    AVFilterLink *inlink = ctx->inputs[0];
    AVFilterLink *outlink = ctx->outputs[0];
    AudioDeclickContext *s = ctx->priv;
    AVFrame *in;
    int ret, status;
    int64_t pts;

    FF_FILTER_FORWARD_STATUS_BACK(outlink, inlink);

    ret = ff_inlink_consume_samples(inlink, s->window_size, s->window_size, &in);
    if (ret < 0)
        return ret;
    if (ret > 0) {
        double *e = (double *)s->enabled->extended_data[0];

        if (s->pts == AV_NOPTS_VALUE)
            s->pts = in->pts;

        ret = av_audio_fifo_write(s->fifo, (void **)in->extended_data,
                                  in->nb_samples);
        for (int i = 0; i < in->nb_samples; i++)
            e[i] = !ctx->is_disabled;

        av_audio_fifo_write(s->efifo, (void**)s->enabled->extended_data, in->nb_samples);
        av_frame_free(&in);
        if (ret < 0)
            return ret;
    }

    if (av_audio_fifo_size(s->fifo) >= s->window_size ||
        s->samples_left > 0)
        return filter_frame(inlink);

    if (av_audio_fifo_size(s->fifo) >= s->window_size) {
        ff_filter_set_ready(ctx, 100);
        return 0;
    }

    if (!s->eof && ff_inlink_acknowledge_status(inlink, &status, &pts)) {
        if (status == AVERROR_EOF) {
            s->eof = 1;
            s->samples_left = av_audio_fifo_size(s->fifo) - s->overlap_skip;
            ff_filter_set_ready(ctx, 100);
            return 0;
        }
    }

    if (s->eof && s->samples_left <= 0) {
        ff_outlink_set_status(outlink, AVERROR_EOF, s->pts);
        return 0;
    }

    if (!s->eof)
        FF_FILTER_FORWARD_WANTED(outlink, inlink);

    return FFERROR_NOT_READY;
}

static av_cold void uninit(AVFilterContext *ctx)
{
    AudioDeclickContext *s = ctx->priv;
    int i;

    if (s->nb_samples > 0)
        av_log(ctx, AV_LOG_INFO, "Detected %s in %"PRId64" of %"PRId64" samples (%g%%).\n",
               s->is_declip ? "clips" : "clicks", s->detected_errors,
               s->nb_samples, 100. * s->detected_errors / s->nb_samples);

    av_audio_fifo_free(s->fifo);
    av_audio_fifo_free(s->efifo);
    av_freep(&s->window_func_lut);
    av_frame_free(&s->enabled);
    av_frame_free(&s->in);
    av_frame_free(&s->out);
    av_frame_free(&s->buffer);
    av_frame_free(&s->is);

    if (s->chan) {
        for (i = 0; i < s->nb_channels; i++) {
            DeclickChannel *c = &s->chan[i];

            av_freep(&c->detection);
            av_freep(&c->auxiliary);
            av_freep(&c->acoefficients);
            av_freep(&c->acorrelation);
            av_freep(&c->tmp);
            av_freep(&c->click);
            av_freep(&c->index);
            av_freep(&c->interpolated);
            av_freep(&c->matrix);
            c->matrix_size = 0;
            av_freep(&c->histogram);
            c->histogram_size = 0;
            av_freep(&c->vector);
            c->vector_size = 0;
            av_freep(&c->y);
            c->y_size = 0;
        }
    }
    av_freep(&s->chan);
    s->nb_channels = 0;
}

static const AVFilterPad inputs[] = {
    {
        .name         = "default",
        .type         = AVMEDIA_TYPE_AUDIO,
        .config_props = config_input,
    },
};


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* -------------------- Constants -------------------- */

#define MAX_CONTACTS    500
#define NAME_LEN        64
#define PHONE_LEN       20
#define EMAIL_LEN       64
#define ADDRESS_LEN     128
#define CATEGORY_LEN    32
#define NOTE_LEN        256
#define FILENAME        "contacts.dat"
#define SEARCH_BUF      128
#define HISTORY_SIZE    10

/* -------------------- Data Structures -------------------- */

typedef struct {
    int    id;
    char   first_name[NAME_LEN];
    char   last_name[NAME_LEN];
    char   phone[PHONE_LEN];
    char   email[EMAIL_LEN];
    char   address[ADDRESS_LEN];
    char   category[CATEGORY_LEN];
    char   notes[NOTE_LEN];
    int    favorite;
    time_t created_at;
    time_t updated_at;
} Contact;

typedef struct {
    Contact contacts[MAX_CONTACTS];
    int     count;
    int     next_id;
    char    history[HISTORY_SIZE][SEARCH_BUF];
    int     history_count;
} ContactDB;

/* -------------------- Function Prototypes -------------------- */

void  init_db(ContactDB *db);
void  display_menu(void);
void  add_contact(ContactDB *db);
void  list_contacts(const ContactDB *db);
void  search_contacts(ContactDB *db);
void  edit_contact(ContactDB *db);
void  delete_contact(ContactDB *db);
void  toggle_favorite(ContactDB *db);
void  show_favorites(const ContactDB *db);
void  sort_contacts(ContactDB *db);
void  show_statistics(const ContactDB *db);
void  export_csv(const ContactDB *db);
void  import_csv(ContactDB *db);
void  save_to_file(const ContactDB *db);
int   load_from_file(ContactDB *db);
void  show_search_history(const ContactDB *db);
void  display_contact(const Contact *c);
void  display_contact_brief(const Contact *c);
void  trim_newline(char *str);
void  str_to_lower(char *dest, const char *src);
int   find_contact_index(const ContactDB *db, int id);
void  add_to_history(ContactDB *db, const char *query);
void  clear_input_buffer(void);
int   confirm_action(const char *message);
char *format_time(time_t t, char *buf, size_t len);
void  print_separator(void);
void  print_header(const char *title);

/* -------------------- Main -------------------- */

int main(void)
{
    ContactDB db;
    int choice;

    init_db(&db);

    if (load_from_file(&db)) {
        printf("[INFO] Loaded %d contact(s) from '%s'.\n", db.count, FILENAME);
    } else {
        printf("[INFO] No existing data found. Starting fresh.\n");
    }

    while (1) {
        display_menu();
        printf("  Enter choice: ");
        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf("\n  [!] Invalid input. Please enter a number.\n");
            continue;
        }
        clear_input_buffer();

        switch (choice) {
            case 1:  add_contact(&db);        break;
            case 2:  list_contacts(&db);      break;
            case 3:  search_contacts(&db);    break;
            case 4:  edit_contact(&db);       break;
            case 5:  delete_contact(&db);     break;
            case 6:  toggle_favorite(&db);    break;
            case 7:  show_favorites(&db);     break;
            case 8:  sort_contacts(&db);      break;
            case 9:  show_statistics(&db);    break;
            case 10: export_csv(&db);         break;
            case 11: import_csv(&db);         break;
            case 12: show_search_history(&db);break;
            case 13: save_to_file(&db);       break;
            case 0:
                save_to_file(&db);
                printf("\n  Goodbye! Contacts saved.\n\n");
                return 0;
            default:
                printf("\n  [!] Invalid choice. Try again.\n");
        }
    }

    return 0;
}

/* -------------------- Initialization -------------------- */

void init_db(ContactDB *db)
{
    memset(db, 0, sizeof(ContactDB));
    db->count = 0;
    db->next_id = 1;
    db->history_count = 0;
}

/* -------------------- UI Helpers -------------------- */

void print_separator(void)
{
    printf("  ");
    for (int i = 0; i < 56; i++) printf("-");
    printf("\n");
}

void print_header(const char *title)
{
    printf("\n");
    print_separator();
    printf("   %s\n", title);
    print_separator();
}

void display_menu(void)
{
    printf("\n");
    printf("  ========================================\n");
    printf("       CONTACT MANAGEMENT SYSTEM\n");
    printf("  ========================================\n");
    printf("   1.  Add Contact\n");
    printf("   2.  List All Contacts\n");
    printf("   3.  Search Contacts\n");
    printf("   4.  Edit Contact\n");
    printf("   5.  Delete Contact\n");
    printf("   6.  Toggle Favorite\n");
    printf("   7.  Show Favorites\n");
    printf("   8.  Sort Contacts\n");
    printf("   9.  Statistics\n");
    printf("   10. Export to CSV\n");
    printf("   11. Import from CSV\n");
    printf("   12. Search History\n");
    printf("   13. Save to File\n");
    printf("   0.  Exit\n");
    printf("  ========================================\n");
}

void clear_input_buffer(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

void str_to_lower(char *dest, const char *src)
{
    while (*src) {
        *dest++ = (char)tolower((unsigned char)*src++);
    }
    *dest = '\0';
}

char *format_time(time_t t, char *buf, size_t len)
{
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buf, "N/A", len);
    }
    return buf;
}

int confirm_action(const char *message)
{
    char response[8];
    printf("  %s (y/n): ", message);
    if (fgets(response, sizeof(response), stdin) == NULL) return 0;
    trim_newline(response);
    return (response[0] == 'y' || response[0] == 'Y');
}

int find_contact_index(const ContactDB *db, int id)
{
    for (int i = 0; i < db->count; i++) {
        if (db->contacts[i].id == id) return i;
    }
    return -1;
}

/* -------------------- Display Functions -------------------- */

void display_contact(const Contact *c)
{
    char time_buf[32];

    printf("\n");
    print_separator();
    printf("   ID:        %d %s\n", c->id, c->favorite ? "[*FAV*]" : "");
    printf("   Name:      %s %s\n", c->first_name, c->last_name);
    printf("   Phone:     %s\n", c->phone);
    printf("   Email:     %s\n", c->email);
    printf("   Address:   %s\n", c->address);
    printf("   Category:  %s\n", c->category);
    printf("   Notes:     %s\n", c->notes);
    printf("   Created:   %s\n", format_time(c->created_at, time_buf, sizeof(time_buf)));
    printf("   Updated:   %s\n", format_time(c->updated_at, time_buf, sizeof(time_buf)));
    print_separator();
}

void display_contact_brief(const Contact *c)
{
    printf("   [%3d] %s%-20s %-20s %-18s %s\n",
           c->id,
           c->favorite ? "*" : " ",
           c->first_name,
           c->last_name,
           c->phone,
           c->category);
}

/* -------------------- Add Contact -------------------- */

void add_contact(ContactDB *db)
{
    if (db->count >= MAX_CONTACTS) {
        printf("\n  [!] Contact database is full (%d max).\n", MAX_CONTACTS);
        return;
    }

    Contact *c = &db->contacts[db->count];
    memset(c, 0, sizeof(Contact));

    print_header("ADD NEW CONTACT");

    printf("   First name: ");
    fgets(c->first_name, NAME_LEN, stdin);
    trim_newline(c->first_name);

    printf("   Last name:  ");
    fgets(c->last_name, NAME_LEN, stdin);
    trim_newline(c->last_name);

    printf("   Phone:      ");
    fgets(c->phone, PHONE_LEN, stdin);
    trim_newline(c->phone);

    printf("   Email:      ");
    fgets(c->email, EMAIL_LEN, stdin);
    trim_newline(c->email);

    printf("   Address:    ");
    fgets(c->address, ADDRESS_LEN, stdin);
    trim_newline(c->address);

    printf("   Category (e.g. Family, Work, Friend): ");
    fgets(c->category, CATEGORY_LEN, stdin);
    trim_newline(c->category);

    printf("   Notes:      ");
    fgets(c->notes, NOTE_LEN, stdin);
    trim_newline(c->notes);

    if (strlen(c->first_name) == 0 && strlen(c->last_name) == 0) {
        printf("\n  [!] Name cannot be empty. Contact not added.\n");
        return;
    }

    c->id = db->next_id++;
    c->favorite = 0;
    c->created_at = time(NULL);
    c->updated_at = c->created_at;
    db->count++;

    printf("\n  [OK] Contact '%s %s' added with ID %d.\n",
           c->first_name, c->last_name, c->id);
}

/* -------------------- List Contacts -------------------- */

void list_contacts(const ContactDB *db)
{
    print_header("ALL CONTACTS");

    if (db->count == 0) {
        printf("   No contacts found.\n");
        print_separator();
        return;
    }

    printf("   %-4s %-1s %-20s %-20s %-18s %s\n",
           "ID", " ", "First Name", "Last Name", "Phone", "Category");
    printf("   ");
    for (int i = 0; i < 80; i++) printf("-");
    printf("\n");

    for (int i = 0; i < db->count; i++) {
        display_contact_brief(&db->contacts[i]);
    }

    printf("\n   Total: %d contact(s)\n", db->count);
    print_separator();

    /* Option to view details */
    printf("\n  Enter contact ID for details (0 to skip): ");
    int id;
    if (scanf("%d", &id) == 1 && id > 0) {
        clear_input_buffer();
        int idx = find_contact_index(db, id);
        if (idx >= 0) {
            display_contact(&db->contacts[idx]);
        } else {
            printf("  [!] Contact ID %d not found.\n", id);
        }
    } else {
        clear_input_buffer();
    }
}

/* -------------------- Search Contacts -------------------- */

void add_to_history(ContactDB *db, const char *query)
{
    if (db->history_count < HISTORY_SIZE) {
        strncpy(db->history[db->history_count], query, SEARCH_BUF - 1);
        db->history[db->history_count][SEARCH_BUF - 1] = '\0';
        db->history_count++;
    } else {
        /* Shift history up */
        for (int i = 0; i < HISTORY_SIZE - 1; i++) {
            strcpy(db->history[i], db->history[i + 1]);
        }
        strncpy(db->history[HISTORY_SIZE - 1], query, SEARCH_BUF - 1);
        db->history[HISTORY_SIZE - 1][SEARCH_BUF - 1] = '\0';
    }
}

void search_contacts(ContactDB *db)
{
    char query[SEARCH_BUF];
    char query_lower[SEARCH_BUF];
    char field_lower[ADDRESS_LEN + NAME_LEN];
    int found = 0;

    print_header("SEARCH CONTACTS");

    printf("   Search by:\n");
    printf("    1. Name\n");
    printf("    2. Phone\n");
    printf("    3. Email\n");
    printf("    4. Category\n");
    printf("    5. All fields\n");
    printf("   Choice: ");

    int mode;
    if (scanf("%d", &mode) != 1 || mode < 1 || mode > 5) {
        clear_input_buffer();
        printf("  [!] Invalid choice.\n");
        return;
    }
    clear_input_buffer();

    printf("   Enter search term: ");
    fgets(query, SEARCH_BUF, stdin);
    trim_newline(query);

    if (strlen(query) == 0) {
        printf("  [!] Empty search term.\n");
        return;
    }

    add_to_history(db, query);
    str_to_lower(query_lower, query);

    printf("\n   Results:\n");
    printf("   ");
    for (int i = 0; i < 80; i++) printf("-");
    printf("\n");

    for (int i = 0; i < db->count; i++) {
        const Contact *c = &db->contacts[i];
        int match = 0;

        switch (mode) {
            case 1: {
                char full_name[NAME_LEN * 2 + 2];
                snprintf(full_name, sizeof(full_name), "%s %s",
                         c->first_name, c->last_name);
                str_to_lower(field_lower, full_name);
                if (strstr(field_lower, query_lower)) match = 1;
                break;
            }
            case 2:
                str_to_lower(field_lower, c->phone);
                if (strstr(field_lower, query_lower)) match = 1;
                break;
            case 3:
                str_to_lower(field_lower, c->email);
                if (strstr(field_lower, query_lower)) match = 1;
                break;
            case 4:
                str_to_lower(field_lower, c->category);
                if (strstr(field_lower, query_lower)) match = 1;
                break;
            case 5: {
                /* Search all fields */
                char combined[512];
                snprintf(combined, sizeof(combined), "%s %s %s %s %s %s %s",
                         c->first_name, c->last_name, c->phone,
                         c->email, c->address, c->category, c->notes);
                str_to_lower(field_lower, combined);
                if (strstr(field_lower, query_lower)) match = 1;
                break;
            }
        }

        if (match) {
            display_contact_brief(c);
            found++;
        }
    }

    printf("\n   Found %d result(s).\n", found);
    print_separator();
}

/* -------------------- Edit Contact -------------------- */

void edit_contact(ContactDB *db)
{
    int id;

    print_header("EDIT CONTACT");

    printf("   Enter contact ID to edit: ");
    if (scanf("%d", &id) != 1) {
        clear_input_buffer();
        printf("  [!] Invalid ID.\n");
        return;
    }
    clear_input_buffer();

    int idx = find_contact_index(db, id);
    if (idx < 0) {
        printf("  [!] Contact ID %d not found.\n", id);
        return;
    }

    Contact *c = &db->contacts[idx];
    display_contact(c);

    printf("   Leave blank to keep current value.\n\n");

    char buf[ADDRESS_LEN];

    printf("   First name [%s]: ", c->first_name);
    fgets(buf, NAME_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->first_name, buf, NAME_LEN - 1);

    printf("   Last name  [%s]: ", c->last_name);
    fgets(buf, NAME_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->last_name, buf, NAME_LEN - 1);

    printf("   Phone      [%s]: ", c->phone);
    fgets(buf, PHONE_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->phone, buf, PHONE_LEN - 1);

    printf("   Email      [%s]: ", c->email);
    fgets(buf, EMAIL_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->email, buf, EMAIL_LEN - 1);

    printf("   Address    [%s]: ", c->address);
    fgets(buf, ADDRESS_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->address, buf, ADDRESS_LEN - 1);

    printf("   Category   [%s]: ", c->category);
    fgets(buf, CATEGORY_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->category, buf, CATEGORY_LEN - 1);

    printf("   Notes      [%s]: ", c->notes);
    fgets(buf, NOTE_LEN, stdin);
    trim_newline(buf);
    if (strlen(buf) > 0) strncpy(c->notes, buf, NOTE_LEN - 1);

    c->updated_at = time(NULL);

    printf("\n  [OK] Contact updated successfully.\n");
}

/* -------------------- Delete Contact -------------------- */

void delete_contact(ContactDB *db)
{
    int id;

    print_header("DELETE CONTACT");

    printf("   Enter contact ID to delete: ");
    if (scanf("%d", &id) != 1) {
        clear_input_buffer();
        printf("  [!] Invalid ID.\n");
        return;
    }
    clear_input_buffer();

    int idx = find_contact_index(db, id);
    if (idx < 0) {
        printf("  [!] Contact ID %d not found.\n", id);
        return;
    }

    display_contact_brief(&db->contacts[idx]);

    if (!confirm_action("Are you sure you want to delete this contact?")) {
        printf("  [INFO] Deletion cancelled.\n");
        return;
    }

    /* Shift remaining contacts */
    char name_buf[NAME_LEN * 2 + 2];
    snprintf(name_buf, sizeof(name_buf), "%s %s",
             db->contacts[idx].first_name, db->contacts[idx].last_name);

    for (int i = idx; i < db->count - 1; i++) {
        db->contacts[i] = db->contacts[i + 1];
    }
    db->count--;

    printf("  [OK] Contact '%s' deleted.\n", name_buf);
}

/* -------------------- Favorites -------------------- */

void toggle_favorite(ContactDB *db)
{
    int id;

    print_header("TOGGLE FAVORITE");

    printf("   Enter contact ID: ");
    if (scanf("%d", &id) != 1) {
        clear_input_buffer();
        printf("  [!] Invalid ID.\n");
        return;
    }
    clear_input_buffer();

    int idx = find_contact_index(db, id);
    if (idx < 0) {
        printf("  [!] Contact ID %d not found.\n", id);
        return;
    }

    db->contacts[idx].favorite = !db->contacts[idx].favorite;
    db->contacts[idx].updated_at = time(NULL);

    printf("  [OK] '%s %s' is %s a favorite.\n",
           db->contacts[idx].first_name,
           db->contacts[idx].last_name,
           db->contacts[idx].favorite ? "now" : "no longer");
}

void show_favorites(const ContactDB *db)
{
    int found = 0;

    print_header("FAVORITE CONTACTS");

    for (int i = 0; i < db->count; i++) {
        if (db->contacts[i].favorite) {
            display_contact_brief(&db->contacts[i]);
            found++;
        }
    }

    if (found == 0) {
        printf("   No favorite contacts.\n");
    } else {
        printf("\n   %d favorite(s)\n", found);
    }
    print_separator();
}

/* -------------------- Sorting -------------------- */

static int cmp_first_name_asc(const void *a, const void *b)
{
    const Contact *ca = (const Contact *)a;
    const Contact *cb = (const Contact *)b;
    return strcasecmp(ca->first_name, cb->first_name);
}

static int cmp_last_name_asc(const void *a, const void *b)
{
    const Contact *ca = (const Contact *)a;
    const Contact *cb = (const Contact *)b;
    return strcasecmp(ca->last_name, cb->last_name);
}

static int cmp_category_asc(const void *a, const void *b)
{
    const Contact *ca = (const Contact *)a;
    const Contact *cb = (const Contact *)b;
    return strcasecmp(ca->category, cb->category);
}

static int cmp_created_desc(const void *a, const void *b)
{
    const Contact *ca = (const Contact *)a;
    const Contact *cb = (const Contact *)b;
    if (cb->created_at > ca->created_at) return 1;
    if (cb->created_at < ca->created_at) return -1;
    return 0;
}

static int cmp_id_asc(const void *a, const void *b)
{
    const Contact *ca = (const Contact *)a;
    const Contact *cb = (const Contact *)b;
    return ca->id - cb->id;
}

void sort_contacts(ContactDB *db)
{
    print_header("SORT CONTACTS");

    if (db->count < 2) {
        printf("   Not enough contacts to sort.\n");
        return;
    }

    printf("   Sort by:\n");
    printf("    1. First name (A-Z)\n");
    printf("    2. Last name (A-Z)\n");
    printf("    3. Category (A-Z)\n");
    printf("    4. Date created (newest first)\n");
    printf("    5. ID (original order)\n");
    printf("   Choice: ");

    int choice;
    if (scanf("%d", &choice) != 1) {
        clear_input_buffer();
        printf("  [!] Invalid choice.\n");
        return;
    }
    clear_input_buffer();

    switch (choice) {
        case 1:
            qsort(db->contacts, db->count, sizeof(Contact), cmp_first_name_asc);
            printf("  [OK] Sorted by first name.\n");
            break;
        case 2:
            qsort(db->contacts, db->count, sizeof(Contact), cmp_last_name_asc);
            printf("  [OK] Sorted by last name.\n");
            break;
        case 3:
            qsort(db->contacts, db->count, sizeof(Contact), cmp_category_asc);
            printf("  [OK] Sorted by category.\n");
            break;
        case 4:
            qsort(db->contacts, db->count, sizeof(Contact), cmp_created_desc);
            printf("  [OK] Sorted by date created.\n");
            break;
        case 5:
            qsort(db->contacts, db->count, sizeof(Contact), cmp_id_asc);
            printf("  [OK] Sorted by ID.\n");
            break;
        default:
            printf("  [!] Invalid sort option.\n");
    }
}

/* -------------------- Statistics -------------------- */

void show_statistics(const ContactDB *db)
{
    print_header("CONTACT STATISTICS");

    printf("   Total contacts:    %d\n", db->count);

    /* Count favorites */
    int fav_count = 0;
    for (int i = 0; i < db->count; i++) {
        if (db->contacts[i].favorite) fav_count++;
    }
    printf("   Favorites:         %d\n", fav_count);

    /* Count by category */
    printf("\n   Contacts by Category:\n");

    typedef struct { char name[CATEGORY_LEN]; int count; } CatCount;
    CatCount categories[MAX_CONTACTS];
    int cat_count = 0;

    for (int i = 0; i < db->count; i++) {
        const char *cat = db->contacts[i].category;
        int found = 0;
        for (int j = 0; j < cat_count; j++) {
            if (strcasecmp(categories[j].name, cat) == 0) {
                categories[j].count++;
                found = 1;
                break;
            }
        }
        if (!found && cat_count < MAX_CONTACTS) {
            strncpy(categories[cat_count].name, cat, CATEGORY_LEN - 1);
            categories[cat_count].name[CATEGORY_LEN - 1] = '\0';
            categories[cat_count].count = 1;
            cat_count++;
        }
    }

    for (int i = 0; i < cat_count; i++) {
        const char *name = strlen(categories[i].name) > 0
                           ? categories[i].name : "(none)";
        printf("    - %-20s : %d\n", name, categories[i].count);
    }

    /* With / without email */
    int with_email = 0, with_phone = 0, with_address = 0;
    for (int i = 0; i < db->count; i++) {
        if (strlen(db->contacts[i].email) > 0)   with_email++;
        if (strlen(db->contacts[i].phone) > 0)   with_phone++;
        if (strlen(db->contacts[i].address) > 0) with_address++;
    }
    printf("\n   Completeness:\n");
    printf("    - With phone:     %d / %d\n", with_phone, db->count);
    printf("    - With email:     %d / %d\n", with_email, db->count);
    printf("    - With address:   %d / %d\n", with_address, db->count);

    /* Most recent contact */
    if (db->count > 0) {
        int newest_idx = 0;
        for (int i = 1; i < db->count; i++) {
            if (db->contacts[i].created_at > db->contacts[newest_idx].created_at) {
                newest_idx = i;
            }
        }
        char time_buf[32];
        printf("\n   Most recent:       %s %s (added %s)\n",
               db->contacts[newest_idx].first_name,
               db->contacts[newest_idx].last_name,
               format_time(db->contacts[newest_idx].created_at,
                           time_buf, sizeof(time_buf)));
    }

    printf("   Search history:    %d queries\n", db->history_count);
    printf("   Database capacity: %d / %d\n", db->count, MAX_CONTACTS);

    print_separator();
}

/* -------------------- CSV Export -------------------- */

void export_csv(const ContactDB *db)
{
    const char *csv_file = "contacts_export.csv";

    print_header("EXPORT TO CSV");

    if (db->count == 0) {
        printf("   No contacts to export.\n");
        return;
    }

    FILE *fp = fopen(csv_file, "w");
    if (!fp) {
        printf("  [!] Failed to open '%s' for writing.\n", csv_file);
        return;
    }

    /* Write CSV header */
    fprintf(fp, "ID,First Name,Last Name,Phone,Email,Address,Category,Notes,Favorite\n");

    for (int i = 0; i < db->count; i++) {
        const Contact *c = &db->contacts[i];
        fprintf(fp, "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d\n",
                c->id, c->first_name, c->last_name, c->phone,
                c->email, c->address, c->category, c->notes, c->favorite);
    }

    fclose(fp);
    printf("  [OK] Exported %d contact(s) to '%s'.\n", db->count, csv_file);
}

/* -------------------- CSV Import -------------------- */

void import_csv(ContactDB *db)
{
    char csv_file[128];

    print_header("IMPORT FROM CSV");

    printf("   Enter CSV filename: ");
    fgets(csv_file, sizeof(csv_file), stdin);
    trim_newline(csv_file);

    if (strlen(csv_file) == 0) {
        printf("  [!] No filename provided.\n");
        return;
    }

    FILE *fp = fopen(csv_file, "r");
    if (!fp) {
        printf("  [!] Failed to open '%s'.\n", csv_file);
        return;
    }

    char line[1024];
    int imported = 0;
    int line_num = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_num++;
        trim_newline(line);

        /* Skip header */
        if (line_num == 1) continue;

        if (db->count >= MAX_CONTACTS) {
            printf("  [!] Database full. Import stopped at line %d.\n", line_num);
            break;
        }

        /* Simple CSV parse (assumes no commas in fields for simplicity) */
        Contact *c = &db->contacts[db->count];
        memset(c, 0, sizeof(Contact));

        char *token;
        int field = 0;
        char *ptr = line;

        while ((token = strsep(&ptr, ",")) != NULL && field < 9) {
            /* Strip quotes */
            size_t tlen = strlen(token);
            if (tlen >= 2 && token[0] == '"' && token[tlen - 1] == '"') {
                token[tlen - 1] = '\0';
                token++;
            }

            switch (field) {
                case 0: /* Skip original ID */ break;
                case 1: strncpy(c->first_name, token, NAME_LEN - 1); break;
                case 2: strncpy(c->last_name, token, NAME_LEN - 1);  break;
                case 3: strncpy(c->phone, token, PHONE_LEN - 1);     break;
                case 4: strncpy(c->email, token, EMAIL_LEN - 1);     break;
                case 5: strncpy(c->address, token, ADDRESS_LEN - 1); break;
                case 6: strncpy(c->category, token, CATEGORY_LEN - 1); break;
                case 7: strncpy(c->notes, token, NOTE_LEN - 1);      break;
                case 8: c->favorite = atoi(token);                     break;
            }
            field++;
        }

        if (strlen(c->first_name) > 0 || strlen(c->last_name) > 0) {
            c->id = db->next_id++;
            c->created_at = time(NULL);
            c->updated_at = c->created_at;
            db->count++;
            imported++;
        }
    }

    fclose(fp);
    printf("  [OK] Imported %d contact(s) from '%s'.\n", imported, csv_file);
}

/* -------------------- File I/O (Binary) -------------------- */

void save_to_file(const ContactDB *db)
{
    FILE *fp = fopen(FILENAME, "wb");
    if (!fp) {
        printf("  [!] Failed to open '%s' for writing.\n", FILENAME);
        return;
    }

    /* Write header info */
    fwrite(&db->count, sizeof(int), 1, fp);
    fwrite(&db->next_id, sizeof(int), 1, fp);

    /* Write contacts */
    fwrite(db->contacts, sizeof(Contact), db->count, fp);

    /* Write search history */
    fwrite(&db->history_count, sizeof(int), 1, fp);
    fwrite(db->history, sizeof(db->history[0]), db->history_count, fp);

    fclose(fp);
    printf("  [OK] Saved %d contact(s) to '%s'.\n", db->count, FILENAME);
}

int load_from_file(ContactDB *db)
{
    FILE *fp = fopen(FILENAME, "rb");
    if (!fp) return 0;

    /* Read header info */
    if (fread(&db->count, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }
    if (fread(&db->next_id, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }

    /* Validate count */
    if (db->count < 0 || db->count > MAX_CONTACTS) {
        fclose(fp);
        init_db(db);
        return 0;
    }

    /* Read contacts */
    if ((int)fread(db->contacts, sizeof(Contact), db->count, fp) != db->count) {
        fclose(fp);
        init_db(db);
        return 0;
    }

    /* Read search history (optional, may not exist in older files) */
    if (fread(&db->history_count, sizeof(int), 1, fp) == 1) {
        if (db->history_count > 0 && db->history_count <= HISTORY_SIZE) {
            fread(db->history, sizeof(db->history[0]), db->history_count, fp);
        }
    }

    fclose(fp);
    return 1;
}

/* -------------------- Search History -------------------- */

void show_search_history(const ContactDB *db)
{
    print_header("SEARCH HISTORY");

    if (db->history_count == 0) {
        printf("   No search history.\n");
        print_separator();
        return;
    }

    for (int i = 0; i < db->history_count; i++) {
        printf("   %2d. \"%s\"\n", i + 1, db->history[i]);
    }

    printf("\n   Total: %d search(es)\n", db->history_count);
    print_separator();
}

/* ==================== End of Program ==================== */