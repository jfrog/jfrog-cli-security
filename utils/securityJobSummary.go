package utils

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils/commandsummary"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
)

const (
	PassedSvg = `<svg width="64" height="25" viewBox="0 0 64 25" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="0.5" y="0.5" width="63" height="24" rx="3.5" fill="#D9FAD2"/><rect x="0.5" y="0.5" width="63" height="24" rx="3.5" stroke="#5E6D81"/><path d="M9.064 8.004H13.474C14.1833 8.004 14.762 8.10667 15.21 8.312C15.658 8.51733 16.0033 8.774 16.246 9.082C16.4887 9.39 16.652 9.726 16.736 10.09C16.8293 10.454 16.876 10.79 16.876 11.098C16.876 11.406 16.8293 11.742 16.736 12.106C16.652 12.4607 16.4887 12.792 16.246 13.1C16.0033 13.408 15.658 13.6647 15.21 13.87C14.762 14.066 14.1833 14.164 13.474 14.164H10.814V18H9.064V8.004ZM10.814 12.736H13.376C13.572 12.736 13.7727 12.708 13.978 12.652C14.1833 12.596 14.37 12.5073 14.538 12.386C14.7153 12.2553 14.8553 12.0873 14.958 11.882C15.07 11.6673 15.126 11.4013 15.126 11.084C15.126 10.7573 15.0793 10.4867 14.986 10.272C14.8927 10.0573 14.7667 9.88933 14.608 9.768C14.4493 9.63733 14.2673 9.54867 14.062 9.502C13.8567 9.45533 13.6373 9.432 13.404 9.432H10.814V12.736ZM24.2399 16.39C24.2399 16.586 24.2632 16.726 24.3099 16.81C24.3659 16.894 24.4686 16.936 24.6179 16.936C24.6646 16.936 24.7206 16.936 24.7859 16.936C24.8512 16.936 24.9259 16.9267 25.0099 16.908V18.014C24.9539 18.0327 24.8792 18.0513 24.7859 18.07C24.7019 18.098 24.6132 18.1213 24.5199 18.14C24.4266 18.1587 24.3332 18.1727 24.2399 18.182C24.1466 18.1913 24.0672 18.196 24.0019 18.196C23.6752 18.196 23.4046 18.1307 23.1899 18C22.9752 17.8693 22.8352 17.6407 22.7699 17.314C22.4526 17.622 22.0606 17.846 21.5939 17.986C21.1366 18.126 20.6932 18.196 20.2639 18.196C19.9372 18.196 19.6246 18.1493 19.3259 18.056C19.0272 17.972 18.7612 17.846 18.5279 17.678C18.3039 17.5007 18.1219 17.2813 17.9819 17.02C17.8512 16.7493 17.7859 16.4367 17.7859 16.082C17.7859 15.634 17.8652 15.27 18.0239 14.99C18.1919 14.71 18.4066 14.4907 18.6679 14.332C18.9386 14.1733 19.2372 14.0613 19.5639 13.996C19.8999 13.9213 20.2359 13.8653 20.5719 13.828C20.8612 13.772 21.1366 13.7347 21.3979 13.716C21.6592 13.688 21.8879 13.646 22.0839 13.59C22.2892 13.534 22.4479 13.45 22.5599 13.338C22.6812 13.2167 22.7419 13.0393 22.7419 12.806C22.7419 12.6007 22.6906 12.4327 22.5879 12.302C22.4946 12.1713 22.3732 12.0733 22.2239 12.008C22.0839 11.9333 21.9252 11.8867 21.7479 11.868C21.5706 11.84 21.4026 11.826 21.2439 11.826C20.7959 11.826 20.4272 11.9193 20.1379 12.106C19.8486 12.2927 19.6852 12.582 19.6479 12.974H18.0519C18.0799 12.5073 18.1919 12.12 18.3879 11.812C18.5839 11.504 18.8312 11.2567 19.1299 11.07C19.4379 10.8833 19.7832 10.7527 20.1659 10.678C20.5486 10.6033 20.9406 10.566 21.3419 10.566C21.6966 10.566 22.0466 10.6033 22.3919 10.678C22.7372 10.7527 23.0452 10.874 23.3159 11.042C23.5959 11.21 23.8199 11.4293 23.9879 11.7C24.1559 11.9613 24.2399 12.2833 24.2399 12.666V16.39ZM22.6439 14.374C22.4012 14.5327 22.1026 14.6307 21.7479 14.668C21.3932 14.696 21.0386 14.7427 20.6839 14.808C20.5159 14.836 20.3526 14.878 20.1939 14.934C20.0352 14.9807 19.8952 15.0507 19.7739 15.144C19.6526 15.228 19.5546 15.3447 19.4799 15.494C19.4146 15.634 19.3819 15.8067 19.3819 16.012C19.3819 16.1893 19.4332 16.3387 19.5359 16.46C19.6386 16.5813 19.7599 16.6793 19.8999 16.754C20.0492 16.8193 20.2079 16.866 20.3759 16.894C20.5532 16.922 20.7119 16.936 20.8519 16.936C21.0292 16.936 21.2206 16.9127 21.4259 16.866C21.6312 16.8193 21.8226 16.74 21.9999 16.628C22.1866 16.516 22.3406 16.376 22.4619 16.208C22.5832 16.0307 22.6439 15.816 22.6439 15.564V14.374ZM27.1612 15.676C27.2079 16.1427 27.3852 16.4693 27.6932 16.656C28.0012 16.8427 28.3699 16.936 28.7992 16.936C28.9485 16.936 29.1165 16.9267 29.3032 16.908C29.4992 16.88 29.6812 16.8333 29.8492 16.768C30.0172 16.7027 30.1525 16.6093 30.2552 16.488C30.3672 16.3573 30.4185 16.1893 30.4092 15.984C30.3999 15.7787 30.3252 15.6107 30.1852 15.48C30.0452 15.3493 29.8632 15.2467 29.6392 15.172C29.4245 15.088 29.1772 15.018 28.8972 14.962C28.6172 14.906 28.3325 14.8453 28.0432 14.78C27.7445 14.7147 27.4552 14.6353 27.1752 14.542C26.9045 14.4487 26.6572 14.3227 26.4332 14.164C26.2185 14.0053 26.0459 13.8047 25.9152 13.562C25.7845 13.31 25.7192 13.002 25.7192 12.638C25.7192 12.246 25.8125 11.9193 25.9992 11.658C26.1952 11.3873 26.4379 11.1727 26.7272 11.014C27.0259 10.846 27.3525 10.7293 27.7072 10.664C28.0712 10.5987 28.4165 10.566 28.7432 10.566C29.1165 10.566 29.4712 10.608 29.8072 10.692C30.1525 10.7667 30.4605 10.8927 30.7312 11.07C31.0112 11.2473 31.2399 11.4807 31.4172 11.77C31.6039 12.05 31.7205 12.3907 31.7672 12.792H30.1012C30.0265 12.4093 29.8492 12.1527 29.5692 12.022C29.2985 11.8913 28.9859 11.826 28.6312 11.826C28.5192 11.826 28.3839 11.8353 28.2252 11.854C28.0759 11.8727 27.9312 11.91 27.7912 11.966C27.6605 12.0127 27.5485 12.0873 27.4552 12.19C27.3619 12.2833 27.3152 12.4093 27.3152 12.568C27.3152 12.764 27.3805 12.9227 27.5112 13.044C27.6512 13.1653 27.8285 13.268 28.0432 13.352C28.2672 13.4267 28.5192 13.492 28.7992 13.548C29.0792 13.604 29.3685 13.6647 29.6672 13.73C29.9565 13.7953 30.2412 13.8747 30.5212 13.968C30.8012 14.0613 31.0485 14.1873 31.2632 14.346C31.4872 14.5047 31.6645 14.7053 31.7952 14.948C31.9352 15.1907 32.0052 15.4893 32.0052 15.844C32.0052 16.2733 31.9072 16.6373 31.7112 16.936C31.5152 17.2347 31.2585 17.4773 30.9412 17.664C30.6332 17.8507 30.2879 17.986 29.9052 18.07C29.5225 18.154 29.1445 18.196 28.7712 18.196C28.3139 18.196 27.8892 18.1447 27.4972 18.042C27.1145 17.9393 26.7785 17.7853 26.4892 17.58C26.2092 17.3653 25.9852 17.104 25.8172 16.796C25.6585 16.4787 25.5745 16.1053 25.5652 15.676H27.1612ZM34.421 15.676C34.4676 16.1427 34.645 16.4693 34.953 16.656C35.261 16.8427 35.6296 16.936 36.059 16.936C36.2083 16.936 36.3763 16.9267 36.563 16.908C36.759 16.88 36.941 16.8333 37.109 16.768C37.277 16.7027 37.4123 16.6093 37.515 16.488C37.627 16.3573 37.6783 16.1893 37.669 15.984C37.6596 15.7787 37.585 15.6107 37.445 15.48C37.305 15.3493 37.123 15.2467 36.899 15.172C36.6843 15.088 36.437 15.018 36.157 14.962C35.877 14.906 35.5923 14.8453 35.303 14.78C35.0043 14.7147 34.715 14.6353 34.435 14.542C34.1643 14.4487 33.917 14.3227 33.693 14.164C33.4783 14.0053 33.3056 13.8047 33.175 13.562C33.0443 13.31 32.979 13.002 32.979 12.638C32.979 12.246 33.0723 11.9193 33.259 11.658C33.455 11.3873 33.6976 11.1727 33.987 11.014C34.2856 10.846 34.6123 10.7293 34.967 10.664C35.331 10.5987 35.6763 10.566 36.003 10.566C36.3763 10.566 36.731 10.608 37.067 10.692C37.4123 10.7667 37.7203 10.8927 37.991 11.07C38.271 11.2473 38.4996 11.4807 38.677 11.77C38.8636 12.05 38.9803 12.3907 39.027 12.792H37.361C37.2863 12.4093 37.109 12.1527 36.829 12.022C36.5583 11.8913 36.2456 11.826 35.891 11.826C35.779 11.826 35.6436 11.8353 35.485 11.854C35.3356 11.8727 35.191 11.91 35.051 11.966C34.9203 12.0127 34.8083 12.0873 34.715 12.19C34.6216 12.2833 34.575 12.4093 34.575 12.568C34.575 12.764 34.6403 12.9227 34.771 13.044C34.911 13.1653 35.0883 13.268 35.303 13.352C35.527 13.4267 35.779 13.492 36.059 13.548C36.339 13.604 36.6283 13.6647 36.927 13.73C37.2163 13.7953 37.501 13.8747 37.781 13.968C38.061 14.0613 38.3083 14.1873 38.523 14.346C38.747 14.5047 38.9243 14.7053 39.055 14.948C39.195 15.1907 39.265 15.4893 39.265 15.844C39.265 16.2733 39.167 16.6373 38.971 16.936C38.775 17.2347 38.5183 17.4773 38.201 17.664C37.893 17.8507 37.5476 17.986 37.165 18.07C36.7823 18.154 36.4043 18.196 36.031 18.196C35.5736 18.196 35.149 18.1447 34.757 18.042C34.3743 17.9393 34.0383 17.7853 33.749 17.58C33.469 17.3653 33.245 17.104 33.077 16.796C32.9183 16.4787 32.8343 16.1053 32.825 15.676H34.421ZM45.4467 13.744C45.4281 13.492 45.3721 13.2493 45.2787 13.016C45.1947 12.7827 45.0734 12.582 44.9147 12.414C44.7654 12.2367 44.5787 12.0967 44.3547 11.994C44.1401 11.882 43.8974 11.826 43.6267 11.826C43.3467 11.826 43.0901 11.8773 42.8567 11.98C42.6327 12.0733 42.4367 12.2087 42.2687 12.386C42.1101 12.554 41.9794 12.7547 41.8767 12.988C41.7834 13.2213 41.7321 13.4733 41.7227 13.744H45.4467ZM41.7227 14.794C41.7227 15.074 41.7601 15.3447 41.8347 15.606C41.9187 15.8673 42.0401 16.096 42.1987 16.292C42.3574 16.488 42.5581 16.6467 42.8007 16.768C43.0434 16.88 43.3327 16.936 43.6687 16.936C44.1354 16.936 44.5087 16.838 44.7887 16.642C45.0781 16.4367 45.2927 16.1333 45.4327 15.732H46.9447C46.8607 16.124 46.7161 16.474 46.5107 16.782C46.3054 17.09 46.0581 17.3513 45.7687 17.566C45.4794 17.7713 45.1527 17.9253 44.7887 18.028C44.4341 18.14 44.0607 18.196 43.6687 18.196C43.0994 18.196 42.5954 18.1027 42.1567 17.916C41.7181 17.7293 41.3447 17.468 41.0367 17.132C40.7381 16.796 40.5094 16.3947 40.3507 15.928C40.2014 15.4613 40.1267 14.948 40.1267 14.388C40.1267 13.8747 40.2061 13.3893 40.3647 12.932C40.5327 12.4653 40.7661 12.0593 41.0647 11.714C41.3727 11.3593 41.7414 11.0793 42.1707 10.874C42.6001 10.6687 43.0854 10.566 43.6267 10.566C44.1961 10.566 44.7047 10.6873 45.1527 10.93C45.6101 11.1633 45.9881 11.476 46.2867 11.868C46.5854 12.26 46.8001 12.7127 46.9307 13.226C47.0707 13.73 47.1081 14.2527 47.0427 14.794H41.7227ZM55.074 18H53.562V17.02H53.534C53.3193 17.44 53.0067 17.7433 52.596 17.93C52.1853 18.1073 51.7513 18.196 51.294 18.196C50.7247 18.196 50.2253 18.098 49.796 17.902C49.376 17.6967 49.026 17.4213 48.746 17.076C48.466 16.7307 48.256 16.3247 48.116 15.858C47.976 15.382 47.906 14.8733 47.906 14.332C47.906 13.6787 47.9947 13.114 48.172 12.638C48.3493 12.162 48.5827 11.77 48.872 11.462C49.1707 11.154 49.5067 10.93 49.88 10.79C50.2627 10.6407 50.65 10.566 51.042 10.566C51.266 10.566 51.4947 10.5893 51.728 10.636C51.9613 10.6733 52.1853 10.7387 52.4 10.832C52.6147 10.9253 52.8107 11.0467 52.988 11.196C53.1747 11.336 53.3287 11.504 53.45 11.7H53.478V8.004H55.074V18ZM49.502 14.458C49.502 14.766 49.5393 15.0693 49.614 15.368C49.698 15.6667 49.8193 15.9327 49.978 16.166C50.146 16.3993 50.356 16.586 50.608 16.726C50.86 16.866 51.1587 16.936 51.504 16.936C51.8587 16.936 52.162 16.8613 52.414 16.712C52.6753 16.5627 52.8853 16.3667 53.044 16.124C53.212 15.8813 53.3333 15.6107 53.408 15.312C53.492 15.004 53.534 14.6913 53.534 14.374C53.534 13.5713 53.352 12.946 52.988 12.498C52.6333 12.05 52.148 11.826 51.532 11.826C51.1587 11.826 50.8413 11.9053 50.58 12.064C50.328 12.2133 50.118 12.414 49.95 12.666C49.7913 12.9087 49.6747 13.1887 49.6 13.506C49.5347 13.814 49.502 14.1313 49.502 14.458Z" fill="#414857"/></svg>`
	FailedSvg = `<svg width="56" height="25" viewBox="0 0 56 25" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="0.5" y="0.5" width="55" height="24" rx="3.5" fill="#FFC7C7"/><rect x="0.5" y="0.5" width="55" height="24" rx="3.5" stroke="#5E6D81"/><path d="M9.064 8.004H15.966V9.516H10.814V12.134H15.336V13.562H10.814V18H9.064V8.004ZM23.2008 16.39C23.2008 16.586 23.2242 16.726 23.2708 16.81C23.3268 16.894 23.4295 16.936 23.5788 16.936C23.6255 16.936 23.6815 16.936 23.7468 16.936C23.8122 16.936 23.8868 16.9267 23.9708 16.908V18.014C23.9148 18.0327 23.8402 18.0513 23.7468 18.07C23.6628 18.098 23.5742 18.1213 23.4808 18.14C23.3875 18.1587 23.2942 18.1727 23.2008 18.182C23.1075 18.1913 23.0282 18.196 22.9628 18.196C22.6362 18.196 22.3655 18.1307 22.1508 18C21.9362 17.8693 21.7962 17.6407 21.7308 17.314C21.4135 17.622 21.0215 17.846 20.5548 17.986C20.0975 18.126 19.6542 18.196 19.2248 18.196C18.8982 18.196 18.5855 18.1493 18.2868 18.056C17.9882 17.972 17.7222 17.846 17.4888 17.678C17.2648 17.5007 17.0828 17.2813 16.9428 17.02C16.8122 16.7493 16.7468 16.4367 16.7468 16.082C16.7468 15.634 16.8262 15.27 16.9848 14.99C17.1528 14.71 17.3675 14.4907 17.6288 14.332C17.8995 14.1733 18.1982 14.0613 18.5248 13.996C18.8608 13.9213 19.1968 13.8653 19.5328 13.828C19.8222 13.772 20.0975 13.7347 20.3588 13.716C20.6202 13.688 20.8488 13.646 21.0448 13.59C21.2502 13.534 21.4088 13.45 21.5208 13.338C21.6422 13.2167 21.7028 13.0393 21.7028 12.806C21.7028 12.6007 21.6515 12.4327 21.5488 12.302C21.4555 12.1713 21.3342 12.0733 21.1848 12.008C21.0448 11.9333 20.8862 11.8867 20.7088 11.868C20.5315 11.84 20.3635 11.826 20.2048 11.826C19.7568 11.826 19.3882 11.9193 19.0988 12.106C18.8095 12.2927 18.6462 12.582 18.6088 12.974H17.0128C17.0408 12.5073 17.1528 12.12 17.3488 11.812C17.5448 11.504 17.7922 11.2567 18.0908 11.07C18.3988 10.8833 18.7442 10.7527 19.1268 10.678C19.5095 10.6033 19.9015 10.566 20.3028 10.566C20.6575 10.566 21.0075 10.6033 21.3528 10.678C21.6982 10.7527 22.0062 10.874 22.2768 11.042C22.5568 11.21 22.7808 11.4293 22.9488 11.7C23.1168 11.9613 23.2008 12.2833 23.2008 12.666V16.39ZM21.6048 14.374C21.3622 14.5327 21.0635 14.6307 20.7088 14.668C20.3542 14.696 19.9995 14.7427 19.6448 14.808C19.4768 14.836 19.3135 14.878 19.1548 14.934C18.9962 14.9807 18.8562 15.0507 18.7348 15.144C18.6135 15.228 18.5155 15.3447 18.4408 15.494C18.3755 15.634 18.3428 15.8067 18.3428 16.012C18.3428 16.1893 18.3942 16.3387 18.4968 16.46C18.5995 16.5813 18.7208 16.6793 18.8608 16.754C19.0102 16.8193 19.1688 16.866 19.3368 16.894C19.5142 16.922 19.6728 16.936 19.8128 16.936C19.9902 16.936 20.1815 16.9127 20.3868 16.866C20.5922 16.8193 20.7835 16.74 20.9608 16.628C21.1475 16.516 21.3015 16.376 21.4228 16.208C21.5442 16.0307 21.6048 15.816 21.6048 15.564V14.374ZM24.9601 8.004H26.5561V9.516H24.9601V8.004ZM24.9601 10.762H26.5561V18H24.9601V10.762ZM28.3371 8.004H29.9331V18H28.3371V8.004ZM36.642 13.744C36.6234 13.492 36.5674 13.2493 36.474 13.016C36.39 12.7827 36.2687 12.582 36.11 12.414C35.9607 12.2367 35.774 12.0967 35.55 11.994C35.3354 11.882 35.0927 11.826 34.822 11.826C34.542 11.826 34.2854 11.8773 34.052 11.98C33.828 12.0733 33.632 12.2087 33.464 12.386C33.3054 12.554 33.1747 12.7547 33.072 12.988C32.9787 13.2213 32.9274 13.4733 32.918 13.744H36.642ZM32.918 14.794C32.918 15.074 32.9554 15.3447 33.03 15.606C33.114 15.8673 33.2354 16.096 33.394 16.292C33.5527 16.488 33.7534 16.6467 33.996 16.768C34.2387 16.88 34.528 16.936 34.864 16.936C35.3307 16.936 35.704 16.838 35.984 16.642C36.2734 16.4367 36.488 16.1333 36.628 15.732H38.14C38.056 16.124 37.9114 16.474 37.706 16.782C37.5007 17.09 37.2534 17.3513 36.964 17.566C36.6747 17.7713 36.348 17.9253 35.984 18.028C35.6294 18.14 35.256 18.196 34.864 18.196C34.2947 18.196 33.7907 18.1027 33.352 17.916C32.9134 17.7293 32.54 17.468 32.232 17.132C31.9334 16.796 31.7047 16.3947 31.546 15.928C31.3967 15.4613 31.322 14.948 31.322 14.388C31.322 13.8747 31.4014 13.3893 31.56 12.932C31.728 12.4653 31.9614 12.0593 32.26 11.714C32.568 11.3593 32.9367 11.0793 33.366 10.874C33.7954 10.6687 34.2807 10.566 34.822 10.566C35.3914 10.566 35.9 10.6873 36.348 10.93C36.8054 11.1633 37.1834 11.476 37.482 11.868C37.7807 12.26 37.9954 12.7127 38.126 13.226C38.266 13.73 38.3034 14.2527 38.238 14.794H32.918ZM46.2693 18H44.7573V17.02H44.7293C44.5147 17.44 44.202 17.7433 43.7913 17.93C43.3807 18.1073 42.9467 18.196 42.4893 18.196C41.92 18.196 41.4207 18.098 40.9913 17.902C40.5713 17.6967 40.2213 17.4213 39.9413 17.076C39.6613 16.7307 39.4513 16.3247 39.3113 15.858C39.1713 15.382 39.1013 14.8733 39.1013 14.332C39.1013 13.6787 39.19 13.114 39.3673 12.638C39.5447 12.162 39.778 11.77 40.0673 11.462C40.366 11.154 40.702 10.93 41.0753 10.79C41.458 10.6407 41.8453 10.566 42.2373 10.566C42.4613 10.566 42.69 10.5893 42.9233 10.636C43.1567 10.6733 43.3807 10.7387 43.5953 10.832C43.81 10.9253 44.006 11.0467 44.1833 11.196C44.37 11.336 44.524 11.504 44.6453 11.7H44.6733V8.004H46.2693V18ZM40.6973 14.458C40.6973 14.766 40.7347 15.0693 40.8093 15.368C40.8933 15.6667 41.0147 15.9327 41.1733 16.166C41.3413 16.3993 41.5513 16.586 41.8033 16.726C42.0553 16.866 42.354 16.936 42.6993 16.936C43.054 16.936 43.3573 16.8613 43.6093 16.712C43.8707 16.5627 44.0807 16.3667 44.2393 16.124C44.4073 15.8813 44.5287 15.6107 44.6033 15.312C44.6873 15.004 44.7293 14.6913 44.7293 14.374C44.7293 13.5713 44.5473 12.946 44.1833 12.498C43.8287 12.05 43.3433 11.826 42.7273 11.826C42.354 11.826 42.0367 11.9053 41.7753 12.064C41.5233 12.2133 41.3133 12.414 41.1453 12.666C40.9867 12.9087 40.87 13.1887 40.7953 13.506C40.73 13.814 40.6973 14.1313 40.6973 14.458Z" fill="#414857"/></svg>`
)

const (
	Build    SecuritySummarySection = "Build-info Scans"
	Binary   SecuritySummarySection = "Artifact Scans"
	Modules  SecuritySummarySection = "Source Code Scans"
	Docker   SecuritySummarySection = "Docker Image Scans"
	Curation SecuritySummarySection = "Curation Audit"

	PreFormat     HtmlTag = "<pre>%s</pre>"
	ImgTag        HtmlTag = "<picture><img alt=\"%s\" src=%s style=\"width: 100%; display: block\"></picture>"
	CenterContent HtmlTag = "<div style=\"display: flex; align-items: center; text-align: center\">%s</div>"
	BoldTxt       HtmlTag = "<b>%s</b>"
	Link          HtmlTag = "<a href=\"%s\">%s</a>"
	NewLine       HtmlTag = "<br>%s"
	Details       HtmlTag = "<details><summary>%s</summary>%s</details>"
	DetailsOpen   HtmlTag = "<details open><summary><h3>%s</h3></summary>%s</details>"
	RedColor      HtmlTag = "<span style=\"color:red\">%s</span>"
	OrangeColor   HtmlTag = "<span style=\"color:orange\">%s</span>"
	GreenColor    HtmlTag = "<span style=\"color:green\">%s</span>"
	TabTag        HtmlTag = "&Tab;%s"

	ApplicableStatus    SeverityStatus = "%d Applicable"
	NotApplicableStatus SeverityStatus = "%d Not Applicable"
)

type SecuritySummarySection string
type HtmlTag string
type SeverityStatus string

func (c HtmlTag) Format(args ...any) string {
	return fmt.Sprintf(string(c), args...)
}

func (c HtmlTag) FormatInt(value int) string {
	return fmt.Sprintf(string(c), fmt.Sprintf("%d", value))
}

func (s SeverityStatus) Format(count int) string {
	return fmt.Sprintf(string(s), count)
}

type SecurityJobSummary struct{}

func NewCurationSummary(cmdResult formats.ResultsSummary) (summary ScanCommandResultSummary) {
	summary.ResultType = Curation
	summary.Summary = cmdResult
	return
}

func newResultSummary(cmdResults *Results, section SecuritySummarySection, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool) (summary ScanCommandResultSummary) {
	summary.ResultType = section
	summary.Args = &ResultSummaryArgs{BaseJfrogUrl: serverDetails.Url}
	summary.Summary = ToSummary(cmdResults, vulnerabilitiesReqested, violationsReqested)
	return
}

func NewBuildScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool, buildName, buildNumber string) (summary ScanCommandResultSummary) {
	summary = newResultSummary(cmdResults, Build, serverDetails, vulnerabilitiesReqested, violationsReqested)
	summary.Args.BuildName = buildName
	summary.Args.BuildNumbers = []string{buildNumber}
	return
}

func NewDockerScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool, dockerImage string) (summary ScanCommandResultSummary) {
	summary = newResultSummary(cmdResults, Docker, serverDetails, vulnerabilitiesReqested, violationsReqested)
	summary.Args.DockerImage = dockerImage
	return
}

func NewBinaryScanSummary(cmdResults *Results, serverDetails *config.ServerDetails, vulnerabilitiesReqested, violationsReqested bool) (summary ScanCommandResultSummary) {
	return newResultSummary(cmdResults, Binary, serverDetails, vulnerabilitiesReqested, violationsReqested)
}

type ResultSummaryArgs struct {
	// Url to more details in JFrog UI
	// MoreInfoUrl string `json:"more_info_url,omitempty"`
	BaseJfrogUrl string `json:"base_jfrog_url,omitempty"`
	// Args to id the result
	DockerImage  string   `json:"docker_image,omitempty"`
	BuildName    string   `json:"build_name,omitempty"`
	BuildNumbers []string `json:"build_numbers,omitempty"`
	// ScanIds 	 []string `json:"scan_ids,omitempty"`
}

func (rsa ResultSummaryArgs) GetUrl(index commandsummary.Index, scanIds ...string) string {
	if rsa.BaseJfrogUrl == "" {
		return ""
	}
	if index == commandsummary.BuildScan {
		return fmt.Sprintf("%s/ui/scans-list/builds-scans", rsa.BaseJfrogUrl)
	} else {
		baseUrl := fmt.Sprintf("%s/ui/onDemandScanning", rsa.BaseJfrogUrl)
		if len(scanIds) == 1 {
			return fmt.Sprintf("%s/%s", baseUrl, scanIds[0])
		}
		return fmt.Sprintf("%s/list", baseUrl)
	}
}

func (rsa ResultSummaryArgs) ToArgs(index commandsummary.Index) (args []string) {
	if index == commandsummary.BuildScan {
		args = append(args, rsa.BuildName)
		args = append(args, rsa.BuildNumbers...)
	} else if index == commandsummary.DockerScan {
		args = append(args, rsa.DockerImage)
	}
	return
}

type ScanCommandResultSummary struct {
	ResultType SecuritySummarySection `json:"resultType"`
	Args       *ResultSummaryArgs     `json:"args,omitempty"`
	Summary    formats.ResultsSummary `json:"summary"`
}

// Manage the job summary for security commands
func NewSecurityJobSummary() (js *commandsummary.CommandSummary, err error) {
	return commandsummary.New(&SecurityJobSummary{}, "security")
}

// Record the security command outputs
func RecordSecurityCommandSummary(content ScanCommandResultSummary) (err error) {
	if !commandsummary.ShouldRecordSummary() {
		return
	}
	manager, err := NewSecurityJobSummary()
	if err != nil || manager == nil {
		return
	}
	if index := getDataIndexFromSection(content.ResultType); index != "" {
		return recordIndexData(manager, content, index)
	}
	return manager.Record(content)
}

func getDataIndexFromSection(section SecuritySummarySection) commandsummary.Index {
	switch section {
	case Build:
		return commandsummary.BuildScan
	case Binary:
		return commandsummary.BinariesScan
	case Docker:
		return commandsummary.DockerScan
	}
	// No index for the section
	return ""
}

func recordIndexData(manager *commandsummary.CommandSummary, content ScanCommandResultSummary, index commandsummary.Index) (err error) {
	if index == commandsummary.BinariesScan {
		for _, scan := range content.Summary.Scans {
			err = errors.Join(err, manager.RecordWithIndex(newScanCommandResultSummary(content.ResultType, content.Args, scan), index, scan.Target))
		}
	} else {
		// Save the results based on the index and the provided arguments (keys)
		// * Docker scan results are saved with the image tag as the key
		// * Build scan results are saved with the build name and number as the key
		err = manager.RecordWithIndex(content, index, content.Args.ToArgs(index)...)
	}
	return
}

func newScanCommandResultSummary(resultType SecuritySummarySection, args *ResultSummaryArgs, scans ...formats.ScanSummary) ScanCommandResultSummary {
	return ScanCommandResultSummary{ResultType: resultType, Args: args, Summary: formats.ResultsSummary{Scans: scans}}
}

func loadContent(dataFiles []string, filterSections ...SecuritySummarySection) ([]formats.ResultsSummary, ResultSummaryArgs, error) {
	data := []formats.ResultsSummary{}
	args := ResultSummaryArgs{}
	for _, dataFilePath := range dataFiles {
		// Load file content
		var cmdResults ScanCommandResultSummary
		if err := commandsummary.UnmarshalFromFilePath(dataFilePath, &cmdResults); err != nil {
			return nil, args, fmt.Errorf("failed while Unmarshal '%s': %w", dataFilePath, err)
		}
		if len(filterSections) == 0 || (slices.Contains(filterSections, cmdResults.ResultType)) {
			data = append(data, cmdResults.Summary)
			if cmdResults.Args == nil {
				continue
			}
			if args.BaseJfrogUrl == "" {
				args.BaseJfrogUrl = cmdResults.Args.BaseJfrogUrl
			}
			if args.DockerImage == "" {
				args.DockerImage = cmdResults.Args.DockerImage
			}
			if args.BuildName == "" {
				args.BuildName = cmdResults.Args.BuildName
			}
			args.BuildNumbers = append(args.BuildNumbers, cmdResults.Args.BuildNumbers...)
		}
	}
	return data, args, nil
}

func (js *SecurityJobSummary) BinaryScan(filePaths []string) (generator DynamicMarkdownGenerator, err error) {
	generator = DynamicMarkdownGenerator{index: commandsummary.BinariesScan, dataFiles: filePaths, extendedView: true}
	err = generator.loadContentFromFiles()
	return
}

func (js *SecurityJobSummary) BuildScan(filePaths []string) (generator DynamicMarkdownGenerator, err error) {
	generator = DynamicMarkdownGenerator{index: commandsummary.BuildScan, dataFiles: filePaths, extendedView: true}
	err = generator.loadContentFromFiles()
	return
}

func (js *SecurityJobSummary) DockerScan(filePaths []string) (generator DynamicMarkdownGenerator, err error) {
	generator = DynamicMarkdownGenerator{index: commandsummary.DockerScan, dataFiles: filePaths, extendedView: true}
	err = generator.loadContentFromFiles()
	return
}

func (js *SecurityJobSummary) GetNonScannedResult() (generator EmptyMarkdownGenerator, _ error) {
	generator = EmptyMarkdownGenerator{}
	return
}

// Generate the Security section (Curation)
func (js *SecurityJobSummary) GenerateMarkdownFromFiles(dataFilePaths []string) (markdown string, err error) {
	curationData, _, err := loadContent(dataFilePaths, Curation)
	if err != nil {
		return
	}
	markdown, err = GenerateSecuritySectionMarkdown(curationData)
	if err == nil && markdown != "" {
		failed := false
		status := ""
		if failed {
			status += " " + FailedSvg
		}
		markdown = DetailsOpen.Format("🔒 " + fmt.Sprintf("Security Summary%s", status), markdown)
	}
	return
}

func GenerateSecuritySectionMarkdown(curationData []formats.ResultsSummary) (markdown string, err error) {
	if !hasCurationCommand(curationData) {
		return
	}
	// Create the markdown content
	markdown += fmt.Sprintf("#### %s\n| Audit Summary | Project name | Audit Details |\n|--------|--------|---------|", Curation)
	for i := range curationData {
		for _, summary := range curationData[i].Scans {
			status := PassedSvg
			if summary.HasBlockedPackages() {
				status = FailedSvg
			}
			markdown += fmt.Sprintf("\n| %s | %s | %s |", status, summary.Target, PreFormat.Format(getCurationDetailsString(summary)))
		}
	}
	return
}

func hasCurationCommand(data []formats.ResultsSummary) bool {
	for _, summary := range data {
		for _, scan := range summary.Scans {
			if scan.HasCuratedPackages() {
				return true
			}
		}
	}
	return false
}

type blockedPackageByType struct {
	BlockedType    string
	BlockedSummary map[string]int
}

func getCurationDetailsString(summary formats.ScanSummary) (content string) {
	if summary.CuratedPackages == nil {
		return
	}
	content += fmt.Sprintf("Total Number of resolved packages: %s", BoldTxt.FormatInt(summary.CuratedPackages.PackageCount))
	blockedPackages := summary.CuratedPackages.GetBlockedCount()
	if blockedPackages == 0 {
		return
	}
	content += NewLine.Format(fmt.Sprintf("🟢 Approved packages: %s", BoldTxt.FormatInt(summary.CuratedPackages.GetApprovedCount())))
	content += NewLine.Format(fmt.Sprintf("🔴 Blocked packages: %s", BoldTxt.FormatInt(blockedPackages)))
	// Display the blocked packages grouped by type
	var blocked []blockedPackageByType
	// Sort the blocked packages by name
	for _, blockTypeValue := range summary.CuratedPackages.Blocked {
		blocked = append(blocked, toBlockedPackgeByType(blockTypeValue))
	}
	sort.Slice(blocked, func(i, j int) bool {
		return blocked[i].BlockedType > blocked[j].BlockedType
	})
	// Display the blocked packages
	for _, blockStruct := range blocked {
		content += NewLine.Format(
			Details.Format(
				fmt.Sprintf("%s (%s)", blockStruct.BlockedType, BoldTxt.FormatInt(len(blockStruct.BlockedSummary))),
				getBlockedPackages(blockStruct.BlockedSummary),
			),
		)
	}
	return
}

func toBlockedPackgeByType(blockTypeValue formats.BlockedPackages) blockedPackageByType {
	return blockedPackageByType{BlockedType: formatPolicyAndCond(blockTypeValue.Policy, blockTypeValue.Condition), BlockedSummary: blockTypeValue.Packages}
}

func formatPolicyAndCond(policy, cond string) string {
	return fmt.Sprintf("%s %s, %s %s", BoldTxt.Format("Violated Policy:"), policy, BoldTxt.Format("Condition:"), cond)
}

func getBlockedPackages(blockedSummary map[string]int) string {
	content := ""
	for blockedPackage, _ := range blockedSummary {
		content += NewLine.Format(fmt.Sprintf("📦 %s", blockedPackage))
	}
	return content
}

type EmptyMarkdownGenerator struct{}

func (g EmptyMarkdownGenerator) GetViolations() (content string) {
	return PreFormat.Format("Not Scanned")
}

func (g EmptyMarkdownGenerator) GetVulnerabilities() (content string) {
	return PreFormat.Format("Not Scanned")
}

type DynamicMarkdownGenerator struct {
	index        commandsummary.Index
	extendedView bool
	dataFiles    []string
	content      []formats.ResultsSummary
	args         ResultSummaryArgs
}

func (mg *DynamicMarkdownGenerator) loadContentFromFiles() (err error) {
	if len(mg.content) > 0 {
		// Already loaded
		return
	}
	mg.content, mg.args, err = loadContent(mg.dataFiles)
	return
}

func (mg DynamicMarkdownGenerator) GetViolations() (content string) {
	summary := formats.GetViolationSummaries(mg.content...)
	if summary == nil {
		content = PreFormat.Format("No watch is defined")
		return
	}
	resultsMarkdown := generateResultsMarkdown(true, getJfrogUrl(mg.index, mg.args, &summary.ScanResultSummary, mg.extendedView), &summary.ScanResultSummary)
	if len(summary.Watches) == 0 {
		content = resultsMarkdown
		return
	}
	watches := "watch"
	if len(summary.Watches) > 1 {
		watches += "es"
	}
	watches += ": " + strings.Join(summary.Watches, ", ")
	content = PreFormat.Format(watches) + NewLine.Format(resultsMarkdown)
	return
}

func (mg DynamicMarkdownGenerator) GetVulnerabilities() (content string) {
	summary := formats.GetVulnerabilitiesSummaries(mg.content...)
	if summary == nil {
		// We are in violation mode and vulnerabilities are not requested (no info to show)
		return
	}
	content = generateResultsMarkdown(false, getJfrogUrl(mg.index, mg.args, summary, mg.extendedView), summary)
	return
}

func getJfrogUrl(index commandsummary.Index, args ResultSummaryArgs, summary *formats.ScanResultSummary, extendedView bool) (url string) {
	if !extendedView {
		return
	}
	if summary.ScaResults != nil {
		if moreInfoUrls := summary.ScaResults.MoreInfoUrls; len(moreInfoUrls) > 0 {
			return Link.Format(moreInfoUrls[0], "See the results of the scan in JFrog")
		}
	}
	if defaultUrl := args.GetUrl(index, summary.GetScanIds()...); defaultUrl != "" {
		return Link.Format(defaultUrl, "See the results of the scan in JFrog")
	}
	return
}

func generateResultsMarkdown(violations bool, moreInfoUrl string, content *formats.ScanResultSummary) (markdown string) {
	if !content.HasIssues() {
		markdown = getNoIssuesMarkdown(violations)
	} else {
		markdown = getResultsTypesSummaryString(violations, content)
		markdown += NewLine.Format(getResultsSeveritySummaryString(content))
		if moreInfoUrl != "" {
			markdown += NewLine.Format(moreInfoUrl)
		}
	}
	markdown = PreFormat.Format(markdown)
	return
}

func getNoIssuesMarkdown(violations bool) (markdown string) {
	noIssuesStr := "No security issues found"
	if violations {
		noIssuesStr = "No violations found"
	}
	return getCenteredSvgWithText(PassedSvg, noIssuesStr)
}

func getCenteredSvgWithText(svg, text string) (markdown string) {
	return CenterContent.Format(fmt.Sprintf("%s %s", svg, text))
}

func getResultsTypesSummaryString(violations bool, summary *formats.ScanResultSummary) (content string) {
	if violations {
		content = fmt.Sprintf("%d Policy Violations:", summary.GetTotal())
	} else {
		content = fmt.Sprintf("%d Security Issues:", summary.GetTotal())
	}
	if summary.ScaResults != nil {
		if violations {
			if count := summary.GetTotal(formats.ScaSecurityResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaSecurityResult.String()))
			}
			if count := summary.GetTotal(formats.ScaOperationalResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaOperationalResult.String()))
			}
			if count := summary.GetTotal(formats.ScaLicenseResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaLicenseResult.String()))
			}
		} else {
			if count := summary.GetTotal(formats.ScaSecurityResult); count > 0 {
				content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.ScaResult.String()))
			}
		}
	}
	if summary.SecretsResults != nil {
		if count := summary.GetTotal(formats.SecretsResult); count > 0 {
			content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.SecretsResult.String()))
		}
	}
	if summary.SastResults != nil {
		if count := summary.GetTotal(formats.SastResult); count > 0 {
			content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.SastResult.String()))
		}
	}
	if summary.IacResults != nil {
		if count := summary.GetTotal(formats.IacResult); count > 0 {
			content += TabTag.Format(fmt.Sprintf("%d %s", count, formats.IacResult.String()))
		}
	}
	return
}

func getResultsSeveritySummaryString(summary *formats.ScanResultSummary) (markdown string) {
	details := summary.GetSummaryBySeverity()
	if details.GetTotal(severityutils.Critical.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Critical, details))
	}
	if details.GetTotal(severityutils.High.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.High, details))
	}
	if details.GetTotal(severityutils.Medium.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Medium, details))
	}
	if details.GetTotal(severityutils.Low.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Low, details))
	}
	if details.GetTotal(severityutils.Unknown.String()) > 0 {
		markdown += NewLine.Format(getSeverityMarkdown(severityutils.Unknown, details))
	}
	return
}

func getSeverityMarkdown(severity severityutils.Severity, details formats.ResultSummary) (markdown string) {
	svg := severityutils.GetSeverityIcon(severity)
	severityStr := severity.String()
	totalSeverityIssues := details.GetTotal(severityStr)
	severityMarkdown := fmt.Sprintf("%d %s%s", totalSeverityIssues, severityStr, getSeverityStatusesCountString(details[severityStr]))
	return getCenteredSvgWithText(svg, severityMarkdown)
}

func getSeverityStatusesCountString(statusCounts map[string]int) string {
	return generateSeverityStatusesCountString(getSeverityDisplayStatuses(statusCounts))
}

func getSeverityDisplayStatuses(statusCounts map[string]int) (displayData map[SeverityStatus]int) {
	displayData = map[SeverityStatus]int{}
	for status, count := range statusCounts {
		switch status {
		case jasutils.Applicability.String():
			displayData[ApplicableStatus] += count
		case jasutils.NotApplicable.String():
			displayData[NotApplicableStatus] += count
		}
	}
	return displayData
}

func generateSeverityStatusesCountString(displayData map[SeverityStatus]int) string {
	if len(displayData) == 0 {
		return ""
	}
	display := []string{}
	if count, ok := displayData[ApplicableStatus]; ok {
		display = append(display, ApplicableStatus.Format(count))
	}
	if count, ok := displayData[NotApplicableStatus]; ok {
		display = append(display, NotApplicableStatus.Format(count))
	}
	return fmt.Sprintf(" (%s)", strings.Join(display, ", "))
}
