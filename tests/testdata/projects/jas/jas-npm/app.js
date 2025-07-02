const express = require('express')
const fileUpload = require('express-fileupload');
const undici = require('undici')
const path = require('path')
const fs = require('fs');
const app = express()
const port = 8080

app.use(fileUpload({parseNested: false}));

app.get('/', (req, res) => {
  console.log(path.join(__dirname+'/views/index.html'))
  res.sendFile(path.join(__dirname+'/views/index.html'));

})

app.post("/uploadFile", (req, res) => {
  if (!req.files) {
    return res.status(400).send("No files were uploaded.");
  }

  const file = req.files.myFile;
  const path = __dirname + "/uploads/" + file.name;

  file.mv(path, (err) => {
    if (err) {
      return res.status(500).send(err);
    }
    return res.send({ status: "success", path: path });
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})