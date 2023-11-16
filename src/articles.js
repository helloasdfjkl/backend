const mongoose = require("mongoose");
const articlesSchema = require("./articlesSchema");
const Article = mongoose.model("article", articlesSchema);

let articles = [
  { id: 0, author: "Mack", body: "Post 1", timestamp: new Date() },
  { id: 1, author: "Jack", body: "Post 2", timestamp: new Date() },
  { id: 2, author: "Zack", body: "Post 3", timestamp: new Date() },
];

// implement GET /articles and GET /articles/:id as one endpoint not two
function getArticle(req, res) {
  const id = req.params.id ? parseInt(req.params.id) : null;

  // If id is provided, fetch the article with that ID
  if (id !== null) {
    Article.find({ id: id }, (err, article) => {
      if (article) {
        res.send({article});
      } else {
        res.status(404).send({ error: "Article not found" });
      }
    });
  }
  // If id is not provided, fetch all articles authored by the logged in user
  else {
    let username = req.username; // Obtained from isLoggedIn middleware
    Article.find({ author: username }, (err, articles) => {
      if (articles) {
        res.send({articles});
      } else {
        res.status(404).send({ error: "No articles found for user" });
      }
    });
  }
}

const addArticle = (req, res) => { // POST /article
  let post = req.body;
  const newArticle = new Article({
    id: articles.length,
    author: post.author,
    body: post.body,
    timestamp: new Date(),
  });
  newArticle.save();
};

function updateArticle(req, res) { //PUT /articles/:id
  //stub
  const id = parseInt(req.params.id);
  let article = articles.find((a) => a.id === id);
  if (article) {
    article.author = req.body.author || article.author;
    article.body = req.body.body || article.body;
    res.send(article);
  } else {
    res.status(404).send({ error: "Article not found" });
  }
}

module.exports = (app) => {
  app.get("/articles/:id?", getArticle); // implement GET /articles and GET /articles/:id as one endpoint not two
  app.post("/article", addArticle);
  app.put("/articles/:id", updateArticle); //stub
};
