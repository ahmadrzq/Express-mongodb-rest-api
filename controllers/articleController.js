const { Article } = require('../models');

exports.createArticle = async (req, res) => {
    try {
        const article = await Article.create(req.body);
        res.status(201).json(article);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
};

exports.getArticles = async (req, res) => {
    const articles = await Article.findAll();
    res.json(articles);
};

exports.getArticleById = async (req, res) => {
    const article = await Article.findByPk(req.params.id);
    if (article) {
        res.json(article);
    } else {
        res.status(404).json({ error: 'Article not found' });
    }
};

exports.updateArticle = async (req, res) => {
    const article = await Article.findByPk(req.params.id);
    if (article) {
        try {
            await article.update(req.body);
            res.json(article);
        } catch (err) {
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(404).json({ error: 'Article not found' });
    }
};

exports.deleteArticle = async (req, res) => {
    const article = await Article.findByPk(req.params.id);
    if (article) {
        await article.destroy();
        res.status(200).json({ message: 'Article deleted' });
    } else {
        res.status(404).json({ error: 'Article not found' });
    }
};
