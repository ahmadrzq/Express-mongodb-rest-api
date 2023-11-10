module.exports = (sequelize, DataTypes) => {
    const Article = sequelize.define('Article', {
        title: DataTypes.STRING,
        body: DataTypes.TEXT,
    });

    return Article;
};
