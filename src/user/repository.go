package user

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Repository struct {
	col *mongo.Collection
}

func NewRepository(db *mongo.Database) *Repository {
	return &Repository{
		col: db.Collection("users"),
	}
}

func (r *Repository) CreateUser(ctx context.Context, u *User) error {
	_, err := r.col.InsertOne(ctx, u)
	return err
}

func (r *Repository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	filter := bson.M{"username": username}

	var u User
	err := r.col.FindOne(ctx, filter).Decode(&u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *Repository) GetUserByPublicID(ctx context.Context, publicID string) (*User, error) {
	filter := bson.M{"id": publicID}

	var u User
	err := r.col.FindOne(ctx, filter).Decode(&u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *Repository) ListUsers(ctx context.Context, limit int64) ([]User, error) {
	opts := options.Find().SetLimit(limit)

	cur, err := r.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var users []User
	for cur.Next(ctx) {
		var u User
		if err := cur.Decode(&u); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, cur.Err()
}
