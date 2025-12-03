package group

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
		col: db.Collection("groups"),
	}
}

func (r *Repository) CreateGroup(ctx context.Context, g *Group) error {
	_, err := r.col.InsertOne(ctx, g)
	return err
}

func (r *Repository) GetGroupByID(ctx context.Context, id string) (*Group, error) {
	filter := bson.M{"id": id}

	var g Group
	err := r.col.FindOne(ctx, filter).Decode(&g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (r *Repository) ListGroups(ctx context.Context, limit int64) ([]Group, error) {
	opts := options.Find().SetLimit(limit)

	cur, err := r.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var groups []Group
	for cur.Next(ctx) {
		var g Group
		if err := cur.Decode(&g); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, cur.Err()
}

func (r *Repository) AddMember(ctx context.Context, groupID string, userID string) error {
	filter := bson.M{"id": groupID}
	update := bson.M{"$addToSet": bson.M{"members": userID}}

	_, err := r.col.UpdateOne(ctx, filter, update)
	return err
}

func (r *Repository) RemoveMember(ctx context.Context, groupID string, userID string) error {
	filter := bson.M{"id": groupID}
	update := bson.M{"$pull": bson.M{"members": userID}}

	_, err := r.col.UpdateOne(ctx, filter, update)
	return err
}

func (r *Repository) RenameGroup(ctx context.Context, groupID string, newName string) error {
	filter := bson.M{"id": groupID}
	update := bson.M{"$set": bson.M{"name": newName}}

	_, err := r.col.UpdateOne(ctx, filter, update)
	return err
}
