package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoService struct {
	client *mongo.Client
	db     *mongo.Database
}

func NewMongoService(uri, dbName string) (*MongoService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	log.Println("Connected to MongoDB")
	return &MongoService{
		client: client,
		db:     client.Database(dbName),
	}, nil
}

func (m *MongoService) Database() *mongo.Database {
	return m.db
}

func (m *MongoService) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}
