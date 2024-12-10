package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
)

var subordinatesCmd = &cobra.Command{
	Use:   "subordinates",
	Short: "Manage subordinates",
	Long:  `Manage subordinates`,
}

var subordinatesAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a subordinate",
	Long:  `Add a subordinate`,
	Args:  cobra.ExactArgs(1),
	RunE:  addSubordinate,
}
var subordinatesRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a subordinate",
	Long:  `Remove a subordinate`,
	Args:  cobra.ExactArgs(1),
	RunE:  removeSubordinate,
}

var entityTypes []string

func init() {
	subordinatesAddCmd.Flags().StringArrayVarP(&entityTypes, "entity_type", "t", []string{}, "entity type")
	subordinatesAddCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesRemoveCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesCmd.AddCommand(subordinatesAddCmd)
	subordinatesCmd.AddCommand(subordinatesRemoveCmd)
	rootCmd.AddCommand(subordinatesCmd)
}

func addSubordinate(cmd *cobra.Command, args []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := subordinateStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load subordinates from storage")
	}

	entityID := args[0]

	entityConfig, err := pkg.GetEntityConfiguration(entityID)
	if err != nil {
		return errors.Wrap(err, "failed to get entity configuration")
	}
	if len(entityTypes) == 0 {
		entityTypes = entityConfig.Metadata.GuessEntityTypes()
	}
	info := storage.SubordinateInfo{
		JWKS:        entityConfig.JWKS,
		EntityTypes: entityTypes,
		EntityID:    entityConfig.Subject,
	}
	if err = subordinateStorage.Write(
		entityConfig.Subject, info,
	); err != nil {
		return errors.Wrap(err, "failed to add subordinate to storage")
	}
	fmt.Println("subordinate added successfully")
	return nil
}

func removeSubordinate(cmd *cobra.Command, args []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := subordinateStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load subordinates from storage")
	}

	entityID := args[0]

	if err := subordinateStorage.Delete(entityID); err != nil {
		return errors.Wrap(err, "failed to remove subordinate from storage")
	}
	fmt.Println("subordinate removed successfully")
	return nil
}
