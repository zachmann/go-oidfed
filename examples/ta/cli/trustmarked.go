package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var tmCmd = &cobra.Command{
	Use: "trustmarks",
	Aliases: []string{
		"tm",
		"trustmarked",
	},
	Short: "Manage trust-marked entities",
	Long:  `Manage trust-marked entities`,
}

var trustmarkAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Entitle an entity to get a certain trust mark",
	Long:  "Entitle an entity to get a certain trust mark",
	Args:  cobra.ExactArgs(2),
	RunE:  addTrustMark,
}
var trustmarkRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a trust mark from an entity",
	Long: `Remove an entity from the list of entities that is entitled to
get a certain trust mark`,
	Args: cobra.ExactArgs(2),
	RunE: removeTrustMark,
}
var trustmarkBlockCmd = &cobra.Command{
	Use:   "block",
	Short: "Block a trust mark from an entity",
	Long:  `Block an entity from the list of entities that is entitled to get a certain trust mark`,
	Args:  cobra.ExactArgs(2),
	RunE:  blockTrustMark,
}

func init() {
	trustmarkAddCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	trustmarkRemoveCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	trustmarkBlockCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	tmCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	tmCmd.AddCommand(trustmarkAddCmd)
	tmCmd.AddCommand(trustmarkRemoveCmd)
	tmCmd.AddCommand(trustmarkBlockCmd)
	rootCmd.AddCommand(tmCmd)
}

func addTrustMark(cmd *cobra.Command, args []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := trustMarkedEntitiesStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load trust-marked entities from storage")
	}

	trustMarkID := args[0]
	entityID := args[1]

	if err := trustMarkedEntitiesStorage.Approve(trustMarkID, entityID); err != nil {
		return errors.Wrap(err, "failed to add trust marked entity to storage")
	}
	fmt.Println("trustmark successfully added")
	return nil
}

func removeTrustMark(cmd *cobra.Command, args []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := trustMarkedEntitiesStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load trust-marked entities from storage")
	}

	trustMarkID := args[0]
	entityID := args[1]

	if err := trustMarkedEntitiesStorage.Delete(trustMarkID, entityID); err != nil {
		return errors.Wrap(err, "failed to remove trust marked entity from storage")
	}
	fmt.Println("trustmark successfully removed")
	return nil
}

func blockTrustMark(cmd *cobra.Command, args []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := trustMarkedEntitiesStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load trust-marked entities from storage")
	}

	trustMarkID := args[0]
	entityID := args[1]

	if err := trustMarkedEntitiesStorage.Block(trustMarkID, entityID); err != nil {
		return errors.Wrap(err, "failed to block trust marked entity")
	}
	fmt.Println("trustmark successfully blocked for entity")
	return nil
}
