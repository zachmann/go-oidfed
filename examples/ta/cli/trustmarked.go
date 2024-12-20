package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/zachmann/go-oidfed/examples/ta/config"
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
var trustmarkManageRequestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Manage trust mark requests",
	Long:  "Manage trust mark requests interactively",
	RunE:  manageTrustMarkRequests,
}

var trustMarkID string
var printFlag bool

func init() {
	trustmarkAddCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	trustmarkRemoveCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	trustmarkBlockCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	trustmarkManageRequestsCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	trustmarkManageRequestsCmd.Flags().BoolVarP(
		&printFlag, "print", "p", false, "if set only the requests will be printed, no management is triggered",
	)
	trustmarkManageRequestsCmd.Flags().StringVar(&trustMarkID, "id", "", "if set only this trust mark id is handled")
	tmCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	tmCmd.AddCommand(trustmarkAddCmd)
	tmCmd.AddCommand(trustmarkRemoveCmd)
	tmCmd.AddCommand(trustmarkBlockCmd)
	tmCmd.AddCommand(trustmarkManageRequestsCmd)
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

func manageTrustMarkRequests(cmd *cobra.Command, _ []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := trustMarkedEntitiesStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load trust-marked entities from storage")
	}

	if trustMarkID != "" {
		return manageTrustMarkRequestsForID(trustMarkID)
	}
	for _, c := range config.Get().TrustMarkSpecs {
		if err := manageTrustMarkRequestsForID(c.ID); err != nil {
			return err
		}
	}
	return nil
}

func manageTrustMarkRequestsForID(id string) error {
	pending, err := trustMarkedEntitiesStorage.Pending(id)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Printf("No pending requests for trust mark id '%s'\n", id)
		return nil
	}
	if printFlag {
		str := strings.Join(pending, "\n")
		fmt.Printf("For trust mark id '%s' the following entities have pending requests:\n%s\n\n", id, str)
		return nil
	}
	fmt.Printf("Managing trust mark id '%s':\n\n", id)
	for _, entityID := range pending {
		if err = promptInTrustMarkRequest(id, entityID); err != nil {
			return err
		}
	}
	return nil
}

func promptInTrustMarkRequest(trustMarkID, entityID string) error {
	approved := promptApproval("Do you approve entity '%s'", entityID)
	if approved {
		return trustMarkedEntitiesStorage.Approve(trustMarkID, entityID)
	}
	return trustMarkedEntitiesStorage.Block(trustMarkID, entityID)
}

func promptApproval(f string, args ...interface{}) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf(f+" (y/n): ", args...)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input)) // Normalize input

		if input == "y" || input == "yes" {
			return true
		} else if input == "n" || input == "no" {
			return false
		} else {
			fmt.Println("Invalid input. Please enter 'y' or 'n'.")
		}
	}
}
