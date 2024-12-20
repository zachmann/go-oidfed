package main

import (
	"encoding/json"
	"fmt"
	"strings"

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
var subordinatesBlockCmd = &cobra.Command{
	Use:   "block",
	Short: "Block a subordinate",
	Long:  `Block a subordinate`,
	Args:  cobra.ExactArgs(1),
	RunE:  blockSubordinate,
}
var subordinatesManageRequestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Manage subordinate requests",
	Long:  "Manage subordinate requests interactively",
	RunE:  manageSubordinateRequests,
}

var entityTypes []string
var onlyIDs bool

func init() {
	subordinatesAddCmd.Flags().StringArrayVarP(&entityTypes, "entity_type", "t", []string{}, "entity type")
	subordinatesAddCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesRemoveCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesBlockCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesManageRequestsCmd.Flags().StringVarP(
		&configFile, "config", "c", "config.yaml", "the config file to use",
	)
	subordinatesManageRequestsCmd.Flags().BoolVarP(
		&printFlag, "print", "p", false, "if set only the requests will be printed, no management is triggered",
	)
	subordinatesManageRequestsCmd.Flags().BoolVar(
		&onlyIDs, "only-ids", false, "if set only the entity ids are printed, not all subordinate info",
	)
	subordinatesCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "the config file to use")
	subordinatesCmd.AddCommand(subordinatesAddCmd)
	subordinatesCmd.AddCommand(subordinatesRemoveCmd)
	subordinatesCmd.AddCommand(subordinatesBlockCmd)
	subordinatesCmd.AddCommand(subordinatesManageRequestsCmd)
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

func blockSubordinate(cmd *cobra.Command, args []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := subordinateStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load subordinates from storage")
	}

	entityID := args[0]

	if err := subordinateStorage.Block(entityID); err != nil {
		return errors.Wrap(err, "failed to block subordinate in storage")
	}
	fmt.Println("subordinate blocked successfully")
	return nil
}

func manageSubordinateRequests(cmd *cobra.Command, _ []string) error {
	if err := loadConfig(); err != nil {
		return err
	}
	if err := subordinateStorage.Load(); err != nil {
		return errors.Wrap(err, "failed to load subordinates from storage")
	}

	pendingQ := subordinateStorage.Pending()
	var pendingIDs []string
	var pendingInfos []storage.SubordinateInfo
	var err error
	if onlyIDs {
		pendingIDs, err = pendingQ.EntityIDs()
	} else {
		pendingInfos, err = pendingQ.Subordinates()
	}
	if err != nil {
		return err
	}
	if len(pendingIDs) == 0 && len(pendingInfos) == 0 {
		fmt.Println("No pending requests")
		return nil
	}
	if printFlag {
		str := strings.Join(pendingIDs, "\n")
		if !onlyIDs {
			for _, info := range pendingInfos {
				s, err := stringSubordinateInfo(info)
				if err != nil {
					return err
				}
				str += fmt.Sprintf("%s\n", s)
			}
		}
		fmt.Printf("The following entities have pending requests:\n%s\n\n", str)
		return nil
	}
	if onlyIDs {
		for _, entityID := range pendingIDs {
			if err = promptInSubordinateRequest(entityID, entityID); err != nil {
				return err
			}
		}
	} else {
		for _, infos := range pendingInfos {
			str, err := stringSubordinateInfo(infos)
			if err != nil {
				return err
			}
			if err = promptInSubordinateRequest(infos.EntityID, str); err != nil {
				return err
			}
		}
	}
	return nil
}

func promptInSubordinateRequest(entityID, str string) error {
	approved := promptApproval("Do you approve entity '%s'", str)
	if approved {
		return subordinateStorage.Approve(entityID)
	}
	return subordinateStorage.Block(entityID)
}

func stringSubordinateInfo(info storage.SubordinateInfo) (string, error) {
	data, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	var generic map[string]interface{}
	if err = json.Unmarshal(data, &generic); err != nil {
		return "", err
	}
	delete(generic, "status")
	data, err = json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
