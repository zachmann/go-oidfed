package main

func main() {
	mustLoadConfig()
	initKeys("fed", "oidc")
	initServer()
}
