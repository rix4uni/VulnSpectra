package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.1"

func PrintVersion() {
	fmt.Printf("Current VulnSpectra version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `
 _    __        __       _____                     __              
| |  / /__  __ / /____  / ___/ ____   ___   _____ / /_ _____ ____ _
| | / // / / // // __ \ \__ \ / __ \ / _ \ / ___// __// ___// __  /
| |/ // /_/ // // / / /___/ // /_/ //  __// /__ / /_ / /   / /_/ / 
|___/ \__,_//_//_/ /_//____// .___/ \___/ \___/ \__//_/    \__,_/  
                           /_/
`
	fmt.Printf("%s\n%60s\n\n", banner, "Current VulnSpectra version "+version)
}
