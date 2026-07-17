package main

// app has no conditional (select()) dependencies of its own. The point of
// this fixture is that discovery must succeed even though an *unrelated*
// target elsewhere under //... has a select() with no matching branch — see
// //broken:dpkg_status_like and the README.
func main() {
	println("app")
}
