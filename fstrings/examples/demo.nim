import std / syncio
import ../src/fstrings

type Planet = object
  name: string
  au: float
  moons: int

proc `$`(p: Planet): string = p.name

let planets = @[Planet(name: "Mercury", au: 0.387, moons: 0),
                Planet(name: "Earth", au: 1.0, moons: 1),
                Planet(name: "Jupiter", au: 5.2, moons: 95)]
let width = 10

echo f"{""Planet"":<{width}}{""AU"":>8}{""Moons"":>7}"
echo f"{""-"":-<{width + 15}}"
for p in planets:
  echo f"{p.name:<{width}}{p.au:>8.3f}{p.moons:>7}"

let total = 96
let ratio = 95.0 / float(total)
echo f"{total=}, {ratio = :.1%}, {planets[2]!r}"
echo f"hex {48879:#x}, bin {10:08b}, big {6_022_140_857:,}"
