<#
    ModWarden - Minecraft Forensic Analyzer
    Detects cheat-client signatures, obfuscation, and suspicious behaviour
    inside Minecraft mod JAR files.

    Usage:
        powershell -ExecutionPolicy Bypass -File ModWarden.ps1

    Or remotely:
        powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/<you>/<repo>/main/ModWarden.ps1')"
#>

# ---------------------------------------------------------------------------
#  SIGNATURE DATA
# ---------------------------------------------------------------------------

$CheatPatterns = @(
    "AimAssist","AnchorTweaks","AutoAnchor","AutoCrystal","AutoDoubleHand",
    "JDWP.VirtualMachine.AllModules","AutoHitCrystal","AutoPot","AutoTotem",
    "AutoArmor","InventoryTotem","LegitTotem","PingSpoof","SelfDestruct",
    "ShieldBreaker","TriggerBot","AxeSpam","WebMacro","FastPlace",
    "WalskyOptimizer","WalksyOptimizer","walsky.optimizer","WalksyCrystalOptimizerMod",
    "Donut","Replace Mod","ShieldDisabler","SilentAim","Totem Hit","Wtap",
    "FakeLag","dev.virel","orchard","BlockESP","dev.krypton","dev/krypton",
    "skid.krypton","skid/krypton","AntiMissClick","LagReach","PopSwitch",
    "SprintReset","ChestSteal","AntiBot","ElytraSwap","FastXP","FastExp",
    "Refill","AirAnchor","jnativehook","FakeInv","HoverTotem","AutoClicker",
    "AutoFirework","PackSpoof","Antiknockback","catlean","AuthBypass",
    "Asteria","Prestige","AutoEat","AutoMine","MaceSwap","Macro198",
    "StunSlam","SafeAnchor","DoubleAnchor","AutoTPA","BaseFinder","Xenon",
    "gypsy","AutoPotRefill","KeyPearl","AutoNethPot","AutoDtap","AutoWeb",
    "AnchorAction",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui.gl3","imgui.glfw","BowAim","Criticals","Fakenick","FakeItem",
    "invsee","ItemExploit","Hellion","hellion","LicenseCheckMixin",
    "ClientPlayerInteractionManagerAccessor","ClientPlayerEntityMixim",
    "dev.gambleclient","obfuscatedAuth","phantom-refmap.json","xyz.greaj",
    "じ.class","ふ.class","ぶ.class","ぷ.class","た.class","ね.class",
    "そ.class","な.class","ど.class","ぐ.class","ず.class","で.class",
    "つ.class","べ.class","せ.class","と.class","み.class","び.class",
    "す.class","の.class"
)

$CheatStrings = @(
    "AutoCrystal","autocrystal","auto crystal","cw crystal","dontPlaceCrystal",
    "dontBreakCrystal","AutoHitCrystal","autohitcrystal","canPlaceCrystalServer",
    "healPotSlot","ＡｕｔｏＣｒｙｓｔａｌ","Ａｕｔｏ Ｃｒｙｓｔａｌ","ＡｕｔｏＨｉｔＣｒｙｓｔａｌ",
    "AutoAnchor","autoanchor","auto anchor","DoubleAnchor","HasAnchor",
    "anchortweaks","anchor macro","safe anchor","safeanchor","SafeAnchor",
    "AirAnchor","ＡｕｔｏＡｎｃｈｏｒ","Ａｕｔｏ Ａｎｃｈｏｒ","ＤｏｕｂｌｅＡｎｃｈｏｒ",
    "Ｄｏｕｂｌｅ Ａｎｃｈｏｒ","ＳａｆｅＡｎｃｈｏｒ","Ｓａｆｅ Ａｎｃｈｏｒ","Ａｎｃｈｏｒ Ｍａｃｒｏ",
    "anchorMacro","AutoTotem","autototem","auto totem","InventoryTotem",
    "inventorytotem","HoverTotem","hover totem","legittotem",
    "ＡｕｔｏＴｏｔｅｍ","Ａｕｔｏ Ｔｏｔｅｍ","ＨｏｖｅｒＴｏｔｅｍ","Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ","Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ","Ａｕｔｏ Ｔｏｔｅｍ Ｈｉｔ",
    "AutoPot","autopot","auto pot","speedPotSlot","strengthPotSlot",
    "AutoArmor","autoarmor","auto armor","ＡｕｔｏＰｏｔ","Ａｕｔｏ Ｐｏｔ",
    "Ａｕｔｏ Ｐｏｔ Ｒｅｆｉｌｌ","AutoPotRefill","ＡｕｔｏＡｒｍｏｒ","Ａｕｔｏ Ａｒｍｏｒ",
    "preventSwordBlockBreaking","preventSwordBlockAttack","ShieldDisabler",
    "ShieldBreaker","ＳｈｉｅｌｄＤｉｓａｂｌｅｒ","Ｓｈｉｅｌｄ Ｄｉｓａｂｌｅｒ",
    "Breaking shield with axe...","AutoDoubleHand","autodoublehand",
    "auto double hand","ＡｕｔｏＤｏｕｂｌｅＨａｎｄ","Ａｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ",
    "AutoClicker","ＡｕｔｏＣｌｉｃｋｅｒ","Failed to switch to mace after axe!",
    "AutoMace","MaceSwap","SpearSwap","ＡｕｔｏＭａｃｅ","Ａｕｔｏ Ｍａｃｅ",
    "ＭａｃｅＳｗａｐ","Ｍａｃｅ Ｓｗａｐ","Ｓｐｅａｒ Ｓｗａｐ",
    "Ｓｔｕｎ Ｓｌａｍ","StunSlam","Donut","JumpReset","axespam","axe spam",
    "findKnockbackSword","attackRegisteredThisClick","AimAssist","aimassist",
    "aim assist","triggerbot","trigger bot","ＡｉｍＡｓｓｉｓｔ","Ａｉｍ Ａｓｓｉｓｔ",
    "ＴｒｉｇｇｅｒＢｏｔ","Ｔｒｉｇｇｅｒ Ｂｏｔ","Silent Rotations","SilentRotations",
    "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ","FakeInv","swapBackToOriginalSlot","FakeLag",
    "pingspoof","ping spoof","ＦａｋｅＬａｇ","Ｆａｋｅ Ｌａｇ","fakePunch",
    "Fake Punch","Ｆａｋｅ Ｐｕｎｃｈ","mace_swap","quick_strike","macro_198",
    "stun_slam","safe_anchor","double_anchor","auto_pot_refill",
    "walksy_optimizer","key_pearl","aim_assist","auto_neth_pot","auto_dtap",
    "trigger_bot","auto_web","DOUBLE_ESCAPE","DOUBLE_RIGHTCLICK_FIRST",
    "DOUBLE_RIGHTCLICK_SECOND","POST_CYCLE_DELAY","PLACE_OBI","WAIT_OBI",
    "PLACE_CRYSTAL","BREAK_CRYSTAL","ROTATING_DOWN","ROTATING_BACK",
    "REFILLING","PLANTING","BONEMEALING","AnchorAction",
    "Places two anchors for massive damage","REOFFHAND_TOTEM","webmacro",
    "web macro","AntiWeb","AutoWeb","Ａｎｔｉ Ｗｅｂ","ＡｕｔｏＷｅｂ",
    "Ｐｌａｃｅｓ Ｗｅｂｓ Ｏｎ Ｅｎｅｍｉｅｓ","lvstrng","dqrkis","selfdestruct",
    "self destruct","WalksyCrystalOptimizerMod","WalksyOptimizer",
    "WalskyOptimizer","Ｗａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ","autoCrystalPlaceClock",
    "AutoFirework","ElytraSwap","FastXP","FastExp","NoJumpDelay",
    "ＥｌｙｔｒａＳｗａｐ","Ｅｌｙｔｒａ Ｓｗａｐ","PackSpoof","Antiknockback","catlean",
    "AuthBypass","obfuscatedAuth","LicenseCheckMixin","BaseFinder","invsee",
    "ItemExploit","FreezePlayer","Ｆｒｅｅｃａｍ","Ｍｏｖｅ ｆｒｅｅｌｙ ｔｈｒｏｕｇｈ ｗａｌｌｓ",
    "Ｎｏ Ｃｌｉｐ","Ｆｒｅｅｚｅ Ｐｌａｙｅｒ","LWFH Crystal","ＬＷＦＨ Ｃｒｙｓｔａｌ",
    "KeyPearl","LootYeeter","ＫｅｙＰｅａｒｌ","Ｋｅｙ Ｐｅａｒｌ","Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "FastPlace","Ｆａｓｔ Ｐｌａｃｅ","Ｐｌａｃｅ ｂｌｏｃｋｓ ｆａｓｔｅｒ","AutoBreach",
    "Ａｕｔｏ Ｂｒｅａｃｈ","setBlockBreakingCooldown","getBlockBreakingCooldown",
    "blockBreakingCooldown","onBlockBreaking","setItemUseCooldown",
    "invokeDoAttack","invokeDoItemUse","invokeOnMouseButton",
    "onPushOutOfBlocks","onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString","POT_CHEATS","Dqrkis Client","Entity.isGlowing",
    "Activate Key","Click Simulation","On RMB","No Count Glitch",
    "No Bounce","NoBounce","Place Delay","Break Delay","Place Chance",
    "Break Chance","Stop On Kill","damagetick","Anti Weakness",
    "Particle Chance","Trigger Key","Switch Delay","Totem Slot",
    "Smooth Rotations","Rotation Speed","Use Easing","Easing Strength",
    "While Use","Glowstone Delay","Glowstone Chance","Explode Delay",
    "Explode Chance","Explode Slot","Only Charge","Reach Distance",
    "Min Height","Min Fall Speed","Attack Delay","Breach Delay",
    "Require Elytra","Auto Switch Back","Check Line of Sight",
    "Only When Falling","Require Crit","Show Status Display",
    "Stop On Crystal","Check Shield","On Pop","Predict Damage","On Ground",
    "Check Players","Predict Crystals","Check Aim","Check Items",
    "Activates Above","Blatant","Force Totem","Stay Open For",
    "Auto Inventory Totem","Only On Pop","Vertical Speed","Swap Speed",
    "Strict One-Tick","Mace Priority","Min Totems","Min Pearls",
    "Totem First","Drop Interval","Random Pattern","Horizontal Aim Speed",
    "Vertical Aim Speed","Include Head","Web Delay","Holding Web",
    "Not When Affects Player","Hit Delay","Require Hold Axe",
    "placeInterval","breakInterval","stopOnKill","activateOnRightClick",
    "holdCrystal","Macro Key","KillAura","ClickAura","MultiAura",
    "ForceField","LegitAura","AimBot","AutoAim","SilentAim","AimLock",
    "HeadSnap","CrystalAura","AnchorAura","AnchorFill","AnchorPlace",
    "BedAura","AutoBed","BedBomb","BedPlace","BowAimbot","BowSpam",
    "AutoBow","AutoCrit","CritBypass","AlwaysCrit","CriticalHit",
    "ReachHack","ExtendReach","LongReach","HitboxExpand","AntiKB",
    "NoKnockback","GrimVelocity","GrimDisabler","VelocitySpoof","KBReduce",
    "OffhandTotem","TotemSwitch","AutoWeapon","AutoSword","AutoCity",
    "Burrow","SelfTrap","HoleFiller","AntiSurround","AntiBurrow","WTap",
    "TargetStrafe","AutoGap","AutoPearl","FlyHack","CreativeFlight",
    "BoatFly","PacketFly","AirJump","SpeedHack","BHop","BunnyHop",
    "AntiFall","NoFallDamage","SafeFall","StepHack","FastClimb",
    "AutoStep","HighStep","WaterWalk","LiquidWalk","LavaWalk","NoSlow",
    "NoSlowdown","NoWeb","NoSoulSand","WallHack","ElytraSpeed",
    "InstantElytra","ScaffoldWalk","FastBridge","BuildHelper","AutoBridge",
    "Nuker","NukerLegit","InstantBreak","GhostHand","NoSwing","PlaceAssist",
    "AirPlace","AutoPlace","InstantPlace","PlayerESP","MobESP","ItemESP",
    "StorageESP","ChestESP","Tracers","NameTagsHack","XRayHack","OreFinder",
    "CaveFinder","OreESP","NewChunks","ChunkBorders","TunnelFinder",
    "TargetHUD","ReachDisplay","DoubleClicker","JitterClick",
    "ButterflyClick","CPSBoost","ChestStealer","InvManager","InvMovebypass",
    "AutoSprint","AntiAFK","AutoRespawn","PopSwitch","FakeLatency",
    "FakePing","SpoofRotation","PositionSpoof","GameSpeed","SpeedTimer",
    "GrimBypass","VulcanBypass","MatrixBypass","AACBypass","VerusDisabler",
    "IntaveBypass","WatchdogBypass","PacketMine","PacketWalk",
    "PacketSneak","PacketCancel","PacketDupe","PacketSpam","SelfDestruct",
    "HideClient","SessionStealer","TokenLogger","TokenGrabber",
    "DiscordToken","RemoteAccess","ReverseShell","C2Server","Backdoor",
    "KeyLogger","StashFinder","TrailFinder","imgui.binding","JNativeHook",
    "GlobalScreen","NativeKeyListener","client-refmap.json",
    "cheat-refmap.json","aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "meteordevelopment","cc/novoline","com/alan/clients","club/maxstats",
    "wtf/moonlight","me/zeroeightsix/kami","net/ccbluex","today/opai",
    "net/minecraft/injection","org/chainlibs/module/impl/modules",
    "xyz/greaj","com/cheatbreaker","com/moonsworth","doomsdayclient",
    "DoomsdayClient","doomsday.jar","novaclient","api.novaclient.lol",
    "vape.gg","vapeclient","VapeClient","VapeLite","intent.store",
    "IntentClient","rise.today","riseclient.com","meteor-client",
    "meteorclient","meteordevelopment.meteorclient","liquidbounce",
    "fdp-client","net.ccbluex","novoware","novoclient","aristois",
    "impactclient","azura","pandaware","skilled","moonClient","astolfo",
    "futureClient","konas","rusherhack","inertia","exhibition",
    "dev.krypton","dev/krypton","skid.krypton","skid/krypton",
    "VirginClient","virgin client","catlean","CatleanClient",
    "catlean client","ArgonClient","argon client","Asteria",
    "AsteriaClient","asteria client","Prestige","PrestigeClient",
    "prestige client","prestigeclient.vip","gypsy","GypsyClient",
    "gypsy client","Xenon","XenonClient","xenon client","GrimClient",
    "grim client","phantom-refmap.json","dqrkis.xyz","Dqrkis Client",
    "dev.virel","orchard","JDWP.VirtualMachine.AllModules"
)

# combine + dedupe for the actual scan
$AllSignatures = ($CheatPatterns + $CheatStrings) | Select-Object -Unique

$KnownObfuscators = @(
    "Skidfuscator","Paramorphism","Radon","Caesium","Bozar","Branchlock",
    "Binscure","SuperBlaubeere27","Qprotect","Zelix","Stringer","JNIC",
    "Scuti","Smoke"
)

$SourceClassification = @{
    "modrinth"        = "SAFE"
    "curseforge"      = "SAFE"
    "github"          = "VERIFY"
    "discord"         = "RISKY"
    "discordapp"      = "RISKY"
    "mediafire"       = "RISKY"
    "mega.nz"         = "RISKY"
    "dropbox"         = "RISKY"
    "drive.google"    = "RISKY"
    "anydesk"         = "SUSPICIOUS"
    "doomsdayclient"  = "SUSPICIOUS"
    "prestigeclient"  = "SUSPICIOUS"
    "198macros"       = "SUSPICIOUS"
    "dqrkis"          = "SUSPICIOUS"
}

$KnownClients = @(
    "DoomsdayClient","AutoClicker","Asteria","Prestige","Xenon","Argon",
    "Hellion","VirginClient","Donut","VapeClient","MeteorClient",
    "LiquidBounce","RusherHack","FutureClient","Aristois","Pandaware",
    "AstolfoClient","Novoclient","IntentClient"
)

# ---------------------------------------------------------------------------
#  UI HELPERS
# ---------------------------------------------------------------------------

$UiWidth = 80

function Write-BoxTop {
    param([int]$Width = $UiWidth, [string]$Color = "DarkCyan")
    Write-Host ("  " + [char]0x2554 + ([string][char]0x2550 * ($Width - 2)) + [char]0x2557) -ForegroundColor $Color
}

function Write-BoxBottom {
    param([int]$Width = $UiWidth, [string]$Color = "DarkCyan")
    Write-Host ("  " + [char]0x255A + ([string][char]0x2550 * ($Width - 2)) + [char]0x255D) -ForegroundColor $Color
}

function Write-BoxDivider {
    param([int]$Width = $UiWidth, [string]$Color = "DarkCyan")
    Write-Host ("  " + [char]0x2560 + ([string][char]0x2550 * ($Width - 2)) + [char]0x2563) -ForegroundColor $Color
}

function Write-BoxLine {
    param(
        [string]$Text = "",
        [string]$BorderColor = "DarkCyan",
        [string]$TextColor = "White",
        [int]$Width = $UiWidth,
        [ValidateSet("Center","Left")][string]$Align = "Center"
    )
    $inner = $Width - 2
    if ($Text.Length -gt $inner) { $Text = $Text.Substring(0, $inner) }
    if ($Align -eq "Center") {
        $totalPad = $inner - $Text.Length
        $left = [Math]::Floor($totalPad / 2)
        $right = $totalPad - $left
        $line = (" " * $left) + $Text + (" " * $right)
    } else {
        $line = ("  " + $Text).PadRight($inner)
    }
    Write-Host ("  " + [char]0x2551) -ForegroundColor $BorderColor -NoNewline
    Write-Host $line -ForegroundColor $TextColor -NoNewline
    Write-Host ([string][char]0x2551) -ForegroundColor $BorderColor
}

function Show-Banner {
    Clear-Host
    Write-BoxTop
    Write-BoxLine -Text ""
    Write-BoxLine -Text "M O D W A R D E N" -TextColor Cyan
    Write-BoxLine -Text "Minecraft Forensic Analyzer" -TextColor DarkCyan
    Write-BoxLine -Text ""
    Write-BoxBottom
    Write-Host ""
}

function Show-MenuOption {
    param([string]$Key, [string]$Title, [string]$Desc = "")
    Write-Host "   " -NoNewline
    Write-Host "[$Key]" -NoNewline -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor White
    if ($Desc) { Write-Host ("        " + $Desc) -ForegroundColor DarkGray }
}

function Write-SectionRule {
    Write-Host ("  " + ([string][char]0x2500 * ($UiWidth - 2))) -ForegroundColor DarkGray
}

function Show-MainMenu {
    Show-Banner
    Write-BoxTop
    Write-BoxLine -Text "SCAN OPTIONS" -TextColor Yellow
    Write-BoxBottom
    Write-Host ""
    Show-MenuOption -Key "1" -Title "MINECRAFT SCAN"    -Desc "Scan selected Minecraft / mod directories."
    Write-Host ""
    Show-MenuOption -Key "2" -Title "FULL PC SCAN"      -Desc "Search known Minecraft/launcher locations across the PC."
    Write-Host ""
    Show-MenuOption -Key "3" -Title "CUSTOM PATH"       -Desc "Scan any directory you specify."
    Write-Host ""
    Show-MenuOption -Key "4" -Title "EXIT"
    Write-Host ""
    Write-SectionRule
    Write-Host ""
    return Read-Host "  Select an option [1-4]"
}

function Show-MinecraftMenu {
    Show-Banner
    Write-BoxTop
    Write-BoxLine -Text "MINECRAFT SCAN" -TextColor Yellow
    Write-BoxBottom
    Write-Host ""
    Write-Host "  Select how ModWarden should locate the mods:" -ForegroundColor DarkGray
    Write-Host ""
    Show-MenuOption -Key "1" -Title "ENTER MODS PATH"            -Desc "Enter the exact folder containing the mods."
    Write-Host ""
    Show-MenuOption -Key "2" -Title "SCAN MINECRAFT DIRECTORIES" -Desc "Search common Minecraft installation locations."
    Write-Host ""
    Show-MenuOption -Key "3" -Title "BACK"
    Write-Host ""
    Write-SectionRule
    Write-Host ""
    return Read-Host "  Select an option [1-3]"
}

# ---------------------------------------------------------------------------
#  DISCOVERY
# ---------------------------------------------------------------------------

function Find-MinecraftInstallations {
    $found = @()
    $userProfile = $env:USERPROFILE

    $candidates = @(
        @{ Name = ".minecraft";        Path = Join-Path $userProfile "AppData\Roaming\.minecraft" }
        @{ Name = "CurseForge Root";   Path = Join-Path $userProfile "curseforge\minecraft\Instances" }
    )

    foreach ($c in $candidates) {
        if ($c.Name -eq ".minecraft") {
            if (Test-Path (Join-Path $c.Path "mods")) {
                $found += @{ Name = ".minecraft"; Path = Join-Path $c.Path "mods" }
            }
        } else {
            if (Test-Path $c.Path) {
                Get-ChildItem -Path $c.Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $modsDir = Join-Path $_.FullName "mods"
                    if (Test-Path $modsDir) {
                        $found += @{ Name = "CurseForge Instance ($($_.Name))"; Path = $modsDir }
                    }
                }
            }
        }
    }

    # Modrinth
    $modrinthRoots = @(
        (Join-Path $userProfile "AppData\Roaming\ModrinthApp\profiles"),
        (Join-Path $userProfile ".modrinth\profiles")
    )
    foreach ($root in $modrinthRoots) {
        if (Test-Path $root) {
            Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $modsDir = Join-Path $_.FullName "mods"
                if (Test-Path $modsDir) {
                    $found += @{ Name = "Modrinth Instance ($($_.Name))"; Path = $modsDir }
                }
            }
        }
    }

    # PrismLauncher
    $prismRoots = @(
        (Join-Path $userProfile "AppData\Roaming\PrismLauncher\instances"),
        (Join-Path $userProfile "AppData\Local\PrismLauncher\instances")
    )
    foreach ($root in $prismRoots) {
        if (Test-Path $root) {
            Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $modsDir = Join-Path $_.FullName ".minecraft\mods"
                if (Test-Path $modsDir) {
                    $found += @{ Name = "Prism Instance ($($_.Name))"; Path = $modsDir }
                }
            }
        }
    }

    return $found
}

function Select-ModsPath {
    while ($true) {
        $choice = Show-MinecraftMenu
        switch ($choice) {
            "1" {
                Show-Banner
                Write-Host "  ENTER MODS PATH"
                Write-Host ""
                Write-Host "  Example:"
                Write-Host "  C:\Users\User\AppData\Roaming\.minecraft\mods"
                Write-Host ""
                $p = Read-Host "  Path"
                if (Test-Path $p) { return $p }
                Write-Host "  Path not found." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
            "2" {
                Show-Banner
                Write-Host "  MINECRAFT DIRECTORIES"
                Write-Host ""
                Write-Host "  Searching..."
                $installs = Find-MinecraftInstallations
                if ($installs.Count -eq 0) {
                    Write-Host "  No installations found." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                    continue
                }
                Write-Host ""
                Write-Host "  Found installations:"
                Write-Host ""
                for ($i = 0; $i -lt $installs.Count; $i++) {
                    Write-Host "  [$($i+1)]  $($installs[$i].Name)"
                    Write-Host "       $($installs[$i].Path)"
                    Write-Host ""
                }
                $sel = Read-Host "  Select installation [1-$($installs.Count)]"
                $idx = 0
                if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $installs.Count) {
                    return $installs[$idx - 1].Path
                }
            }
            "3" { return $null }
            default { }
        }
    }
}

# ---------------------------------------------------------------------------
#  ANALYSIS HELPERS
# ---------------------------------------------------------------------------

function Get-Sha1Hash {
    param([string]$FilePath)
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA1 -ErrorAction Stop).Hash.ToLower()
    } catch { return $null }
}

function Test-ModrinthVerified {
    param([string]$Hash)
    try {
        $resp = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" -Method Get -TimeoutSec 6 -ErrorAction Stop
        if ($resp -and $resp.project_id) {
            return $resp.project_id
        }
    } catch { }
    return $null
}

function Get-DownloadSource {
    param([string]$FilePath)
    try {
        $zone = Get-Content -Path $FilePath -Stream Zone.Identifier -ErrorAction Stop
        $urlLine = $zone | Where-Object { $_ -match "^HostUrl=" }
        if ($urlLine) {
            $url = $urlLine -replace "^HostUrl=", ""
            foreach ($key in $SourceClassification.Keys) {
                if ($url -match [regex]::Escape($key)) {
                    return @{ Url = $url; Classification = $SourceClassification[$key] }
                }
            }
            return @{ Url = $url; Classification = "UNKNOWN" }
        }
    } catch { }
    return $null
}

function Test-FullwidthUnicode {
    param([string]$Text)
    return ($Text -match '[\uFF00-\uFFEF]')
}

function Get-ObfuscationFlags {
    param([string[]]$ClassNames)

    $flags = @()
    $total = $ClassNames.Count
    if ($total -eq 0) { return $flags }

    $numeric   = ($ClassNames | Where-Object { $_ -match '^\d+$' }).Count
    $shortName = ($ClassNames | Where-Object { $_ -match '^[A-Za-z]{1,2}$' }).Count
    $unicode   = ($ClassNames | Where-Object { $_ -match '[^\x00-\x7F]' }).Count
    $fullwidth = ($ClassNames | Where-Object { Test-FullwidthUnicode $_ }).Count
    $japanese  = ($ClassNames | Where-Object { $_ -match '[\p{IsHiragana}\p{IsKatakana}]' }).Count
    $confusion = ($ClassNames | Where-Object { $_ -match '^[IlO01_]+$' }).Count

    if ($total -gt 0) {
        if (($numeric / $total) -gt 0.15)   { $flags += "Numeric class names ($numeric/$total)" }
        if (($shortName / $total) -gt 0.30) { $flags += "Single/two-letter class names ($shortName/$total)" }
        if ($unicode -gt 0)                 { $flags += "Unicode class names ($unicode)" }
        if ($fullwidth -gt 0)               { $flags += "Fullwidth Unicode class names ($fullwidth)" }
        if ($japanese -gt 0)                { $flags += "Japanese obfuscation ($japanese classes)" }
        if ($confusion -gt 0)               { $flags += "Confusion-character class names ($confusion)" }
    }

    return $flags
}

function Test-KnownObfuscator {
    param([string]$Content)
    $hits = @()
    foreach ($obf in $KnownObfuscators) {
        if ($Content -match [regex]::Escape($obf)) { $hits += $obf }
    }
    return $hits
}

# ---------------------------------------------------------------------------
#  JAR ANALYSIS
# ---------------------------------------------------------------------------

function Analyze-Jar {
    param([string]$JarPath)

    $result = [PSCustomObject][ordered]@{
        Name              = Split-Path $JarPath -Leaf
        Path              = $JarPath
        Verified          = $false
        VerifiedProject   = $null
        PatternHits       = @()
        StringHits        = @()
        FullwidthHits     = @()
        BypassFlags       = @()
        ObfuscationFlags  = @()
        ObfuscatorHits    = @()
        NestedJars        = @()
        Source            = $null
        Score             = 0
    }

    $hash = Get-Sha1Hash -FilePath $JarPath
    if ($hash) {
        $proj = Test-ModrinthVerified -Hash $hash
        if ($proj) {
            $result.Verified = $true
            $result.VerifiedProject = $proj
        }
    }

    $result.Source = Get-DownloadSource -FilePath $JarPath

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
    } catch {
        $result.BypassFlags += "Unable to open archive (corrupt or password protected)"
        return $result
    }

    $classNames = @()
    $textBlobs  = New-Object System.Text.StringBuilder
    $hasRuntimeExec  = $false
    $hasHttpDownload = $false
    $hasHttpPost     = $false
    $entryCount      = 0

    foreach ($entry in $zip.Entries) {
        $entryCount++
        $entryName = $entry.FullName

        # Nested jars
        if ($entryName -match "META-INF/jars/.*\.jar$") {
            $result.NestedJars += $entryName
        }

        # Class name capture for obfuscation heuristics
        if ($entryName -match '\.class$') {
            $short = [System.IO.Path]::GetFileNameWithoutExtension($entryName)
            $classNames += $short
        }

        # pattern match on path/name
        foreach ($pat in $CheatPatterns) {
            if ($entryName -match [regex]::Escape($pat)) {
                if ($result.PatternHits -notcontains $pat) { $result.PatternHits += $pat }
            }
        }

        if (Test-FullwidthUnicode $entryName) {
            if ($result.FullwidthHits -notcontains $entryName) { $result.FullwidthHits += $entryName }
        }

        # only read text content of relevant, reasonably small entries
        $isTextTarget = $entryName -match '\.class$' -or $entryName -match '\.json$' -or $entryName -match 'MANIFEST\.MF$'
        if ($isTextTarget -and $entry.Length -lt 3MB) {
            try {
                $stream = $entry.Open()
                $reader = New-Object System.IO.StreamReader($stream)
                $content = $reader.ReadToEnd()
                $reader.Close(); $stream.Close()

                foreach ($str in $CheatStrings) {
                    if ($content -match [regex]::Escape($str)) {
                        if ($result.StringHits -notcontains $str) { $result.StringHits += $str }
                    }
                }

                if (Test-FullwidthUnicode $content) {
                    if ($result.FullwidthHits -notcontains "$entryName (content)") {
                        $result.FullwidthHits += "$entryName (content)"
                    }
                }

                if ($content -match 'Runtime\.exec|ProcessBuilder') { $hasRuntimeExec = $true }
                if ($content -match 'HttpURLConnection|URL\(.*http|openStream\(') { $hasHttpDownload = $true }
                if ($content -match '"POST"|HttpPost|setRequestMethod\("POST"\)') { $hasHttpPost = $true }

                $obfHits = Test-KnownObfuscator -Content $content
                foreach ($o in $obfHits) {
                    if ($result.ObfuscatorHits -notcontains $o) { $result.ObfuscatorHits += $o }
                }
            } catch { }
        }
    }

    $zip.Dispose()

    $result.ObfuscationFlags = Get-ObfuscationFlags -ClassNames $classNames

    if ($result.NestedJars.Count -gt 0) {
        $result.BypassFlags += "Nested JAR(s) embedded in META-INF/jars ($($result.NestedJars.Count))"
    }
    if ($hasRuntimeExec)  { $result.BypassFlags += "Runtime.exec / ProcessBuilder usage detected" }
    if ($hasHttpDownload) { $result.BypassFlags += "HTTP download capability detected" }
    if ($hasHttpPost)     { $result.BypassFlags += "HTTP POST (possible exfiltration) detected" }

    # Fake identity: claims to be a known safe mod but has cheat hits
    $safeMods = @("lithium","sodium","phosphor","fabric-api","optifine","iris")
    foreach ($safe in $safeMods) {
        if ($result.Name -match $safe -and ($result.PatternHits.Count -gt 0 -or $result.StringHits.Count -gt 0)) {
            $result.BypassFlags += "Possible fake identity: named like '$safe' but contains cheat-related content"
        }
    }

    # ---- SCORE ----
    $score = 0
    if ($result.PatternHits.Count -gt 0)     { $score += 15 + [Math]::Min(20, $result.PatternHits.Count * 3) }
    if ($result.StringHits.Count -gt 0)      { $score += 20 + [Math]::Min(25, $result.StringHits.Count * 2) }
    if ($result.FullwidthHits.Count -gt 0)   { $score += 10 }
    if ($result.BypassFlags.Count -gt 0)     { $score += 10 * $result.BypassFlags.Count }
    if ($result.ObfuscationFlags.Count -gt 0){ $score += 5 * $result.ObfuscationFlags.Count }
    if ($result.ObfuscatorHits.Count -gt 0)  { $score += 15 }
    if ($result.KnownClient) { $score += 25 }
    if ($result.Verified) { $score = [Math]::Max(0, $score - 30) }

    foreach ($kc in $KnownClients) {
        if ($result.Name -match [regex]::Escape($kc) -or $result.PatternHits -contains $kc -or $result.StringHits -contains $kc) {
            $score += 25
            break
        }
    }

    $result.Score = [Math]::Min(100, $score)
    return $result
}

# ---------------------------------------------------------------------------
#  JVM / RUNTIME INJECTION CHECK
# ---------------------------------------------------------------------------

function Get-JvmInjectionFlags {
    $flags = @()
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'java.exe' OR Name = 'javaw.exe'" -ErrorAction Stop
    } catch {
        return @{ Running = $false; Flags = @() }
    }

    if (-not $procs) { return @{ Running = $false; Flags = @() } }

    foreach ($p in $procs) {
        $cmd = $p.CommandLine
        if (-not $cmd) { continue }
        if ($cmd -match '-javaagent:')          { $flags += "PID $($p.ProcessId): -javaagent flag present" }
        if ($cmd -match '-Xbootclasspath/p:')    { $flags += "PID $($p.ProcessId): -Xbootclasspath/p (bootstrap override)" }
        if ($cmd -match '-Xbootclasspath/a:')    { $flags += "PID $($p.ProcessId): -Xbootclasspath/a (bootstrap append)" }
        if ($cmd -match '-agentlib:jdwp')        { $flags += "PID $($p.ProcessId): -agentlib:jdwp (remote debug agent)" }
        if ($cmd -match '-agentpath:')           { $flags += "PID $($p.ProcessId): -agentpath (native agent)" }
    }

    return @{ Running = $true; Flags = $flags }
}

# ---------------------------------------------------------------------------
#  SCAN ORCHESTRATION
# ---------------------------------------------------------------------------

function Invoke-ModsScan {
    param([string]$ModsPath, [string]$TargetLabel)

    $jars = Get-ChildItem -Path $ModsPath -Filter *.jar -File -ErrorAction SilentlyContinue
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $results = Invoke-ParallelJarAnalysis -Jars $jars
    Write-Host ""
    $sw.Stop()

    $jvm = Get-JvmInjectionFlags

    Show-Report -Results $results -TargetLabel $TargetLabel -FilesAnalyzed $jars.Count -ElapsedSeconds $sw.Elapsed.TotalSeconds -Mode "MINECRAFT" -JvmInfo $jvm
}

# Known launcher / mod-instance locations. Scanning only these (plus a shallow,
# name-filtered pass over other drives) is what makes "Full PC Scan" fast -
# the previous version walked every file on every drive before filtering,
# which is what made it slow.
function Get-FullPcScanTargets {
    $userProfile = $env:USERPROFILE
    $targets = New-Object System.Collections.Generic.List[string]

    $known = @(
        (Join-Path $userProfile "AppData\Roaming\.minecraft"),
        (Join-Path $userProfile "curseforge\minecraft\Instances"),
        (Join-Path $userProfile "AppData\Roaming\ModrinthApp\profiles"),
        (Join-Path $userProfile ".modrinth\profiles"),
        (Join-Path $userProfile "AppData\Roaming\PrismLauncher\instances"),
        (Join-Path $userProfile "AppData\Local\PrismLauncher\instances"),
        (Join-Path $userProfile "AppData\Roaming\MultiMC\instances"),
        (Join-Path $userProfile "AppData\Roaming\.technic\modpacks"),
        (Join-Path $userProfile "Downloads")
    )
    foreach ($k in $known) {
        if (Test-Path $k) { $targets.Add($k) }
    }

    # Other fixed drives: only look one level deep for obviously relevant
    # folder names, instead of recursing the whole drive.
    try {
        $systemRoot = (Join-Path $env:SystemDrive "")
        $otherDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Free -ne $null -and (Join-Path "$($_.Root)" "") -ne $systemRoot }

        foreach ($d in $otherDrives) {
            Get-ChildItem -Path $d.Root -Directory -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.Name -match '(?i)minecraft|mods|curseforge|modrinth|prism|multimc|technic|launcher' } |
                ForEach-Object { $targets.Add($_.FullName) }
        }
    } catch { }

    return $targets | Select-Object -Unique
}

# Runs Analyze-Jar across a runspace pool so per-file work (hashing, the
# Modrinth verification lookup, unzip + text scan) happens concurrently
# instead of one file at a time - this is the other big speed win, since
# each Modrinth lookup can take a couple of seconds on its own.
function Invoke-ParallelJarAnalysis {
    param(
        [System.IO.FileInfo[]]$Jars,
        [int]$ThrottleLimit = 8
    )

    if (-not $Jars -or $Jars.Count -eq 0) { return @() }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

    foreach ($fn in @(
        'Get-Sha1Hash','Test-ModrinthVerified','Get-DownloadSource',
        'Test-FullwidthUnicode','Get-ObfuscationFlags','Test-KnownObfuscator','Analyze-Jar'
    )) {
        $def = Get-Item "function:$fn" -ErrorAction Stop
        $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $def.Definition)
        $iss.Commands.Add($entry)
    }

    foreach ($varName in @('CheatPatterns','CheatStrings','KnownObfuscators','SourceClassification','KnownClients')) {
        $val = Get-Variable -Name $varName -Scope Script -ValueOnly
        $entry = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($varName, $val, $null)
        $iss.Variables.Add($entry)
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
    $pool.Open()

    $tasks = New-Object System.Collections.Generic.List[object]
    foreach ($jar in $Jars) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($Path)
            Analyze-Jar -JarPath $Path
        }).AddArgument($jar.FullName)

        $tasks.Add([pscustomobject]@{
            Pipe   = $ps
            Handle = $ps.BeginInvoke()
        })
    }

    $results = @()
    $done = 0
    $total = $tasks.Count
    foreach ($t in $tasks) {
        $done++
        Write-Host "`r  Analyzing $done / $total".PadRight(90) -NoNewline
        try {
            $r = $t.Pipe.EndInvoke($t.Handle)
            if ($r) { $results += $r }
        } catch { }
        finally { $t.Pipe.Dispose() }
    }

    $pool.Close()
    $pool.Dispose()

    return $results
}

function Invoke-FullPcScan {
    Write-Host "  Searching known Minecraft/launcher locations..." -ForegroundColor DarkGray
    $targets = Get-FullPcScanTargets

    $allJars = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        Get-ChildItem -Path $t -Filter *.jar -Recurse -File -ErrorAction SilentlyContinue -Force |
            ForEach-Object { $allJars.Add($_) }
    }
    $allJars = $allJars | Sort-Object FullName -Unique

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $results = Invoke-ParallelJarAnalysis -Jars $allJars
    Write-Host ""
    $sw.Stop()

    $jvm = Get-JvmInjectionFlags
    Show-Report -Results $results -TargetLabel "Full PC ($($targets.Count) location(s) checked)" -FilesAnalyzed $allJars.Count -ElapsedSeconds $sw.Elapsed.TotalSeconds -Mode "FULL PC" -JvmInfo $jvm
}

# ---------------------------------------------------------------------------
#  REPORT
# ---------------------------------------------------------------------------

function Show-Report {
    param($Results, $TargetLabel, $FilesAnalyzed, $ElapsedSeconds, $Mode, $JvmInfo)

    Show-Banner

    $jarCount = @($Results).Count
    $sortedResults = @(
        $Results |
        Sort-Object @{Expression = { [int]$_.Score }; Descending = $true},
                    @{Expression = { $_.Name }; Ascending = $true}
    )

    $suspicious = @($sortedResults | Where-Object { [int]$_.Score -ge 25 })

    $topScore = 0
    if ($jarCount -gt 0) {
        $topScore = [int](($sortedResults | Select-Object -First 1).Score)
    }

    $verdictLabel = "CLEAN"
    if ($topScore -ge 71)      { $verdictLabel = "HIGH CONFIDENCE CHEATER" }
    elseif ($topScore -ge 51)  { $verdictLabel = "LIKELY CHEATER" }
    elseif ($topScore -ge 25)  { $verdictLabel = "SUSPICIOUS" }

    $verdictColor = switch ($verdictLabel) {
        "HIGH CONFIDENCE CHEATER" { "Red" }
        "LIKELY CHEATER"          { "Red" }
        "SUSPICIOUS"              { "Yellow" }
        default                   { "Green" }
    }

    $barLen = 34
    $filled = [Math]::Max(0, [Math]::Min($barLen, [Math]::Round(($topScore / 100) * $barLen)))
    $bar = ("█" * $filled) + ("░" * ($barLen - $filled))

    Write-BoxTop -Color DarkGreen
    Write-BoxLine -Text "SCAN COMPLETE" -BorderColor DarkGreen -TextColor Green
    Write-BoxBottom -Color DarkGreen
    Write-Host ""

    Write-Host "  SCAN" -ForegroundColor Cyan
    Write-Host "  ├─ MODE            $Mode"
    Write-Host "  ├─ TARGET          $TargetLabel"
    Write-Host "  ├─ FILES ANALYZED  $FilesAnalyzed"
    Write-Host "  ├─ JAR FILES       $jarCount"
    Write-Host "  └─ SCAN TIME       $([Math]::Round($ElapsedSeconds,2))s"
    Write-Host ""

    Write-Host "  RISK ASSESSMENT" -ForegroundColor Yellow
    Write-Host "  $topScore / 100" -ForegroundColor $verdictColor
    Write-Host "  $bar" -ForegroundColor $verdictColor
    Write-Host "  $verdictLabel" -ForegroundColor $verdictColor
    Write-Host ""

    if ($suspicious.Count -gt 0) {
        Write-Host "  CHEATER DETECTIONS" -ForegroundColor Red
        Write-Host ""

        $i = 1
        foreach ($r in $suspicious) {
            $conf = "LOW"
            if ($r.Score -ge 71) { $conf = "HIGH" }
            elseif ($r.Score -ge 51) { $conf = "MEDIUM" }

            Write-Host ("  [{0:D2}] {1}" -f $i, $r.Name) -ForegroundColor White
            Write-Host "       Confidence: $conf" -ForegroundColor $verdictColor

            if ($r.PatternHits.Count -gt 0) {
                Write-Host "       ├─ Pattern signatures: $($r.PatternHits.Count)"
            }
            if ($r.StringHits.Count -gt 0) {
                Write-Host "       ├─ Component/string matches: $($r.StringHits.Count)"
            }
            if ($r.BypassFlags.Count -gt 0) {
                Write-Host "       ├─ Supporting indicators: $($r.BypassFlags.Count)"
            }
            if ($r.ObfuscationFlags.Count -gt 0) {
                Write-Host "       ├─ Obfuscation indicators: $($r.ObfuscationFlags.Count)"
            }
            if ($r.ObfuscatorHits.Count -gt 0) {
                Write-Host "       ├─ Known obfuscator: $($r.ObfuscatorHits.Count)"
            }
            if ($r.FullwidthHits.Count -gt 0) {
                Write-Host "       ├─ Fullwidth Unicode indicators: $($r.FullwidthHits.Count)"
            }
            if ($r.Source) {
                Write-Host "       ├─ Source: $($r.Source.Url) [$($r.Source.Classification)]"
            }
            Write-Host "       └─ Final Score: $([int]$r.Score) / 100" -ForegroundColor Yellow
            Write-Host ""

            $i++
        }
    }
    else {
        Write-Host "  CHEATER DETECTIONS" -ForegroundColor Green
        Write-Host "  └─ None above the suspicious threshold." -ForegroundColor Green
        Write-Host ""
    }

    if ($JvmInfo.Running) {
        Write-Host "  JVM / RUNTIME" -ForegroundColor Cyan
        if ($JvmInfo.Flags.Count -gt 0) {
            Write-Host "  └─ Injection flags detected:"
            foreach ($f in $JvmInfo.Flags) {
                Write-Host "     • $f"
            }
        }
        else {
            Write-Host "  └─ Java process active; no injection flags found." -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    Write-SectionRule
    Write-Host ""
    Write-Host "  VERDICT" -ForegroundColor Yellow
    Write-Host "  $verdictLabel" -ForegroundColor $verdictColor
    Write-Host "  Threshold: 51 / 100" -ForegroundColor DarkGray
    Write-Host ""
    Write-SectionRule
    Write-Host ""
    Write-Host "  MODWARDEN - by albyi_" -ForegroundColor DarkCyan
    Write-Host "  Discord: albyi_i" -ForegroundColor DarkGray
    Write-Host "  Unsure about a detection? Contact me on Discord for review." -ForegroundColor DarkGray
    Write-Host ""
    Write-SectionRule
    Write-Host ""
    Read-Host "  Press Enter to return to the main menu"
}

# ---------------------------------------------------------------------------
#  MAIN LOOP
# ---------------------------------------------------------------------------

while ($true) {
    $choice = Show-MainMenu
    switch ($choice) {
        "1" {
            $path = Select-ModsPath
            if ($path) {
                Show-Banner
                Write-Host "  Scanning: $path"
                Write-Host ""
                Invoke-ModsScan -ModsPath $path -TargetLabel $path
            }
        }
        "2" {
            Show-Banner
            Write-BoxTop
            Write-BoxLine -Text "FULL PC SCAN" -TextColor Yellow
            Write-BoxBottom
            Write-Host ""
            Write-Host "  ModWarden will search known Minecraft/launcher locations" -ForegroundColor DarkGray
            Write-Host "  across the PC instead of walking the entire filesystem," -ForegroundColor DarkGray
            Write-Host "  so this stays fast even on large drives." -ForegroundColor DarkGray
            Write-Host ""
            Show-MenuOption -Key "1" -Title "CONTINUE"
            Write-Host ""
            Show-MenuOption -Key "2" -Title "BACK"
            Write-Host ""
            Write-SectionRule
            Write-Host ""
            $c = Read-Host "  Select an option [1-2]"
            if ($c -eq "1") { Invoke-FullPcScan }
        }
        "3" {
            Show-Banner
            Write-BoxTop
            Write-BoxLine -Text "CUSTOM PATH" -TextColor Yellow
            Write-BoxBottom
            Write-Host ""
            $p = Read-Host "  Enter directory to scan"
            if (Test-Path $p) {
                Invoke-ModsScan -ModsPath $p -TargetLabel $p
            } else {
                Write-Host "  Path not found." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        "4" { Write-Host "  Exiting ModWarden." -ForegroundColor DarkGray; break }
        default { }
    }
}
