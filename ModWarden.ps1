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
    "stun_slam","safe_anchor","double_anchor","auto_pot_refill","walksy_optimizer",
    "key_pearl","aim_assist","auto_neth_pot","auto_dtap","trigger_bot","auto_web",
    "DOUBLE_ESCAPE","DOUBLE_RIGHTCLICK_FIRST","DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY","PLACE_OBI","WAIT_OBI","PLACE_CRYSTAL","BREAK_CRYSTAL",
    "ROTATING_DOWN","ROTATING_BACK","REFILLING","PLANTING","BONEMEALING",
    "AnchorAction","Places two anchors for massive damage","REOFFHAND_TOTEM",
    "webmacro","web macro","AntiWeb","AutoWeb","Ａｎｔｉ Ｗｅｂ","ＡｕｔｏＷｅｂ",
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
    "onPushOutOfBlocks","onIsGlowing","Automatically switches to sword when hitting with totem",
    "arrayOfString","POT_CHEATS","Dqrkis Client","Entity.isGlowing","Activate Key",
    "Click Simulation","On RMB","No Count Glitch","No Bounce","NoBounce","Place Delay",
    "Break Delay","Place Chance","Break Chance","Stop On Kill","damagetick",
    "Anti Weakness","Particle Chance","Trigger Key","Switch Delay","Totem Slot",
    "Smooth Rotations","Rotation Speed","Use Easing","Easing Strength","While Use",
    "Glowstone Delay","Glowstone Chance","Explode Delay","Explode Chance","Explode Slot",
    "Only Charge","Reach Distance","Min Height","Min Fall Speed","Attack Delay",
    "Breach Delay","Require Elytra","Auto Switch Back","Check Line of Sight",
    "Only When Falling","Require Crit","Show Status Display","Stop On Crystal",
    "Check Shield","On Pop","Predict Damage","On Ground","Check Players",
    "Predict Crystals","Check Aim","Check Items","Activates Above","Blatant",
    "Force Totem","Stay Open For","Auto Inventory Totem","Only On Pop","Vertical Speed",
    "Swap Speed","Strict One-Tick","Mace Priority","Min Totems","Min Pearls",
    "Totem First","Drop Interval","Random Pattern","Horizontal Aim Speed",
    "Vertical Aim Speed","Include Head","Web Delay","Holding Web",
    "Not When Affects Player","Hit Delay","Require Hold Axe","placeInterval",
    "breakInterval","stopOnKill","activateOnRightClick","holdCrystal","Macro Key",
    "KillAura","ClickAura","MultiAura","ForceField","LegitAura","AimBot","AutoAim",
    "SilentAim","AimLock","HeadSnap","CrystalAura","AnchorAura","AnchorFill",
    "AnchorPlace","BedAura","AutoBed","BedBomb","BedPlace","BowAimbot","BowSpam",
    "AutoBow","AutoCrit","CritBypass","AlwaysCrit","CriticalHit","ReachHack",
    "ExtendReach","LongReach","HitboxExpand","AntiKB","NoKnockback","GrimVelocity",
    "GrimDisabler","VelocitySpoof","KBReduce","OffhandTotem","TotemSwitch","AutoWeapon",
    "AutoSword","AutoCity","Burrow","SelfTrap","HoleFiller","AntiSurround","AntiBurrow",
    "WTap","TargetStrafe","AutoGap","AutoPearl","FlyHack","CreativeFlight","BoatFly",
    "PacketFly","AirJump","SpeedHack","BHop","BunnyHop","AntiFall","NoFallDamage",
    "SafeFall","StepHack","FastClimb","AutoStep","HighStep","WaterWalk","LiquidWalk",
    "LavaWalk","NoSlow","NoSlowdown","NoWeb","NoSoulSand","WallHack","ElytraSpeed",
    "InstantElytra","ScaffoldWalk","FastBridge","BuildHelper","AutoBridge","Nuker",
    "NukerLegit","InstantBreak","GhostHand","NoSwing","PlaceAssist","AirPlace",
    "AutoPlace","InstantPlace","PlayerESP","MobESP","ItemESP","StorageESP","ChestESP",
    "Tracers","NameTagsHack","XRayHack","OreFinder","CaveFinder","OreESP","NewChunks",
    "ChunkBorders","TunnelFinder","TargetHUD","ReachDisplay","DoubleClicker","JitterClick",
    "ButterflyClick","CPSBoost","ChestStealer","InvManager","InvMovebypass","AutoSprint",
    "AntiAFK","AutoRespawn","PopSwitch","FakeLatency","FakePing","SpoofRotation",
    "PositionSpoof","GameSpeed","SpeedTimer","GrimBypass","VulcanBypass","MatrixBypass",
    "AACBypass","VerusDisabler","IntaveBypass","WatchdogBypass","PacketMine","PacketWalk",
    "PacketSneak","PacketCancel","PacketDupe","PacketSpam","SelfDestruct","HideClient",
    "SessionStealer","TokenLogger","TokenGrabber","DiscordToken","RemoteAccess",
    "ReverseShell","C2Server","Backdoor","KeyLogger","StashFinder","TrailFinder",
    "imgui.binding","JNativeHook","GlobalScreen","NativeKeyListener","client-refmap.json",
    "cheat-refmap.json","aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "meteordevelopment","cc/novoline","com/alan/clients","club/maxstats",
    "wtf/moonlight","me/zeroeightsix/kami","net/ccbluex","today/opai",
    "net/minecraft/injection","org/chainlibs/module/impl/modules","xyz/greaj",
    "com/cheatbreaker","com/moonsworth","doomsdayclient","DoomsdayClient",
    "doomsday.jar","novaclient","api.novaclient.lol","vape.gg","vapeclient",
    "VapeClient","VapeLite","intent.store","IntentClient","rise.today","riseclient.com",
    "meteor-client","meteorclient","meteordevelopment.meteorclient","liquidbounce",
    "fdp-client","net.ccbluex","novoware","novoclient","aristois","impactclient",
    "azura","pandaware","skilled","moonClient","astolfo","futureClient","konas",
    "rusherhack","inertia","exhibition","dev.krypton","dev/krypton","skid.krypton",
    "skid/krypton","VirginClient","virgin client","catlean","CatleanClient",
    "catlean client","ArgonClient","argon client","Asteria","AsteriaClient",
    "asteria client","Prestige","PrestigeClient","prestige client","prestigeclient.vip",
    "gypsy","GypsyClient","gypsy client","Xenon","XenonClient","xenon client",
    "GrimClient","grim client","phantom-refmap.json","dqrkis.xyz","Dqrkis Client",
    "dev.virel","orchard","JDWP.VirtualMachine.AllModules"
)

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

function Show-Banner {
    Clear-Host
    Write-Host "+----------------------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "|                                                                            |" -ForegroundColor DarkCyan
    Write-Host "|                              M O D W A R D E N                             |" -ForegroundColor Cyan
    Write-Host "|                         MINECRAFT FORENSIC ANALYZER                         |" -ForegroundColor DarkCyan
    Write-Host "|                                                                            |" -ForegroundColor DarkCyan
    Write-Host "+----------------------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-MainMenu {
    Show-Banner
    Write-Host "  SCAN OPTIONS"
    Write-Host ""
    Write-Host "  [1]  MINECRAFT SCAN"
    Write-Host "       Scan selected Minecraft / mod directories."
    Write-Host ""
    Write-Host "  [2]  FULL PC SCAN"
    Write-Host "       Search the accessible PC for relevant signatures."
    Write-Host ""
    Write-Host "  [3]  CUSTOM PATH"
    Write-Host "       Scan any directory you specify."
    Write-Host ""
    Write-Host "  [4]  EXIT"
    Write-Host ""
    return Read-Host "  Select an option [1-4]"
}

function Show-MinecraftMenu {
    Show-Banner
    Write-Host "  MINECRAFT SCAN"
    Write-Host ""
    Write-Host "  Select how ModWarden should locate the mods:"
    Write-Host ""
    Write-Host "  [1]  ENTER MODS PATH"
    Write-Host "       Enter the exact folder containing the mods."
    Write-Host ""
    Write-Host "  [2]  SCAN MINECRAFT DIRECTORIES"
    Write-Host "       Search common Minecraft installation locations."
    Write-Host ""
    Write-Host "  [3]  BACK"
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

                if (Test-Path $p) {
                    return $p
                }

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

                if ([int]::TryParse($sel, [ref]$idx) -and
                    $idx -ge 1 -and
                    $idx -le $installs.Count) {
                    return $installs[$idx - 1].Path
                }
            }

            "3" {
                return $null
            }

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
    }
    catch {
        return $null
    }
}

function Test-ModrinthVerified {
    param([string]$Hash)

    try {
        $resp = Invoke-RestMethod `
            -Uri "https://api.modrinth.com/v2/version_file/$Hash" `
            -Method Get `
            -TimeoutSec 6 `
            -ErrorAction Stop

        if ($resp -and $resp.project_id) {
            return $resp.project_id
        }
    }
    catch { }

    return $null
}

function Get-DownloadSource {
    param([string]$FilePath)

    try {
        $zone = Get-Content `
            -Path $FilePath `
            -Stream Zone.Identifier `
            -ErrorAction Stop

        $urlLine = $zone | Where-Object { $_ -match "^HostUrl=" }

        if ($urlLine) {
            $url = $urlLine -replace "^HostUrl=", ""

            foreach ($key in $SourceClassification.Keys) {
                if ($url -match [regex]::Escape($key)) {
                    return @{
                        Url = $url
                        Classification = $SourceClassification[$key]
                    }
                }
            }

            return @{
                Url = $url
                Classification = "UNKNOWN"
            }
        }
    }
    catch { }

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

    if ($total -eq 0) {
        return $flags
    }

    $numeric   = ($ClassNames | Where-Object { $_ -match '^\d+$' }).Count
    $shortName = ($ClassNames | Where-Object { $_ -match '^[A-Za-z]{1,2}$' }).Count
    $unicode   = ($ClassNames | Where-Object { $_ -match '[^\x00-\x7F]' }).Count
    $fullwidth = ($ClassNames | Where-Object { Test-FullwidthUnicode $_ }).Count
    $japanese  = ($ClassNames | Where-Object { $_ -match '[\p{IsHiragana}\p{IsKatakana}]' }).Count
    $confusion = ($ClassNames | Where-Object { $_ -match '^[IlO01_]+$' }).Count

    if ($total -gt 0) {
        if (($numeric / $total) -gt 0.15) {
            $flags += "Numeric class names ($numeric/$total)"
        }

        if (($shortName / $total) -gt 0.30) {
            $flags += "Single/two-letter class names ($shortName/$total)"
        }

        if ($unicode -gt 0) {
            $flags += "Unicode class names ($unicode)"
        }

        if ($fullwidth -gt 0) {
            $flags += "Fullwidth Unicode class names ($fullwidth)"
        }

        if ($japanese -gt 0) {
            $flags += "Japanese obfuscation ($japanese classes)"
        }

        if ($confusion -gt 0) {
            $flags += "Confusion-character class names ($confusion)"
        }
    }

    return $flags
}

function Test-KnownObfuscator {
    param([string]$Content)

    $hits = @()

    foreach ($obf in $KnownObfuscators) {
        if ($Content -match [regex]::Escape($obf)) {
            $hits += $obf
        }
    }

    return $hits
}

# ---------------------------------------------------------------------------
#  JAR ANALYSIS
# ---------------------------------------------------------------------------

function Analyze-Jar {
    param([string]$JarPath)

    $result = [ordered]@{
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
    }
    catch {
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

        # Pattern match on path/name
        foreach ($pat in $CheatPatterns) {
            if ($entryName -match [regex]::Escape($pat)) {
                if ($result.PatternHits -notcontains $pat) {
                    $result.PatternHits += $pat
                }
            }
        }

        if (Test-FullwidthUnicode $entryName) {
            if ($result.FullwidthHits -notcontains $entryName) {
                $result.FullwidthHits += $entryName
            }
        }

        # Only read text content of relevant, reasonably small entries
        $isTextTarget =
            $entryName -match '\.class$' -or
            $entryName -match '\.json$' -or
            $entryName -match 'MANIFEST\.MF$'

        if ($isTextTarget -and $entry.Length -lt 3MB) {
            try {
                $stream = $entry.Open()
                $reader = New-Object System.IO.StreamReader($stream)
                $content = $reader.ReadToEnd()

                $reader.Close()
                $stream.Close()

                foreach ($str in $CheatStrings) {
                    if ($content -match [regex]::Escape($str)) {
                        if ($result.StringHits -notcontains $str) {
                            $result.StringHits += $str
                        }
                    }
                }

                if (Test-FullwidthUnicode $content) {
                    if ($result.FullwidthHits -notcontains "$entryName (content)") {
                        $result.FullwidthHits += "$entryName (content)"
                    }
                }

                if ($content -match 'Runtime\.exec|ProcessBuilder') {
                    $hasRuntimeExec = $true
                }

                if ($content -match 'HttpURLConnection|URL\(.*http|openStream\(') {
                    $hasHttpDownload = $true
                }

                if ($content -match '"POST"|HttpPost|setRequestMethod\("POST"\)') {
                    $hasHttpPost = $true
                }

                $obfHits = Test-KnownObfuscator -Content $content

                foreach ($o in $obfHits) {
                    if ($result.ObfuscatorHits -notcontains $o) {
                        $result.ObfuscatorHits += $o
                    }
                }
            }
            catch { }
        }
    }

    $zip.Dispose()

    $result.ObfuscationFlags = Get-ObfuscationFlags -ClassNames $classNames

    if ($result.NestedJars.Count -gt 0) {
        $result.BypassFlags += "Nested JAR(s) embedded in META-INF/jars ($($result.NestedJars.Count))"
    }

    if ($hasRuntimeExec) {
        $result.BypassFlags += "Runtime.exec / ProcessBuilder usage detected"
    }

    if ($hasHttpDownload) {
        $result.BypassFlags += "HTTP download capability detected"
    }

    if ($hasHttpPost) {
        $result.BypassFlags += "HTTP POST (possible exfiltration) detected"
    }

    # Fake identity
    $safeMods = @(
        "lithium",
        "sodium",
        "phosphor",
        "fabric-api",
        "optifine",
        "iris"
    )

    foreach ($safe in $safeMods) {
        if ($result.Name -match $safe -and
            ($result.PatternHits.Count -gt 0 -or $result.StringHits.Count -gt 0)) {

            $result.BypassFlags += `
                "Possible fake identity: named like '$safe' but contains cheat-related content"
        }
    }

    # -----------------------------------------------------------------------
    # SCORE
    # -----------------------------------------------------------------------

    $score = 0

    if ($result.PatternHits.Count -gt 0) {
        $score += 15 + [Math]::Min(20, $result.PatternHits.Count * 3)
    }

    if ($result.StringHits.Count -gt 0) {
        $score += 20 + [Math]::Min(25, $result.StringHits.Count * 2)
    }

    if ($result.FullwidthHits.Count -gt 0) {
        $score += 10
    }

    if ($result.BypassFlags.Count -gt 0) {
        $score += 10 * $result.BypassFlags.Count
    }

    if ($result.ObfuscationFlags.Count -gt 0) {
        $score += 5 * $result.ObfuscationFlags.Count
    }

    if ($result.ObfuscatorHits.Count -gt 0) {
        $score += 15
    }

    if ($result.KnownClient) {
        $score += 25
    }

    if ($result.Verified) {
        $score = [Math]::Max(0, $score - 30)
    }

    foreach ($kc in $KnownClients) {
        if ($result.Name -match [regex]::Escape($kc) -or
            $result.PatternHits -contains $kc -or
            $result.StringHits -contains $kc) {

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
        $procs = Get-CimInstance Win32_Process `
            -Filter "Name = 'java.exe' OR Name = 'javaw.exe'" `
            -ErrorAction Stop
    }
    catch {
        return @{
            Running = $false
            Flags = @()
        }
    }

    if (-not $procs) {
        return @{
            Running = $false
            Flags = @()
        }
    }

    foreach ($p in $procs) {
        $cmd = $p.CommandLine

        if (-not $cmd) {
            continue
        }

        if ($cmd -match '-javaagent:') {
            $flags += "PID $($p.ProcessId): -javaagent flag present"
        }

        if ($cmd -match '-Xbootclasspath/p:') {
            $flags += "PID $($p.ProcessId): -Xbootclasspath/p (bootstrap override)"
        }

        if ($cmd -match '-Xbootclasspath/a:') {
            $flags += "PID $($p.ProcessId): -Xbootclasspath/a (bootstrap append)"
        }

        if ($cmd -match '-agentlib:jdwp') {
            $flags += "PID $($p.ProcessId): -agentlib:jdwp (remote debug agent)"
        }

        if ($cmd -match '-agentpath:') {
            $flags += "PID $($p.ProcessId): -agentpath (native agent)"
        }
    }

    return @{
        Running = $true
        Flags = $flags
    }
}

# ---------------------------------------------------------------------------
#  SCAN ORCHESTRATION
# ---------------------------------------------------------------------------

function Invoke-ModsScan {
    param(
        [string]$ModsPath,
        [string]$TargetLabel
    )

    $jars = Get-ChildItem `
        -Path $ModsPath `
        -Filter *.jar `
        -File `
        -ErrorAction SilentlyContinue

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $results = @()
    $count = 0

    foreach ($jar in $jars) {
        $count++

        Write-Host "`r  Analyzing $count / $($jars.Count): $($jar.Name)".PadRight(90) -NoNewline

        $results += Analyze-Jar -JarPath $jar.FullName
    }

    Write-Host ""

    $sw.Stop()

    $jvm = Get-JvmInjectionFlags

    Show-Report `
        -Results $results `
        -TargetLabel $TargetLabel `
        -FilesAnalyzed $jars.Count `
        -ElapsedSeconds $sw.Elapsed.TotalSeconds `
        -Mode "MINECRAFT" `
        -JvmInfo $jvm
}

function Invoke-FullPcScan {
    $drives = Get-PSDrive -PSProvider FileSystem |
        Where-Object { $_.Free -ne $null }

    $allJars = @()

    Write-Host "  Searching accessible drives for JAR files (this can take a while)..."

    foreach ($d in $drives) {
        try {
            $allJars += Get-ChildItem `
                -Path "$($d.Root)" `
                -Filter *.jar `
                -Recurse `
                -File `
                -ErrorAction SilentlyContinue `
                -Force |
                Where-Object {
                    $_.FullName -match '(?i)mods|minecraft|modrinth|prismlauncher|curseforge'
                }
        }
        catch { }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $results = @()
    $count = 0

    foreach ($jar in $allJars) {
        $count++

        Write-Host "`r  Analyzing $count / $($allJars.Count): $($jar.Name)".PadRight(90) -NoNewline

        $results += Analyze-Jar -JarPath $jar.FullName
    }

    Write-Host ""

    $sw.Stop()

    $jvm = Get-JvmInjectionFlags

    Show-Report `
        -Results $results `
        -TargetLabel "Full PC" `
        -FilesAnalyzed $allJars.Count `
        -ElapsedSeconds $sw.Elapsed.TotalSeconds `
        -Mode "FULL PC" `
        -JvmInfo $jvm
}

# ---------------------------------------------------------------------------
#  REPORT
# ---------------------------------------------------------------------------

function Show-Report {
    param(
        $Results,
        $TargetLabel,
        $FilesAnalyzed,
        $ElapsedSeconds,
        $Mode,
        $JvmInfo
    )

    Show-Banner

    Write-Host "+----------------------------------------------------------------------------+" -ForegroundColor DarkGreen
    Write-Host "|                           SCAN COMPLETE                                    |" -ForegroundColor Green
    Write-Host "+----------------------------------------------------------------------------+" -ForegroundColor DarkGreen
    Write-Host ""

    $jarCount = $Results.Count

    Write-Host "  SCAN"
    Write-Host "  |- MODE                    $Mode"
    Write-Host "  |- TARGET                  $TargetLabel"
    Write-Host "  |- FILES ANALYZED          $FilesAnalyzed"
    Write-Host "  |- JAR FILES               $jarCount"
    Write-Host "  ``- SCAN TIME              $([Math]::Round($ElapsedSeconds,2))s"
    Write-Host ""

    # -----------------------------------------------------------------------
    #  ONLY SUSPICIOUS MODS
    # -----------------------------------------------------------------------

    $suspicious = @(
        $Results |
        Where-Object { $_.Score -ge 25 } |
        Sort-Object Score -Descending
    )

    # Highest score
    $topScore = 0

    if ($Results.Count -gt 0) {
        $topScore = ($Results | Measure-Object -Property Score -Maximum).Maximum
    }

    # Verdict
    $verdictLabel = "CLEAN"

    if ($topScore -ge 71) {
        $verdictLabel = "HIGH CONFIDENCE CHEATER"
    }
    elseif ($topScore -ge 51) {
        $verdictLabel = "LIKELY CHEATER"
    }
    elseif ($topScore -ge 25) {
        $verdictLabel = "SUSPICIOUS"
    }

    # -----------------------------------------------------------------------
    #  SUSPICIOUS MODS
    # -----------------------------------------------------------------------

    Write-Host "  SUSPICIOUS MODS"
    Write-Host ""

    if ($suspicious.Count -gt 0) {
        $i = 1

        foreach ($r in $suspicious) {
            Write-Host ("  [{0:D2}] {1}  -  Score: {2}/100" -f $i, $r.Name, $r.Score)
            $i++
        }
    }
    else {
        Write-Host "  No suspicious mods detected." -ForegroundColor Green
    }

    Write-Host ""

    # -----------------------------------------------------------------------
    #  RISK ASSESSMENT
    # -----------------------------------------------------------------------

    Write-Host "  RISK ASSESSMENT"
    Write-Host ""

    $barLen = 34
    $filled = [Math]::Round(($topScore / 100) * $barLen)

    $bar = ("#" * $filled).PadRight($barLen, '.')

    Write-Host "                              $topScore / 100"
    Write-Host "                   $bar"
    Write-Host ""
    Write-Host "                         $verdictLabel"
    Write-Host ""

    # -----------------------------------------------------------------------
    #  JVM / RUNTIME
    # -----------------------------------------------------------------------

    if ($JvmInfo.Running) {
        Write-Host "  JVM / RUNTIME"

        if ($JvmInfo.Flags.Count -gt 0) {
            Write-Host "  Injection flags detected:"

            foreach ($f in $JvmInfo.Flags) {
                Write-Host "       - $f"
            }
        }
        else {
            Write-Host "  No injection flags detected."
        }

        Write-Host ""
    }

    # -----------------------------------------------------------------------
    #  VERDICT
    # -----------------------------------------------------------------------

    Write-Host "  VERDICT"
    Write-Host ""
    Write-Host "                            $verdictLabel"
    Write-Host
