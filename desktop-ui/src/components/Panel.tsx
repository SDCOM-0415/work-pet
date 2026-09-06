import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Info,
  Settings,
  Loader2,
  RefreshCw,
  Save,
  User,
  X,
  Zap,
  Minus,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import robotIcon from "@/assets/robot.png";
import { Switch } from "@/components/ui/switch";
import { getConfig, saveConfig, exportAllAccounts, importBackup } from "@/api";
import WorkBuddyTab from "@/components/WorkBuddyTab";
import SharedAccountCard, { toExpireSec } from "@/components/AccountCardShared";
import traeworkIcon from "@/assets/traework.png";
import workbuddyIcon from "@/assets/workbuddy.png";
import codebuddyIcon from "@/assets/codebuddy.png";
import type { Account, Entitlement, Status } from "@/types";
import { fmtCredits } from "@/api";
import { cn } from "@/lib/utils";

interface PanelProps {
  status: Status | null;
  accounts: Account[];
  current: Account | null;
  entitlements: Entitlement[];
  loading: boolean;
  error: string | null;
  bootstrap: "booting" | "ready" | "failed";
  bootError: string | null;
  claimResults: Record<string, { ok: boolean; already: boolean; msg: string }>;
  armed: Record<string, boolean>;
  onClose: () => void;
  onToggleTheme: () => void;
  onRefresh: () => void;
  onClaimAll: () => void;
  displayCurrentUid: string | null;
  onBackup: () => void;
  onSwitch: (uid: string) => void;
  onDelete: (uid: string) => void;
  hidePet: boolean;
  onHidePetChange: (v: boolean) => void;
  deviceClaimDate: string;
  onHideToTray: () => void;
}

type Tab = "accounts" | "wb" | "cb" | "settings" | "about";

const MAIN_TABS: { key: Tab; label: string; img: string }[] = [
  { key: "accounts", label: "TraeWork", img: traeworkIcon },
  { key: "wb", label: "WorkBuddy", img: workbuddyIcon },
  { key: "cb", label: "CodeBuddy", img: codebuddyIcon },
];
const ICON_TABS: { key: Tab; label: string; icon: typeof User }[] = [
  { key: "settings", label: "设置", icon: Settings },
  { key: "about", label: "关于", icon: Info },
];

export default function Panel(p: PanelProps) {
  const [tab, setTab] = useState<Tab>("wb");
  const [tabOrder, setTabOrder] = useState<Tab[]>(["wb", "accounts", "cb"]);
  const dragTabRef = useRef<Tab | null>(null);
  const [fontScale, setFontScale] = useState<number>(1);
  const [cbLaunch, setCbLaunch] = useState<boolean>(false);
  const [hidePetState, setHidePetState] = useState<boolean | null>(null);
  const [wdRefreshTick, setWdRefreshTick] = useState(0); // 100% 基准 = 原 115% 渲染大小
  // 标题栏拖动窗口（与宠物卡片拖动同款逻辑）
  const dragRef = useRef<{ sx: number; sy: number; dragging: boolean } | null>(null);

  const [showPhone, setShowPhone] = useState<boolean | null>(null);
  // 每秒心跳，驱动倒计时走秒
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    getConfig().then((c) => setShowPhone(c.showPhone)).catch(() => {});
    getConfig().then((c) => setFontScale(c.fontScale || 1)).catch(() => {});
    getConfig().then((c) => setCbLaunch(c.cbLaunchOnStart)).catch(() => {});
    getConfig()
      .then((c) => {
        const known: Tab[] = ["accounts", "wb", "cb"];
        const arr = (c.tabOrder ?? []).filter((t): t is Tab => known.includes(t as Tab));
        const uniq = Array.from(new Set(arr));
        if (uniq.length === known.length) setTabOrder(uniq);
      })
      .catch(() => {});
    getConfig().then((c) => setHidePetState(c.hidePet)).catch(() => {});
  }, []);

  const checked = p.status?.checked_in ?? false;

  // 主 Tab 拖拽排序：拖到目标 Tab 上松手即交换位置，并持久化
  const orderedMainTabs = (() => {
    const known = MAIN_TABS.map((t) => t.key);
    const head = tabOrder.filter((t) => known.includes(t));
    const rest = known.filter((t) => !head.includes(t));
    return head.concat(rest).map((key) => MAIN_TABS.find((t) => t.key === key)!);
  })();
  const handleTabDrop = (target: Tab) => {
    const from = dragTabRef.current;
    dragTabRef.current = null;
    if (!from || from === target) return;
    setTabOrder((prev) => {
      const known: Tab[] = ["accounts", "wb", "cb"];
      const head = prev.filter((t) => known.includes(t));
      const arr = head.concat(known.filter((t) => !head.includes(t)));
      const fromIdx = arr.indexOf(from);
      if (fromIdx < 0) return prev;
      arr.splice(fromIdx, 1);
      arr.splice(arr.indexOf(target), 0, from);
      saveConfig({ tabOrder: arr }).catch(() => {});
      return arr;
    });
  };

  return (
    <Card
      className="flex h-full flex-col gap-2 overflow-hidden rounded-2xl bg-card/85 p-3 shadow-lg backdrop-blur-xl"
      style={{ zoom: fontScale * 1.15 }}
    >
      {/* 头部：标题（可拖动窗口） + 手动刷新 + 主题 + 关闭 */}
      <div
        className="flex items-center gap-1"
        onMouseDown={(e) => {
          if (e.button !== 0) return;
          dragRef.current = { sx: e.screenX, sy: e.screenY, dragging: false };
        }}
        onMouseMove={(e) => {
          const d = dragRef.current;
          if (!d || d.dragging) return;
          if (Math.abs(e.screenX - d.sx) > 5 || Math.abs(e.screenY - d.sy) > 5) {
            d.dragging = true;
            invoke("start_window_drag").catch(() => {});
          }
        }}
        onMouseUp={() => {
          dragRef.current = null;
        }}
        style={{ cursor: "grab" }}
      >
        <span className="text-base font-bold">Work Pet</span>
        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={p.onClaimAll} title="全部签到（TraeWork + WorkBuddy + CodeBuddy）">
          <Zap className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={p.onBackup} title="备份所有账号（单文件导出）">
          <Save className="h-4 w-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={() => {
            p.onRefresh();
            setWdRefreshTick((t) => t + 1);
          }}
          title="刷新数据"
        >
          <RefreshCw className={cn("h-4 w-4", p.loading && "animate-spin")} />
        </Button>
        <div className="ml-auto flex items-center gap-0.5">
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={p.onToggleTheme} title="切换主题">
            <span className="text-sm">◐</span>
          </Button>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={p.onClose} title="缩到最小（收起面板，保留机器人）">
            <Minus className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={p.onHideToTray} title="隐藏到托盘">
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Tab 栏：主 Tab 带文字居左，可拖拽调序（自动保存）；设置/关于仅图标居右 */}
      <div className="flex items-center gap-1">
        {orderedMainTabs.map(({ key, label, img }) => (
          <Button
            key={key}
            variant="ghost"
            size="sm"
            draggable
            onDragStart={() => {
              dragTabRef.current = key;
            }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={() => handleTabDrop(key)}
            onDragEnd={() => {
              dragTabRef.current = null;
            }}
            onClick={() => setTab(key)}
            className={cn(
              "h-8 cursor-grab gap-1.5 rounded-lg px-3 text-xs font-medium active:cursor-grabbing",
              tab === key
                ? "bg-primary text-primary-foreground hover:bg-primary"
                : "text-foreground/70 hover:bg-muted hover:text-foreground"
            )}
            title={`${label}（拖拽调整顺序）`}
          >
            <img src={img} alt="" draggable={false} className="h-3.5 w-3.5" /> {label}
          </Button>
        ))}
        <div className="ml-auto flex items-center gap-0.5">
          {ICON_TABS.map(({ key, label, icon: Icon }) => (
            <Button
              key={key}
              variant="ghost"
              size="icon"
              onClick={() => setTab(key)}
              title={label}
              className={cn(
                "h-8 w-8 rounded-lg",
                tab === key
                  ? "bg-primary text-primary-foreground hover:bg-primary"
                  : "text-foreground/70 hover:bg-muted hover:text-foreground"
              )}
            >
              <Icon className="h-3.5 w-3.5" />
            </Button>
          ))}
        </div>
      </div>

      {p.bootstrap !== "ready" ? (
        <BootstrapNotice bootstrap={p.bootstrap} bootError={p.bootError} />
      ) : p.error && !p.status ? (
        <div className="px-1 py-2 text-xs">
          <p className="text-destructive">{p.error}</p>
          <p className="mt-1 text-muted-foreground">
            启动失败：请确认已安装 Node.js，或重启桌面客户端重试
          </p>
        </div>
      ) : p.loading && !p.status ? (
        <div className="flex items-center gap-2 px-1 py-2 text-xs text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> 读取签到状态…
        </div>
      ) : tab === "accounts" ? (
        <AccountsTab p={p} checked={checked} />
      ) : tab === "wb" || tab === "cb" ? (
        /* WorkBuddy / CodeBuddy 常驻挂载，切 Tab 不重新拉数据 */
        <>
          <div className={cn("min-h-0 flex-1 flex-col", tab === "wb" ? "flex" : "hidden")}>
            <WorkBuddyTab
              showPhone={!!showPhone}
              kind="wb"
              refreshTick={wdRefreshTick}
              onLaunch={(force) => invoke("launch_workbuddy", { force: force ?? false }).then(() => undefined)}
            />
          </div>
          <div className={cn("min-h-0 flex-1 flex-col", tab === "cb" ? "flex" : "hidden")}>
            <WorkBuddyTab
              showPhone={!!showPhone}
              kind="cb"
              label="CodeBuddy"
              refreshTick={wdRefreshTick}
              onLaunch={(force) => invoke("launch_codebuddy", { force: force ?? false }).then(() => undefined)}
              onLaunchCli={() => invoke("launch_codebuddy_cli").then(() => undefined)}
            />
          </div>
        </>
      ) : tab === "settings" ? (
        <SettingsTab
          showPhone={showPhone}
          onShowPhoneChange={setShowPhone}
          fontScale={fontScale}
          onFontScaleChange={setFontScale}
          cbLaunch={cbLaunch}
          onCbLaunchChange={setCbLaunch}
          hidePet={p.hidePet}
          hidePetState={hidePetState}
          onHidePetChange={(v) => {
            setHidePetState(v);
            p.onHidePetChange(v);
          }}
          onRestored={p.onRefresh}
        />
      ) : (
        <AboutTab />
      )}
    </Card>
  );
}

function BootstrapNotice({ bootstrap, bootError }: { bootstrap: string; bootError: string | null }) {
  return (
    <div className="flex items-center gap-2 px-1 py-3 text-xs text-muted-foreground">
      {bootstrap === "booting" ? (
        <>
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          正在启动后台服务…
        </>
      ) : (
        <span className="text-destructive">{bootError ?? "后台服务启动失败"}</span>
      )}
    </div>
  );
}



/* ---------------- 账号 Tab ---------------- */

function AccountsTab({ p, checked }: { p: PanelProps; checked: boolean }) {
  const displayCurrentUid = p.displayCurrentUid ?? p.current?.uid ?? null;
  // 已签账号数（当前账号用实时状态，其余用缓存）；
  // Trae 签到按设备计算：设备名额被任一账号领走 → 全部账号视为已签
  const deviceClaimedToday =
    !!p.deviceClaimDate &&
    p.deviceClaimDate ===
      (() => {
        const d = new Date();
        const z = (n: number) => String(n).padStart(2, "0");
        return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}`;
      })();
  const signedCount = p.accounts.filter(
    (a) =>
      a.credits?.checkedIn ||
      (p.current?.uid === a.uid && checked) ||
      deviceClaimedToday
  ).length;
  // 总积分 = 所有账号剩余积分之和（当前账号用实时权益数据，其余用缓存）
  const totalCredits = p.accounts.reduce((s, a) => {
    if (p.current?.uid === a.uid && p.entitlements.length > 0) {
      return s + p.entitlements.reduce((x, e) => x + e.remaining, 0);
    }
    return s + (a.credits?.remaining ?? 0);
  }, 0);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      {/* 统计行 */}
      <div className="flex items-center gap-3 rounded-lg bg-muted/60 px-3 py-2 text-xs">
        <span className="text-muted-foreground">
          账号数 <span className="font-semibold text-foreground">{p.accounts.length}</span>
        </span>
        <span className="h-3 w-px bg-border" />
        <span className="text-muted-foreground">
          已签 <span className="font-semibold text-foreground">{signedCount}</span>/{p.accounts.length}
        </span>
        <span className="h-3 w-px bg-border" />
        <span className="text-muted-foreground">
          总积分 <span className="font-semibold text-foreground">{fmtCredits(totalCredits)}</span>
        </span>
        {checked ? (
          <Badge className="ml-auto h-5 rounded-full border-0 bg-success px-2 text-[10px] text-white">
            今日已签到 ✓
          </Badge>
        ) : (
          <span className="ml-auto" />
        )}
      </div>

      {/* 账号卡片列表 */}
      {p.accounts.length === 0 ? (
        <p className="px-1 text-[11px] text-muted-foreground">
          暂无备份账号，点击顶部 💾（备份所有账号）保存当前登录账号
        </p>
      ) : (
        <ScrollArea className="min-h-0 flex-1">
          <div className="flex flex-col gap-2 pr-2">
            {p.accounts.map((a) => (
              <AccountCard
                key={a.uid}
                account={a}
                isCurrent={displayCurrentUid === a.uid}
                status={p.status}
                entitlements={p.entitlements}
                armed={p.armed}
                deviceClaimDate={p.deviceClaimDate}
                onSwitch={p.onSwitch}
                onDelete={p.onDelete}
              />
            ))}
          </div>
        </ScrollArea>
      )}

    </div>
  );
}

function AccountCard({
  account,
  isCurrent,
  status,
  entitlements,
  armed,
  deviceClaimDate,
  onSwitch,
  onDelete,
}: {
  account: Account;
  isCurrent: boolean;
  status: Status | null;
  entitlements: Entitlement[];
  armed: Record<string, boolean>;
  deviceClaimDate?: string;
  onSwitch: (uid: string) => void;
  onDelete: (uid: string) => void;
}) {
  const signedIn = account.credits?.checkedIn || (isCurrent && status?.checked_in);
  // Trae 设备签到：每台设备每日只有一个账号能领；名额被占时其余账号显示「本设备已签」
  const today = (() => {
    const d = new Date();
    const z = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}`;
  })();
  // Trae 签到按设备计算：设备名额被任一账号领走后，所有账号都视为已完成签到
  const deviceClaimedByOther = !signedIn && !!deviceClaimDate && deviceClaimDate === today;
  const liveSum =
    entitlements.length > 0 ? entitlements.reduce((s, e) => s + e.remaining, 0) : null;
  const credits = isCurrent
    ? (liveSum ?? account.credits?.remaining ?? null)
    : (account.credits?.remaining ?? null);

  return (
    <SharedAccountCard
      name={account.nickname || "(未命名)"}
      phone={account.mobile || account.uid}
      showFullPhone={false} // TraeWork 源数据仅有打码手机号
      cookieExpireSec={toExpireSec(account.expired_at)}
      isCurrent={isCurrent}
      badge={
        signedIn || deviceClaimedByOther
          ? { text: "已签", tone: "success" as const }
          : null
      }
      credits={credits}
      packs={
        isCurrent && entitlements.length > 0
          ? entitlements
          : (account.credits?.packs ?? [])
      }
      switchArmed={!!armed[`switch:${account.uid}`]}
      deleteArmed={!!armed[`del:${account.uid}`]}
      onSwitch={() => onSwitch(account.uid)}
      onDelete={() => onDelete(account.uid)}
    />
  );
}

/* ---------------- 备份/恢复（单文件全账号） ---------------- */

function BackupRestoreCard({ onRestored }: { onRestored?: () => void }) {
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  return (
    <div className="flex flex-col gap-2 rounded-xl bg-muted/60 px-3 py-2.5">
      <div className="flex items-center gap-2">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">账号备份 / 恢复</span>
          <span className="text-[10px] text-muted-foreground">
            三端全部账号导出为一个 JSON（WorkPet 安装根目录）；拷到其他电脑后从文件恢复
          </span>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="ml-auto h-7 shrink-0 rounded-full px-3 text-xs"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            exportAllAccounts()
              .then((r) => {
                setMsg(
                  `已导出 ${r.file}（Trae ${r.counts.traework} / WB ${r.counts.workbuddy} / CB ${r.counts.codebuddy}）`
                );
                onRestored?.();
              })
              .catch((e) => setMsg(`导出失败：${String(e).slice(0, 60)}`))
              .finally(() => setBusy(false));
          }}
        >
          导出全部账号
        </Button>
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          className="h-7 shrink-0 rounded-full px-3 text-xs"
          disabled={busy}
          onClick={() => fileRef.current?.click()}
        >
          从 JSON 文件恢复…
        </Button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          className="hidden"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (!f) return;
            setBusy(true);
            setMsg(null);
            try {
              const text = await f.text();
              const data = JSON.parse(text);
              const c = await importBackup(data);
              setMsg(`已恢复：Trae ${c.traework} / WB ${c.workbuddy} / CB ${c.codebuddy} 个账号`);
              onRestored?.();
            } catch (err) {
              setMsg(`恢复失败：${String(err).slice(0, 60)}`);
            } finally {
              setBusy(false);
            }
          }}
        />
        <span className="min-w-0 truncate text-[10px] text-muted-foreground">
          选择备份 JSON 后立即导入，无需重启客户端
        </span>
      </div>
      {msg && <p className="px-1 text-[10px] text-muted-foreground">{msg}</p>}
    </div>
  );
}

/* ---------------- 关于 Tab ---------------- */

function SettingsTab({
  showPhone,
  onShowPhoneChange,
  fontScale,
  onFontScaleChange,
  cbLaunch,
  onCbLaunchChange,
  hidePet,
  hidePetState,
  onHidePetChange,
  onRestored,
}: {
  showPhone: boolean | null;
  onShowPhoneChange: (v: boolean) => void;
  fontScale: number;
  onFontScaleChange: (v: number) => void;
  cbLaunch: boolean;
  onCbLaunchChange: (v: boolean) => void;
  hidePet: boolean;
  hidePetState: boolean | null;
  onHidePetChange: (v: boolean) => void;
  onRestored: () => void;
}) {
  const toggleHidePet = () => {
    const next = !hidePet;
    onHidePetChange(next);
    saveConfig({ hidePet: next }).catch(() => onHidePetChange(!next));
  };
  const toggleCbLaunch = () => {
    const next = !cbLaunch;
    onCbLaunchChange(next);
    saveConfig({ cbLaunchOnStart: next }).catch(() => onCbLaunchChange(!next));
  };
  const [launchHost, setLaunchHost] = useState<boolean | null>(null);
  const [wdLaunch, setWdLaunch] = useState<boolean | null>(null);
  const [saveErr, setSaveErr] = useState(false);
  const [autoStart, setAutoStart] = useState<boolean | null>(null);

  useEffect(() => {
    getConfig()
      .then((c) => setLaunchHost(c.launchHostOnStart))
      .catch(() => setLaunchHost(false));
    invoke<boolean>("is_autostart_enabled")
      .then(setAutoStart)
      .catch(() => setAutoStart(false));
    getConfig()
      .then((c) => setWdLaunch(c.wbLaunchOnStart))
      .catch(() => setWdLaunch(false));
  }, []);

  const toggleShowPhone = () => {
    if (showPhone === null) return;
    const next = !showPhone;
    onShowPhoneChange(next);
    saveConfig({ showPhone: next }).catch(() => onShowPhoneChange(!next));
  };

  const toggleWdLaunch = () => {
    if (wdLaunch === null) return;
    const next = !wdLaunch;
    setWdLaunch(next);
    saveConfig({ wbLaunchOnStart: next }).catch(() => setWdLaunch(!next));
  };

  const toggleAutoStart = () => {
    if (autoStart === null) return;
    const next = !autoStart;
    setAutoStart(next);
    invoke("set_autostart", { enable: next }).catch(() => setAutoStart(!next));
  };

  const toggleLaunchHost = () => {
    if (launchHost === null) return;
    const next = !launchHost;
    setLaunchHost(next);
    setSaveErr(false);
    saveConfig({ launchHostOnStart: next }).catch(() => {
      setLaunchHost(!next);
      setSaveErr(true);
    });
  };

  return (
    <ScrollArea className="min-h-0 flex-1">
      <div className="flex flex-col gap-3 pr-2">
      {/* 设置：随系统启动 */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">随系统启动</span>
          <span className="text-[10px] text-muted-foreground">开机后自动运行 Work Pet</span>
        </div>
        <Switch
          checked={autoStart ?? false}
          disabled={autoStart === null}
          onCheckedChange={toggleAutoStart}
          className="ml-auto shrink-0"
        />
      </div>

      {/* 设置：字体大小（滑杆） */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">字体大小</span>
          <span className="text-[10px] text-muted-foreground">拖动调节面板缩放</span>
        </div>
        <span className="ml-auto shrink-0 font-mono text-xs tabular-nums">
          {Math.round(fontScale * 100)}%
        </span>
        <input
          type="range"
          min={0.85}
          max={1.25}
          step={0.05}
          value={fontScale}
          onChange={(e) => {
            const v = Number(e.target.value);
            onFontScaleChange(v);
            saveConfig({ fontScale: v }).catch(() => onFontScaleChange(fontScale));
          }}
          className="h-1 w-28 shrink-0 cursor-pointer appearance-none rounded-full accent-primary"
        />
      </div>

      {/* 设置：显示手机号 */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">显示完整手机号</span>
          <span className="text-[10px] text-muted-foreground">
            关=打码（前3后4，默认）；开=完整号码。TraeWork 数据源仅提供打码号
          </span>
        </div>
        <Switch
          checked={showPhone ?? false}
          disabled={showPhone === null}
          onCheckedChange={toggleShowPhone}
          className="ml-auto shrink-0"
        />
      </div>

      {/* 设置：隐藏桌面宠物 */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">隐藏桌面宠物</span>
          <span className="text-[10px] text-muted-foreground">
            不显示机器人卡片；收起面板时整个窗口隐藏到托盘，点托盘图标恢复
          </span>
        </div>
        <Switch
          checked={hidePetState ?? hidePet}
          disabled={hidePetState === null}
          onCheckedChange={toggleHidePet}
          className="ml-auto shrink-0"
        />
      </div>

      {/* 设置：打开 Pet 时启动 CodeBuddy（CDP 注入） */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">打开 Pet 时同时启动 CodeBuddy</span>
          <span className="text-[10px] text-muted-foreground">
            以调试模式重启 CodeBuddy 并注入面板（CDP 9224）
          </span>
        </div>
        <Switch
          checked={cbLaunch}
          onCheckedChange={toggleCbLaunch}
          className="ml-auto shrink-0"
        />
      </div>

      {/* 设置：打开 Pet 时启动 WorkBuddy */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">打开 Pet 时同时启动 WorkBuddy</span>
          <span className="text-[10px] text-muted-foreground">
            以调试模式拉起 WorkBuddy 客户端
          </span>
        </div>
        <Switch
          checked={wdLaunch ?? false}
          disabled={wdLaunch === null}
          onCheckedChange={toggleWdLaunch}
          className="ml-auto shrink-0"
        />
      </div>

      {/* 设置：打开 Pet 时启动 TraeWork */}
      <div className="flex items-center gap-3 rounded-xl bg-muted/60 px-3 py-2.5">
        <div className="flex min-w-0 flex-col">
          <span className="text-xs font-medium">打开 Pet 时同时启动 TraeWork</span>
          <span className="text-[10px] text-muted-foreground">
            关闭时签到照常进行，不拉起 TraeWork
          </span>
        </div>
        <Switch
          checked={launchHost ?? false}
          disabled={launchHost === null}
          onCheckedChange={toggleLaunchHost}
          className="ml-auto shrink-0"
        />
      </div>
      {/* 备份/恢复：单文件全账号，跨电脑迁移 */}
      <BackupRestoreCard onRestored={onRestored} />

      {saveErr && (
        <p className="px-1 text-[10px] text-destructive">设置保存失败，请确认后台服务正常运行</p>
      )}

      </div>
    </ScrollArea>
  );
}

/* ---------------- 关于 Tab ---------------- */

function AboutTab() {
  return (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-2 text-center">
      <img src={robotIcon} alt="Work Pet" className="h-14 w-14" draggable={false} />
      <p className="text-sm font-semibold">Work Pet</p>
      <p className="text-[11px] text-muted-foreground">版本 1.0.0</p>
      <p className="max-w-full px-2 text-[11px] leading-4 text-foreground/80">
        Work Pet 是多 AI Agent 签到宠物：打开即自动为全部账号签到；
        多账号集中管理与一键切换；积分条按到期时间归类，到期一目了然。
      </p>
      <a
        href="https://github.com/connoryang331/work-pet"
        target="_blank"
        rel="noopener noreferrer"
        onClick={(e) => {
          e.preventDefault();
          invoke("open_external", { url: "https://github.com/connoryang331/work-pet" }).catch(() => {});
        }}
        className="mt-1 flex items-center gap-1.5 rounded-full border border-border bg-muted/60 px-3 py-1 text-[10px] text-muted-foreground hover:text-foreground"
        title="GitHub 仓库"
      >
        <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor" aria-hidden="true"><path d="M12 .3a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.03c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.33-1.76-1.33-1.76-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.31.76-1.61-2.66-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.11-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6.01 0c2.29-1.55 3.3-1.23 3.3-1.23.65 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.81 5.62-5.49 5.92.43.37.82 1.1.82 2.22v3.29c0 .32.22.7.83.58A12 12 0 0 0 12 .3z"/></svg>
        github.com/connoryang331/work-pet
      </a>
    </div>
  );
}
