"""Post-time fixtures for the Active hours tests.

Each person lives by a real local clock (Python's time-zone database, so
daylight saving changes happen on the real dates): they wake, work and sleep
at their own hours, post more in the evening, and keep their own weekend.
Times are written the way each source writes them. Seeded, so the files are
the same every run.

  telegram-group.json   Telegram Desktop export (result.json): a group with
                        "Dmitri K" (Moscow, Sat–Sun weekend, no DST) and
                        "jake_nyc" (New York, Sat–Sun weekend, DST)
  reddit-user.json      Reddit listing for u/north_wind_77 — the same Moscow
                        person under another name
  discord-channel.json  DiscordChatExporter JSON: "faisal.r" in Riyadh with a
                        Friday–Saturday weekend
  bot.csv               a news bot posting around the clock
"""
import json, random, datetime as dt
from zoneinfo import ZoneInfo

R = random.Random(20261119)
UTC = dt.timezone.utc

def person(zone, start, days, wake=7.5, bed=23.6, weekend=(5, 6), per_day=6.0, work=True, spread=0.7):
    z = ZoneInfo(zone); out = []
    d0 = dt.date.fromisoformat(start)
    for i in range(days):
        day = d0 + dt.timedelta(days=i); wd = day.weekday(); off = wd in weekend
        n = max(0, int(R.gauss(per_day * (1.25 if off and not work else 0.45 if off and work else 1.0), 1.5)))
        w = wake + R.gauss(0, spread) + (1.5 if off else 0); b = bed + R.gauss(0, spread)
        for _ in range(n):
            # more in the evening, some at lunch, some in the morning
            u = R.random()
            h = R.uniform(w, w + 2) if u < .2 else R.uniform(12, 14) if u < .4 else R.uniform(17.5, b) if u < .9 else R.uniform(w, b)
            if h >= 24: h -= 24
            hh, mm = int(h), int((h % 1) * 60); ss = R.randint(0, 59)
            local = dt.datetime(day.year, day.month, day.day, hh, mm, ss, tzinfo=z)
            out.append(local.astimezone(UTC))
    return sorted(out)

dmitri = person('Europe/Moscow', '2026-01-05', 190, wake=7.8, bed=24.2)
jake = person('America/New_York', '2026-01-05', 190, wake=7.0, bed=23.2)
north = person('Europe/Moscow', '2026-01-05', 190, wake=7.8, bed=24.2, per_day=3.0)   # same person, other name: same routine
faisal = person('Asia/Riyadh', '2026-02-01', 120, wake=8.0, bed=24.5, weekend=(4, 5))

# Telegram Desktop export
msgs = []
for who, fid, L in [('Dmitri K', 'user101', dmitri), ('jake_nyc', 'user202', jake)]:
    for t in L: msgs.append((t, who, fid))
msgs.sort()
tg = {"name": "Night shift", "type": "private_supergroup", "id": 1700000001, "messages": [
    {"id": i + 1, "type": "message", "date": t.astimezone(ZoneInfo('Europe/Berlin')).strftime('%Y-%m-%dT%H:%M:%S'), "date_unixtime": str(int(t.timestamp())), "from": who, "from_id": fid, "text": "…"}
    for i, (t, who, fid) in enumerate(msgs)]}
tg["messages"].insert(3, {"id": 99999, "type": "service", "date": "2026-01-05T10:00:00", "date_unixtime": "1767607200", "actor": "Dmitri K", "actor_id": "user101", "action": "invite_members"})
json.dump(tg, open('telegram-group.json', 'w'), ensure_ascii=False, indent=1)

# Reddit listing
rd = {"kind": "Listing", "data": {"after": None, "children": [{"kind": "t1", "data": {"author": "north_wind_77", "created_utc": float(int(t.timestamp())), "body": "…", "subreddit": "europe"}} for t in reversed(north)]}}
json.dump(rd, open('reddit-user.json', 'w'), indent=1)

# DiscordChatExporter
dc = {"guild": {"id": "1", "name": "Market"}, "channel": {"id": "2", "name": "general"}, "messages": [
    {"id": str(10**17 + i), "type": "Default", "timestamp": t.astimezone(ZoneInfo('Asia/Riyadh')).isoformat(timespec='milliseconds'), "content": "…", "author": {"id": "3", "name": "faisal.r", "nickname": "Faisal"}}
    for i, t in enumerate(faisal)]}
json.dump(dc, open('discord-channel.json', 'w'), ensure_ascii=False, indent=1)

# a bot: every 40–80 minutes, all day, every day
t = dt.datetime(2026, 3, 1, tzinfo=UTC); rows = ['timestamp,author,text']
while t < dt.datetime(2026, 4, 1, tzinfo=UTC):
    rows.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")},newsbot_24,"headline"'); t += dt.timedelta(minutes=R.randint(40, 80))
open('bot.csv', 'w').write('\n'.join(rows) + '\n')
print(len(msgs), len(north), len(faisal), len(rows) - 1)
