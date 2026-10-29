"""Read-only terminal views with a new SQLite snapshot on each refresh."""
import curses
import time
from atlas.detection.rules import analyze
from atlas.core.events import clean
from atlas.storage.reader import reader


def snapshot(path,selected='all',mode='observations',limit=2000):
    if selected not in ('all','wifi','ble','service','cellular') or mode not in ('observations','findings'):
        raise ValueError('unsupported dashboard view')
    with reader(path) as store:
        rows=store.observations(limit)
        counts=store.stats()
        tables={r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        retained={t:store.db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]
                  for t in ('wifi_baselines','ble_findings','detection_findings','cellular_baselines') if t in tables}
        import json
        saved=[]
        saved_bytes=0
        saved_truncated=False
        if mode=='findings':
            for table in ('ble_findings','detection_findings'):
                if table in tables:
                    if retained[table]>100: saved_truncated=True
                    for (body,) in store.db.execute(f'SELECT substr(body,1,65537) FROM {table} ORDER BY rowid DESC LIMIT 100'):
                        size=len(body.encode())
                        if size>65536 or saved_bytes+size>2*1024*1024:
                            saved_truncated=True;continue
                        saved_bytes+=size
                        saved.append(json.loads(body))
    selected_rows=[o for o in rows if selected=='all' or o['kind']==selected or (selected=='ble' and o['kind']=='ble_gatt')]
    if mode=='findings':
        from atlas.cellular.analysis import analyze as cellular_analyze
        cellular_findings = cellular_analyze(selected_rows)['findings']
        lines=[f"{o['severity']:6} {o['rule']} {o['identity']} {o['evidence']}" for o in analyze(selected_rows) + cellular_findings]
        for finding in saved:
            assets=finding.get('affected_assets',[dict(kind='ble',observed_id=finding.get('observed_address',''))])
            if selected=='all' or any(asset['kind']==selected or (selected=='ble' and asset['kind']=='ble_gatt') for asset in assets):
                lines.append(f"saved {finding['confidence']} {finding.get('rule_id',finding.get('rule'))} {', '.join(a['observed_id'] for a in assets)}")
    else:
        lines=[f"{o['observed_at'][:19]} {o['kind']:8} {o['id']:24} {o.get('name','')} {o.get('security','')} {o.get('rssi','')} {o.get('technology','')} {o.get('cellular_event','')} {o.get('cell_freshness','')} {o['source']}" for o in reversed(selected_rows)]
    header=["ATLAS RF | q quit | 1 all 2 Wi-Fi 3 BLE 4 TCP 5 cellular | f findings | o history | arrows scroll",
            f"{mode} / {selected} | counts {counts} | latest {limit} observations",
            f"Retained evidence: {retained} | findings truncated: {saved_truncated} | no collection",
            'Historical observations; addresses do not prove identity; RSSI is not location.','']
    return dict(lines=[clean(line) for line in header+lines],counts=counts,retained=retained,
                analyzed=len(rows),total=sum(counts.values()),truncated=sum(counts.values())>len(rows),
                read_only=True,saved_findings_truncated=saved_truncated,view=mode,protocol=selected)


def dashboard(path):
    # Backward-compatible callers can supply a Store, but CLI callers pass only a path.
    path=getattr(path,'path',path)
    snapshot(path) # Fail before entering curses if storage is invalid.
    def draw(screen):
        screen.timeout(250)
        selected,mode,offset,refreshed='all','observations',0,0
        frame=None
        while True:
            if frame is None or time.monotonic()-refreshed>=2:
                frame=snapshot(path,selected,mode)
                refreshed=time.monotonic()
            screen.erase()
            height,width=screen.getmaxyx()
            header,lines=frame['lines'][:5],frame['lines'][5:]
            page=max(1,height-len(header)-1)
            offset=min(max(0,offset),max(0,len(lines)-page))
            for y,line in enumerate(header+lines[offset:offset+page]):
                if y>=height-1: break
                try: screen.addnstr(y,0,line,max(0,width-1))
                except curses.error: pass
            screen.refresh()
            key=screen.getch()
            if key in (ord('q'),27): break
            if key in (ord('1'),ord('2'),ord('3'),ord('4'),ord('5')):
                selected={ord('1'):'all',ord('2'):'wifi',ord('3'):'ble',ord('4'):'service',ord('5'):'cellular'}[key]
                mode,offset,frame='observations',0,None
            elif key in (ord('f'),ord('o')):
                mode,offset,frame=('findings' if key==ord('f') else 'observations'),0,None
            elif key==curses.KEY_DOWN: offset+=1
            elif key==curses.KEY_UP: offset-=1
            elif key==curses.KEY_NPAGE: offset+=page
            elif key==curses.KEY_PPAGE: offset-=page
    curses.wrapper(draw)
