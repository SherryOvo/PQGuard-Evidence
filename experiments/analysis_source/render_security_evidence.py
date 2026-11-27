"""Replot retained batching cells and unchanged, source-backed outcome counts."""
from pathlib import Path
import argparse,csv,math,statistics,json
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import black,white
p=argparse.ArgumentParser();p.add_argument('--batching-csv',type=Path,required=True);p.add_argument('--outcomes-json',type=Path,required=True);p.add_argument('--font-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
for name,file in [('Plot','Arial.ttf'),('PlotBold','Arial Bold.ttf')]:pdfmetrics.registerFont(TTFont(name,str(a.font_dir/file)))
rows=list(csv.DictReader(a.batching_csv.open()));assert len(rows)==24
outcomes=json.loads(a.outcomes_json.read_text());assert len(outcomes['categories'])==6
c=canvas.Canvas(str(a.output),pagesize=(554,234),initialFontName='Plot',initialFontSize=10);c.setAuthor('Anonymous');c.setTitle('Measured batching and independently checkable outcomes');c.setFillColor(black);c.setStrokeColor(black)
c.setFont('PlotBold',10.5);c.drawString(17,216,'a  Merkle batching reduces signature work');c.drawString(310,216,'b  Independently checkable outcomes')
def marker(x,y,kind):
 c.setFillColor(white)
 if kind==0:c.circle(x,y,2.5,fill=1,stroke=1)
 elif kind==1:
  q=c.beginPath();q.moveTo(x,y+3);q.lineTo(x-3,y-2.5);q.lineTo(x+3,y-2.5);q.close();c.drawPath(q,fill=1,stroke=1)
 elif kind==2:c.rect(x-2.5,y-2.5,5,5,fill=1,stroke=1)
 else:
  q=c.beginPath();q.moveTo(x,y+3);q.lineTo(x-3,y);q.lineTo(x,y-3);q.lineTo(x+3,y);q.close();c.drawPath(q,fill=1,stroke=1)
 c.setFillColor(black)
c.setFont('Plot',10.5);c.setLineWidth(.6);c.line(52,45,263,45);c.line(52,45,52,163)
def yy(v):return 45+118*(math.log10(v)-1.5)/2.5
for v in [100,1000,10000]:
 y=yy(v);c.line(49,y,52,y);c.drawRightString(45,y-3,f'{v:,}')
xs=[70,130,190,250]
for x,label in zip(xs,['Per record','10','50','100']):c.drawCentredString(x,31,label)
c.drawCentredString(157,15,'Entries authenticated per signature')
c.saveState();c.translate(12,105);c.rotate(90);c.drawCentredString(0,0,'Fixed-work throughput (entries/s, log)');c.restoreState()
styles=[[],[4,2],[1,2],[5,2,1,2]]
for i,concurrency in enumerate([1,8,32,64]):
 baseline=statistics.median(float(r['entries_per_s_median']) for r in rows if int(r['concurrency'])==concurrency and r['schedule']=='per-record')
 values=[baseline]+[float(next(r['entries_per_s_median'] for r in rows if int(r['concurrency'])==concurrency and r['schedule']=='batched' and int(r['batch_size'])==b)) for b in [10,50,100]]
 c.setDash(styles[i]);c.setLineWidth(.9)
 q=c.beginPath();q.moveTo(xs[0],yy(values[0]))
 for x,v in zip(xs[1:],values[1:]):q.lineTo(x,yy(v))
 c.drawPath(q);c.setDash([])
 for x,v in zip(xs,values):marker(x,yy(v),i)
 lx=83+(i//2)*90;ly=188-(i%2)*16;c.setDash(styles[i]);c.line(lx-14,ly,lx+2,ly);c.setDash([]);marker(lx-6,ly,i);c.setFont('Plot',10.5);c.drawString(lx+7,ly-3,f'c={concurrency}')
for i,r in enumerate(outcomes['categories']):
 y=184-i*25;c.setFont('Plot',10.3);c.drawRightString(426,y-3,r['label'])
 x=445+90*(math.log10(r['count'])-3);c.setLineWidth(.7);c.line(436,y,x,y);c.circle(x,y,2.3,fill=1,stroke=1);c.setFont('PlotBold',10);c.drawString(x+5,y-3,f"{r['count']:,}")
c.setLineWidth(.5);c.line(436,45,539,45);c.setFont('Plot',10)
for x,label in [(445,'1,000'),(535,'10,000')]:c.line(x,42,x,45);c.drawCentredString(x,30,label)
c.drawCentredString(488,15,'Outcome count (log)');c.showPage();c.save()
