from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--analysis-output',required=True)
parser.add_argument('--figure-output',required=True)
args=parser.parse_args()
CASE=Path(args.analysis_output).expanduser().resolve()
OUT=Path(args.figure_output).expanduser().resolve()
OUT.mkdir(parents=True,exist_ok=True)
(CASE/'figures').mkdir(exist_ok=True)
F=json.loads((CASE/'tables/VERIFIED_FACTS.json').read_text())
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'axes.titlesize':10,'axes.labelsize':9,'legend.fontsize':8,'pdf.fonttype':42,'ps.fonttype':42,'axes.spines.top':False,'axes.spines.right':False,'axes.edgecolor':'#59616c','xtick.color':'#404650','ytick.color':'#404650','savefig.facecolor':'white'})

def finish(fig,name,top):
    fig.subplots_adjust(top=top,bottom=.20,left=.08,right=.985,wspace=.39)
    fig.savefig(OUT/(name+'.pdf'))
    fig.savefig(CASE/'figures'/(name+'.png'),dpi=135)
    plt.close(fig)

fig,ax=plt.subplots(1,2,figsize=(7.2,2.85))
for profile,color in [('classical','#167a87'),('post_quantum','#9b526d')]:
    for impl,style,mark in [('submitted_cbas','-','o'),('conventional_strong','--','s')]:
        rows=sorted((x for x in F['cpu']['groups'] if (x['profile'],x['implementation'])==(profile,impl)),key=lambda x:x['concurrency'])
        x=[r['concurrency'] for r in rows]
        label=('Classical' if profile=='classical' else 'Hybrid PQ')+' / '+('CBAS' if impl=='submitted_cbas' else 'matched store')
        ax[0].plot(x,[r['median_of_cell_medians_ms'] for r in rows],style,marker=mark,color=color,label=label,linewidth=1.7,markersize=4)
        ax[1].plot(x,[r['mean_cell_throughput_rps'] for r in rows],style,marker=mark,color=color,linewidth=1.7,markersize=4)
for a,title in zip(ax,['a  Request latency','b  Durable-path throughput']):
    a.set_title(title,loc='left',fontweight='bold');a.set_xscale('log',base=2);a.set_xticks([1,8,32,64],['1','8','32','64']);a.set_xlabel('Client concurrency');a.set_yscale('log');a.grid(axis='y',color='#dfe3e8',linewidth=.6);a.set_axisbelow(True)
ax[0].set_ylabel('Median cell latency (ms)');ax[1].set_ylabel('Mean cell throughput (requests/s)')
fig.legend(*ax[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.53,1),ncol=2,frameon=False,columnspacing=2)
finish(fig,'Fig3_cbas_scalability',.71)

colors={'plain':'#9199a4','transport':'#167a87','conventional_full':'#b58c35','submitted_full':'#304b78','merkle8':'#b65e67'}
labels={'plain':'Plain','transport':'Transport','conventional_full':'Matched store','submitted_full':'Per-record CBAS','merkle8':'Merkle (cap 8)'}
fig,ax=plt.subplots(1,3,figsize=(7.7,3.0))
for a,w,title in zip(ax,['short','long','mixed'],['a  Short: 64 / 64 tokens','b  Long: 1,024 / 256 tokens','c  Mixed lengths']):
    for mode in colors:
        rows=sorted((x for x in F['gpu']['groups'] if (x['workload'],x['mode'])==(w,mode)),key=lambda x:x['concurrency']);x=[r['concurrency'] for r in rows]
        a.plot(x,[r['mean_cell_throughput_rps'] for r in rows],color=colors[mode],linestyle='--' if mode in ['transport','conventional_full'] else '-',marker='^' if mode=='merkle8' else 'o',linewidth=1.5,markersize=3.5,label=labels[mode])
        a.fill_between(x,[r['min_cell_throughput_rps'] for r in rows],[r['max_cell_throughput_rps'] for r in rows],color=colors[mode],alpha=.12,linewidth=0)
    a.set_title(title,loc='left',fontweight='bold',fontsize=9);a.set_xscale('log',base=2);a.set_xticks([1,8,32],['1','8','32']);a.set_xlabel('Client concurrency');a.set_ylim(bottom=0);a.grid(axis='y',color='#dfe3e8',linewidth=.6);a.set_axisbelow(True)
ax[0].set_ylabel('Throughput (requests/s)')
fig.legend(*ax[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.52,1),ncol=3,frameon=False,columnspacing=1.8)
finish(fig,'Fig5_continuous_gpu',.71)

fig,ax=plt.subplots(1,2,figsize=(7.2,3.0))
for w,color in [('short','#167a87'),('long','#9b526d'),('mixed','#b58c35')]:
    ds=sorted((x for x in F['gpu']['differences'] if x['workload']==w and x['treatment']=='merkle8'),key=lambda x:x['concurrency'])
    x=np.array([r['concurrency'] for r in ds]);v=np.array([r['mean_difference_ms'] for r in ds]);lo=np.array([r['seed_difference_min_ms'] for r in ds]);hi=np.array([r['seed_difference_max_ms'] for r in ds])
    ax[0].errorbar(x,v,yerr=[v-lo,hi-v],color=color,marker='o',linewidth=1.5,capsize=3,markersize=4,label=w.capitalize())
    bs=sorted((r for r in F['gpu']['batches'] if r['workload']==w),key=lambda x:x['concurrency'])
    ax[1].plot(x,[r['effective_batch_mean'] for r in bs],color=color,marker='o',linewidth=1.5,markersize=4,label=w.capitalize())
for a,title in zip(ax,['a  Merkle minus per-record latency','b  Observed terminal batch size']):
    a.set_title(title,loc='left',fontweight='bold',fontsize=9);a.set_xscale('log',base=2);a.set_xticks([1,8,32],['1','8','32']);a.set_xlabel('Client concurrency');a.grid(axis='y',color='#dfe3e8',linewidth=.6);a.set_axisbelow(True)
ax[0].axhline(0,color='#505865',linewidth=.8,linestyle=':');ax[0].set_yscale('symlog',linthresh=60);ax[0].set_yticks([-1500,-500,0,50],['−1,500','−500','0','50']);ax[0].set_ylabel('Latency difference (ms)')
ax[1].set_ylim(.7,8.4);ax[1].axhline(8,color='#505865',linewidth=.8,linestyle=':');ax[1].set_ylabel('Measured records / sealed batches')
fig.legend(*ax[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.52,.99),ncol=3,frameon=False)
finish(fig,'Fig6_merkle_tradeoff',.76)
print('FIGURES_GENERATED',3)
