Return-Path: <kasan-dev+bncBC7OD3FKWUERBN6E6GXQMGQE7IB2EYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D068885D97
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:13 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-21e7751f76fsf1330918fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039032; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jo7Lp8rTYaVkTeqbeBa6zWsRwtHl05J+n31iLBT3UACscNgNlNWABbsCYUDE3BuiJi
         KhidT0tPNjHNmfO5ZX0NPwTrby3I7t9UdpCPjYOZfeDVt8CQniXchFva3HErbBnti6BG
         6U5WZkELw5jejdEJ/LqZCpQYVNm1/ostMXVDPL8Ak69+yhiM6E7/ShWcDaoMFDI39jjg
         M8tE6Oj8SG1k7xBWm9eWZGIWfLNDAsm0NywthYgVTwhAoUnQEROmxTKUdf/NvqoU4Bkb
         egC2X9fzaqMJsKptVHEEGmDTHjCXNIS5rmGoU4vidxT1dYFEkb4dGB5gB7YhHt+4SRkU
         AGWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=JfAGOzNe5XPYCyVeFH5IwJAuhzKKATorgrDK6CoIExw=;
        fh=Cy5r/OWu3ZdmOecFc+7MAndIW9icenN4V53oYXwY78s=;
        b=EB9OfziILCSP/Gjfg6lgKAq/ODZ7L3/0vZHhK+tU2JFIYLeni+uKhNsqYzZYug3ukD
         b1KBgQuAJ5YU24zgzBYvJFDmngm0k4CdP67Ch/QCirw8DtWIoGlCkxWiyAkDZCwKysWR
         sbcHt9RMLOjgJcxCd4IyI9g4zttd2iGwr3o97T5J081MzgQTCSyGPPKn0zPZ+zzwoJNP
         xsgBw+atkDm+YhWsI5yw8CKlGD8dJ0AHeRe6dh6+NiHGy/ByVInV5TaF2KfkFawYuxOO
         LYvyAMF29GQQaZ/s4Wboggj444GON/3iYEZiqyFcg8Dhhf4omrP2vfnd0n1BIk6XYVsf
         BFzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zbiZH43o;
       spf=pass (google.com: domain of 3nml8zqykcsmrtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3NmL8ZQYKCSMRTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039032; x=1711643832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JfAGOzNe5XPYCyVeFH5IwJAuhzKKATorgrDK6CoIExw=;
        b=h8Hq3eGNdFb5UHfjRidvSiZiitWBAPwR8JPJhnHRS0/iRzkVe6zxlhOjZj9w6Z1sjh
         VRMXrieeuen42aBOxHuwxl8kF1GF2g36frNYaZDp0q7pb6sd8pc4ASVPg2kT38RcQzPS
         mL6NiDyOVrroXK3PwZCJeTmtgcswoI35x3lYzCS6rBQKG7Pe4vPssh4bScOchqmRBR+t
         QxvOj8zHJsQ9A6vM2NfL95CRjCspVdKPiNmk0MtRzPJuMBJ0FLkxNpqNN0/6M3Shmzjx
         tsaWWUvY3G3uWc6eHNiyYKKSJTy4tEFP7yRUEBEZusgZgzj/PgZ85oiNMxuC/gpDMYOR
         8P6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039032; x=1711643832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JfAGOzNe5XPYCyVeFH5IwJAuhzKKATorgrDK6CoIExw=;
        b=B7oRiX3GEvZUysxlf6uZCNLoJyNyY/bNUnohzHQ1ibGv24hUEu7zCTiro5CZt/tUmi
         70cVcoo9gpRHENRz4qLlMIIx00oJo8sBHAxIWRrUwwoD2J/YLywBJARffbB0e9QFgjiV
         TX9HgCkJb8prbWbm2ypByOQF4CW9+SVpCWvk4aFV7Fl1Hvi1G6rZQC6Fb3b9DDrIy1ks
         ts5XU/N3Pip5gV4FYZzX8QxOokyJjBPIYau0++GGHgAm8p/KhOtqfgfytopErEb8FXXS
         9r/GWezyMgYqHM8Wd5OO8D9+SiT3RLm55K6GojGdUpgy9t0MMasfh801PgPM+JQ5/9OM
         SUlA==
X-Forwarded-Encrypted: i=2; AJvYcCUQJ/2WAwyyol1uPsiRCbrsKtw18TX4bDy8Hd1ZQ98hfusM/m5TDKufymaOntMNhKYwRNoov4qew+nalp1nk1s++4HNNBTYtA==
X-Gm-Message-State: AOJu0YyIMMJW8BziQrqdgWI2D+tIwj7s6ApPH+rHgsAVrMjMPN1TSi96
	lzOMRYrqGmkBul5sPZc3gUwi8tWRssFcBnNghJh6KRhiINNA+Gv1
X-Google-Smtp-Source: AGHT+IFmiMExTcTrMptfdFIGApbZjEinA5IlwpDDQTtpcRciLjbRa8fPZ25Du5/Ikf7VA9KA2Y2Dsg==
X-Received: by 2002:a05:6870:e308:b0:220:932f:1a1e with SMTP id z8-20020a056870e30800b00220932f1a1emr25235308oad.12.1711039031809;
        Thu, 21 Mar 2024 09:37:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ac2b:b0:221:a638:4496 with SMTP id
 kw43-20020a056870ac2b00b00221a6384496ls1461575oab.2.-pod-prod-01-us; Thu, 21
 Mar 2024 09:37:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzsM4bnF9IqXIKLbBKWsLmvfVfSJrQZaM22Q82Esyca8ypVs5oHxgl/BHJop2/PU0HQ+rEapOy54gFeueuI1f0U6bFZ1ozrnZIsQ==
X-Received: by 2002:a05:6870:a2c7:b0:222:69b8:44c6 with SMTP id w7-20020a056870a2c700b0022269b844c6mr24846525oak.9.1711039031020;
        Thu, 21 Mar 2024 09:37:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039031; cv=none;
        d=google.com; s=arc-20160816;
        b=a12FdIz5oGr9novZvKXNXUMOgHA4zWuLfX5LNY83rqcX8m5fMc4lCEPi2SW72n6Vma
         cSM4F9UWiLUW43vB3aPDOfGseopy0jV6fFJBK27jFydWME9ZP+qAU4TdyH/SK13WmlTl
         C6rypU0+Pkx4A9YglOZR8QjwFo154vt/6UXLPTI74/5WvUPTABMU//K9pOtVTpBxy7eo
         kwrflWalsWSVd+cP5Mi/YONd23BQfpbmcaDl+Wccy+JiPqpezpoimHQ7TFbVSZdQW3Tw
         jNTmaVwZYk9WM/evImCMsBj/oxdfY2I9w6wjU154YSXB+gOPwlDlEF5GhCkToDLsWgrZ
         h2kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=ZtzEdHMO1nsPqRyTOFCp2rzxqc4SYrWbhYHVl+Yksck=;
        fh=I+fIW/EzVf7d3ubUNPrv81znGZKl1HBz9qYHYRWWbEU=;
        b=02uOk9X9IM4d4dnFMBco1G3N4rkvBrVnDkr9FX3pMYokNIsRiRmy/xj9W5j/XbWhV8
         bYpk+umfLYV8u2SZnX2PNWP7E28Mby1XO5JOMmtriEN+3n0V+QAYDVrrSwGQTlg9C5X1
         Vq97d7W4eZ4OQjJndLjkjgd5lueGeuQBOD6HH8Q+kFROJYc2k8CPD02Z0N2TBfgyQNNI
         FLDmF8yjGAOsD/aMm75BXeBlNtEPH+HLoneSgDZfuVBegFJeOglVBE+6QpV3+q/K0Gph
         Kc8HqBmjl2fHfDtFBzIYQUvCtRJp8L8mea7GeIjdzcpC/ehthLGQcTIBUz6ykJdHvGvf
         phbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zbiZH43o;
       spf=pass (google.com: domain of 3nml8zqykcsmrtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3NmL8ZQYKCSMRTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id hm14-20020a0568701b8e00b00221d905d771si34368oab.2.2024.03.21.09.37.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nml8zqykcsmrtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dced704f17cso1819004276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXRellt9W9K+6M7Ke0COcV68KWSrpP6NvPX9ClDwvV/5tTFlsymGiJb3jvarh35YDmhLBQR0FDEqS6d+vJ+UveJX+4tTdNy4VKlRg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:11cc:b0:dd9:2789:17fb with SMTP id
 n12-20020a05690211cc00b00dd9278917fbmr720533ybu.3.1711039030449; Thu, 21 Mar
 2024 09:37:10 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:22 -0700
Mime-Version: 1.0
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-1-surenb@google.com>
Subject: [PATCH v6 00/37] Memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zbiZH43o;       spf=pass
 (google.com: domain of 3nml8zqykcsmrtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3NmL8ZQYKCSMRTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Overview:
Low overhead [1] per-callsite memory allocation profiling. Not just for
debug kernels, overhead low enough to be deployed in production.

Example output:
  root@moria-kvm:~# sort -rn /proc/allocinfo
   127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
    56373248     4737 mm/slub.c:2259 func:alloc_slab_page
    14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
    14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
    13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
    11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
     9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
     4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
     4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
     3940352      962 mm/memory.c:4214 func:alloc_anon_folio
     2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
     ...

Since v5 [2]:
- Added Reviewed-by and Acked-by, per Vlastimil Babka and Miguel Ojeda
- Changed pgalloc_tag_{add|sub} to use number of pages instead of order, per Matthew Wilcox
- Changed pgalloc_tag_sub_bytes to pgalloc_tag_sub_pages and adjusted the usage, per Matthew Wilcox
- Moved static key check before prepare_slab_obj_exts_hook(), per Vlastimil Babka
- Fixed RUST helper, per Miguel Ojeda
- Fixed documentation, per Randy Dunlap
- Rebased over mm-unstable

Usage:
kconfig options:
 - CONFIG_MEM_ALLOC_PROFILING
 - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
 - CONFIG_MEM_ALLOC_PROFILING_DEBUG
   adds warnings for allocations that weren't accounted because of a
   missing annotation

sysctl:
  /proc/sys/vm/mem_profiling

Runtime info:
  /proc/allocinfo

Notes:

[1]: Overhead
To measure the overhead we are comparing the following configurations:
(1) Baseline with CONFIG_MEMCG_KMEM=n
(2) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n)
(3) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=y)
(4) Enabled at runtime (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n && /proc/sys/vm/mem_profiling=1)
(5) Baseline with CONFIG_MEMCG_KMEM=y && allocating with __GFP_ACCOUNT
(6) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n)  && CONFIG_MEMCG_KMEM=y
(7) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=y) && CONFIG_MEMCG_KMEM=y

Performance overhead:
To evaluate performance we implemented an in-kernel test executing
multiple get_free_page/free_page and kmalloc/kfree calls with allocation
sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
affinity set to a specific CPU to minimize the noise. Below are results
from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
56 core Intel Xeon:

                        kmalloc                 pgalloc
(1 baseline)            6.764s                  16.902s
(2 default disabled)    6.793s  (+0.43%)        17.007s (+0.62%)
(3 default enabled)     7.197s  (+6.40%)        23.666s (+40.02%)
(4 runtime enabled)     7.405s  (+9.48%)        23.901s (+41.41%)
(5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)
(6 def disabled+memcg)  13.332s (+97.10%)       48.105s (+184.61%)
(7 def enabled+memcg)   13.446s (+98.78%)       54.963s (+225.18%)

Memory overhead:
Kernel size:

   text           data        bss         dec         diff
(1) 26515311	      18890222    17018880    62424413
(2) 26524728	      19423818    16740352    62688898    264485
(3) 26524724	      19423818    16740352    62688894    264481
(4) 26524728	      19423818    16740352    62688898    264485
(5) 26541782	      18964374    16957440    62463596    39183

Memory consumption on a 56 core Intel CPU with 125GB of memory:
Code tags:           192 kB
PageExts:         262144 kB (256MB)
SlabExts:           9876 kB (9.6MB)
PcpuExts:            512 kB (0.5MB)

Total overhead is 0.2% of total memory.

Benchmarks:

Hackbench tests run 100 times:
hackbench -s 512 -l 200 -g 15 -f 25 -P
      baseline       disabled profiling           enabled profiling
avg   0.3543         0.3559 (+0.0016)             0.3566 (+0.0023)
stdev 0.0137         0.0188                       0.0077


hackbench -l 10000
      baseline       disabled profiling           enabled profiling
avg   6.4218         6.4306 (+0.0088)             6.5077 (+0.0859)
stdev 0.0933         0.0286                       0.0489

stress-ng tests:
stress-ng --class memory --seq 4 -t 60
stress-ng --class cpu --seq 4 -t 60
Results posted at: https://evilpiepirate.org/~kent/memalloc_prof_v4_stress-ng/

[2] https://lore.kernel.org/all/20240306182440.2003814-1-surenb@google.com/

Kent Overstreet (13):
  fix missing vmalloc.h includes
  asm-generic/io.h: Kill vmalloc.h dependency
  mm/slub: Mark slab_free_freelist_hook() __always_inline
  scripts/kallysms: Always include __start and __stop symbols
  fs: Convert alloc_inode_sb() to a macro
  rust: Add a rust helper for krealloc()
  mempool: Hook up to memory allocation profiling
  mm: percpu: Introduce pcpuobj_ext
  mm: percpu: Add codetag reference into pcpuobj_ext
  mm: vmalloc: Enable memory allocation profiling
  rhashtable: Plumb through alloc tag
  MAINTAINERS: Add entries for code tagging and memory allocation
    profiling
  memprofiling: Documentation

Suren Baghdasaryan (24):
  mm: introduce slabobj_ext to support slab object extensions
  mm: introduce __GFP_NO_OBJ_EXT flag to selectively prevent slabobj_ext
    creation
  mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
  slab: objext: introduce objext_flags as extension to
    page_memcg_data_flags
  lib: code tagging framework
  lib: code tagging module support
  lib: prevent module unloading if memory is not freed
  lib: add allocation tagging support for memory allocation profiling
  lib: introduce support for page allocation tagging
  lib: introduce early boot parameter to avoid page_ext memory overhead
  mm: percpu: increase PERCPU_MODULE_RESERVE to accommodate allocation
    tags
  change alloc_pages name in dma_map_ops to avoid name conflicts
  mm: enable page allocation tagging
  mm: create new codetag references during page splitting
  mm: fix non-compound multi-order memory accounting in __free_pages
  mm/page_ext: enable early_page_ext when
    CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
  lib: add codetag reference into slabobj_ext
  mm/slab: add allocation accounting into slab allocation and free paths
  mm/slab: enable slab allocation tagging for kmalloc and friends
  mm: percpu: enable per-cpu allocation tagging
  lib: add memory allocations report in show_mem()
  codetag: debug: skip objext checking when it's for objext itself
  codetag: debug: mark codetags for reserved pages as empty
  codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark failed slab_ext
    allocations

 Documentation/admin-guide/sysctl/vm.rst       |  16 +
 Documentation/filesystems/proc.rst            |  29 ++
 Documentation/mm/allocation-profiling.rst     | 100 ++++++
 Documentation/mm/index.rst                    |   1 +
 MAINTAINERS                                   |  17 +
 arch/alpha/kernel/pci_iommu.c                 |   2 +-
 arch/alpha/lib/checksum.c                     |   1 +
 arch/alpha/lib/fpreg.c                        |   1 +
 arch/alpha/lib/memcpy.c                       |   1 +
 arch/arm/kernel/irq.c                         |   1 +
 arch/arm/kernel/traps.c                       |   1 +
 arch/arm64/kernel/efi.c                       |   1 +
 arch/loongarch/include/asm/kfence.h           |   1 +
 arch/mips/jazz/jazzdma.c                      |   2 +-
 arch/powerpc/kernel/dma-iommu.c               |   2 +-
 arch/powerpc/kernel/iommu.c                   |   1 +
 arch/powerpc/mm/mem.c                         |   1 +
 arch/powerpc/platforms/ps3/system-bus.c       |   4 +-
 arch/powerpc/platforms/pseries/vio.c          |   2 +-
 arch/riscv/kernel/elf_kexec.c                 |   1 +
 arch/riscv/kernel/probes/kprobes.c            |   1 +
 arch/s390/kernel/cert_store.c                 |   1 +
 arch/s390/kernel/ipl.c                        |   1 +
 arch/x86/include/asm/io.h                     |   1 +
 arch/x86/kernel/amd_gart_64.c                 |   2 +-
 arch/x86/kernel/cpu/sgx/main.c                |   1 +
 arch/x86/kernel/irq_64.c                      |   1 +
 arch/x86/mm/fault.c                           |   1 +
 drivers/accel/ivpu/ivpu_mmu_context.c         |   1 +
 drivers/gpu/drm/gma500/mmu.c                  |   1 +
 drivers/gpu/drm/i915/gem/i915_gem_pages.c     |   1 +
 .../gpu/drm/i915/gem/selftests/mock_dmabuf.c  |   1 +
 drivers/gpu/drm/i915/gt/shmem_utils.c         |   1 +
 drivers/gpu/drm/i915/gvt/firmware.c           |   1 +
 drivers/gpu/drm/i915/gvt/gtt.c                |   1 +
 drivers/gpu/drm/i915/gvt/handlers.c           |   1 +
 drivers/gpu/drm/i915/gvt/mmio.c               |   1 +
 drivers/gpu/drm/i915/gvt/vgpu.c               |   1 +
 drivers/gpu/drm/i915/intel_gvt.c              |   1 +
 drivers/gpu/drm/imagination/pvr_vm_mips.c     |   1 +
 drivers/gpu/drm/mediatek/mtk_drm_gem.c        |   1 +
 drivers/gpu/drm/omapdrm/omap_gem.c            |   1 +
 drivers/gpu/drm/v3d/v3d_bo.c                  |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_binding.c       |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_cmd.c           |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c       |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_drv.c           |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c       |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_ioctl.c         |   1 +
 drivers/gpu/drm/xen/xen_drm_front_gem.c       |   1 +
 drivers/hwtracing/coresight/coresight-trbe.c  |   1 +
 drivers/iommu/dma-iommu.c                     |   2 +-
 .../marvell/octeon_ep/octep_pfvf_mbox.c       |   1 +
 .../marvell/octeon_ep_vf/octep_vf_mbox.c      |   1 +
 .../net/ethernet/microsoft/mana/hw_channel.c  |   1 +
 drivers/parisc/ccio-dma.c                     |   2 +-
 drivers/parisc/sba_iommu.c                    |   2 +-
 drivers/platform/x86/uv_sysfs.c               |   1 +
 drivers/scsi/mpi3mr/mpi3mr_transport.c        |   2 +
 drivers/staging/media/atomisp/pci/hmm/hmm.c   |   2 +-
 drivers/vfio/pci/pds/dirty.c                  |   1 +
 drivers/virt/acrn/mm.c                        |   1 +
 drivers/virtio/virtio_mem.c                   |   1 +
 drivers/xen/grant-dma-ops.c                   |   2 +-
 drivers/xen/swiotlb-xen.c                     |   2 +-
 include/asm-generic/codetag.lds.h             |  14 +
 include/asm-generic/io.h                      |   1 -
 include/asm-generic/vmlinux.lds.h             |   3 +
 include/linux/alloc_tag.h                     | 205 +++++++++++
 include/linux/codetag.h                       |  81 +++++
 include/linux/dma-map-ops.h                   |   2 +-
 include/linux/fortify-string.h                |   5 +-
 include/linux/fs.h                            |   6 +-
 include/linux/gfp.h                           | 126 ++++---
 include/linux/gfp_types.h                     |  11 +
 include/linux/memcontrol.h                    |  56 ++-
 include/linux/mempool.h                       |  73 ++--
 include/linux/mm.h                            |   9 +
 include/linux/mm_types.h                      |   4 +-
 include/linux/page_ext.h                      |   1 -
 include/linux/pagemap.h                       |   9 +-
 include/linux/pds/pds_common.h                |   2 +
 include/linux/percpu.h                        |  27 +-
 include/linux/pgalloc_tag.h                   | 134 +++++++
 include/linux/rhashtable-types.h              |  11 +-
 include/linux/sched.h                         |  24 ++
 include/linux/slab.h                          | 179 +++++-----
 include/linux/string.h                        |   4 +-
 include/linux/vmalloc.h                       |  60 +++-
 include/rdma/rdmavt_qp.h                      |   1 +
 init/Kconfig                                  |   4 +
 kernel/dma/mapping.c                          |   4 +-
 kernel/kallsyms_selftest.c                    |   2 +-
 kernel/module/main.c                          |  29 +-
 lib/Kconfig.debug                             |  31 ++
 lib/Makefile                                  |   3 +
 lib/alloc_tag.c                               | 243 +++++++++++++
 lib/codetag.c                                 | 283 +++++++++++++++
 lib/rhashtable.c                              |  28 +-
 mm/compaction.c                               |   7 +-
 mm/debug_vm_pgtable.c                         |   1 +
 mm/filemap.c                                  |   6 +-
 mm/huge_memory.c                              |   2 +
 mm/kfence/core.c                              |  14 +-
 mm/kfence/kfence.h                            |   4 +-
 mm/memcontrol.c                               |  56 +--
 mm/mempolicy.c                                |  52 +--
 mm/mempool.c                                  |  36 +-
 mm/mm_init.c                                  |  13 +-
 mm/nommu.c                                    |  64 ++--
 mm/page_alloc.c                               |  71 ++--
 mm/page_ext.c                                 |  13 +
 mm/page_owner.c                               |   2 +-
 mm/percpu-internal.h                          |  26 +-
 mm/percpu.c                                   | 120 +++----
 mm/show_mem.c                                 |  26 ++
 mm/slab.h                                     |  51 ++-
 mm/slab_common.c                              |   6 +-
 mm/slub.c                                     | 327 +++++++++++++++---
 mm/util.c                                     |  44 +--
 mm/vmalloc.c                                  |  88 ++---
 rust/helpers.c                                |   8 +
 scripts/kallsyms.c                            |  13 +
 scripts/module.lds.S                          |   7 +
 sound/pci/hda/cs35l41_hda.c                   |   1 +
 125 files changed, 2319 insertions(+), 652 deletions(-)
 create mode 100644 Documentation/mm/allocation-profiling.rst
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 include/linux/codetag.h
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 lib/alloc_tag.c
 create mode 100644 lib/codetag.c


base-commit: a824831a082f1d8f9b51a4c0598e633d38555fcf
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-1-surenb%40google.com.
