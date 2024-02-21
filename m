Return-Path: <kasan-dev+bncBC7OD3FKWUERBSVD3GXAMGQELIW7NQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EFF785E768
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:40:59 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-dce775fa8adsf2075762276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:40:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544458; cv=pass;
        d=google.com; s=arc-20160816;
        b=ac9g2Z1O/uk7izrZGZDkZ2eyLCcEhBOzVQjPD2Kh84Rw+SV8Nc7bw/a7E/3GCcwRWU
         0pL0ymM1r3BDm6su8ar/xQAp/zYjnZfWR570BUmLhLAEAjm6fuLG6dgfoNaxEvC/LmlM
         uNaMFcRtBvQ7jYv4Ema82HpivYY+swXiFZ75qTPPOl2Jle+ISr8mRPLwGrJjXVnavagZ
         PYEQXXTfOgmRY6jmmsplO6UuoilocDwXG6oBCPCwoSCoLePewlkqqJFPpBLb8L8v60W7
         B7gLT9HrNMMEiiMzm5A4y1mT604QIeVl6Q6LQbPowycKxHERh2vguzr5O3E1I1UjyOH3
         f8Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=F0319Z6+0mlwgia3Th7Kuvo2W1vymIxcjtOII5oaLUk=;
        fh=tT7vmZ+JR/XR3KMrYDeJ5TAGOyNP03+htfCfZxT5Uhc=;
        b=dUySWKm784IVnvTIFTHtb19YcVmYQuQosop1G3GUeoHY/bJBIxEI+1J8UP7M+iobSi
         y0lx/vRHdZjG8jtz4BNSISOPHe3RrkULtd4/YdLtwSNYSMLM5rNmKTv88VIhs9PFLUGc
         43+/7dctRvPfFljriFStBto+OMcHsZOIbz1RUs9pZmWd4QepX0umP6nmSztldXt1nk3X
         /29MAMv4lHTdVSc0UNOD1qsXHDVazLzWfiSfW6v/0X0rgNSE4dYwU4RiEbdIf3VrLe9f
         jB/YIOnWkOAiOBbHKeAKvjMPDLJIsglvbbvIof4dUmUz0+DJ/w03q5yLCg7pKl0UWDqz
         xAyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qj+MhQST;
       spf=pass (google.com: domain of 3yfhwzqykcfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3yFHWZQYKCfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544458; x=1709149258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F0319Z6+0mlwgia3Th7Kuvo2W1vymIxcjtOII5oaLUk=;
        b=gifyyOVOtfKMlwaNjanmW/iUUfzjt7Y8wJzParPEcHfZgKn+8gsydQEvZdxnTbgF3h
         wd02H2y2sNThPEAnpGL0RaY5Okn/eoPtKi3KrLxfA2HGqY0ghGZyem7XU80lEQOK55iw
         K3sVGIifQvJ48Wi2w866ROelF7ntXzeXhdZOStUF6BbNrlm2Y0rk+iCZgoBe/pR7vDXY
         JIupWtUXtI07s2hvrLDXmDEo7yExQVAVeH8edlOmyla7eyoToKCWyvxn5/Wz49F0qXFf
         5CqgvFFg+pQcl/yQONc4+rNbSUYCg90B3cwzbGfOC8EQST+HitJ6uKwOJepIJRg1gxAu
         XFUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544458; x=1709149258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F0319Z6+0mlwgia3Th7Kuvo2W1vymIxcjtOII5oaLUk=;
        b=ufZxxE2hVtiVG6l27vpoz6S22fXIgfT5x9zasUxvdiVwzMVUPSWTiby0oPr29zoacs
         ifvbslu8NJjtNnZDxythu226uVGCgdvLQc8T98f6pDjrpHSh/fJhxa2H3trooZf1EPPD
         gz1DfaagzDZJ8SKL1TsBcUibw5+T3Hsx+Qn67hLtIzel27Mv/Mk/OB+D+dxwbLo5jboh
         KfREGpUAn4bVD8OId6BeKjMPCzSUsJZ4k343Pk34SfgQgsrGBn08RHhRnznhYcSZdfAG
         X156YS64sTZ+Zp5K8KNTylTi2+EAZHkumeQM+n5tNDQmi/9Z8N9wfVoLHBrsNbcobLHa
         T8Qw==
X-Forwarded-Encrypted: i=2; AJvYcCXmktomnBUruLogjZ/jl8iw5iR5/exkrbrdBABehmJivxLXXlh94n7jLQY+nWfiSlyDIUNaupHWtPqv0XmsfqhymFhlS1yQUQ==
X-Gm-Message-State: AOJu0YwUCvyjn7N+p0VUKMS9Mj1T48vE4V0kQlaPoATV1oa/ZVcoeM4+
	xdQD9+V0i07NVrNOK9pDCRHtzTlW7Pyibg4Qut1tcxfTV2FXNH5m
X-Google-Smtp-Source: AGHT+IEVy582iE6cYba4CCo/YS87EW04ib+vuxzqIV110jnvWl4ttUEdBbAEDqYiLTCCN9EHj+Y47w==
X-Received: by 2002:a25:8b81:0:b0:dcc:744d:b486 with SMTP id j1-20020a258b81000000b00dcc744db486mr295003ybl.39.1708544458356;
        Wed, 21 Feb 2024 11:40:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d88b:0:b0:dc7:4363:dc02 with SMTP id p133-20020a25d88b000000b00dc74363dc02ls2577427ybg.1.-pod-prod-06-us;
 Wed, 21 Feb 2024 11:40:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwwiswahlnI2WMx2yoHWnuHHSmC1YBNwli7HunoKwTri9PZSltVAqu3GcKZZnoJNW0ZFWwO79UcA04w1kqK9zRGYUc4qYtNi/zgQ==
X-Received: by 2002:a0d:e60f:0:b0:607:8344:7a53 with SMTP id p15-20020a0de60f000000b0060783447a53mr19728071ywe.17.1708544456627;
        Wed, 21 Feb 2024 11:40:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544456; cv=none;
        d=google.com; s=arc-20160816;
        b=L1nhg5dl6Y52tKjhPUz3qgXDNjISh+5L0hfFO0M81F4+9wiwrXpj+LIWAmNpEKH+W5
         VvN7rvgPyjSZI2S2i8WG233a81ll5xb+/GzLwi7jfIdlhc7ED8Lu7+3+sKMa+Fru4bSW
         oqQzYxr/fOgahbIC5G18PvWYUXrLLs9ta9nJYVcVMWHTqVJkvt8fA6BIKXkNv7wE4kuV
         X8WfR7enpA8NEPNmQhD6keaHMPIUzv9oGMSdEEeaIu1HOfbXUA9gFrxM0SWgjsSlRgvP
         7T2f8s0RyqP955miwJ468nSTqEEsk0O27hqJCkmOb7KL1HDBG37MkbYpQ3hVebs76qrA
         P8jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=h6iKERH6ntSMYXEOBWW++ghbM5EttVzR7SwASxK2UGU=;
        fh=gpZM3eU5eqKulcRmXZzfjGRkfRx1Fr77QjB/P6CVGVQ=;
        b=OF4AKFMOr65mwWGJVjv9OvuapI98uyoJ3TH3c1rQva2kSiX8dcLdfjLdKLhlcXu5o+
         y2LFrtow3qrEhuZyN+TRxY/BBZI525Mv5FMv84APwdDWJvPOZa4aHR+hqiFVfM9PiPia
         HjHEYX1or8wo4kOvP3vz876CTrOH1LdhoeUQlUc48Q+a3MJE4OF90bgRrJWel4UVSaXa
         7BDlf4txsw2RkLuf5f9kWlsgSjAZi37O4UZnQs90w+5mE1mZysuIrEDdGFu4arw6jY2v
         ks4RTHBXFW/bNekzc9kCBgSou88fqWSADB6p6nOtlLmtlST95+bF63rHJbCy+kNWbZ0b
         GQZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qj+MhQST;
       spf=pass (google.com: domain of 3yfhwzqykcfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3yFHWZQYKCfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id l23-20020a81ad57000000b006079da1b99asi1311944ywk.4.2024.02.21.11.40.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:40:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yfhwzqykcfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6087e575573so22015657b3.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:40:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU8qWvVWgRYIGqHyGa0reRm3RWHhGbJI4vcmF6AbCMavNpVreSoW7K4YFRzTFeOpDqXOqBhwdGwGtH26EK/Zr4rGFIQsjgS310RYg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:92ce:0:b0:607:74b2:579c with SMTP id
 j197-20020a8192ce000000b0060774b2579cmr4971839ywg.1.1708544456179; Wed, 21
 Feb 2024 11:40:56 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:13 -0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-1-surenb@google.com>
Subject: [PATCH v4 00/36] Memory allocation profiling
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
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Qj+MhQST;       spf=pass
 (google.com: domain of 3yfhwzqykcfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3yFHWZQYKCfktvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
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

Since v3:
 - Dropped patch changing string_get_size() [2] as not needed
 - Dropped patch modifying xfs allocators [3] as non needed,
   per Dave Chinner
 - Added Reviewed-by, per Kees Cook
 - Moved prepare_slab_obj_exts_hook() and alloc_slab_obj_exts() where they
   are used, per Vlastimil Babka
 - Fixed SLAB_NO_OBJ_EXT definition to use unused bit, per Vlastimil Babka
 - Refactored patch [4] into other patches, per Vlastimil Babka
 - Replaced snprintf() with seq_buf_printf(), per Kees Cook
 - Changed output to report bytes, per Andrew Morton and Pasha Tatashin
 - Changed output to report [module] only for loadable modules,
   per Vlastimil Babka
 - Moved mem_alloc_profiling_enabled() check earlier, per Vlastimil Babka
 - Changed the code to handle page splitting to be more understandable,
   per Vlastimil Babka
 - Moved alloc_tagging_slab_free_hook(), mark_objexts_empty(),
   mark_failed_objexts_alloc() and handle_failed_objexts_alloc(),
   per Vlastimil Babka
 - Fixed loss of __alloc_size(1, 2) in kvmalloc functions,
   per Vlastimil Babka
 - Refactored the code in show_mem() to avoid memory allocations,
   per Michal Hocko
 - Changed to trylock in show_mem() to avoid blocking in atomic context,
   per Tetsuo Handa
 - Added mm mailing list into MAINTAINERS, per Kees Cook
 - Added base commit SHA, per Andy Shevchenko
 - Added a patch with documentation, per Jani Nikula
 - Fixed 0day bugs
 - Added benchmark results [5], per Steven Rostedt
 - Rebased over Linux 6.8-rc5

Items not yet addressed:
 - An early_boot option to prevent pageext overhead. We are looking into
   ways for using the same sysctr instead of adding additional early boot
   parameter.

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

[2] https://lore.kernel.org/all/20240212213922.783301-2-surenb@google.com/
[3] https://lore.kernel.org/all/20240212213922.783301-26-surenb@google.com/
[4] https://lore.kernel.org/all/20240212213922.783301-9-surenb@google.com/
[5] Benchmarks:

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

Suren Baghdasaryan (23):
  mm: enumerate all gfp flags
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
  mm: percpu: increase PERCPU_MODULE_RESERVE to accommodate allocation
    tags
  change alloc_pages name in dma_map_ops to avoid name conflicts
  mm: enable page allocation tagging
  mm: create new codetag references during page splitting
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
 Documentation/mm/allocation-profiling.rst     |  86 ++++++
 MAINTAINERS                                   |  17 ++
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
 include/linux/alloc_tag.h                     | 195 ++++++++++++
 include/linux/codetag.h                       |  81 +++++
 include/linux/dma-map-ops.h                   |   2 +-
 include/linux/fortify-string.h                |   5 +-
 include/linux/fs.h                            |   6 +-
 include/linux/gfp.h                           | 126 +++++---
 include/linux/gfp_types.h                     | 101 +++++--
 include/linux/memcontrol.h                    |  56 +++-
 include/linux/mempool.h                       |  73 +++--
 include/linux/mm.h                            |   9 +
 include/linux/mm_types.h                      |   4 +-
 include/linux/page_ext.h                      |   1 -
 include/linux/pagemap.h                       |   9 +-
 include/linux/pds/pds_common.h                |   2 +
 include/linux/percpu.h                        |  27 +-
 include/linux/pgalloc_tag.h                   | 110 +++++++
 include/linux/rhashtable-types.h              |  11 +-
 include/linux/sched.h                         |  24 ++
 include/linux/slab.h                          | 175 +++++------
 include/linux/string.h                        |   4 +-
 include/linux/vmalloc.h                       |  60 +++-
 include/rdma/rdmavt_qp.h                      |   1 +
 init/Kconfig                                  |   4 +
 kernel/dma/mapping.c                          |   4 +-
 kernel/kallsyms_selftest.c                    |   2 +-
 kernel/module/main.c                          |  25 +-
 lib/Kconfig.debug                             |  31 ++
 lib/Makefile                                  |   3 +
 lib/alloc_tag.c                               | 204 +++++++++++++
 lib/codetag.c                                 | 283 ++++++++++++++++++
 lib/rhashtable.c                              |  28 +-
 mm/compaction.c                               |   7 +-
 mm/debug_vm_pgtable.c                         |   1 +
 mm/filemap.c                                  |   6 +-
 mm/huge_memory.c                              |   2 +
 mm/kfence/core.c                              |  14 +-
 mm/kfence/kfence.h                            |   4 +-
 mm/memcontrol.c                               |  56 +---
 mm/mempolicy.c                                |  52 ++--
 mm/mempool.c                                  |  36 +--
 mm/mm_init.c                                  |  13 +-
 mm/nommu.c                                    |  64 ++--
 mm/page_alloc.c                               |  66 ++--
 mm/page_ext.c                                 |  13 +
 mm/page_owner.c                               |   2 +-
 mm/percpu-internal.h                          |  26 +-
 mm/percpu.c                                   | 120 +++-----
 mm/show_mem.c                                 |  26 ++
 mm/slab.h                                     | 126 ++++++--
 mm/slab_common.c                              |   6 +-
 mm/slub.c                                     | 244 +++++++++++----
 mm/util.c                                     |  44 +--
 mm/vmalloc.c                                  |  88 +++---
 rust/helpers.c                                |   8 +
 scripts/kallsyms.c                            |  13 +
 scripts/module.lds.S                          |   7 +
 sound/pci/hda/cs35l41_hda.c                   |   1 +
 123 files changed, 2269 insertions(+), 682 deletions(-)
 create mode 100644 Documentation/mm/allocation-profiling.rst
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 include/linux/codetag.h
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 lib/alloc_tag.c
 create mode 100644 lib/codetag.c


base-commit: 39133352cbed6626956d38ed72012f49b0421e7b
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-1-surenb%40google.com.
