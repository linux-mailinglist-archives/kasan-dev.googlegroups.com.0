Return-Path: <kasan-dev+bncBC7OD3FKWUERBFVAVKXAMGQEJ5RHSHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ED78851FBD
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:36 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-363f8682e11sf11615ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773975; cv=pass;
        d=google.com; s=arc-20160816;
        b=LTX2eoT72HE+AwrzI/s6qwxC6W/Gl/XUf3pdR2tsPLxBgYaA6e/e5XCKn9Ee7AiQPI
         yDRTNuiAh1dX0dSI7Hdtsipp//tOE+wHAZC0OwJrj2gLe0x3BuB41metI+7jxjY5oVzp
         i5rEmip4r4u/Egz/P9xg1vu+NEjDhxIFPHPwt62s994eEoqmQovIRx36gcUpwAFJCYID
         JVt3vA1e7LCqjJVeANwvlXfCnnx00I/FmCbvovyq4o/+YyG/9IW4+y6eG7U/oIArvC1E
         uASVNUAcOTWj6jrHdI0t6gcJGu6Ji2c0KvoTr/57vD5J+N0FT0vVzJFiKIyooYDbJr/s
         6qGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=YImssbfYOO1WmbP47MhQ72JcFGcNwrKwinZ34Zprmsk=;
        fh=5JPt8oGXrSr1a2GSGoNEqsTubkZ90GTP4nZtQkqRG4A=;
        b=H+hok/ZmBFfo9O7Dvh4w34C4/SZZbWTsboE+wCwQ2AABrYokm7p2uIp28NwRAAJVbz
         1aopHeSfqBVaG2omzVyhp2vexvk4wCXt/8Ht+zZ4LOulAJ+H7vaawvurJg79vULy1AnG
         d4k+zpd8qLIITpLuvosRhdrMoeFz9GhqEl8u9SMbYdB3wn2OvDGk1Qr1GFh9hmMRkQgL
         Q+0TBp4wYmXWumlpp7ctgaluR+rxtlu7TYezGTb85tQqHYxyeXOawIEYNZly5pU4r1mx
         dxi5Chtt0T7LROKtOqnVQxYkvUCrocVGcSfnP75V6e4ijolMm2xlQJ3HdTtu6OwpnjEC
         +Eow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hQSfzmcs;
       spf=pass (google.com: domain of 3fjdkzqykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FJDKZQYKCZMFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773975; x=1708378775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YImssbfYOO1WmbP47MhQ72JcFGcNwrKwinZ34Zprmsk=;
        b=SqYxuHePPAyin0Ad/wtYQZjg81aBkMK78miW91Q/s1vBhEvFy5b9uWrjkFzocb+KQW
         2S86Bq5Rhw8j8406K3AIGMXi39gNzzNpuOkIusDZp+zUvJ0h6rG0X03M/BFfYDXWsG/G
         07a5SOi0z6XYAuJMEREgljc9mkZVTHAPZJVi7cMBUmO5Z8RXx7G+5OIa5D3/FaCrpcAc
         VmtVY7ipBsaN44FJ4x81009hAdSmZbQSrrIlQxNKMpIjzQNP2cIeItXg6pdK59yvb+GR
         TClmniFHWWG4Rb6faDrBCWXKXoTnsdwjBT6W44L5P662AFTxCWpEOEBzu3DytAkLviP6
         0+pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773975; x=1708378775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YImssbfYOO1WmbP47MhQ72JcFGcNwrKwinZ34Zprmsk=;
        b=bVLkRm3ndxhKCWgkysn6hw+LnXBVcCW/KknQw50lJ38M0H5eVXPktpYwl8GfIk2OUx
         WH0CheKMiWGoy7Vfuym8Mf5lnuQE6LOWjCRwW5cfkDio7trZ/047oUdVu+6QYmFpXmAr
         ENT6+o+iKwNWCynCSNAnVWLPhYSPqr0oMLl+52iE8BCH83J17+6um1O7tmVxjGYraTVB
         Q3jznCUg22Wat3rfi0hWtFOoqw5bj0FPct5hIsRUkOyljjX8fbc4kfViQad4I3sGWd6a
         ybcCE3SyaidRrqdRk4acRkqSOSaMhfCk4s7k13nIBYY1A9msk0yVVorQA0nifY+LPfZy
         z5dg==
X-Gm-Message-State: AOJu0YzKQdw4LMYswuXgazBDryBIp0z8mzCmto6pDGrEO+KLMuTP5r1k
	lSGKbPFndpFOGCJFMO1tDctiZKA+6oyc5/h4klc9po6ALAn4FCS1
X-Google-Smtp-Source: AGHT+IH1lQ3LIToIVZlBYmz5Tq/jgEhHPoZ1I+bIWmVmiZnzKEt/GnnDMSZHWPmnaCM+nEFORTsC4Q==
X-Received: by 2002:a05:6e02:f0e:b0:363:c5ec:9fe6 with SMTP id x14-20020a056e020f0e00b00363c5ec9fe6mr9370ilj.29.1707773974966;
        Mon, 12 Feb 2024 13:39:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3307:b0:363:7be8:179c with SMTP id
 bm7-20020a056e02330700b003637be8179cls2250872ilb.2.-pod-prod-04-us; Mon, 12
 Feb 2024 13:39:33 -0800 (PST)
X-Received: by 2002:a05:6602:590:b0:7c4:5262:103f with SMTP id v16-20020a056602059000b007c45262103fmr7794979iox.8.1707773973110;
        Mon, 12 Feb 2024 13:39:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773973; cv=none;
        d=google.com; s=arc-20160816;
        b=Ep4W3rzYzGNaF1llGAnjVwcF2i206fTlrhk4ERU/kUmYd7WZXJSJcjzsKLTyvM9c1O
         cSxxWP+X+R+gUz3x73Pme5WIeV/cED6wIvuKQiT5GjBx0RhO7fHiEKurRfPnsWWg36SM
         xT97xjNkGzcTIk/4Gu9yZQfvcZJphtH75TjkGaXVE9ecL1A2rJ5WYHabDfo3g/X48qiG
         eeJuQ32L9LRXnsDXd62NkQs+gTxAj+6htgL113GT3gUDJCasX8iuxH1eHYH1RyI238GG
         m6WIT5RSvsery1dJKW4ShHVaF8ZZ1MCDRYer+KdMtu+mSrQUSursL0wIZpCCPxFZPqA9
         JP6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=vA/ePHR05wabM4Y5MMpygOj0r4Hku8hMtHDwkSr6xQQ=;
        fh=5JPt8oGXrSr1a2GSGoNEqsTubkZ90GTP4nZtQkqRG4A=;
        b=sLHXwrIh9EEr0L6op0P4TMoDfIlOgpuJI9oIT8wV3/weM5tvOxR5sBWSg+gMfxJx7o
         OSKqBpRB4t/eBeohs3WVaYJyhZcuBdI/O0KiOxsMV5QuHev2smtw5uC85sPLwtJAo/Xc
         1GNhrlAIl0ADR4Eykt2Aq/Tuwy8MyH2vvW447k05El9UGHgeOhR3MoBygYcEjbhmfyDI
         NBdzHxpFL3Ro4bDQ3UDQTH5Q7vytyXQa6Bp42S6hYSpcQx3oXYAoLEt0/mf1wZHq6zQ5
         y7qp9mWUagqB+fhJgXYzEmuMr1XBwat65Xl7FoNIkjsLMHZBQ1IFyMACKgsywxuYtBgD
         pHAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hQSfzmcs;
       spf=pass (google.com: domain of 3fjdkzqykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FJDKZQYKCZMFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXbRw7mYyfZY2scP4jM2YCp5Zu76TOu5nRYkXXlXSb0yDtsDwf0JJ9UJV4VF1Nh8PsVreoLwQj5JXaY0Zkg07BCohmYUSnOCdE8/A==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id v13-20020a02384d000000b00473ac84c0c0si364914jae.6.2024.02.12.13.39.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fjdkzqykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcc58cddb50so290813276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:33 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:188c:b0:dbd:b165:441 with SMTP id
 cj12-20020a056902188c00b00dbdb1650441mr2291367ybb.0.1707773972271; Mon, 12
 Feb 2024 13:39:32 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:46 -0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-1-surenb@google.com>
Subject: [PATCH v3 00/35] Memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=hQSfzmcs;       spf=pass
 (google.com: domain of 3fjdkzqykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FJDKZQYKCZMFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
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

Memory allocation, v3 and final:

Overview:
Low overhead [1] per-callsite memory allocation profiling. Not just for debug
kernels, overhead low enough to be deployed in production.

We're aiming to get this in the next merge window, for 6.9. The feedback
we've gotten has been that even out of tree this patchset has already
been useful, and there's a significant amount of other work gated on the
code tagging functionality included in this patchset [2].

Example output:
  root@moria-kvm:~# sort -h /proc/allocinfo|tail
   3.11MiB     2850 fs/ext4/super.c:1408 module:ext4 func:ext4_alloc_inode
   3.52MiB      225 kernel/fork.c:356 module:fork func:alloc_thread_stack_node
   3.75MiB      960 mm/page_ext.c:270 module:page_ext func:alloc_page_ext
   4.00MiB        2 mm/khugepaged.c:893 module:khugepaged func:hpage_collapse_alloc_folio
   10.5MiB      168 block/blk-mq.c:3421 module:blk_mq func:blk_mq_alloc_rqs
   14.0MiB     3594 include/linux/gfp.h:295 module:filemap func:folio_alloc_noprof
   26.8MiB     6856 include/linux/gfp.h:295 module:memory func:folio_alloc_noprof
   64.5MiB    98315 fs/xfs/xfs_rmap_item.c:147 module:xfs func:xfs_rui_init
   98.7MiB    25264 include/linux/gfp.h:295 module:readahead func:folio_alloc_noprof
    125MiB     7357 mm/slub.c:2201 module:slub func:alloc_slab_page

Since v2:
 - tglx noticed a circular header dependency between sched.h and percpu.h;
   a bunch of header cleanups were merged into 6.8 to ameliorate this [3].

 - a number of improvements, moving alloc_hooks() annotations to the
   correct place for better tracking (mempool), and bugfixes.

 - looked at alternate hooking methods.
   There were suggestions on alternate methods (compiler attribute,
   trampolines), but they wouldn't have made the patchset any cleaner
   (we still need to have different function versions for accounting vs. no
   accounting to control at which point in a call chain the accounting
   happens), and they would have added a dependency on toolchain
   support.

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

Performance overhead:
To evaluate performance we implemented an in-kernel test executing
multiple get_free_page/free_page and kmalloc/kfree calls with allocation
sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
affinity set to a specific CPU to minimize the noise. Below are results
from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
56 core Intel Xeon:

                        kmalloc                 pgalloc
(1 baseline)            6.764s                  16.902s
(2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
(3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
(4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
(5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)

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

[2]: Improved fault injection is the big one; the alloc_hooks() macro
this patchset introduces is also used for per-callsite fault injection
points in the dynamic fault injection patchset, which means we can
easily do fault injection on a per module or per file basis; this makes
it much easier to integrate memory fault injection into existing tests.

Vlastimil recently raised concerns about exposing GFP_NOWAIT as a
PF_MEMALLOC_* flag, as this might introduce GFP_NOWAIT to allocation
paths that have never had their failure paths tested - this is something
we need to address.

[3]: The circular dependency looks to be unavoidable; the issue is that
alloc_tag_save() -> current -> get_current() requires percpu.h, and
percpu.h requires sched.h because of course it does. But this doesn't
actually cause build errors because we're only using macros, so the main
concern is just not leaving a difficult-to-disentangle minefield for
later.
So, sched.h is now pretty close to being a types only header that
imports types and declares types - this is the header cleanups that were
merged for 6.8.


Kent Overstreet (11):
  lib/string_helpers: Add flags param to string_get_size()
  scripts/kallysms: Always include __start and __stop symbols
  fs: Convert alloc_inode_sb() to a macro
  mm/slub: Mark slab_free_freelist_hook() __always_inline
  mempool: Hook up to memory allocation profiling
  xfs: Memory allocation profiling fixups
  mm: percpu: Introduce pcpuobj_ext
  mm: percpu: Add codetag reference into pcpuobj_ext
  mm: vmalloc: Enable memory allocation profiling
  rhashtable: Plumb through alloc tag
  MAINTAINERS: Add entries for code tagging and memory allocation
    profiling

Suren Baghdasaryan (24):
  mm: enumerate all gfp flags
  mm: introduce slabobj_ext to support slab object extensions
  mm: introduce __GFP_NO_OBJ_EXT flag to selectively prevent slabobj_ext
    creation
  mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
  mm: prevent slabobj_ext allocations for slabobj_ext and kmem_cache
    objects
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

 Documentation/admin-guide/sysctl/vm.rst       |  16 ++
 Documentation/filesystems/proc.rst            |  28 ++
 MAINTAINERS                                   |  16 ++
 arch/alpha/kernel/pci_iommu.c                 |   2 +-
 arch/mips/jazz/jazzdma.c                      |   2 +-
 arch/powerpc/kernel/dma-iommu.c               |   2 +-
 arch/powerpc/mm/book3s64/radix_pgtable.c      |   2 +-
 arch/powerpc/platforms/ps3/system-bus.c       |   4 +-
 arch/powerpc/platforms/pseries/vio.c          |   2 +-
 arch/x86/kernel/amd_gart_64.c                 |   2 +-
 drivers/block/virtio_blk.c                    |   4 +-
 drivers/gpu/drm/gud/gud_drv.c                 |   2 +-
 drivers/iommu/dma-iommu.c                     |   2 +-
 drivers/mmc/core/block.c                      |   4 +-
 drivers/mtd/spi-nor/debugfs.c                 |   6 +-
 .../ethernet/chelsio/cxgb4/cxgb4_debugfs.c    |   4 +-
 drivers/parisc/ccio-dma.c                     |   2 +-
 drivers/parisc/sba_iommu.c                    |   2 +-
 drivers/scsi/sd.c                             |   8 +-
 drivers/staging/media/atomisp/pci/hmm/hmm.c   |   2 +-
 drivers/xen/grant-dma-ops.c                   |   2 +-
 drivers/xen/swiotlb-xen.c                     |   2 +-
 fs/xfs/kmem.c                                 |   4 +-
 fs/xfs/kmem.h                                 |  10 +-
 include/asm-generic/codetag.lds.h             |  14 +
 include/asm-generic/vmlinux.lds.h             |   3 +
 include/linux/alloc_tag.h                     | 188 +++++++++++++
 include/linux/codetag.h                       |  83 ++++++
 include/linux/dma-map-ops.h                   |   2 +-
 include/linux/fortify-string.h                |   5 +-
 include/linux/fs.h                            |   6 +-
 include/linux/gfp.h                           | 126 +++++----
 include/linux/gfp_types.h                     | 101 +++++--
 include/linux/memcontrol.h                    |  56 +++-
 include/linux/mempool.h                       |  73 +++--
 include/linux/mm.h                            |   8 +
 include/linux/mm_types.h                      |   4 +-
 include/linux/page_ext.h                      |   1 -
 include/linux/pagemap.h                       |   9 +-
 include/linux/percpu.h                        |  27 +-
 include/linux/pgalloc_tag.h                   | 105 +++++++
 include/linux/rhashtable-types.h              |  11 +-
 include/linux/sched.h                         |  24 ++
 include/linux/slab.h                          | 184 +++++++------
 include/linux/string.h                        |   4 +-
 include/linux/string_helpers.h                |  11 +-
 include/linux/vmalloc.h                       |  60 +++-
 init/Kconfig                                  |   4 +
 kernel/dma/mapping.c                          |   4 +-
 kernel/kallsyms_selftest.c                    |   2 +-
 kernel/module/main.c                          |  25 +-
 lib/Kconfig.debug                             |  31 +++
 lib/Makefile                                  |   3 +
 lib/alloc_tag.c                               | 213 +++++++++++++++
 lib/codetag.c                                 | 258 ++++++++++++++++++
 lib/rhashtable.c                              |  52 +++-
 lib/string_helpers.c                          |  22 +-
 lib/test-string_helpers.c                     |   4 +-
 mm/compaction.c                               |   7 +-
 mm/filemap.c                                  |   6 +-
 mm/huge_memory.c                              |   2 +
 mm/hugetlb.c                                  |   8 +-
 mm/kfence/core.c                              |  14 +-
 mm/kfence/kfence.h                            |   4 +-
 mm/memcontrol.c                               |  56 +---
 mm/mempolicy.c                                |  52 ++--
 mm/mempool.c                                  |  36 +--
 mm/mm_init.c                                  |  10 +
 mm/page_alloc.c                               |  66 +++--
 mm/page_ext.c                                 |  13 +
 mm/page_owner.c                               |   2 +-
 mm/percpu-internal.h                          |  26 +-
 mm/percpu.c                                   | 120 ++++----
 mm/show_mem.c                                 |  15 +
 mm/slab.h                                     | 176 ++++++++++--
 mm/slab_common.c                              |  65 ++++-
 mm/slub.c                                     | 138 ++++++----
 mm/util.c                                     |  44 +--
 mm/vmalloc.c                                  |  88 +++---
 scripts/kallsyms.c                            |  13 +
 scripts/module.lds.S                          |   7 +
 81 files changed, 2126 insertions(+), 695 deletions(-)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 include/linux/codetag.h
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 lib/alloc_tag.c
 create mode 100644 lib/codetag.c

-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-1-surenb%40google.com.
