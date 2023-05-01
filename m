Return-Path: <kasan-dev+bncBC7OD3FKWUERB3G5X6RAMGQEWXEKG4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BDF26F33B1
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:10 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1aad9af33c1sf22356645ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960109; cv=pass;
        d=google.com; s=arc-20160816;
        b=vzXJOXjDXnagVWqr7hl6QZ5Z3HiRxT7g8V7yewJpPoEIA5s7QuiQmlPlQXxjy3v4de
         phrbyw03BBPFZcnSZXaeEdRLTyv6pdmtDWpF3yvIwWWvCmhO5fSODPpR6bXA0ufhDc8V
         7LFvrL6wu9m90H1dViomIYUDfL32Ua+mbEAVYYGWNOO4eaccu9gTtMBz5EE48NtZBX/V
         lL3HO6jfgX2RlHpLZ/pYKs8i1FJC/9DFV8p6L+hol/FJFOlqmZ22gGpisJ6qddqCDMIp
         60Dw4EQbhdkdO/Dnhiv4jwd2P8zawwkl9NfdP9NIuFmgMZtwxovBoSqmkNChhWZo+cW7
         3qwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=FMb6CU3I6WfPPSYh/PKuj+SOKCGSH1qRB1cG28ytyIE=;
        b=RRCbwX1q/BonKe0ktJ+IBQoFjltr/cLAGmQQHTPu/X4ESFr4UlzBx3Kgg2DnbKdJL0
         0xHRSJMUDGrZoBP+wx6R72PM3es53amkDAV4vPBj2iLyCV92roGNYRMUkBFtKk23lQcv
         wibheqd1WjWPoqhALSyo0Bl/SrkyJag9l07Beiabg7DiF2InhNFKKVBhRD4Py1lhIPiv
         60/sfJxpWPawO/mfh1Ok+l6W9aF+473zoo6gez9DosR0UwI5dylive+cL+zAgX0Z8SpP
         /n6Yg/R8hKiQuFSQMIax3QNQeBVPPtQH/PE0ZNWhauGgzxs21yDNV1TQ419z6j0vlfbd
         5jAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=IEVlqToz;
       spf=pass (google.com: domain of 36-5pzaykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=36-5PZAYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960109; x=1685552109;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FMb6CU3I6WfPPSYh/PKuj+SOKCGSH1qRB1cG28ytyIE=;
        b=tJotE2ABl+N51TshZB8UnXIU/iFtV8+a/HmZlJ62ENU3WE1y5mT9p585JJ90oyUHSu
         JS4MGlekgV3zRS3auHxqSMYN4DWtzQ/LlyOlfSph/mbL1/j92ybiA3lk+6fDoN+M/31r
         tXM57y1r+PahLynUScS29I8qtDr08MXg7TpeedP12mMETXOO9zemO3/9IGNg692z87pg
         UfxOYXut1V07ZMRvcAcGa1Pj2anP3krPkzbofm5Y7fqp+UvXbAb2b+1jrwXuTHS6e16N
         PruO9OG977QK++xPyudkEa99EYUQ+8PqyCEGPsTTQOEqgt1aD8t7tbRM1mUQe3zgQHUo
         AMtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960109; x=1685552109;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FMb6CU3I6WfPPSYh/PKuj+SOKCGSH1qRB1cG28ytyIE=;
        b=PFIUPIt6Qpkn9/ezyqyeUdrCNI8lI9j9N9vTREf33bOfUNr8BRGl+9ynf8ZYBQi8tE
         klS6oAohKNi9zNJ4tew5b+vY1PTAAzw+jizLmIq3B1UYMA3whSuxz0QV4qFGtmGVcsD6
         tpvJWyRUSuc/BxUldt1/36kbOVzw1BWDyuJwHosBno4eMjXt2snF/klF03M1LjwMthit
         TH1/i3oilqDhOoWPDnt/WY8FFDzqC5gzuMt0pFymlf/0ZwidXgQqSqfwgpx/GTKcyldd
         4R95/3q8misTebOrejbjquc8PHi/kvkOa92prkPH8/cHy+HGm10A81G+x08q4JtqoqQl
         ae4w==
X-Gm-Message-State: AC+VfDxKWfkR54isFBv2QWqsacBu8eCD6GnqKnyc0aQqiZWab6u9kNRY
	gRtlLgrbHKkLDYU6KJQc1PI=
X-Google-Smtp-Source: ACHHUZ61B3RiPJ6HlPHFkVAheYnkKpYYYfhNoFR+TSNqdFb+fT/VYtlKey3T5E8LOKoU/zgTdY8YsQ==
X-Received: by 2002:a17:903:1103:b0:1a5:e03:55d with SMTP id n3-20020a170903110300b001a50e03055dmr4896015plh.11.1682960108718;
        Mon, 01 May 2023 09:55:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce09:b0:1a0:482d:27cc with SMTP id
 k9-20020a170902ce0900b001a0482d27ccls8028230plg.3.-pod-prod-gmail; Mon, 01
 May 2023 09:55:07 -0700 (PDT)
X-Received: by 2002:a05:6a20:3942:b0:f3:c08:ce12 with SMTP id r2-20020a056a20394200b000f30c08ce12mr23456548pzg.5.1682960107849;
        Mon, 01 May 2023 09:55:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960107; cv=none;
        d=google.com; s=arc-20160816;
        b=aZi6Q6UUSasYJ7pSPEESmUBB+EQUYUz6b9T2UEKojHEn5JJlHNAvq0P33ojEd7Rxb6
         R0eiVF327nn070GPdKwJH6gmAj2PazE/k40KseImBuxpNXaZD2RxsKBbo6SzZ3J4cK1D
         dbWQLnqIw08u5CteL1SA397zTzXSy9C3goYlZ+W2vdWiwJ5WEVmFPQngSa5eKlCicMWX
         aXRk44Ff4UdYKExzxebzvBM9KUBmPbM8z+08Ww0bH2q+AffYWnAFweLxpWftZ/b3JAoY
         PKLqjDv+nvOeQZnwFlviRPl4e4FC2Efx9OQH8213Ji8eqsN4DGG2m0nXCxIIzcbtka2f
         eWVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=rhc7v9a1uLQqVXD+LsRhZoVqkW3m5tSXn3Qy4JSVLy4=;
        b=WNDh3zA6xrsRgtUBKppWd2XCZiO5zLeB/sQH5lCIEKbG4h2C+rD82KKCDzi824fT16
         O3AggYsVSkSfyRzPMAOBWXkQ4T3qiXaMqTacblxLz8gh2KRj4xbNwwESV3esKoxjYcPG
         d6qRWDBrNbplTDJeaxUQA0hvgcEd4Uq/UkptnANGLtwozCepAyCL9WIul18xfBOojCvv
         +9po781DlbNm2qCMBeXY6N6x7hrAUZe3pPyas1T37U0kDNhn45UtvB/d4sbPKRMAehJ1
         ZQXC2kxXo5CSOhMVgVEDvXiPeItyybbiv1PKF2kHizv7IxTvT6HZAKQAVqquN8kzL0YI
         MwWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=IEVlqToz;
       spf=pass (google.com: domain of 36-5pzaykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=36-5PZAYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id o23-20020a637e57000000b00513924516ddsi1547584pgn.5.2023.05.01.09.55.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36-5pzaykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id d2e1a72fcca58-64115ef7234so23366182b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:07 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:902:ec8a:b0:1a4:f550:de0b with SMTP id
 x10-20020a170902ec8a00b001a4f550de0bmr6525014plg.4.1682960107332; Mon, 01 May
 2023 09:55:07 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:10 -0700
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-1-surenb@google.com>
Subject: [PATCH 00/40] Memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=IEVlqToz;       spf=pass
 (google.com: domain of 36-5pzaykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=36-5PZAYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
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

Memory allocation profiling infrastructure provides a low overhead
mechanism to make all kernel allocations in the system visible. It can be
used to monitor memory usage, track memory hotspots, detect memory leaks,
identify memory regressions.

To keep the overhead to the minimum, we record only allocation sizes for
every allocation in the codebase. With that information, if users are
interested in more detailed context for a specific allocation, they can
enable in-depth context tracking, which includes capturing the pid, tgid,
task name, allocation size, timestamp and call stack for every allocation
at the specified code location.

The data is exposed to the user space via a read-only debugfs file called
allocations. Usage example:

$ sort -hr /sys/kernel/debug/allocations|head
  153MiB     8599 mm/slub.c:1826 module:slub func:alloc_slab_page
 6.08MiB      49 mm/slab_common.c:950 module:slab_common func:_kmalloc_order
 5.09MiB     6335 mm/memcontrol.c:2814 module:memcontrol func:alloc_slab_obj_exts
 4.54MiB      78 mm/page_alloc.c:5777 module:page_alloc func:alloc_pages_exact
 1.32MiB      338 include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
 1.16MiB      603 fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvmalloc
 1.00MiB      256 mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cgroup_prepare
  734KiB     5380 fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
  640KiB      160 kernel/rcu/tree.c:3184 module:tree func:fill_page_cache_func
  640KiB      160 drivers/char/virtio_console.c:452 module:virtio_console func:alloc_buf

For allocation context capture, a new debugfs file called allocations.ctx
is used to select which code location should capture allocation context
and to read captured context information. Usage example:

$ cd /sys/kernel/debug/
$ echo "file include/asm-generic/pgalloc.h line 63 enable" > allocations.ctx
$ cat allocations.ctx
  920KiB      230 include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
    size: 4096
    pid: 1474
    tgid: 1474
    comm: bash
    ts: 175332940994
    call stack:
         pte_alloc_one+0xfe/0x130
         __pte_alloc+0x22/0xb0
         copy_page_range+0x842/0x1640
         dup_mm+0x42d/0x580
         copy_process+0xfb1/0x1ac0
         kernel_clone+0x92/0x3e0
         __do_sys_clone+0x66/0x90
         do_syscall_64+0x38/0x90
         entry_SYSCALL_64_after_hwframe+0x63/0xcd
...

Implementation utilizes a more generic concept of code tagging, introduced
as part of this patchset. Code tag is a structure identifying a specific
location in the source code which is generated at compile time and can be
embedded in an application-specific structure. A number of applications
for code tagging have been presented in the original RFC [1].
Code tagging uses the old trick of "define a special elf section for
objects of a given type so that we can iterate over them at runtime" and
creates a proper library for it. 

To profile memory allocations, we instrument page, slab and percpu
allocators to record total memory allocated in the associated code tag at
every allocation in the codebase. Every time an allocation is performed by
an instrumented allocator, the code tag at that location increments its
counter by allocation size. Every time the memory is freed the counter is
decremented. To decrement the counter upon freeing, allocated object needs
a reference to its code tag. Page allocators use page_ext to record this
reference while slab allocators use memcg_data (renamed into more generic
slabobj_ext) of the slab page.

Module allocations are accounted the same way as other kernel allocations.
Module loading and unloading is supported. If a module is unloaded while
one or more of its allocations is still not freed (rather rare condition),
its data section will be kept in memory to allow later code tag
referencing when the allocation is freed later on.

As part of this series we introduce several kernel configs:
CODE_TAGGING - to enable code tagging framework
CONFIG_MEM_ALLOC_PROFILING - to enable memory allocation profiling
CONFIG_MEM_ALLOC_PROFILING_DEBUG - to enable memory allocation profiling
validation
Note: CONFIG_MEM_ALLOC_PROFILING enables CONFIG_PAGE_EXTENSION to store
code tag reference in the page_ext object. 

nomem_profiling kernel command-line parameter is also provided to disable
the functionality and avoid the performance overhead.
Performance overhead:
To evaluate performance we implemented an in-kernel test executing
multiple get_free_page/free_page and kmalloc/kfree calls with allocation
sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
affinity set to a specific CPU to minimize the noise. Below is performance
comparison between the baseline kernel, profiling when enabled, profiling
when disabled (nomem_profiling=y) and (for comparison purposes) baseline
with CONFIG_MEMCG_KMEM enabled and allocations using __GFP_ACCOUNT:

			kmalloc			pgalloc
Baseline (6.3-rc7)	9.200s			31.050s
profiling disabled	9.800 (+6.52%)		32.600 (+4.99%)
profiling enabled	12.500 (+35.87%)	39.010 (+25.60%)
memcg_kmem enabled	41.400 (+350.00%)	70.600 (+127.38%)

[1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/

Kent Overstreet (15):
  lib/string_helpers: Drop space in string_get_size's output
  scripts/kallysms: Always include __start and __stop symbols
  fs: Convert alloc_inode_sb() to a macro
  nodemask: Split out include/linux/nodemask_types.h
  prandom: Remove unused include
  lib/string.c: strsep_no_empty()
  Lazy percpu counters
  lib: code tagging query helper functions
  mm/slub: Mark slab_free_freelist_hook() __always_inline
  mempool: Hook up to memory allocation profiling
  timekeeping: Fix a circular include dependency
  mm: percpu: Introduce pcpuobj_ext
  mm: percpu: Add codetag reference into pcpuobj_ext
  arm64: Fix circular header dependency
  MAINTAINERS: Add entries for code tagging and memory allocation
    profiling

Suren Baghdasaryan (25):
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
  change alloc_pages name in dma_map_ops to avoid name conflicts
  mm: enable page allocation tagging
  mm/page_ext: enable early_page_ext when
    CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
  mm: create new codetag references during page splitting
  lib: add codetag reference into slabobj_ext
  mm/slab: add allocation accounting into slab allocation and free paths
  mm/slab: enable slab allocation tagging for kmalloc and friends
  mm: percpu: enable per-cpu allocation tagging
  move stack capture functionality into a separate function for reuse
  lib: code tagging context capture support
  lib: implement context capture support for tagged allocations
  lib: add memory allocations report in show_mem()
  codetag: debug: skip objext checking when it's for objext itself
  codetag: debug: mark codetags for reserved pages as empty
  codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark failed slab_ext
    allocations

 .../admin-guide/kernel-parameters.txt         |   2 +
 MAINTAINERS                                   |  22 +
 arch/arm64/include/asm/spectre.h              |   4 +-
 arch/x86/kernel/amd_gart_64.c                 |   2 +-
 drivers/iommu/dma-iommu.c                     |   2 +-
 drivers/xen/grant-dma-ops.c                   |   2 +-
 drivers/xen/swiotlb-xen.c                     |   2 +-
 include/asm-generic/codetag.lds.h             |  14 +
 include/asm-generic/vmlinux.lds.h             |   3 +
 include/linux/alloc_tag.h                     | 161 ++++++
 include/linux/codetag.h                       | 159 ++++++
 include/linux/codetag_ctx.h                   |  48 ++
 include/linux/dma-map-ops.h                   |   2 +-
 include/linux/fs.h                            |   6 +-
 include/linux/gfp.h                           | 123 ++--
 include/linux/gfp_types.h                     |  12 +-
 include/linux/hrtimer.h                       |   2 +-
 include/linux/lazy-percpu-counter.h           | 102 ++++
 include/linux/memcontrol.h                    |  56 +-
 include/linux/mempool.h                       |  73 ++-
 include/linux/mm.h                            |   8 +
 include/linux/mm_types.h                      |   4 +-
 include/linux/nodemask.h                      |   2 +-
 include/linux/nodemask_types.h                |   9 +
 include/linux/page_ext.h                      |   1 -
 include/linux/pagemap.h                       |   9 +-
 include/linux/percpu.h                        |  19 +-
 include/linux/pgalloc_tag.h                   |  95 ++++
 include/linux/prandom.h                       |   1 -
 include/linux/sched.h                         |  32 +-
 include/linux/slab.h                          | 182 +++---
 include/linux/slab_def.h                      |   2 +-
 include/linux/slub_def.h                      |   4 +-
 include/linux/stackdepot.h                    |  16 +
 include/linux/string.h                        |   1 +
 include/linux/time_namespace.h                |   2 +
 init/Kconfig                                  |   4 +
 kernel/dma/mapping.c                          |   4 +-
 kernel/module/main.c                          |  25 +-
 lib/Kconfig                                   |   3 +
 lib/Kconfig.debug                             |  26 +
 lib/Makefile                                  |   5 +
 lib/alloc_tag.c                               | 464 +++++++++++++++
 lib/codetag.c                                 | 529 ++++++++++++++++++
 lib/lazy-percpu-counter.c                     | 127 +++++
 lib/show_mem.c                                |  15 +
 lib/stackdepot.c                              |  68 +++
 lib/string.c                                  |  19 +
 lib/string_helpers.c                          |   3 +-
 mm/compaction.c                               |   9 +-
 mm/filemap.c                                  |   6 +-
 mm/huge_memory.c                              |   2 +
 mm/kfence/core.c                              |  14 +-
 mm/kfence/kfence.h                            |   4 +-
 mm/memcontrol.c                               |  56 +-
 mm/mempolicy.c                                |  30 +-
 mm/mempool.c                                  |  28 +-
 mm/mm_init.c                                  |   1 +
 mm/page_alloc.c                               |  75 ++-
 mm/page_ext.c                                 |  21 +-
 mm/page_owner.c                               |  54 +-
 mm/percpu-internal.h                          |  26 +-
 mm/percpu.c                                   | 122 ++--
 mm/slab.c                                     |  22 +-
 mm/slab.h                                     | 224 ++++++--
 mm/slab_common.c                              |  95 +++-
 mm/slub.c                                     |  24 +-
 mm/util.c                                     |  10 +-
 scripts/kallsyms.c                            |  13 +
 scripts/module.lds.S                          |   7 +
 70 files changed, 2765 insertions(+), 554 deletions(-)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 include/linux/codetag.h
 create mode 100644 include/linux/codetag_ctx.h
 create mode 100644 include/linux/lazy-percpu-counter.h
 create mode 100644 include/linux/nodemask_types.h
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 lib/alloc_tag.c
 create mode 100644 lib/codetag.c
 create mode 100644 lib/lazy-percpu-counter.c

-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-1-surenb%40google.com.
