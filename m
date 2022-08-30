Return-Path: <kasan-dev+bncBC7OD3FKWUERBZMLXKMAMGQE25D4IMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id DF39C5A6F73
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:26 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id k5-20020ad44505000000b00499075b621esf3677438qvu.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896165; cv=pass;
        d=google.com; s=arc-20160816;
        b=hYOHkb4QZ8FrlmrYO5b9xKk5kldeARMkfD2dQoCGQHyuKC64HO4svOS5QGR3cNjTxC
         6jv/fn/Cf8RxHTNy3zxkIdzVyiBSdkbq/M0D1k78ujt0o3l78Ekmew9VTpeU45b6ipi8
         pLGm7wMgISGqVFRichtc4lwwegtC2muuMyBISnksxOs3Siya2Gd9NEfmh5VktTSgX37G
         YWBpT046D/rlaVJyY117ePEDSKctQpoO1+IqDml2eE5W35hNXqVIvnACT4CL8NxM5GuG
         oanZipsjI+3d/orz53Ta/9IU62vyYYXlG7PSxb8y/m3bfU8+qe9pHcIVSZn7p1Ko9LD5
         BVfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=1djTmN98/wZUw9EtBSB053ZklLrwOj+WlOZ9A+kfhp0=;
        b=b5x2nb0y93RR0ds3g5gXf2JrSeux+7lbIc2kE9kpBplaavC4GXs4Blxye+DeQe4U6Q
         +ED6wVN1SNKI59lAiJ29b+HQi1c+RY2WPiOvpJZydUWbwzNgZs6OcssIRVfplfPaRcvo
         07kFG2dg8hbMaYXkunG2ZpWjqlMt1R5QqDLd5tQr9aypRZrUd7cTA6ENMGUB2tGOe6cv
         c7ASV73MPAFRBTAVzjE9yfKu/UUcqLcesa5fJ76lh0j7Y2BF83XCPeIx3inWUUUVujPE
         sR9fOYGYBjW/+K63bANCynWcNdH7yRUmLUQuBbByfbT8zMeiW+iTnRAZojjziJEsEdLt
         qoDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TLaJItWb;
       spf=pass (google.com: domain of 35iuoywykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=35IUOYwYKCUk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc;
        bh=1djTmN98/wZUw9EtBSB053ZklLrwOj+WlOZ9A+kfhp0=;
        b=FWTDKIZnVopOfd93r2gAyZ80lQpaWg197kFU08yuaUufR+VtRYhYtoL3Uj3C9OFQW3
         /riNCaUrjtM3Hqu/kJptPQNDYo4XygcoaI8p4xaFgHShjGdGE6x2jFJbFGByhz/XCfqf
         dFddwb5dtg69l0dSf8EMA8TT0JLnhVliSp/6BGqHTew5eCXvipLYPmN9TiNvL5OyyT4N
         FHznY27cx8J2vP5G2YQDuf0pbXv4PNzZYs5S/a3cQMMPiTOKTI24wrEteZFuA6chKfiF
         Ly4VljyfRS0IK3z0dxW5eaOvzg+n5j2oKrHJyq2C693l5Uuyzc8gDucS5M6cYZH1w1mK
         o1ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc;
        bh=1djTmN98/wZUw9EtBSB053ZklLrwOj+WlOZ9A+kfhp0=;
        b=36VpDGqqQoD8oifYGpyymXqMPT4DBz0NF7VmXu8L0Yz/zxxY/L0V5PmTbvOeQr+4mb
         zbb4I1KvjLF1rf9TgYGCIG3o2dXlxQ0f9kkYYzi4OtRi1UPHnqIJgdS98/9x9SV72IiP
         0Hl+WSgVn1IxQjPRDRk5MVi9P2SawkrqU7vLxwPUqLN/EwV1b/M4vIrWc5M60V2ef8I0
         vQua11hQDyhPRQg3blCCkcXBxa4cjbkvl1tDMlNwdgZpKHMur5WLU0uYL638AwnIF4yO
         fMABY72c2zLpoCXvTgLU8hfzhwVjT0darfzYaqAZDkOoxs/ZWSoZp2yeN+gepVkLzyTR
         NU2g==
X-Gm-Message-State: ACgBeo3V6QRZzz2SGp+CCHtzpYhyWOIhuiFogiNPWMACl+E5eVYmP4o2
	4fODcvjnOXdE9wp9ZikbCW8=
X-Google-Smtp-Source: AA6agR71IP/wRYyX3jG7vBL1Pr2+BrLet5L0Jt+Rhymwljk+ePLPMs5vG6fbDAhkFWPnhXiwTDq9Ng==
X-Received: by 2002:ac8:5cd2:0:b0:343:557e:98a9 with SMTP id s18-20020ac85cd2000000b00343557e98a9mr16480131qta.658.1661896165455;
        Tue, 30 Aug 2022 14:49:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a947:0:b0:498:f330:9b60 with SMTP id z7-20020a0ca947000000b00498f3309b60ls5375962qva.5.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:49:25 -0700 (PDT)
X-Received: by 2002:ad4:5bad:0:b0:476:e202:32eb with SMTP id 13-20020ad45bad000000b00476e20232ebmr17198397qvq.3.1661896164947;
        Tue, 30 Aug 2022 14:49:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896164; cv=none;
        d=google.com; s=arc-20160816;
        b=D9Pwsw/Fw+4XI3ERtD1EV4vlVxdokMpDutupLZgYyXi/aMxymjzSC7NiJY5F1svxtc
         1oamnbUDwANl4WepfHCniPsxelHat+tcdisBCnKcribVYJZp+WjPHpRTbhDGhO2NhsuK
         h1KKN/lAf0UKzXVY4DGpU0bJtrV0MYPd6FA6RGJ8mz+5YUXUoiSALIReATMQJCblZSFx
         ANjnSJKOOHNifppgobpFkPpA8r/ZSQaaZktT1DWJp4wyXYHTeBHz9ZRJU/ZrdDcUJcVb
         Mnku8vsBI7mVm/d1+xlG7fxKHMe0/OBOSnHP1TgFuWosEdBdu0ISQI3StFSTjo7j9QN7
         cURw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=1lX3k8bH6+3ighIlH+rh55fF9o5O4fyOugMRXdd7M+o=;
        b=n2s2CuRaq4On4H5y54i9JqGtk/IzBU/VsgtLkpkXKIXIN7ObwCoCVBKwb9QktN8IDw
         91kogLTXODy/hAvb48cmWE/ZhxUwRRxpXiqC9Nfpnfv37iabodYdyZL63/AnYKyKFbiY
         KxpMwdWT3RX75tlRaMl38e9HF7e3EvuTZ8rFap+8xdkX+rG28VRbpH1upzTMvxKq3Wct
         b1BCOhb5IM8hAi2ee2BTyWgf7dSA/kUfaX/EmqVooobMaxEppgG2WvSsrze7Fn+fs/nS
         ZehXhcLM+VosNPWSwyXu9t47oCsEjhbvXAvjiBzwuH5ZKUqdM2BAz8+gBfIINmlGyiWS
         GRxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TLaJItWb;
       spf=pass (google.com: domain of 35iuoywykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=35IUOYwYKCUk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id d21-20020ac84e35000000b00341a027f09fsi592950qtw.4.2022.08.30.14.49.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35iuoywykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id n16-20020a258d10000000b0068df1e297c0so718989ybl.15
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:24 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a81:7992:0:b0:336:8015:4889 with SMTP id
 u140-20020a817992000000b0033680154889mr16036203ywc.80.1661896164558; Tue, 30
 Aug 2022 14:49:24 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:49 -0700
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-1-surenb@google.com>
Subject: [RFC PATCH 00/30] Code tagging framework and applications
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TLaJItWb;       spf=pass
 (google.com: domain of 35iuoywykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=35IUOYwYKCUk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
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

===========================
Code tagging framework
===========================
Code tag is a structure identifying a specific location in the source code
which is generated at compile time and can be embedded in an application-
specific structure. Several applications of code tagging are included in
this RFC, such as memory allocation tracking, dynamic fault injection,
latency tracking and improved error code reporting.
Basically, it takes the old trick of "define a special elf section for
objects of a given type so that we can iterate over them at runtime" and
creates a proper library for it.

===========================
Memory allocation tracking
===========================
The goal for using codetags for memory allocation tracking is to minimize
performance and memory overhead. By recording only the call count and
allocation size, the required operations are kept at the minimum while
collecting statistics for every allocation in the codebase. With that
information, if users are interested in mode detailed context for a
specific allocation, they can enable more in-depth context tracking,
which includes capturing the pid, tgid, task name, allocation size,
timestamp and call stack for every allocation at the specified code
location.
Memory allocation tracking is implemented in two parts:

part1: instruments page and slab allocators to record call count and total
memory allocated at every allocation in the source code. Every time an
allocation is performed by an instrumented allocator, the codetag at that
location increments its call and size counters. Every time the memory is
freed these counters are decremented. To decrement the counters upon free,
allocated object needs a reference to its codetag. Page allocators use
page_ext to record this reference while slab allocators use memcg_data of
the slab page.
The data is exposed to the user space via a read-only debugfs file called
alloc_tags.

Usage example:

$ sort -hr /sys/kernel/debug/alloc_tags|head
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

part2: adds support for the user to select a specific code location to capture
allocation context. A new debugfs file called alloc_tags.ctx is used to select
which code location should capture allocation context and to read captured
context information.

Usage example:

$ cd /sys/kernel/debug/
$ echo "file include/asm-generic/pgalloc.h line 63 enable" > alloc_tags.ctx
$ cat alloc_tags.ctx
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

NOTE: slab allocation tracking is not yet stable and has a leak that
shows up in long-running tests. We are working on fixing it and posting
the RFC early to collect some feedback and to have a reference code in
public before presenting the idea at LPC2022.

===========================
Dynamic fault injection
===========================
Dynamic fault injection lets you do fault injection with a single call
to dynamic_fault(), with a debugfs interface similar to dynamic_debug.

Calls to dynamic_fault are listed in debugfs and can be enabled at
runtime (oneshot mode or a defined frequency are also available). This
patch also uses the memory allocation wrapper macros introduced by the
memory allocation tracking patches to add distinct fault injection
points for every memory allocation in the kernel.

Example fault injection points, after hooking memory allocation paths:

  fs/xfs/libxfs/xfs_iext_tree.c:606 module:xfs func:xfs_iext_realloc_rootclass:memory disabled "
  fs/xfs/libxfs/xfs_inode_fork.c:503 module:xfs func:xfs_idata_reallocclass:memory disabled "
  fs/xfs/libxfs/xfs_inode_fork.c:399 module:xfs func:xfs_iroot_reallocclass:memory disabled "
  fs/xfs/xfs_buf.c:373 module:xfs func:xfs_buf_alloc_pagesclass:memory disabled "
  fs/xfs/xfs_iops.c:497 module:xfs func:xfs_vn_get_linkclass:memory disabled "
  fs/xfs/xfs_mount.c:85 module:xfs func:xfs_uuid_mountclass:memory disabled "

===========================
Latency tracking
===========================
This lets you instrument code for measuring latency with just two calls
to code_tag_time_stats_start() and code_tag_time_stats_finish(), and
makes statistics available in debugfs on a per-callsite basis.

Recorded statistics include total count, frequency/rate, average
duration, max duration, and event duration quantiles.

Additionally, this patch instruments prepare_to_wait() and finish_wait().

Example output:

  fs/xfs/xfs_extent_busy.c:589 module:xfs func:xfs_extent_busy_flush
  count:          61
  rate:           0/sec
  frequency:    19 sec
  avg duration:   632 us
  max duration:   2 ms
  quantiles (us): 274 288 288 296 296 296 296 336 336 336 336 336 336 336 336

===========================
Improved error codes
===========================
Ever waste hours trying to figure out which line of code from some
obscure module is returning you -EINVAL and nothing else?

What if we had... more error codes?

This patch adds ERR(), which returns a unique error code that is related
to the error code that passed to it: the original error code can be
recovered with error_class(), and errname() (as well as %pE) returns an
error string that includes the file and line number of the ERR() call.

Example output:

  VFS: Cannot open root device "sda" or unknown-block(8,0): error -EINVAL at fs/ext4/super.c:4387

===========================
Dynamic debug conversion to code tagging
===========================
There are several open coded implementations of the "define a special elf
section for objects and iterate" technique that should be converted to
code tagging. This series just converts dynamic debug; there are others
(multiple in ftrace, in particular) that should also be converted.

===========================

The patchset applies cleanly over Linux 6.0-rc3
The tree for testing is published at:
https://github.com/surenbaghdasaryan/linux/tree/alloc_tags_rfc

The structure of the patchset is:
- code tagging framework (patches 1-6)
- page allocation tracking (patches 7-10)
- slab allocation tracking (patch 11-16)
- allocation context capture (patch 17-21)
- dynamic fault injection (patch 22)
- latency tracking (patch 23-27)
- improved error codes (patch 28)
- dynamic debug conversion to code tagging (patch 29)
- MAINTAINERS update (patch 30)

Next steps:
- track and fix slab allocator leak mentioned earlier;
- instrument more allocators: vmalloc, per-cpu allocations, others?


Kent Overstreet (14):
  lib/string_helpers: Drop space in string_get_size's output
  Lazy percpu counters
  scripts/kallysms: Always include __start and __stop symbols
  lib/string.c: strsep_no_empty()
  codetag: add codetag query helper functions
  Code tagging based fault injection
  timekeeping: Add a missing include
  wait: Clean up waitqueue_entry initialization
  lib/time_stats: New library for statistics on events
  bcache: Convert to lib/time_stats
  Code tagging based latency tracking
  Improved symbolic error names
  dyndbg: Convert to code tagging
  MAINTAINERS: Add entries for code tagging & related

Suren Baghdasaryan (16):
  kernel/module: move find_kallsyms_symbol_value declaration
  lib: code tagging framework
  lib: code tagging module support
  lib: add support for allocation tagging
  lib: introduce page allocation tagging
  change alloc_pages name in dma_map_ops to avoid name conflicts
  mm: enable page allocation tagging for __get_free_pages and
    alloc_pages
  mm: introduce slabobj_ext to support slab object extensions
  mm: introduce __GFP_NO_OBJ_EXT flag to selectively prevent slabobj_ext
    creation
  mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
  mm: prevent slabobj_ext allocations for slabobj_ext and kmem_cache
    objects
  lib: introduce slab allocation tagging
  mm: enable slab allocation tagging for kmalloc and friends
  move stack capture functionality into a separate function for reuse
  lib: introduce support for storing code tag context
  lib: implement context capture support for page and slab allocators

 MAINTAINERS                         |  34 ++
 arch/x86/kernel/amd_gart_64.c       |   2 +-
 drivers/iommu/dma-iommu.c           |   2 +-
 drivers/md/bcache/Kconfig           |   1 +
 drivers/md/bcache/bcache.h          |   1 +
 drivers/md/bcache/bset.c            |   8 +-
 drivers/md/bcache/bset.h            |   1 +
 drivers/md/bcache/btree.c           |  12 +-
 drivers/md/bcache/super.c           |   3 +
 drivers/md/bcache/sysfs.c           |  43 ++-
 drivers/md/bcache/util.c            |  30 --
 drivers/md/bcache/util.h            |  57 ---
 drivers/xen/grant-dma-ops.c         |   2 +-
 drivers/xen/swiotlb-xen.c           |   2 +-
 include/asm-generic/codetag.lds.h   |  18 +
 include/asm-generic/vmlinux.lds.h   |   8 +-
 include/linux/alloc_tag.h           |  84 +++++
 include/linux/codetag.h             | 159 +++++++++
 include/linux/codetag_ctx.h         |  48 +++
 include/linux/codetag_time_stats.h  |  54 +++
 include/linux/dma-map-ops.h         |   2 +-
 include/linux/dynamic_debug.h       |  11 +-
 include/linux/dynamic_fault.h       |  79 +++++
 include/linux/err.h                 |   2 +-
 include/linux/errname.h             |  50 +++
 include/linux/gfp.h                 |  10 +-
 include/linux/gfp_types.h           |  12 +-
 include/linux/io_uring_types.h      |   2 +-
 include/linux/lazy-percpu-counter.h |  67 ++++
 include/linux/memcontrol.h          |  23 +-
 include/linux/module.h              |   1 +
 include/linux/page_ext.h            |   3 +-
 include/linux/pgalloc_tag.h         |  63 ++++
 include/linux/sbitmap.h             |   6 +-
 include/linux/sched.h               |   6 +-
 include/linux/slab.h                | 136 +++++---
 include/linux/slab_def.h            |   2 +-
 include/linux/slub_def.h            |   4 +-
 include/linux/stackdepot.h          |   3 +
 include/linux/string.h              |   1 +
 include/linux/time_stats.h          |  44 +++
 include/linux/timekeeping.h         |   1 +
 include/linux/wait.h                |  72 ++--
 include/linux/wait_bit.h            |   7 +-
 init/Kconfig                        |   5 +
 kernel/dma/mapping.c                |   4 +-
 kernel/module/internal.h            |   3 -
 kernel/module/main.c                |  27 +-
 kernel/sched/wait.c                 |  15 +-
 lib/Kconfig                         |   6 +
 lib/Kconfig.debug                   |  46 +++
 lib/Makefile                        |  10 +
 lib/alloc_tag.c                     | 391 +++++++++++++++++++++
 lib/codetag.c                       | 519 ++++++++++++++++++++++++++++
 lib/codetag_time_stats.c            | 143 ++++++++
 lib/dynamic_debug.c                 | 452 +++++++++---------------
 lib/dynamic_fault.c                 | 372 ++++++++++++++++++++
 lib/errname.c                       | 103 ++++++
 lib/lazy-percpu-counter.c           | 141 ++++++++
 lib/pgalloc_tag.c                   |  22 ++
 lib/stackdepot.c                    |  68 ++++
 lib/string.c                        |  19 +
 lib/string_helpers.c                |   3 +-
 lib/time_stats.c                    | 236 +++++++++++++
 mm/kfence/core.c                    |   2 +-
 mm/memcontrol.c                     |  62 ++--
 mm/mempolicy.c                      |   4 +-
 mm/page_alloc.c                     |  13 +-
 mm/page_ext.c                       |   6 +
 mm/page_owner.c                     |  54 +--
 mm/slab.c                           |   4 +-
 mm/slab.h                           | 125 ++++---
 mm/slab_common.c                    |  49 ++-
 mm/slob.c                           |   2 +
 mm/slub.c                           |   7 +-
 scripts/kallsyms.c                  |  13 +
 scripts/module.lds.S                |   7 +
 77 files changed, 3406 insertions(+), 703 deletions(-)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 include/linux/codetag.h
 create mode 100644 include/linux/codetag_ctx.h
 create mode 100644 include/linux/codetag_time_stats.h
 create mode 100644 include/linux/dynamic_fault.h
 create mode 100644 include/linux/lazy-percpu-counter.h
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 include/linux/time_stats.h
 create mode 100644 lib/alloc_tag.c
 create mode 100644 lib/codetag.c
 create mode 100644 lib/codetag_time_stats.c
 create mode 100644 lib/dynamic_fault.c
 create mode 100644 lib/lazy-percpu-counter.c
 create mode 100644 lib/pgalloc_tag.c
 create mode 100644 lib/time_stats.c

-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-1-surenb%40google.com.
