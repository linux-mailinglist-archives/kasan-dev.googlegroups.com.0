Return-Path: <kasan-dev+bncBC7OD3FKWUERBCXKUKXQMGQEL6E7XTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 59DCA873E81
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:16 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-29a94e1bc5asf5508320a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749515; cv=pass;
        d=google.com; s=arc-20160816;
        b=BEfUFauyUVVKO4dPWBVGx/X9C7CGQroUqWa6HSm1f6NiSNv3M8K5zU59o9mFxmRZ0v
         DahnlNs8IsZYcDcPZ0Yxj0Hu6HD5vs4XomaP3kf3qoDH/qW4kTfh9yS2owvy7oGdO0wS
         Pq0IAozIknbkULmMqM+wjPUE6yFEd1/LeMZsqDZs2jZ9eQfz1b4frCsWwrmDJ054c5ga
         y3zD4pOmjX2p9yozELJoAO9lYujxVhxdJCGp75B4H9wSoTtBCICRzaTiImnu1l7BeOJZ
         /Be15eiGrYgGDcUFC6OmR2X200Ddh3cLM2+1U6qZrh2j2yFxpuir9PNllflJfQQw7eTR
         D6Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6d91GYtannTjnwrd0mm36y7F2kLhyzVRXtP/0P7gN/4=;
        fh=z1YEfTDrdBDXOd702q3pUWkTSlEE0SKtQLpiJrm5TiU=;
        b=Bpv1UMFdyJH2gx0m0Iuhgl0pDJIvrfFTxduKhjILHOrIDj+4C2YzxckFXmnrFOcjrR
         E66Ihanr/QXZ2L+ZnEWBhj7+DPe6pVi8o46RNuJYfEijd/qqDoOi3IrO4x+0GvyI2cAx
         zMhuJoH+MeBi4s0DRV2tlwna6wWUWt8uewEFhQJnBS2yT2Q24HF8MWPBgqLpeNNhmaj5
         9stRMtLznRzZZO93+OlxaGXLDpVFSbyZtTPwPjhCW4cE+dwBh8PzjIZUDiz7QOq0OjuF
         dM1R6AfJRrlnWf8qp25ASWE5GLNX1l6n+jLcrHxQlJ7Vk7ZFbLD6LL8PgQdPfYc9Zub9
         +B4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jHkO8jLC;
       spf=pass (google.com: domain of 3clxozqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3CLXoZQYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749515; x=1710354315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6d91GYtannTjnwrd0mm36y7F2kLhyzVRXtP/0P7gN/4=;
        b=rBLMG/UPEcJUmvtngQhh8TrGdDDVP5MQ9Lkq3Nh10XWzIdF86YQu5qltRtJCOYWB6P
         WvRY4fHyJPKrut1+JbQYzVweKU4A03ykpKz3OpXYCD57txq5tz5n0rKHFeH6lrBUiVs0
         I4xV2WeSvhkUzVo8X269Hq4wxfXBXv4ryeGgr7bEGspnjzkbwpHcxhxfVMRCNthYLHhg
         dm6jSpVRzKSgbGRIEO3m3zt6VV2CQKuA/ch7T6QYr0fSHkjCYvTPB2TIHWTSXKdY9L7C
         68NhzFV0r/I/mXz1Gait5wH0G6fXxNQTyb9lYbl6B0PU1IyjTxunBj0iB0TFj1tSPut4
         CoJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749515; x=1710354315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6d91GYtannTjnwrd0mm36y7F2kLhyzVRXtP/0P7gN/4=;
        b=QB9BFLWRn60Z+e5LMFkzB94Vlh7x8cdIEOSTNA0CpyFpYUXYC3Tws47gXm0YCSQa0c
         hEkTfyfcMhAy60rm0FAoqwOS/tclI9phJ/zzz7a41j312YaPuHlAOItglZvJqEU70XOV
         uy3FUFp19VLs6mPUPublUoW1rvywmtYyBqBQrHIUH+i+ImBk/1XwE4tiaah42vaSKhn1
         LnI/gnhFJQaIDDUDBhTHhYsRpVPuVSBRZB+g6r4UXwb07s/KmYY4Zt7Xhq4bfJct4z3l
         ZyoCLLiF1cuovIn0Zk6bjdCuAHiv2YZmKF0G/5dS/rKuiDl+qcas2RiwOxE8NlFU/Io1
         QQPg==
X-Forwarded-Encrypted: i=2; AJvYcCWruWMiT4EDSqqOgxzG2OP9l24fc2kNh7gyes4pGPZixCC6F/rOVGPfpdpYq9E+hr29ItEQFm94kfViXtj5oN2SIddTIT8baA==
X-Gm-Message-State: AOJu0YxLP7rATd2UvvH5okZ8dlWjK9DLLyPIQ9dgnlVp2g+B2rQL+gkP
	eRLbqsVw6ZSo90OX1JJNvezgZO4jwRT7pUAm130MmG8w0NWO8nJu
X-Google-Smtp-Source: AGHT+IECfEfxdnqt0l2mvaoPGJBFqW6oPRA0qD5MqZowF/ual4S/HzUDz1cTkMXPg0Kqrk825C16DQ==
X-Received: by 2002:a17:90a:da05:b0:29a:9d38:9e2b with SMTP id e5-20020a17090ada0500b0029a9d389e2bmr11336294pjv.47.1709749514976;
        Wed, 06 Mar 2024 10:25:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8d02:b0:29b:53a4:aee2 with SMTP id
 c2-20020a17090a8d0200b0029b53a4aee2ls59667pjo.1.-pod-prod-07-us; Wed, 06 Mar
 2024 10:25:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU/XKl/KCz/EPd4i406/5KoF7eZkZpN/fxWFRAkxs5SRZrwYb5MeY4nlW4bFVXHHd1r6YMIknecPv6bTIwp5fuXz7r3kb8DjvXZbQ==
X-Received: by 2002:a17:90a:ac01:b0:29b:645:103e with SMTP id o1-20020a17090aac0100b0029b0645103emr13167934pjq.1.1709749513915;
        Wed, 06 Mar 2024 10:25:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749513; cv=none;
        d=google.com; s=arc-20160816;
        b=qf2yob7rkX3sGFFfk8W5rHI4XGcmo9ONo53VJYHitLryObGeDYG282Z/Jqc8UbjT7c
         y20bPlJIcM27nxckqdwzV5k2bsBj2Jewfh0MkntD+1iWzc5QiyJbkqCPmPGB5IznFEa1
         k68rhNs284EMvJhDevH8ejjBU+hEbppr9MjmIJSfZKYQmye53aQPm64gKJ3L7oouQPra
         aYK2zIaCEhIch6dMRDUnKb2SopS39dUwQM4TLD4k8L7MSaGwZQB3pypjFmpwf9LUCqLe
         Vry93rX8TTO16CcRACK6i5gq5a/X1xo7tyX//WIPgAgAvBxQvMe/JxlNfV+M4gc32Lva
         jAyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VnpH2fzc60uRea0gIp8vcDyDoI+2TUkhYU4AGh25C8A=;
        fh=N/nC/GgbknwB7oj8D8PjicMAE1Z0YZ0lWkk/Suxrj9g=;
        b=eShOZCg5I0/I1tM8JAeYTopeQcGBFvYgxAmDZ/tdo8whnjC7BgU99I3acisxOSLc4v
         zGi3s0TZv6g9wtWtNf1iRL0Mc0qOy2wbt3XQ2p978848yRFgKDUkLXMy220qqvgXHFbt
         rjA9QVfwoIa8BnClgitkea9P0NzStQ+qYDszlQYKdTKOWT81uLexcuaG56axXmqCV4cy
         Vbbzgdg664HNw5aRcgPhNr3JS6nLMevZWOehI9cfBt2jJZ8smEuLlCGr1tAYl/0+Jlov
         qGM6cM71Cydjawx/2YtKUUfuFirkKhYWdVN5KrQxkfxyu4zAZXPl0Db1JsepmNttvVyH
         HuNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jHkO8jLC;
       spf=pass (google.com: domain of 3clxozqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3CLXoZQYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id i3-20020a17090acf8300b0029b670ef17asi9373pju.0.2024.03.06.10.25.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3clxozqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dbf216080f5so11877066276.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtv3+1mc266/fMpXpnPbQaTuBOxNf96CaWJQB5JS1Ylj8RZtyQ3pb3wS31b1zKnCeBHlrwgm7thAqn6NM5Navps6T7tWHWQG/4rg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1891:b0:dcc:54d0:85e0 with SMTP id
 cj17-20020a056902189100b00dcc54d085e0mr4037556ybb.11.1709749512799; Wed, 06
 Mar 2024 10:25:12 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:11 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-14-surenb@google.com>
Subject: [PATCH v5 13/37] lib: add allocation tagging support for memory
 allocation profiling
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=jHkO8jLC;       spf=pass
 (google.com: domain of 3clxozqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3CLXoZQYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
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

Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easily
instrument memory allocators. It registers an "alloc_tags" codetag type
with /proc/allocinfo interface to output allocation tag information when
the feature is enabled.
CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
allocation profiling instrumentation.
Memory allocation profiling can be enabled or disabled at runtime using
/proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=n.
CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
profiling by default.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 Documentation/admin-guide/sysctl/vm.rst |  16 +++
 Documentation/filesystems/proc.rst      |  29 +++++
 include/asm-generic/codetag.lds.h       |  14 +++
 include/asm-generic/vmlinux.lds.h       |   3 +
 include/linux/alloc_tag.h               | 145 +++++++++++++++++++++++
 include/linux/sched.h                   |  24 ++++
 lib/Kconfig.debug                       |  25 ++++
 lib/Makefile                            |   2 +
 lib/alloc_tag.c                         | 149 ++++++++++++++++++++++++
 scripts/module.lds.S                    |   7 ++
 10 files changed, 414 insertions(+)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 lib/alloc_tag.c

diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/admin-guide/sysctl/vm.rst
index c59889de122b..e86c968a7a0e 100644
--- a/Documentation/admin-guide/sysctl/vm.rst
+++ b/Documentation/admin-guide/sysctl/vm.rst
@@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
 - legacy_va_layout
 - lowmem_reserve_ratio
 - max_map_count
+- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=y)
 - memory_failure_early_kill
 - memory_failure_recovery
 - min_free_kbytes
@@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
 The default value is 65530.
 
 
+mem_profiling
+==============
+
+Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=y)
+
+1: Enable memory profiling.
+
+0: Disable memory profiling.
+
+Enabling memory profiling introduces a small performance overhead for all
+memory allocations.
+
+The default value depends on CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT.
+
+
 memory_failure_early_kill:
 ==========================
 
diff --git a/Documentation/filesystems/proc.rst b/Documentation/filesystems/proc.rst
index 104c6d047d9b..8150dc3d689c 100644
--- a/Documentation/filesystems/proc.rst
+++ b/Documentation/filesystems/proc.rst
@@ -688,6 +688,7 @@ files are there, and which are missing.
  ============ ===============================================================
  File         Content
  ============ ===============================================================
+ allocinfo    Memory allocations profiling information
  apm          Advanced power management info
  bootconfig   Kernel command line obtained from boot config,
  	      and, if there were kernel parameters from the
@@ -953,6 +954,34 @@ also be allocatable although a lot of filesystem metadata may have to be
 reclaimed to achieve this.
 
 
+allocinfo
+~~~~~~~
+
+Provides information about memory allocations at all locations in the code
+base. Each allocation in the code is identified by its source file, line
+number, module (if originates from a loadable module) and the function calling
+the allocation. The number of bytes allocated and number of calls at each
+location are reported.
+
+Example output.
+
+::
+
+    > sort -rn /proc/allocinfo
+   127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
+    56373248     4737 mm/slub.c:2259 func:alloc_slab_page
+    14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
+    14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
+    13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
+    11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
+     9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
+     4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
+     4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
+     3940352      962 mm/memory.c:4214 func:alloc_anon_folio
+     2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
+     ...
+
+
 meminfo
 ~~~~~~~
 
diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
new file mode 100644
index 000000000000..64f536b80380
--- /dev/null
+++ b/include/asm-generic/codetag.lds.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+#ifndef __ASM_GENERIC_CODETAG_LDS_H
+#define __ASM_GENERIC_CODETAG_LDS_H
+
+#define SECTION_WITH_BOUNDARIES(_name)	\
+	. = ALIGN(8);			\
+	__start_##_name = .;		\
+	KEEP(*(_name))			\
+	__stop_##_name = .;
+
+#define CODETAG_SECTIONS()		\
+	SECTION_WITH_BOUNDARIES(alloc_tags)
+
+#endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 5dd3a61d673d..c9997dc50c50 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -50,6 +50,8 @@
  *               [__nosave_begin, __nosave_end] for the nosave data
  */
 
+#include <asm-generic/codetag.lds.h>
+
 #ifndef LOAD_OFFSET
 #define LOAD_OFFSET 0
 #endif
@@ -366,6 +368,7 @@
 	. = ALIGN(8);							\
 	BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)		\
 	BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)				\
+	CODETAG_SECTIONS()						\
 	LIKELY_PROFILE()		       				\
 	BRANCH_PROFILE()						\
 	TRACE_PRINTKS()							\
diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
new file mode 100644
index 000000000000..b970ff1c80dc
--- /dev/null
+++ b/include/linux/alloc_tag.h
@@ -0,0 +1,145 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * allocation tagging
+ */
+#ifndef _LINUX_ALLOC_TAG_H
+#define _LINUX_ALLOC_TAG_H
+
+#include <linux/bug.h>
+#include <linux/codetag.h>
+#include <linux/container_of.h>
+#include <linux/preempt.h>
+#include <asm/percpu.h>
+#include <linux/cpumask.h>
+#include <linux/static_key.h>
+
+struct alloc_tag_counters {
+	u64 bytes;
+	u64 calls;
+};
+
+/*
+ * An instance of this structure is created in a special ELF section at every
+ * allocation callsite. At runtime, the special section is treated as
+ * an array of these. Embedded codetag utilizes codetag framework.
+ */
+struct alloc_tag {
+	struct codetag			ct;
+	struct alloc_tag_counters __percpu	*counters;
+} __aligned(8);
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
+{
+	return container_of(ct, struct alloc_tag, ct);
+}
+
+#ifdef ARCH_NEEDS_WEAK_PER_CPU
+/*
+ * When percpu variables are required to be defined as weak, static percpu
+ * variables can't be used inside a function (see comments for DECLARE_PER_CPU_SECTION).
+ */
+#error "Memory allocation profiling is incompatible with ARCH_NEEDS_WEAK_PER_CPU"
+#endif
+
+#define DEFINE_ALLOC_TAG(_alloc_tag)						\
+	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
+	static struct alloc_tag _alloc_tag __used __aligned(8)			\
+	__section("alloc_tags") = {						\
+		.ct = CODE_TAG_INIT,						\
+		.counters = &_alloc_tag_cntr };
+
+DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
+			mem_alloc_profiling_key);
+
+static inline bool mem_alloc_profiling_enabled(void)
+{
+	return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
+				   &mem_alloc_profiling_key);
+}
+
+static inline struct alloc_tag_counters alloc_tag_read(struct alloc_tag *tag)
+{
+	struct alloc_tag_counters v = { 0, 0 };
+	struct alloc_tag_counters *counter;
+	int cpu;
+
+	for_each_possible_cpu(cpu) {
+		counter = per_cpu_ptr(tag->counters, cpu);
+		v.bytes += counter->bytes;
+		v.calls += counter->calls;
+	}
+
+	return v;
+}
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+static inline void alloc_tag_add_check(union codetag_ref *ref, struct alloc_tag *tag)
+{
+	WARN_ONCE(ref && ref->ct,
+		  "alloc_tag was not cleared (got tag for %s:%u)\n",
+		  ref->ct->filename, ref->ct->lineno);
+
+	WARN_ONCE(!tag, "current->alloc_tag not set");
+}
+
+static inline void alloc_tag_sub_check(union codetag_ref *ref)
+{
+	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
+}
+#else
+static inline void alloc_tag_add_check(union codetag_ref *ref, struct alloc_tag *tag) {}
+static inline void alloc_tag_sub_check(union codetag_ref *ref) {}
+#endif
+
+/* Caller should verify both ref and tag to be valid */
+static inline void __alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag *tag)
+{
+	ref->ct = &tag->ct;
+	/*
+	 * We need in increment the call counter every time we have a new
+	 * allocation or when we split a large allocation into smaller ones.
+	 * Each new reference for every sub-allocation needs to increment call
+	 * counter because when we free each part the counter will be decremented.
+	 */
+	this_cpu_inc(tag->counters->calls);
+}
+
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
+{
+	alloc_tag_add_check(ref, tag);
+	if (!ref || !tag)
+		return;
+
+	__alloc_tag_ref_set(ref, tag);
+	this_cpu_add(tag->counters->bytes, bytes);
+}
+
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	struct alloc_tag *tag;
+
+	alloc_tag_sub_check(ref);
+	if (!ref || !ref->ct)
+		return;
+
+	tag = ct_to_alloc_tag(ref->ct);
+
+	this_cpu_sub(tag->counters->bytes, bytes);
+	this_cpu_dec(tag->counters->calls);
+
+	ref->ct = NULL;
+}
+
+#else /* CONFIG_MEM_ALLOC_PROFILING */
+
+#define DEFINE_ALLOC_TAG(_alloc_tag)
+static inline bool mem_alloc_profiling_enabled(void) { return false; }
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
+				 size_t bytes) {}
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
+#endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 998861865b84..f85b58e385a3 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -770,6 +770,10 @@ struct task_struct {
 	unsigned int			flags;
 	unsigned int			ptrace;
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	struct alloc_tag		*alloc_tag;
+#endif
+
 #ifdef CONFIG_SMP
 	int				on_cpu;
 	struct __call_single_node	wake_entry;
@@ -810,6 +814,7 @@ struct task_struct {
 	struct task_group		*sched_task_group;
 #endif
 
+
 #ifdef CONFIG_UCLAMP_TASK
 	/*
 	 * Clamp values requested for a scheduling entity.
@@ -2185,4 +2190,23 @@ static inline int sched_core_idle_cpu(int cpu) { return idle_cpu(cpu); }
 
 extern void sched_set_stop_task(int cpu, struct task_struct *stop);
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
+{
+	swap(current->alloc_tag, tag);
+	return tag;
+}
+
+static inline void alloc_tag_restore(struct alloc_tag *tag, struct alloc_tag *old)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN(current->alloc_tag != tag, "current->alloc_tag was changed:\n");
+#endif
+	current->alloc_tag = old;
+}
+#else
+#define alloc_tag_save(_tag)			NULL
+#define alloc_tag_restore(_tag, _old)		do {} while (0)
+#endif
+
 #endif
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 5485a5780fa7..0dd6ab986246 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -972,6 +972,31 @@ config CODE_TAGGING
 	bool
 	select KALLSYMS
 
+config MEM_ALLOC_PROFILING
+	bool "Enable memory allocation profiling"
+	default n
+	depends on PROC_FS
+	depends on !DEBUG_FORCE_WEAK_PER_CPU
+	select CODE_TAGGING
+	help
+	  Track allocation source code and record total allocation size
+	  initiated at that code location. The mechanism can be used to track
+	  memory leaks with a low performance and memory impact.
+
+config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+	bool "Enable memory allocation profiling by default"
+	default y
+	depends on MEM_ALLOC_PROFILING
+
+config MEM_ALLOC_PROFILING_DEBUG
+	bool "Memory allocation profiler debugging"
+	default n
+	depends on MEM_ALLOC_PROFILING
+	select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+	help
+	  Adds warnings with helpful error messages for memory allocation
+	  profiling.
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 source "lib/Kconfig.kmsan"
diff --git a/lib/Makefile b/lib/Makefile
index 6b48b22fdfac..859112f09bf5 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -236,6 +236,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
 obj-$(CONFIG_CODE_TAGGING) += codetag.o
+obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o
+
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
new file mode 100644
index 000000000000..f09c8a422bc2
--- /dev/null
+++ b/lib/alloc_tag.c
@@ -0,0 +1,149 @@
+// SPDX-License-Identifier: GPL-2.0-only
+#include <linux/alloc_tag.h>
+#include <linux/fs.h>
+#include <linux/gfp.h>
+#include <linux/module.h>
+#include <linux/proc_fs.h>
+#include <linux/seq_buf.h>
+#include <linux/seq_file.h>
+
+static struct codetag_type *alloc_tag_cttype;
+
+DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
+			mem_alloc_profiling_key);
+
+static void *allocinfo_start(struct seq_file *m, loff_t *pos)
+{
+	struct codetag_iterator *iter;
+	struct codetag *ct;
+	loff_t node = *pos;
+
+	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
+	m->private = iter;
+	if (!iter)
+		return NULL;
+
+	codetag_lock_module_list(alloc_tag_cttype, true);
+	*iter = codetag_get_ct_iter(alloc_tag_cttype);
+	while ((ct = codetag_next_ct(iter)) != NULL && node)
+		node--;
+
+	return ct ? iter : NULL;
+}
+
+static void *allocinfo_next(struct seq_file *m, void *arg, loff_t *pos)
+{
+	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
+	struct codetag *ct = codetag_next_ct(iter);
+
+	(*pos)++;
+	if (!ct)
+		return NULL;
+
+	return iter;
+}
+
+static void allocinfo_stop(struct seq_file *m, void *arg)
+{
+	struct codetag_iterator *iter = (struct codetag_iterator *)m->private;
+
+	if (iter) {
+		codetag_lock_module_list(alloc_tag_cttype, false);
+		kfree(iter);
+	}
+}
+
+static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
+{
+	struct alloc_tag *tag = ct_to_alloc_tag(ct);
+	struct alloc_tag_counters counter = alloc_tag_read(tag);
+	s64 bytes = counter.bytes;
+
+	seq_buf_printf(out, "%12lli %8llu ", bytes, counter.calls);
+	codetag_to_text(out, ct);
+	seq_buf_putc(out, ' ');
+	seq_buf_putc(out, '\n');
+}
+
+static int allocinfo_show(struct seq_file *m, void *arg)
+{
+	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
+	char *bufp;
+	size_t n = seq_get_buf(m, &bufp);
+	struct seq_buf buf;
+
+	seq_buf_init(&buf, bufp, n);
+	alloc_tag_to_text(&buf, iter->ct);
+	seq_commit(m, seq_buf_used(&buf));
+	return 0;
+}
+
+static const struct seq_operations allocinfo_seq_op = {
+	.start	= allocinfo_start,
+	.next	= allocinfo_next,
+	.stop	= allocinfo_stop,
+	.show	= allocinfo_show,
+};
+
+static void __init procfs_init(void)
+{
+	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
+}
+
+static bool alloc_tag_module_unload(struct codetag_type *cttype,
+				    struct codetag_module *cmod)
+{
+	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
+	struct alloc_tag_counters counter;
+	bool module_unused = true;
+	struct alloc_tag *tag;
+	struct codetag *ct;
+
+	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
+		if (iter.cmod != cmod)
+			continue;
+
+		tag = ct_to_alloc_tag(ct);
+		counter = alloc_tag_read(tag);
+
+		if (WARN(counter.bytes,
+			 "%s:%u module %s func:%s has %llu allocated at module unload",
+			 ct->filename, ct->lineno, ct->modname, ct->function, counter.bytes))
+			module_unused = false;
+	}
+
+	return module_unused;
+}
+
+static struct ctl_table memory_allocation_profiling_sysctls[] = {
+	{
+		.procname	= "mem_profiling",
+		.data		= &mem_alloc_profiling_key,
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+		.mode		= 0444,
+#else
+		.mode		= 0644,
+#endif
+		.proc_handler	= proc_do_static_key,
+	},
+	{ }
+};
+
+static int __init alloc_tag_init(void)
+{
+	const struct codetag_type_desc desc = {
+		.section	= "alloc_tags",
+		.tag_size	= sizeof(struct alloc_tag),
+		.module_unload	= alloc_tag_module_unload,
+	};
+
+	alloc_tag_cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(alloc_tag_cttype))
+		return PTR_ERR(alloc_tag_cttype);
+
+	register_sysctl_init("vm", memory_allocation_profiling_sysctls);
+	procfs_init();
+
+	return 0;
+}
+module_init(alloc_tag_init);
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index bf5bcf2836d8..45c67a0994f3 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -9,6 +9,8 @@
 #define DISCARD_EH_FRAME	*(.eh_frame)
 #endif
 
+#include <asm-generic/codetag.lds.h>
+
 SECTIONS {
 	/DISCARD/ : {
 		*(.discard)
@@ -47,12 +49,17 @@ SECTIONS {
 	.data : {
 		*(.data .data.[0-9a-zA-Z_]*)
 		*(.data..L*)
+		CODETAG_SECTIONS()
 	}
 
 	.rodata : {
 		*(.rodata .rodata.[0-9a-zA-Z_]*)
 		*(.rodata..L*)
 	}
+#else
+	.data : {
+		CODETAG_SECTIONS()
+	}
 #endif
 }
 
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-14-surenb%40google.com.
