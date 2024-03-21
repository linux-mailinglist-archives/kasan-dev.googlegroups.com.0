Return-Path: <kasan-dev+bncBC7OD3FKWUERBU6E6GXQMGQEDJ6WZ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 90477885DAC
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:40 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-430ac211fbbsf12735861cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039059; cv=pass;
        d=google.com; s=arc-20160816;
        b=FfwxCXlhjUD2rNszuTNTbuC+B5uzv4AxZ+lQPfEkU1NeVVymBcYzxtLiycMKXUQh6S
         8SUp3h4q5ALJUFcYIAs5haVTZi4yJwWb6wwnoRe4dmwaNoiDqakiWIJmlV4Kg3GPtCYO
         KKZcA69nIot0YsUUnwdcTS7o9G0Etlq5Fls9pjm6Ng4Wf9sf6VyQW4TNxFVB2tyHhJnh
         ylrTVb6dQ55gBY69m3J6dsNmhuuvYBsdCvxXW4N7pKkDuBOVuSSOFa7vlJNBDOmYKHcp
         CZg5BIi75PvIGytQhjR7r6IYOFzzY9LXr3OoKE8UnviedtMwBQhFxcjWpkN2A47NeZHH
         uJZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=orFIIw/kTgCzCEc1T66J6wWCRRbjAGt6d/Xtd3lyYk8=;
        fh=6Y1Gu+KDWogWbXhjluWTpimQGyzNi5WZcA3Dni0gplk=;
        b=B2gejRROx6xa2aT/+COp8N2Sn9JuNUDes5ad0j3OydzFX6oTRzwdRDj2rXv2uS0eWz
         IN0Wa63eHb1uThrvUTZDeGB35YvSiutwqIKM7zjqPE0g3YkxMbcNYbYGuhUCLDFvozNX
         H4iFdXGjZFJY+s7ai5bHkh8kfEHcxumvQ37iR1NLMWc46g/Sc0I8dvLgUH7cUrnrtp6t
         0ldEjzPAduY74ZIyGJYD78gA+WiFSfS6jmjvqMdgeSgTrdZp6cyW2ykt2RhfGhm0rFgo
         erjgJf2/7jOR87D9LihXHub/i4DB1zVFns0//21c9luDncasLo7rxca1INo+m4H4a1ex
         gPLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1KJW3vB8;
       spf=pass (google.com: domain of 3uml8zqykct8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3UmL8ZQYKCT8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039059; x=1711643859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=orFIIw/kTgCzCEc1T66J6wWCRRbjAGt6d/Xtd3lyYk8=;
        b=eTfLMvN8eA4acDLBjPF/4x7XbMvRNfTlwHHuHDDy9vevtakt/R77tqhDSx1ACCSTuX
         jbZ9npRUe9TdGNmjTBcdDKpHP407vtn8cipjYwtOs4kM6ZoEKn/u1NPNWKkOUCAXkaun
         GpC4D+WmsUyIH/KFuY8ngyyT734rFR4xl1LP9jP07c5Uj6s4812OjU5UXKn/cLAEuE3j
         SnXl+6DxXTm2CTRrM9iKkn9JfbVht1eWNWB4x1cy7MyTbJl55qj+TGQGxF3tDNoUSQsi
         jjGkL5WrDqV+VIVA7Yjo//TjKdUwf/XaAZ6lUvEQcNN54l2uycrFbsqTdwAO2Mg0W2JB
         H3WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039059; x=1711643859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=orFIIw/kTgCzCEc1T66J6wWCRRbjAGt6d/Xtd3lyYk8=;
        b=F+wGhI7lXn26MdwGWqqaPH/CZAolDLxYDAdyh+SEQ7JTaRxCrbWJdfaO/yB3+yWyNw
         J77lQiqwoZWYdKKoneqLcLKjOI7Ps19NMH9cYMwiKfWLJMB21YAXLsF9q0VI4MBH+vpu
         vd3y/2EHceu+gGEk5IGu8JwFcO1uG8FH1ZGgFF5eaUPi3d5SHKm5vD4LGtBCv5GLq9sD
         uXQHVibP+H7MgMvHH8W9gJ9v+NUbRxSfV5G76lLidjyW1dKWiYOimqHicLkB4WALXODp
         ugaCPGXXIXK2D5YU7/YOsFmPPCPUeyKCRNDs3UhnbsnAnTmPfV0QkAgHMUV5K3EqdlkN
         rB3A==
X-Forwarded-Encrypted: i=2; AJvYcCWXrsOOGZDWc5HUy09fBUqRRSzLgr3kSCcRs2AGvY7U1RVFWr+Fy8UiTSTOqYsQ7I1mGzrzic7cMFxRlWcbCOZFj14acBmjnA==
X-Gm-Message-State: AOJu0Yz28FymtweV0QpKrEAghxKXyLIZV0jqQOJuknVQN9hj3sNPv+9m
	VdYE4nIqCF11RBnvbeBA7fBQJSPmSuxdv3ep6MgT4WMmOk3oXt5Q
X-Google-Smtp-Source: AGHT+IFZ46use359RlwiumCt5q661wa7BvUQI8EDhytbYHgjT5Ud3ymBbn+kFyIOyrCPJuoj7BGOQA==
X-Received: by 2002:ac8:5f92:0:b0:431:2007:48ac with SMTP id j18-20020ac85f92000000b00431200748acmr2798367qta.38.1711039059339;
        Thu, 21 Mar 2024 09:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1011:b0:430:edac:58f4 with SMTP id
 d17-20020a05622a101100b00430edac58f4ls1645546qte.0.-pod-prod-01-us; Thu, 21
 Mar 2024 09:37:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQ/rbYOYH8bSjwg/pbJrJHvibN7vpAACafFnA+I88jT73YoevkCy6v3u6uvJinV9obtZNyfJ8yhk9eYXlaBT8U8mjgga0YAV/+RA==
X-Received: by 2002:a05:6102:508a:b0:474:c306:9062 with SMTP id bl10-20020a056102508a00b00474c3069062mr55561vsb.12.1711039058638;
        Thu, 21 Mar 2024 09:37:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039058; cv=none;
        d=google.com; s=arc-20160816;
        b=TrqNKO/916OKiCqieCHTAda3QAFub3sOtxQ8UkRA7AHPskUMAN/SbukfmrvLzpV8OD
         PBzuBA3tsDu/PfrsXTx7kYiffQI/X25D66w37rM37wKEDsoi6eayuom7q4KrDK87o/ZH
         KvdvZ/BrlU2+DMQfpvkvfJGyUQ8JsnfEaIoxaCXwfn6nbodAjuPMX3NJfxE9I2TqDF+p
         28l+AzfmynZVq6/uC2yRHCzfyljKsNQ0brZRLfxlFODkaqZgyPB4TAIaLWcAVbPqYhMD
         ScHUzPK1Ic+oRthJfMUuLlbfjrdMKr7RMR9loD0KXASl6KNCS2GzVD1QiJzjbiYkLFob
         68Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kphxAsbZBCd3nBfcxo1fm19K6BicOHdsdiKRJJ1Q0RA=;
        fh=YOZ3L5HBjag15532jr1TrI0MF657ob09ebyo2IMzRHI=;
        b=eJcEypYX9bunyNPjnrfRk8RbV9p5W9YG/jnl7jhb5LmkhsTZdCtuzVL6+5ecIh75uH
         1cx8hDse/U82iJ4jg6In1yC6eyj7j1a8VgQ+SZF1Xj8ic9mYFFAXT8B52ZQRN9TgVZ2M
         O4p4VJNwSGjVgRYAcjuKChai2E4NBQVz16McZUIRj2gikTeJrzuDTjfww6L71+HdRqvT
         cqGa/rf2mAY4SHCJu839/LfJSPmzvCDD9uTEhDfPLDY8RkGoLgfL2EDrrwuQRXthhudE
         Px2lqZvmDs9/VAqWVhY0XVBSrTpD0UfpttLBHB83C+MHBK3bzzOU06BuCMMY1c7Ps1tp
         SHTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1KJW3vB8;
       spf=pass (google.com: domain of 3uml8zqykct8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3UmL8ZQYKCT8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id w10-20020a0562140b2a00b00696419ee0desi9612qvj.4.2024.03.21.09.37.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uml8zqykct8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60a55cd262aso20239727b3.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU7lRRX2TzA73+wzPv5NpM3TBLza1w5x3zoc4jWCmLNxEF0b3KoHwuRavbAjTm9+w8Eyd3A3393DAChzxAIJDE7R2vgJ9uKajteZA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a0d:cc83:0:b0:611:19e0:dfcf with SMTP id
 o125-20020a0dcc83000000b0061119e0dfcfmr32561ywd.10.1711039058133; Thu, 21 Mar
 2024 09:37:38 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:35 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-14-surenb@google.com>
Subject: [PATCH v6 13/37] lib: add allocation tagging support for memory
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
 header.i=@google.com header.s=20230601 header.b=1KJW3vB8;       spf=pass
 (google.com: domain of 3uml8zqykct8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3UmL8ZQYKCT8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
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
index c6a6b9df2104..5d2fc58b5b1f 100644
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
index f7749d0f2562..3e4497b5135a 100644
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
index 3c2abbc587b4..4118b3f959c3 100644
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
@@ -2187,4 +2192,23 @@ static inline int sched_core_idle_cpu(int cpu) { return idle_cpu(cpu); }
 
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
index d2dbdd45fd9a..d9a6477afdb1 100644
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
index 910335da8f13..2f4e17bfb299 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -234,6 +234,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-14-surenb%40google.com.
