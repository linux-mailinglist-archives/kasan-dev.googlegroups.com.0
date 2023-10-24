Return-Path: <kasan-dev+bncBC7OD3FKWUERBZEV36UQMGQEZ3SHJJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E07587D5246
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:17 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6c4e46e43absf1173996a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155236; cv=pass;
        d=google.com; s=arc-20160816;
        b=maLXzhs3MEQzDXoJWwWD2Q0XpY2cK5jUF6eBSfYPgPQuROnPqscKZlX7zZ4l96NJge
         x7QubQ+XFsiKTUw28pObXXi3TfEu5tLMRcRJR5Jwy2tX9Ad5SnGSDFhbqgbFYLPoRhfc
         7w5npEyrsNb4l7myqCEPzKTowf/PU/fh8b++i1Uy7Zl2vTNu64P5p8yb3ldl0BrqzsKY
         8J2spvcyXBg2MMovD3nvfYFk3QZ8tlCPSnsGGTakTs+NbfZNz1Zi0cwX/Iml0ANyhb/K
         kF6FIfB+pf6Mj61hEpvcu5TXnKbzx0OcePxfHQeeQei5rf53fDN/DNuhAUfAeKC2JYNH
         y3LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=p+h8rZODW7YpHvUWf1nqPXdvUh96UI5yVuxiYD+tj6E=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=lGboIFmgX+XZwmD0fXOLIopbuQxnDTxnk1BQ0JWC5STQDCM1dGnuljvanxbia30Lf7
         jIXuqcWmaqc7beNrL0U4RR6PvHq5JUpXevzPTduwPJMEGx2nZpS4jSGq0jtFX7fM7Qbc
         YqNBmXRZeIOz5ksLizpYanM9DJC/s966cqLFw0VJtBDu1iMazBnp/Q4/w7qikdPE8aZn
         z11cEZlY4u+HY5SnyMQwPUa0oCupxoKld3o34eYLATGXnA04WHDeHMameMNudUL9BHFd
         2S6hH0mUcjpAjFy/TeDZ43+V57MI7h3qXlqr9pVbkPqRCOWJaU/eMFdju4A8p4g4vpcQ
         rhmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BbkaWWJ8;
       spf=pass (google.com: domain of 34so3zqykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=34so3ZQYKCYc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155236; x=1698760036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=p+h8rZODW7YpHvUWf1nqPXdvUh96UI5yVuxiYD+tj6E=;
        b=pR8YOLd0One1JRXPRvlh5vikV+HgO1rprGYlTK+xU/1W/0wKY9D+AMdofz4NbdNlLB
         Yw05rC9sav9sRiNTl65uB0To6zKF3hdIZ9OclkuX1N7C/hPfLq5c2mt+5U1ybHbwKGTW
         5QRhRwYUTp7DX22geNGljmCxpxgGhChVczLbdws1+PRPcbRfM8cMbeyRfuGTQawEV8qt
         XKTBllwbU7I+MaTwlQD5rfHUqNLJT4Q6v+SyIwqK4/p1+16a9lPVp/EM9vijmpEIsHke
         3Y2syboBUhXGpPPwYY//i6yuwgee9hMQdw9UlhPAqJ97XzUxUaSGhOrY6UjbrSq/iKmi
         FZog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155236; x=1698760036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p+h8rZODW7YpHvUWf1nqPXdvUh96UI5yVuxiYD+tj6E=;
        b=jF3oNBa7deJYiT8QvHY2/KvdNB739EW3FdCilI00c3RRmsIF65pNNaKzIU8gHudPI8
         4WzaPqFw+WKA9hkqx9YXM+Vo+jtlNdA7ot9UcBqPbvTce0Vd3mqj4Z2PUPnanjikyxq3
         p4Yv0cXwDTrmrHwRYMhNmntj9iqWEDwCUCqrDLeuHNk/zcuaG/kAkg2VNE1YMlh5TX+p
         2wfe+0b87jicsUVeMuAbCZfWPpB1qfv22d8Dss6wlmxA3iGDlbdEqz7TSpsKLNGDybxu
         OYWbymbNxcPeTRzK5NuvcUmTfSNnqX9m2ie1Cj/mXcc2yeNHmTRH5Q8G8hdl3FdS7oYl
         HbCw==
X-Gm-Message-State: AOJu0Yw8t/Is57e13pIJn8DrQT7G1BsinkZz3dktRH+1ZJJQ6caajk92
	fQnDz01YnaoF94FeE5v9XAY=
X-Google-Smtp-Source: AGHT+IGyepr5hI7BaJWltZ+BA84iod/yJJwoYYHuzDbi5ZV/hDcNYKLh8wRe9l9qsbrnLYoOx828nQ==
X-Received: by 2002:a05:6871:220e:b0:1e9:adec:bf5e with SMTP id sc14-20020a056871220e00b001e9adecbf5emr12485515oab.2.1698155236684;
        Tue, 24 Oct 2023 06:47:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f21d:b0:1e9:923e:98cc with SMTP id
 t29-20020a056870f21d00b001e9923e98ccls527487oao.0.-pod-prod-00-us; Tue, 24
 Oct 2023 06:47:15 -0700 (PDT)
X-Received: by 2002:a05:6870:c1d0:b0:1d4:eefb:3ae5 with SMTP id i16-20020a056870c1d000b001d4eefb3ae5mr8690527oad.15.1698155235591;
        Tue, 24 Oct 2023 06:47:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155235; cv=none;
        d=google.com; s=arc-20160816;
        b=tudYx2bFCSC07LOq9xZZBmUfBoOuRk9qM+wXMf4NP9zCRi7JJw9FTKjWa2JQEK/GnY
         M80ywo/e1EBrfp5eV5FKmiYBWVmH4/F0gqSaYozlxhZNORxOeC2v8KOqpx95PRxIR+Dg
         2wLoQUzZSHKoqOCqhWdTVXibMrXydSfVKG2LYnIe5pyH4jGY09vJrktWd8nAztvZR9V1
         3Lv7I3L1cFuCJ/zSGz4zr5aSRi9ujiT87U2afUAU4oMUTiwK3iOT7+rkULpVnj/CwQVh
         +nB0qiwsuGzeaHcOLE4G6VcCh8FcAt2Weck6e+17mdfWf1hvaO944Y1LH7w8FV2kYlJ+
         oKug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=K+jSKdm0qvzH//duzEhIZcT0jtfDLsmvFXjZdfhiaL8=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=H9sQHcsiInJzj3TwQpoPwy23FUM4kozjD0GXW4j+AiZn19TSHkBJyRkmpFjKIQGPcj
         Fq5sM5NI1Qi/70lGyuQ19rg8lfo5jnUWSXxCiTS4QmHrw1r5mpaO5Kw/ZPOJXYT3VMXM
         iT8nH+5yX9/wJYcbxava/i0Xo8IpBxYMU1EUInSTEiw4pWu4qXqIXD3oSj5CUoyCFwms
         jOOWTGemIMq3B9iI5f9xoZujhT1Ptgzxyn16eeVI5r0xSyO1DtG4oyFRc3eSeer+MwBz
         I8GjCS5jljCK1SWE1WjO4mUrA/ygznRoinhp0Eh+cQHqtorQ69z7ysYXwVjQP2gz7k/c
         e11g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BbkaWWJ8;
       spf=pass (google.com: domain of 34so3zqykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=34so3ZQYKCYc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id lc28-20020a056871419c00b001eac55e3d6csi1477178oab.5.2023.10.24.06.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34so3zqykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9a528c2c8bso5307648276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:15 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:1083:b0:d9a:cc6b:cf1a with SMTP id
 v3-20020a056902108300b00d9acc6bcf1amr317480ybu.8.1698155234917; Tue, 24 Oct
 2023 06:47:14 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:12 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-16-surenb@google.com>
Subject: [PATCH v2 15/39] lib: add allocation tagging support for memory
 allocation profiling
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
 header.i=@google.com header.s=20230601 header.b=BbkaWWJ8;       spf=pass
 (google.com: domain of 34so3zqykcyc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=34so3ZQYKCYc352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
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

Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 Documentation/admin-guide/sysctl/vm.rst |  16 +++
 Documentation/filesystems/proc.rst      |  28 +++++
 include/asm-generic/codetag.lds.h       |  14 +++
 include/asm-generic/vmlinux.lds.h       |   3 +
 include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
 include/linux/sched.h                   |  24 ++++
 lib/Kconfig.debug                       |  25 ++++
 lib/Makefile                            |   2 +
 lib/alloc_tag.c                         | 158 ++++++++++++++++++++++++
 scripts/module.lds.S                    |   7 ++
 10 files changed, 410 insertions(+)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 lib/alloc_tag.c

diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/admin-guide/sysctl/vm.rst
index 45ba1f4dc004..0a012ac13a38 100644
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
+0: Disabld memory profiling.
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
index 2b59cff8be17..41a7e6d95fe8 100644
--- a/Documentation/filesystems/proc.rst
+++ b/Documentation/filesystems/proc.rst
@@ -688,6 +688,7 @@ files are there, and which are missing.
  ============ ===============================================================
  File         Content
  ============ ===============================================================
+ allocinfo    Memory allocations profiling information
  apm          Advanced power management info
  buddyinfo    Kernel memory allocator information (see text)	(2.5)
  bus          Directory containing bus specific information
@@ -947,6 +948,33 @@ also be allocatable although a lot of filesystem metadata may have to be
 reclaimed to achieve this.
 
 
+allocinfo
+~~~~~~~
+
+Provides information about memory allocations at all locations in the code
+base. Each allocation in the code is identified by its source file, line
+number, module and the function calling the allocation. The number of bytes
+allocated at each location is reported.
+
+Example output.
+
+::
+
+    > cat /proc/allocinfo
+
+      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
+     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc_order
+     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_slab_obj_exts
+     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pages_exact
+     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
+     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvmalloc
+     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cgroup_prepare
+      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
+      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page_cache_func
+      640KiB     drivers/char/virtio_console.c:452 module:virtio_console func:alloc_buf
+      ...
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
index 67d8dd2f1bde..f04661824939 100644
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
@@ -367,6 +369,7 @@
 	. = ALIGN(8);							\
 	BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)		\
 	BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)				\
+	CODETAG_SECTIONS()						\
 	LIKELY_PROFILE()		       				\
 	BRANCH_PROFILE()						\
 	TRACE_PRINTKS()							\
diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
new file mode 100644
index 000000000000..cf55a149fa84
--- /dev/null
+++ b/include/linux/alloc_tag.h
@@ -0,0 +1,133 @@
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
+#define DEFINE_ALLOC_TAG(_alloc_tag, _old)					\
+	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
+	static struct alloc_tag _alloc_tag __used __aligned(8)			\
+	__section("alloc_tags") = {						\
+		.ct = CODE_TAG_INIT,						\
+		.counters = &_alloc_tag_cntr };					\
+	struct alloc_tag * __maybe_unused _old = alloc_tag_save(&_alloc_tag)
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
+static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	struct alloc_tag *tag;
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
+#endif
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
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	__alloc_tag_sub(ref, bytes);
+}
+
+static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
+{
+	__alloc_tag_sub(ref, bytes);
+}
+
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN_ONCE(ref && ref->ct,
+		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
+		  ref->ct->filename, ref->ct->lineno);
+
+	WARN_ONCE(!tag, "current->alloc_tag not set");
+#endif
+	if (!ref || !tag)
+		return;
+
+	ref->ct = &tag->ct;
+	this_cpu_add(tag->counters->bytes, bytes);
+	this_cpu_inc(tag->counters->calls);
+}
+
+#else
+
+#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
+static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
+				 size_t bytes) {}
+
+#endif
+
+#endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 12a2554a3164..d35901d8de06 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -767,6 +767,10 @@ struct task_struct {
 	unsigned int			flags;
 	unsigned int			ptrace;
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	struct alloc_tag		*alloc_tag;
+#endif
+
 #ifdef CONFIG_SMP
 	int				on_cpu;
 	struct __call_single_node	wake_entry;
@@ -806,6 +810,7 @@ struct task_struct {
 	struct task_group		*sched_task_group;
 #endif
 
+
 #ifdef CONFIG_UCLAMP_TASK
 	/*
 	 * Clamp values requested for a scheduling entity.
@@ -2457,4 +2462,23 @@ static inline int sched_core_idle_cpu(int cpu) { return idle_cpu(cpu); }
 
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
+static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag) { return NULL; }
+#define alloc_tag_restore(_tag, _old)
+#endif
+
 #endif
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 2acbef24e93e..475a14e70566 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -966,6 +966,31 @@ config CODE_TAGGING
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
index b50212b5b999..4525469637fe 100644
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
index 000000000000..4fc031f9cefd
--- /dev/null
+++ b/lib/alloc_tag.c
@@ -0,0 +1,158 @@
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
+	char val[10], *p = val;
+
+	if (bytes < 0) {
+		*p++ = '-';
+		bytes = -bytes;
+	}
+
+	string_get_size(bytes, 1,
+			STRING_SIZE_BASE2|STRING_SIZE_NOSPACE,
+			p, val + ARRAY_SIZE(val) - p);
+
+	seq_buf_printf(out, "%8s %8llu ", val, counter.calls);
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
+		if (WARN(counter.bytes, "%s:%u module %s func:%s has %llu allocated at module unload",
+			  ct->filename, ct->lineno, ct->modname, ct->function, counter.bytes))
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-16-surenb%40google.com.
