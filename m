Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXRZT5QKGQEO6XNFAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E00C327CF56
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:38:46 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id fx20sf995293ejb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:38:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386726; cv=pass;
        d=google.com; s=arc-20160816;
        b=nC6UF1b15f02fWaj30b6S+APwnys6d3KJevnKujMDopfzcRnmIFK1KSqqJXPF8I8GH
         zxGwg0NA6pYYhdG82cAasXUj9g3mn6Tc4v6F7thq4s1pWS7ULFrdp7z2anL4+b0hxyLS
         IXK9IbG98ki3Tw+mi/L0Vr44A1Z3REEuJeSU1s7ZdS2t0VBmI/Ldu95lCtHnFCamyVgX
         wXC6DAgeEEqWaSPUbNn/MQLOoCu3lxdrVeHddcm+51Hr954OvUCZokjRqs9H3AtuB+A6
         BA+KsWw6gM8qOSiOQm76KthqikxZ+bomf9dxqbOeyBIOaD3qtRnZviZbUNrPd4R1wZzw
         yyOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tK4WX5DoE6unNV6tk1R0TDnar9Bxz1txynMF793wiWU=;
        b=yYiolpJ58gY9mp7zAuVFsXoZEzKrAN89CUTuFvauVTbHllAnzvotOX5e4jH7W6m4/d
         l0FBiXM6lVjLYaqHnVno+myGFrk9igTI/Q0fZfboHov1m+UARbddtsRqpfYZhMX13bCR
         O6lK3mD4EttJRuymKCnNtUcfULX3mbJuMt4zVtvoKYpPORI3n+z3zOu3c8IJ8ETBIUZS
         jPmbr6OzFvvY2AFngZs2i4QM0rWP8dfoau28lDggLXbd8syXCYVcH9TuMxT7zfW30XZC
         1Df99Td2SUv5xMEA77Yl8C4UoM0DiY3Mrf1A4gJPO9SIj0QfFxdRH8Zfsm/D+NQe4BoM
         K3zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MnLBJqBy;
       spf=pass (google.com: domain of 35dhzxwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35DhzXwUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tK4WX5DoE6unNV6tk1R0TDnar9Bxz1txynMF793wiWU=;
        b=aIbnGiMk9uq6MjOeEaTy8QY+80OP6s8KmoRccKUMc/PsgQRK25aRw5PI2A13Kde+zr
         aV7xy/4uwmSQWFP4k4UzdvmOSoCJAJTNSy+K0VAv8QZYmWUXXz5ph85g7LOfukzWFDYg
         eip9gEr7LQAK9YWEcKEztn8X4kuxKk8dKsb97nnouty0t2+7kK8ZTcBRiyCuUNt7pACl
         et5SHANw9ruTlHQ7ktzflPn5ygDDksdKgxUjbo7qFoWN2h5Ug8SJK7fWNbb96RrOePUh
         u0WXtWWF6NWTjd+AjGpb9OO8mA9HamD0tcAnrjvvEaBTxOR3PGf/eQH9/2JHEsUeovSs
         V9kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tK4WX5DoE6unNV6tk1R0TDnar9Bxz1txynMF793wiWU=;
        b=KUkbUUteby8H8MoqlMqJ6j+jjrU8wq9D261Cy0VAiW/VRvOJc12bwWEUAf9o9YlFdL
         fB6U2EqjtuxxnroUs9xWmizH0f/7vSvgbozj/idB1f0I0Pmqj/fvX7wXpbqOkBHAbky9
         HzwnESf/ojSwURGDlIz19Mc7C5PN1jNSJDL8RXCGK0shqi2Z0lz5MvfDlW/OQ5IL8mGW
         pfckaeZilz8xRHgt0aXmrh2O4ZX/QaBuEqtj0fBZMX5W0E7FBJkdgA/k5/Js6r1rJ/Dm
         vb9hU8cxGHAI1dAUQwhKJSHN0iZLCAzO+u1wBSjSTQGBVLchQDZyiKQR7r9408aJULfz
         5Ehg==
X-Gm-Message-State: AOAM533gfhf66QtLAP6nyfoHOdVSRuiaTWnoXZMsuwfrOMDbVmISps1P
	zm+0TsU4KYrZ8YwLnC3LJSo=
X-Google-Smtp-Source: ABdhPJwnP35t5rDzi09uJIFEQ2r/6qIhes7939S/0NNZJb9WK1mV4C9dPZazxVUiTYommni2Mah3xA==
X-Received: by 2002:a50:abc3:: with SMTP id u61mr3199400edc.129.1601386726479;
        Tue, 29 Sep 2020 06:38:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:547:: with SMTP id k7ls1328589eja.7.gmail; Tue, 29
 Sep 2020 06:38:45 -0700 (PDT)
X-Received: by 2002:a17:906:30c7:: with SMTP id b7mr4065181ejb.7.1601386725249;
        Tue, 29 Sep 2020 06:38:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386725; cv=none;
        d=google.com; s=arc-20160816;
        b=mO/DWlgfPu0bly4GChtW4oP0gUQoNbrGgIFws81NKn7VzayZYybl1LOrLxXCQZSRKv
         1QWnKS98ANppdBwNSqvqiuXztO52kAtkZ6gZDNpa2DHjPCiTG7QIoiTJp01NqWC6gILM
         HclUmUpyzNISZrknPcWXqKQjSW3dEjEeT1MfSHAut8m5oxcuxb9jKSMm3x6SW/pABeoP
         u9Px+0KAv2FlpiFUsE/gi24Jz8CeERSnVHNXHuURlgh7TN3eemxCqtuTumncwKzprxDc
         zPSCilvQO7mbdSaydVgAhEgSu7WB6Sj/m3uEBt4wRYFAzgYDFUKGD9y2Gk28HIxTjQke
         2ceQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oNHjsoJGzinfIWGKnw9EQuiBEFMQiTXcQBd8cTGXRwM=;
        b=SNegZOpxzB/uvKOvcKoS+6P5xYx2XxvCbWliSzCiv8epvarvAVkdz4mfKvunWJse9B
         KljfoBcvKgRx80ixIEYB8ymmdodRqfVpmu2IeRAKFGxizYDPZViDkaURw2bWOXZJOr5m
         S/pB7rGNrR3fGPCDH5rQKov/W6qOxfRK8Z79aCkQ2fGT5Lx48xZ0bVEhBJTqO8849mf9
         iQ9LINg8L9RymeXUw4WmUuJHS3Bkd+6yRzrqUs7WubuubI5NhskMAuLEyoEXJjlodfvp
         YJ/Yk9FP39f33EkK5XL4NyMpLP+R0NmO71ZihlDcV2eBHUTekRvR8dQdwXqqct7dBODm
         kjSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MnLBJqBy;
       spf=pass (google.com: domain of 35dhzxwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35DhzXwUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f17si112962edx.5.2020.09.29.06.38.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35dhzxwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id c204so1725602wmd.5
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:45 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c958:: with SMTP id i24mr4903792wml.50.1601386724678;
 Tue, 29 Sep 2020 06:38:44 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:04 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-2-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MnLBJqBy;       spf=pass
 (google.com: domain of 35dhzxwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35DhzXwUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
low-overhead sampling-based memory safety error detector of heap
use-after-free, invalid-free, and out-of-bounds access errors.

KFENCE is designed to be enabled in production kernels, and has near
zero performance overhead. Compared to KASAN, KFENCE trades performance
for precision. The main motivation behind KFENCE's design, is that with
enough total uptime KFENCE will detect bugs in code paths not typically
exercised by non-production test workloads. One way to quickly achieve a
large enough total uptime is when the tool is deployed across a large
fleet of machines.

KFENCE objects each reside on a dedicated page, at either the left or
right page boundaries. The pages to the left and right of the object
page are "guard pages", whose attributes are changed to a protected
state, and cause page faults on any attempted access to them. Such page
faults are then intercepted by KFENCE, which handles the fault
gracefully by reporting a memory access error. To detect out-of-bounds
writes to memory within the object's page itself, KFENCE also uses
pattern-based redzones. The following figure illustrates the page
layout:

  ---+-----------+-----------+-----------+-----------+-----------+---
     | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
     | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
     | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
     | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
     | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
     | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
  ---+-----------+-----------+-----------+-----------+-----------+---

Guarded allocations are set up based on a sample interval (can be set
via kfence.sample_interval). After expiration of the sample interval, a
guarded allocation from the KFENCE object pool is returned to the main
allocator (SLAB or SLUB). At this point, the timer is reset, and the
next allocation is set up after the expiration of the interval.

To enable/disable a KFENCE allocation through the main allocator's
fast-path without overhead, KFENCE relies on static branches via the
static keys infrastructure. The static branch is toggled to redirect the
allocation to KFENCE. To date, we have verified by running synthetic
benchmarks (sysbench I/O workloads) that a kernel compiled with KFENCE
is performance-neutral compared to the non-KFENCE baseline.

For more details, see Documentation/dev-tools/kfence.rst (added later in
the series).

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: SeongJae Park <sjpark@amazon.de>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v4
* Make static memory pool's attrs entirely arch-dependent.
* Revert MAINTAINERS, and make separate patch.
* Fix report generation if __slab_free tail-called.

v3:
* Reports by SeongJae Park:
  * Remove reference to Documentation/dev-tools/kfence.rst.
  * Remove redundant braces.
  * Use CONFIG_KFENCE_NUM_OBJECTS instead of ARRAY_SIZE(...).
  * Align some comments.
* Add figure from Documentation/dev-tools/kfence.rst added later in
  series to patch description.

v2:
* Add missing __printf attribute to seq_con_printf, and fix new warning.
  [reported by kernel test robot <lkp@intel.com>]
* Fix up some comments [reported by Jonathan Cameron].
* Remove 2 cases of redundant stack variable initialization
  [reported by Jonathan Cameron].
* Fix printf format [reported by kernel test robot <lkp@intel.com>].
* Print (in kfence-#nn) after address, to more clearly establish link
  between first and second stacktrace [reported by Andrey Konovalov].
* Make choice between KASAN and KFENCE clearer in Kconfig help text
  [suggested by Dave Hansen].
* Document CONFIG_KFENCE_SAMPLE_INTERVAL=0.
* Shorten memory corruption report line length.
* Make /sys/module/kfence/parameters/sample_interval root-writable for
  all builds (to enable debugging, automatic dynamic tweaking).
* Reports by Dmitry Vyukov:
  * Do not store negative size for right-located objects
  * Only cache-align addresses of right-located objects.
  * Run toggle_allocation_gate() after KFENCE is enabled.
  * Add empty line between allocation and free stacks.
  * Add comment about SLAB_TYPESAFE_BY_RCU.
  * Also skip internals for allocation/free stacks.
  * s/KFENCE_FAULT_INJECTION/KFENCE_STRESS_TEST_FAULTS/ as FAULT_INJECTION
    is already overloaded in different contexts.
  * Parenthesis for macro variable.
  * Lower max of KFENCE_NUM_OBJECTS config variable.
---
 include/linux/kfence.h | 174 ++++++++++
 init/main.c            |   2 +
 lib/Kconfig.debug      |   1 +
 lib/Kconfig.kfence     |  63 ++++
 mm/Makefile            |   1 +
 mm/kfence/Makefile     |   3 +
 mm/kfence/core.c       | 733 +++++++++++++++++++++++++++++++++++++++++
 mm/kfence/kfence.h     | 102 ++++++
 mm/kfence/report.c     | 225 +++++++++++++
 9 files changed, 1304 insertions(+)
 create mode 100644 include/linux/kfence.h
 create mode 100644 lib/Kconfig.kfence
 create mode 100644 mm/kfence/Makefile
 create mode 100644 mm/kfence/core.c
 create mode 100644 mm/kfence/kfence.h
 create mode 100644 mm/kfence/report.c

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
new file mode 100644
index 000000000000..8128ba7b5e90
--- /dev/null
+++ b/include/linux/kfence.h
@@ -0,0 +1,174 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _LINUX_KFENCE_H
+#define _LINUX_KFENCE_H
+
+#include <linux/mm.h>
+#include <linux/percpu.h>
+#include <linux/static_key.h>
+#include <linux/types.h>
+
+#ifdef CONFIG_KFENCE
+
+/*
+ * We allocate an even number of pages, as it simplifies calculations to map
+ * address to metadata indices; effectively, the very first page serves as an
+ * extended guard page, but otherwise has no special purpose.
+ */
+#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
+#ifdef CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL
+extern char __kfence_pool[KFENCE_POOL_SIZE];
+#else
+extern char *__kfence_pool;
+#endif
+
+extern struct static_key_false kfence_allocation_key;
+
+/**
+ * is_kfence_address() - check if an address belongs to KFENCE pool
+ * @addr: address to check
+ *
+ * Return: true or false depending on whether the address is within the KFENCE
+ * object range.
+ *
+ * KFENCE objects live in a separate page range and are not to be intermixed
+ * with regular heap objects (e.g. KFENCE objects must never be added to the
+ * allocator freelists). Failing to do so may and will result in heap
+ * corruptions, therefore is_kfence_address() must be used to check whether
+ * an object requires specific handling.
+ */
+static __always_inline bool is_kfence_address(const void *addr)
+{
+	return unlikely((char *)addr >= __kfence_pool &&
+			(char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
+}
+
+/**
+ * kfence_init() - perform KFENCE initialization at boot time
+ */
+void kfence_init(void);
+
+/**
+ * kfence_shutdown_cache() - handle shutdown_cache() for KFENCE objects
+ * @s: cache being shut down
+ *
+ * Return: true on success, false if any leftover objects persist.
+ *
+ * Before shutting down a cache, one must ensure there are no remaining objects
+ * allocated from it. KFENCE objects are not referenced from the cache, so
+ * kfence_shutdown_cache() takes care of them.
+ */
+bool __must_check kfence_shutdown_cache(struct kmem_cache *s);
+
+/*
+ * Allocate a KFENCE object. Allocators must not call this function directly,
+ * use kfence_alloc() instead.
+ */
+void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);
+
+/**
+ * kfence_alloc() - allocate a KFENCE object with a low probability
+ * @s:     struct kmem_cache with object requirements
+ * @size:  exact size of the object to allocate (can be less than @s->size
+ *         e.g. for kmalloc caches)
+ * @flags: GFP flags
+ *
+ * Return:
+ * * NULL     - must proceed with allocating as usual,
+ * * non-NULL - pointer to a KFENCE object.
+ *
+ * kfence_alloc() should be inserted into the heap allocation fast path,
+ * allowing it to transparently return KFENCE-allocated objects with a low
+ * probability using a static branch (the probability is controlled by the
+ * kfence.sample_interval boot parameter).
+ */
+static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
+{
+	return static_branch_unlikely(&kfence_allocation_key) ? __kfence_alloc(s, size, flags) :
+								      NULL;
+}
+
+/**
+ * kfence_ksize() - get actual amount of memory allocated for a KFENCE object
+ * @addr: pointer to a heap object
+ *
+ * Return:
+ * * 0     - not a KFENCE object, must call __ksize() instead,
+ * * non-0 - this many bytes can be accessed without causing a memory error.
+ *
+ * kfence_ksize() returns the number of bytes requested for a KFENCE object at
+ * allocation time. This number may be less than the object size of the
+ * corresponding struct kmem_cache.
+ */
+size_t kfence_ksize(const void *addr);
+
+/**
+ * kfence_object_start() - find the beginning of a KFENCE object
+ * @addr - address within a KFENCE-allocated object
+ *
+ * Return: address of the beginning of the object.
+ *
+ * SL[AU]B-allocated objects are laid out within a page one by one, so it is
+ * easy to calculate the beginning of an object given a pointer inside it and
+ * the object size. The same is not true for KFENCE, which places a single
+ * object at either end of the page. This helper function is used to find the
+ * beginning of a KFENCE-allocated object.
+ */
+void *kfence_object_start(const void *addr);
+
+/*
+ * Release a KFENCE-allocated object to KFENCE pool. Allocators must not call
+ * this function directly, use kfence_free() instead.
+ */
+void __kfence_free(void *addr);
+
+/**
+ * kfence_free() - try to release an arbitrary heap object to KFENCE pool
+ * @addr: object to be freed
+ *
+ * Return:
+ * * false - object doesn't belong to KFENCE pool and was ignored,
+ * * true  - object was released to KFENCE pool.
+ *
+ * Release a KFENCE object and mark it as freed. May be called on any object,
+ * even non-KFENCE objects, to simplify integration of the hooks into the
+ * allocator's free codepath. The allocator must check the return value to
+ * determine if it was a KFENCE object or not.
+ */
+static __always_inline __must_check bool kfence_free(void *addr)
+{
+	if (!is_kfence_address(addr))
+		return false;
+	__kfence_free(addr);
+	return true;
+}
+
+/**
+ * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
+ * @addr: faulting address
+ *
+ * Return:
+ * * false - address outside KFENCE pool,
+ * * true  - page fault handled by KFENCE, no additional handling required.
+ *
+ * A page fault inside KFENCE pool indicates a memory error, such as an
+ * out-of-bounds access, a use-after-free or an invalid memory access. In these
+ * cases KFENCE prints an error message and marks the offending page as
+ * present, so that the kernel can proceed.
+ */
+bool __must_check kfence_handle_page_fault(unsigned long addr);
+
+#else /* CONFIG_KFENCE */
+
+static inline bool is_kfence_address(const void *addr) { return false; }
+static inline void kfence_init(void) { }
+static inline bool __must_check kfence_shutdown_cache(struct kmem_cache *s) { return true; }
+static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
+static inline size_t kfence_ksize(const void *addr) { return 0; }
+static inline void *kfence_object_start(const void *addr) { return NULL; }
+static inline bool __must_check kfence_free(void *addr) { return false; }
+static inline bool __must_check kfence_handle_page_fault(unsigned long addr) { return false; }
+
+#endif
+
+#endif /* _LINUX_KFENCE_H */
diff --git a/init/main.c b/init/main.c
index ae78fb68d231..ec7de9dc1ed8 100644
--- a/init/main.c
+++ b/init/main.c
@@ -39,6 +39,7 @@
 #include <linux/security.h>
 #include <linux/smp.h>
 #include <linux/profile.h>
+#include <linux/kfence.h>
 #include <linux/rcupdate.h>
 #include <linux/moduleparam.h>
 #include <linux/kallsyms.h>
@@ -942,6 +943,7 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
 	hrtimers_init();
 	softirq_init();
 	timekeeping_init();
+	kfence_init();
 
 	/*
 	 * For best initial stack canary entropy, prepare it after:
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index e068c3c7189a..d09c6a306532 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -880,6 +880,7 @@ config DEBUG_STACKOVERFLOW
 	  If in doubt, say "N".
 
 source "lib/Kconfig.kasan"
+source "lib/Kconfig.kfence"
 
 endmenu # "Memory Debugging"
 
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
new file mode 100644
index 000000000000..4c2ea1c722de
--- /dev/null
+++ b/lib/Kconfig.kfence
@@ -0,0 +1,63 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+config HAVE_ARCH_KFENCE
+	bool
+
+config HAVE_ARCH_KFENCE_STATIC_POOL
+	bool
+	help
+	  If the architecture supports using the static pool.
+
+menuconfig KFENCE
+	bool "KFENCE: low-overhead sampling-based memory safety error detector"
+	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
+	depends on JUMP_LABEL # To ensure performance, require jump labels
+	select STACKTRACE
+	help
+	  KFENCE is low-overhead sampling-based detector for heap out-of-bounds
+	  access, use-after-free, and invalid-free errors. KFENCE is designed
+	  to have negligible cost to permit enabling it in production
+	  environments.
+
+	  Note that, KFENCE is not a substitute for explicit testing with tools
+	  such as KASAN. KFENCE can detect a subset of bugs that KASAN can
+	  detect, albeit at very different performance profiles. If you can
+	  afford to use KASAN, continue using KASAN, for example in test
+	  environments. If your kernel targets production use, and cannot
+	  enable KASAN due to its cost, consider using KFENCE.
+
+if KFENCE
+
+config KFENCE_SAMPLE_INTERVAL
+	int "Default sample interval in milliseconds"
+	default 100
+	help
+	  The KFENCE sample interval determines the frequency with which heap
+	  allocations will be guarded by KFENCE. May be overridden via boot
+	  parameter "kfence.sample_interval".
+
+	  Set this to 0 to disable KFENCE by default, in which case only
+	  setting "kfence.sample_interval" to a non-zero value enables KFENCE.
+
+config KFENCE_NUM_OBJECTS
+	int "Number of guarded objects available"
+	default 255
+	range 1 16383
+	help
+	  The number of guarded objects available. For each KFENCE object, 2
+	  pages are required; with one containing the object and two adjacent
+	  ones used as guard pages.
+
+config KFENCE_STRESS_TEST_FAULTS
+	int "Stress testing of fault handling and error reporting"
+	default 0
+	depends on EXPERT
+	help
+	  The inverse probability with which to randomly protect KFENCE object
+	  pages, resulting in spurious use-after-frees. The main purpose of
+	  this option is to stress test KFENCE with concurrent error reports
+	  and allocations/frees. A value of 0 disables stress testing logic.
+
+	  The option is only to test KFENCE; set to 0 if you are unsure.
+
+endif # KFENCE
diff --git a/mm/Makefile b/mm/Makefile
index d5649f1c12c0..afdf1ae0900b 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -81,6 +81,7 @@ obj-$(CONFIG_PAGE_POISONING) += page_poison.o
 obj-$(CONFIG_SLAB) += slab.o
 obj-$(CONFIG_SLUB) += slub.o
 obj-$(CONFIG_KASAN)	+= kasan/
+obj-$(CONFIG_KFENCE) += kfence/
 obj-$(CONFIG_FAILSLAB) += failslab.o
 obj-$(CONFIG_MEMORY_HOTPLUG) += memory_hotplug.o
 obj-$(CONFIG_MEMTEST)		+= memtest.o
diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
new file mode 100644
index 000000000000..d991e9a349f0
--- /dev/null
+++ b/mm/kfence/Makefile
@@ -0,0 +1,3 @@
+# SPDX-License-Identifier: GPL-2.0
+
+obj-$(CONFIG_KFENCE) := core.o report.o
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
new file mode 100644
index 000000000000..938da1648304
--- /dev/null
+++ b/mm/kfence/core.c
@@ -0,0 +1,733 @@
+// SPDX-License-Identifier: GPL-2.0
+
+#define pr_fmt(fmt) "kfence: " fmt
+
+#include <linux/atomic.h>
+#include <linux/bug.h>
+#include <linux/debugfs.h>
+#include <linux/kcsan-checks.h>
+#include <linux/kfence.h>
+#include <linux/list.h>
+#include <linux/lockdep.h>
+#include <linux/moduleparam.h>
+#include <linux/random.h>
+#include <linux/rcupdate.h>
+#include <linux/seq_file.h>
+#include <linux/slab.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+
+#include <asm/kfence.h>
+
+#include "kfence.h"
+
+/* Disables KFENCE on the first warning assuming an irrecoverable error. */
+#define KFENCE_WARN_ON(cond)                                                   \
+	({                                                                     \
+		const bool __cond = WARN_ON(cond);                             \
+		if (unlikely(__cond))                                          \
+			WRITE_ONCE(kfence_enabled, false);                     \
+		__cond;                                                        \
+	})
+
+#ifndef CONFIG_KFENCE_STRESS_TEST_FAULTS /* Only defined with CONFIG_EXPERT. */
+#define CONFIG_KFENCE_STRESS_TEST_FAULTS 0
+#endif
+
+/* === Data ================================================================= */
+
+static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
+
+#ifdef MODULE_PARAM_PREFIX
+#undef MODULE_PARAM_PREFIX
+#endif
+#define MODULE_PARAM_PREFIX "kfence."
+module_param_named(sample_interval, kfence_sample_interval, ulong, 0600);
+
+static bool kfence_enabled __read_mostly;
+
+/*
+ * The pool of pages used for guard pages and objects. If supported, allocated
+ * statically, so that is_kfence_address() avoids a pointer load, and simply
+ * compares against a constant address. Assume that if KFENCE is compiled into
+ * the kernel, it is usually enabled, and the space is to be allocated one way
+ * or another.
+ */
+#ifdef CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL
+char __kfence_pool[KFENCE_POOL_SIZE] __kfence_pool_attrs;
+#else
+char *__kfence_pool __read_mostly;
+#endif
+EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
+
+/*
+ * Per-object metadata, with one-to-one mapping of object metadata to
+ * backing pages (in __kfence_pool).
+ */
+static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
+struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+
+/* Freelist with available objects. */
+static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
+static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+
+/* The static key to set up a KFENCE allocation. */
+DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
+
+/* Gates the allocation, ensuring only one succeeds in a given period. */
+static atomic_t allocation_gate = ATOMIC_INIT(1);
+
+/* Wait queue to wake up allocation-gate timer task. */
+static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
+
+/* Statistics counters for debugfs. */
+enum kfence_counter_id {
+	KFENCE_COUNTER_ALLOCATED,
+	KFENCE_COUNTER_ALLOCS,
+	KFENCE_COUNTER_FREES,
+	KFENCE_COUNTER_BUGS,
+	KFENCE_COUNTER_COUNT,
+};
+static atomic_long_t counters[KFENCE_COUNTER_COUNT];
+static const char *const counter_names[] = {
+	[KFENCE_COUNTER_ALLOCATED]	= "currently allocated",
+	[KFENCE_COUNTER_ALLOCS]		= "total allocations",
+	[KFENCE_COUNTER_FREES]		= "total frees",
+	[KFENCE_COUNTER_BUGS]		= "total bugs",
+};
+static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
+
+/* === Internals ============================================================ */
+
+static bool kfence_protect(unsigned long addr)
+{
+	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
+}
+
+static bool kfence_unprotect(unsigned long addr)
+{
+	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false));
+}
+
+static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
+{
+	long index;
+
+	/* The checks do not affect performance; only called from slow-paths. */
+
+	if (!is_kfence_address((void *)addr))
+		return NULL;
+
+	/*
+	 * May be an invalid index if called with an address at the edge of
+	 * __kfence_pool, in which case we would report an "invalid access"
+	 * error.
+	 */
+	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
+	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
+		return NULL;
+
+	return &kfence_metadata[index];
+}
+
+static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
+{
+	unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
+	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
+
+	/* The checks do not affect performance; only called from slow-paths. */
+
+	/* Only call with a pointer into kfence_metadata. */
+	if (KFENCE_WARN_ON(meta < kfence_metadata ||
+			   meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
+		return 0;
+
+	/*
+	 * This metadata object only ever maps to 1 page; verify the calculation
+	 * happens and that the stored address was not corrupted.
+	 */
+	if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
+		return 0;
+
+	return pageaddr;
+}
+
+/*
+ * Update the object's metadata state, including updating the alloc/free stacks
+ * depending on the state transition.
+ */
+static noinline void metadata_update_state(struct kfence_metadata *meta,
+					   enum kfence_object_state next)
+{
+	unsigned long *entries = next == KFENCE_OBJECT_FREED ? meta->free_stack : meta->alloc_stack;
+	/*
+	 * Skip over 1 (this) functions; noinline ensures we do not accidentally
+	 * skip over the caller by never inlining.
+	 */
+	const int nentries = stack_trace_save(entries, KFENCE_STACK_DEPTH, 1);
+
+	lockdep_assert_held(&meta->lock);
+
+	if (next == KFENCE_OBJECT_FREED)
+		meta->num_free_stack = nentries;
+	else
+		meta->num_alloc_stack = nentries;
+
+	/*
+	 * Pairs with READ_ONCE() in
+	 *	kfence_shutdown_cache(),
+	 *	kfence_handle_page_fault().
+	 */
+	WRITE_ONCE(meta->state, next);
+}
+
+/* Write canary byte to @addr. */
+static inline bool set_canary_byte(u8 *addr)
+{
+	*addr = KFENCE_CANARY_PATTERN(addr);
+	return true;
+}
+
+/* Check canary byte at @addr. */
+static inline bool check_canary_byte(u8 *addr)
+{
+	if (*addr == KFENCE_CANARY_PATTERN(addr))
+		return true;
+
+	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
+	kfence_report_error((unsigned long)addr, addr_to_metadata((unsigned long)addr),
+			    KFENCE_ERROR_CORRUPTION);
+	return false;
+}
+
+static inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
+{
+	unsigned long addr;
+
+	lockdep_assert_held(&meta->lock);
+
+	for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
+		if (!fn((u8 *)addr))
+			break;
+	}
+
+	for (addr = meta->addr + meta->size; addr < PAGE_ALIGN(meta->addr); addr++) {
+		if (!fn((u8 *)addr))
+			break;
+	}
+}
+
+static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
+{
+	struct kfence_metadata *meta = NULL;
+	unsigned long flags;
+	void *addr;
+
+	/* Try to obtain a free object. */
+	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
+	if (!list_empty(&kfence_freelist)) {
+		meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
+		list_del_init(&meta->list);
+	}
+	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
+	if (!meta)
+		return NULL;
+
+	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
+		/*
+		 * This is extremely unlikely -- we are reporting on a
+		 * use-after-free, which locked meta->lock, and the reporting
+		 * code via printk calls kmalloc() which ends up in
+		 * kfence_alloc() and tries to grab the same object that we're
+		 * reporting on. While it has never been observed, lockdep does
+		 * report that there is a possibility of deadlock. Fix it by
+		 * using trylock and bailing out gracefully.
+		 */
+		raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
+		/* Put the object back on the freelist. */
+		list_add_tail(&meta->list, &kfence_freelist);
+		raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
+
+		return NULL;
+	}
+
+	meta->addr = metadata_to_pageaddr(meta);
+	/* Unprotect if we're reusing this page. */
+	if (meta->state == KFENCE_OBJECT_FREED)
+		kfence_unprotect(meta->addr);
+
+	/*
+	 * Note: for allocations made before RNG initialization, will always
+	 * return zero. We still benefit from enabling KFENCE as early as
+	 * possible, even when the RNG is not yet available, as this will allow
+	 * KFENCE to detect bugs due to earlier allocations. The only downside
+	 * is that the out-of-bounds accesses detected are deterministic for
+	 * such allocations.
+	 */
+	if (prandom_u32_max(2)) {
+		/* Allocate on the "right" side, re-calculate address. */
+		meta->addr += PAGE_SIZE - size;
+		meta->addr = ALIGN_DOWN(meta->addr, cache->align);
+	}
+
+	/* Update remaining metadata. */
+	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
+	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
+	WRITE_ONCE(meta->cache, cache);
+	meta->size = size;
+	for_each_canary(meta, set_canary_byte);
+	virt_to_page(meta->addr)->slab_cache = cache;
+
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
+
+	/* Memory initialization. */
+
+	/*
+	 * We check slab_want_init_on_alloc() ourselves, rather than letting
+	 * SL*B do the initialization, as otherwise we might overwrite KFENCE's
+	 * redzone.
+	 */
+	addr = (void *)meta->addr;
+	if (unlikely(slab_want_init_on_alloc(gfp, cache)))
+		memzero_explicit(addr, size);
+	if (cache->ctor)
+		cache->ctor(addr);
+
+	if (CONFIG_KFENCE_STRESS_TEST_FAULTS && !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS))
+		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */
+
+	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCATED]);
+	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCS]);
+
+	return addr;
+}
+
+static void kfence_guarded_free(void *addr, struct kfence_metadata *meta)
+{
+	struct kcsan_scoped_access assert_page_exclusive;
+	unsigned long flags;
+
+	raw_spin_lock_irqsave(&meta->lock, flags);
+
+	if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
+		/* Invalid or double-free, bail out. */
+		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
+		kfence_report_error((unsigned long)addr, meta, KFENCE_ERROR_INVALID_FREE);
+		raw_spin_unlock_irqrestore(&meta->lock, flags);
+		return;
+	}
+
+	/* Detect racy use-after-free, or incorrect reallocation of this page by KFENCE. */
+	kcsan_begin_scoped_access((void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE), PAGE_SIZE,
+				  KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT,
+				  &assert_page_exclusive);
+
+	if (CONFIG_KFENCE_STRESS_TEST_FAULTS)
+		kfence_unprotect((unsigned long)addr); /* To check canary bytes. */
+
+	/* Restore page protection if there was an OOB access. */
+	if (meta->unprotected_page) {
+		kfence_protect(meta->unprotected_page);
+		meta->unprotected_page = 0;
+	}
+
+	/* Check canary bytes for memory corruption. */
+	for_each_canary(meta, check_canary_byte);
+
+	/*
+	 * Clear memory if init-on-free is set. While we protect the page, the
+	 * data is still there, and after a use-after-free is detected, we
+	 * unprotect the page, so the data is still accessible.
+	 */
+	if (unlikely(slab_want_init_on_free(meta->cache)))
+		memzero_explicit(addr, meta->size);
+
+	/* Mark the object as freed. */
+	metadata_update_state(meta, KFENCE_OBJECT_FREED);
+
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
+
+	/* Protect to detect use-after-frees. */
+	kfence_protect((unsigned long)addr);
+
+	/* Add it to the tail of the freelist for reuse. */
+	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
+	KFENCE_WARN_ON(!list_empty(&meta->list));
+	list_add_tail(&meta->list, &kfence_freelist);
+	kcsan_end_scoped_access(&assert_page_exclusive);
+	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
+
+	atomic_long_dec(&counters[KFENCE_COUNTER_ALLOCATED]);
+	atomic_long_inc(&counters[KFENCE_COUNTER_FREES]);
+}
+
+static void rcu_guarded_free(struct rcu_head *h)
+{
+	struct kfence_metadata *meta = container_of(h, struct kfence_metadata, rcu_head);
+
+	kfence_guarded_free((void *)meta->addr, meta);
+}
+
+static bool __init kfence_initialize_pool(void)
+{
+	unsigned long addr;
+	struct page *pages;
+	int i;
+
+	if (!arch_kfence_initialize_pool())
+		return false;
+
+	addr = (unsigned long)__kfence_pool;
+	pages = virt_to_page(addr);
+
+	/*
+	 * Set up object pages: they must have PG_slab set, to avoid freeing
+	 * these as real pages.
+	 *
+	 * We also want to avoid inserting kfence_free() in the kfree()
+	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
+	 * enters __slab_free() slow-path.
+	 */
+	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
+		if (!i || (i % 2))
+			continue;
+
+		__SetPageSlab(&pages[i]);
+	}
+
+	/*
+	 * Protect the first 2 pages. The first page is mostly unnecessary, and
+	 * merely serves as an extended guard page. However, adding one
+	 * additional page in the beginning gives us an even number of pages,
+	 * which simplifies the mapping of address to metadata index.
+	 */
+	for (i = 0; i < 2; i++) {
+		if (unlikely(!kfence_protect(addr)))
+			return false;
+
+		addr += PAGE_SIZE;
+	}
+
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		struct kfence_metadata *meta = &kfence_metadata[i];
+
+		/* Initialize metadata. */
+		INIT_LIST_HEAD(&meta->list);
+		raw_spin_lock_init(&meta->lock);
+		meta->state = KFENCE_OBJECT_UNUSED;
+		meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
+		list_add_tail(&meta->list, &kfence_freelist);
+
+		/* Protect the right redzone. */
+		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
+			return false;
+
+		addr += 2 * PAGE_SIZE;
+	}
+
+	return true;
+}
+
+/* === DebugFS Interface ==================================================== */
+
+static int stats_show(struct seq_file *seq, void *v)
+{
+	int i;
+
+	seq_printf(seq, "enabled: %i\n", READ_ONCE(kfence_enabled));
+	for (i = 0; i < KFENCE_COUNTER_COUNT; i++)
+		seq_printf(seq, "%s: %ld\n", counter_names[i], atomic_long_read(&counters[i]));
+
+	return 0;
+}
+DEFINE_SHOW_ATTRIBUTE(stats);
+
+/*
+ * debugfs seq_file operations for /sys/kernel/debug/kfence/objects.
+ * start_object() and next_object() return the object index + 1, because NULL is used
+ * to stop iteration.
+ */
+static void *start_object(struct seq_file *seq, loff_t *pos)
+{
+	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
+		return (void *)((long)*pos + 1);
+	return NULL;
+}
+
+static void stop_object(struct seq_file *seq, void *v)
+{
+}
+
+static void *next_object(struct seq_file *seq, void *v, loff_t *pos)
+{
+	++*pos;
+	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
+		return (void *)((long)*pos + 1);
+	return NULL;
+}
+
+static int show_object(struct seq_file *seq, void *v)
+{
+	struct kfence_metadata *meta = &kfence_metadata[(long)v - 1];
+	unsigned long flags;
+
+	raw_spin_lock_irqsave(&meta->lock, flags);
+	kfence_print_object(seq, meta);
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
+	seq_puts(seq, "---------------------------------\n");
+
+	return 0;
+}
+
+static const struct seq_operations object_seqops = {
+	.start = start_object,
+	.next = next_object,
+	.stop = stop_object,
+	.show = show_object,
+};
+
+static int open_objects(struct inode *inode, struct file *file)
+{
+	return seq_open(file, &object_seqops);
+}
+
+static const struct file_operations objects_fops = {
+	.open = open_objects,
+	.read = seq_read,
+	.llseek = seq_lseek,
+};
+
+static int __init kfence_debugfs_init(void)
+{
+	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
+
+	debugfs_create_file("stats", 0444, kfence_dir, NULL, &stats_fops);
+	debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
+	return 0;
+}
+
+late_initcall(kfence_debugfs_init);
+
+/* === Allocation Gate Timer ================================================ */
+
+/*
+ * Set up delayed work, which will enable and disable the static key. We need to
+ * use a work queue (rather than a simple timer), since enabling and disabling a
+ * static key cannot be done from an interrupt.
+ */
+static struct delayed_work kfence_timer;
+static void toggle_allocation_gate(struct work_struct *work)
+{
+	if (!READ_ONCE(kfence_enabled))
+		return;
+
+	/* Enable static key, and await allocation to happen. */
+	atomic_set(&allocation_gate, 0);
+	static_branch_enable(&kfence_allocation_key);
+	wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
+
+	/* Disable static key and reset timer. */
+	static_branch_disable(&kfence_allocation_key);
+	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_interval));
+}
+static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
+
+/* === Public interface ===================================================== */
+
+void __init kfence_init(void)
+{
+	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
+	if (!kfence_sample_interval)
+		return;
+
+	if (!kfence_initialize_pool()) {
+		pr_err("%s failed\n", __func__);
+		return;
+	}
+
+	WRITE_ONCE(kfence_enabled, true);
+	schedule_delayed_work(&kfence_timer, 0);
+	pr_info("initialized - using %lu bytes for %d objects", KFENCE_POOL_SIZE,
+		CONFIG_KFENCE_NUM_OBJECTS);
+	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
+			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
+	else
+		pr_cont("\n");
+}
+
+bool kfence_shutdown_cache(struct kmem_cache *s)
+{
+	unsigned long flags;
+	struct kfence_metadata *meta;
+	int i;
+
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		bool in_use;
+
+		meta = &kfence_metadata[i];
+
+		/*
+		 * If we observe some inconsistent cache and state pair where we
+		 * should have returned false here, cache destruction is racing
+		 * with either kmem_cache_alloc() or kmem_cache_free(). Taking
+		 * the lock will not help, as different critical section
+		 * serialization will have the same outcome.
+		 */
+		if (READ_ONCE(meta->cache) != s ||
+		    READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
+			continue;
+
+		raw_spin_lock_irqsave(&meta->lock, flags);
+		in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
+		raw_spin_unlock_irqrestore(&meta->lock, flags);
+
+		if (in_use)
+			return false;
+	}
+
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		meta = &kfence_metadata[i];
+
+		/* See above. */
+		if (READ_ONCE(meta->cache) != s || READ_ONCE(meta->state) != KFENCE_OBJECT_FREED)
+			continue;
+
+		raw_spin_lock_irqsave(&meta->lock, flags);
+		if (meta->cache == s && meta->state == KFENCE_OBJECT_FREED)
+			meta->cache = NULL;
+		raw_spin_unlock_irqrestore(&meta->lock, flags);
+	}
+
+	return true;
+}
+
+void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
+{
+	/*
+	 * allocation_gate only needs to become non-zero, so it doesn't make
+	 * sense to continue writing to it and pay the associated contention
+	 * cost, in case we have a large number of concurrent allocations.
+	 */
+	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) > 1)
+		return NULL;
+	wake_up(&allocation_wait);
+
+	if (!READ_ONCE(kfence_enabled))
+		return NULL;
+
+	if (size > PAGE_SIZE)
+		return NULL;
+
+	return kfence_guarded_alloc(s, size, flags);
+}
+
+size_t kfence_ksize(const void *addr)
+{
+	const struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
+
+	/*
+	 * Read locklessly -- if there is a race with __kfence_alloc(), this is
+	 * either a use-after-free or invalid access.
+	 */
+	return meta ? meta->size : 0;
+}
+
+void *kfence_object_start(const void *addr)
+{
+	const struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
+
+	/*
+	 * Read locklessly -- if there is a race with __kfence_alloc(), this is
+	 * either a use-after-free or invalid access.
+	 */
+	return meta ? (void *)meta->addr : NULL;
+}
+
+void __kfence_free(void *addr)
+{
+	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
+
+	/*
+	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
+	 * the object, as the object page may be recycled for other-typed
+	 * objects once it has been freed.
+	 */
+	if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
+		call_rcu(&meta->rcu_head, rcu_guarded_free);
+	else
+		kfence_guarded_free(addr, meta);
+}
+
+bool kfence_handle_page_fault(unsigned long addr)
+{
+	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
+	struct kfence_metadata *to_report = NULL;
+	enum kfence_error_type error_type;
+	unsigned long flags;
+
+	if (!is_kfence_address((void *)addr))
+		return false;
+
+	if (!READ_ONCE(kfence_enabled)) /* If disabled at runtime ... */
+		return kfence_unprotect(addr); /* ... unprotect and proceed. */
+
+	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
+
+	if (page_index % 2) {
+		/* This is a redzone, report a buffer overflow. */
+		struct kfence_metadata *meta;
+		int distance = 0;
+
+		meta = addr_to_metadata(addr - PAGE_SIZE);
+		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
+			to_report = meta;
+			/* Data race ok; distance calculation approximate. */
+			distance = addr - data_race(meta->addr + meta->size);
+		}
+
+		meta = addr_to_metadata(addr + PAGE_SIZE);
+		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
+			/* Data race ok; distance calculation approximate. */
+			if (!to_report || distance > data_race(meta->addr) - addr)
+				to_report = meta;
+		}
+
+		if (!to_report)
+			goto out;
+
+		raw_spin_lock_irqsave(&to_report->lock, flags);
+		to_report->unprotected_page = addr;
+		error_type = KFENCE_ERROR_OOB;
+
+		/*
+		 * If the object was freed before we took the look we can still
+		 * report this as an OOB -- the report will simply show the
+		 * stacktrace of the free as well.
+		 */
+	} else {
+		to_report = addr_to_metadata(addr);
+		if (!to_report)
+			goto out;
+
+		raw_spin_lock_irqsave(&to_report->lock, flags);
+		error_type = KFENCE_ERROR_UAF;
+		/*
+		 * We may race with __kfence_alloc(), and it is possible that a
+		 * freed object may be reallocated. We simply report this as a
+		 * use-after-free, with the stack trace showing the place where
+		 * the object was re-allocated.
+		 */
+	}
+
+out:
+	if (to_report) {
+		kfence_report_error(addr, to_report, error_type);
+		raw_spin_unlock_irqrestore(&to_report->lock, flags);
+	} else {
+		/* This may be a UAF or OOB access, but we can't be sure. */
+		kfence_report_error(addr, NULL, KFENCE_ERROR_INVALID);
+	}
+
+	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
+}
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
new file mode 100644
index 000000000000..2f606a3f58b6
--- /dev/null
+++ b/mm/kfence/kfence.h
@@ -0,0 +1,102 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef MM_KFENCE_KFENCE_H
+#define MM_KFENCE_KFENCE_H
+
+#include <linux/mm.h>
+#include <linux/slab.h>
+#include <linux/spinlock.h>
+#include <linux/types.h>
+
+#include "../slab.h" /* for struct kmem_cache */
+
+/* For non-debug builds, avoid leaking kernel pointers into dmesg. */
+#ifdef CONFIG_DEBUG_KERNEL
+#define PTR_FMT "%px"
+#else
+#define PTR_FMT "%p"
+#endif
+
+/*
+ * Get the canary byte pattern for @addr. Use a pattern that varies based on the
+ * lower 3 bits of the address, to detect memory corruptions with higher
+ * probability, where similar constants are used.
+ */
+#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))
+
+/* Maximum stack depth for reports. */
+#define KFENCE_STACK_DEPTH 64
+
+/* KFENCE object states. */
+enum kfence_object_state {
+	KFENCE_OBJECT_UNUSED,		/* Object is unused. */
+	KFENCE_OBJECT_ALLOCATED,	/* Object is currently allocated. */
+	KFENCE_OBJECT_FREED,		/* Object was allocated, and then freed. */
+};
+
+/* KFENCE metadata per guarded allocation. */
+struct kfence_metadata {
+	struct list_head list;		/* Freelist node; access under kfence_freelist_lock. */
+	struct rcu_head rcu_head;	/* For delayed freeing. */
+
+	/*
+	 * Lock protecting below data; to ensure consistency of the below data,
+	 * since the following may execute concurrently: __kfence_alloc(),
+	 * __kfence_free(), kfence_handle_page_fault(). However, note that we
+	 * cannot grab the same metadata off the freelist twice, and multiple
+	 * __kfence_alloc() cannot run concurrently on the same metadata.
+	 */
+	raw_spinlock_t lock;
+
+	/* The current state of the object; see above. */
+	enum kfence_object_state state;
+
+	/*
+	 * Allocated object address; cannot be calculated from size, because of
+	 * alignment requirements.
+	 *
+	 * Invariant: ALIGN_DOWN(addr, PAGE_SIZE) is constant.
+	 */
+	unsigned long addr;
+
+	/*
+	 * The size of the original allocation.
+	 */
+	size_t size;
+
+	/*
+	 * The kmem_cache cache of the last allocation; NULL if never allocated
+	 * or the cache has already been destroyed.
+	 */
+	struct kmem_cache *cache;
+
+	/*
+	 * In case of an invalid access, the page that was unprotected; we
+	 * optimistically only store address.
+	 */
+	unsigned long unprotected_page;
+
+	/* Allocation and free stack information. */
+	int num_alloc_stack;
+	int num_free_stack;
+	unsigned long alloc_stack[KFENCE_STACK_DEPTH];
+	unsigned long free_stack[KFENCE_STACK_DEPTH];
+};
+
+extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+
+/* KFENCE error types for report generation. */
+enum kfence_error_type {
+	KFENCE_ERROR_OOB,		/* Detected a out-of-bounds access. */
+	KFENCE_ERROR_UAF,		/* Detected a use-after-free access. */
+	KFENCE_ERROR_CORRUPTION,	/* Detected a memory corruption on free. */
+	KFENCE_ERROR_INVALID,		/* Invalid access of unknown type. */
+	KFENCE_ERROR_INVALID_FREE,	/* Invalid free. */
+};
+
+void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
+			 enum kfence_error_type type);
+
+void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta);
+
+#endif /* MM_KFENCE_KFENCE_H */
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
new file mode 100644
index 000000000000..e6c6734ae859
--- /dev/null
+++ b/mm/kfence/report.c
@@ -0,0 +1,225 @@
+// SPDX-License-Identifier: GPL-2.0
+
+#include <stdarg.h>
+
+#include <linux/kernel.h>
+#include <linux/lockdep.h>
+#include <linux/printk.h>
+#include <linux/seq_file.h>
+#include <linux/stacktrace.h>
+#include <linux/string.h>
+
+#include <asm/kfence.h>
+
+#include "kfence.h"
+
+/* Helper function to either print to a seq_file or to console. */
+__printf(2, 3)
+static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	if (seq)
+		seq_vprintf(seq, fmt, args);
+	else
+		vprintk(fmt, args);
+	va_end(args);
+}
+
+/*
+ * Get the number of stack entries to skip get out of MM internals. @type is
+ * optional, and if set to NULL, assumes an allocation or free stack.
+ */
+static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries,
+			    const enum kfence_error_type *type)
+{
+	char buf[64];
+	int skipnr, fallback = 0;
+	bool is_access_fault = false;
+
+	if (type) {
+		/* Depending on error type, find different stack entries. */
+		switch (*type) {
+		case KFENCE_ERROR_UAF:
+		case KFENCE_ERROR_OOB:
+		case KFENCE_ERROR_INVALID:
+			is_access_fault = true;
+			break;
+		case KFENCE_ERROR_CORRUPTION:
+		case KFENCE_ERROR_INVALID_FREE:
+			break;
+		}
+	}
+
+	for (skipnr = 0; skipnr < num_entries; skipnr++) {
+		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
+
+		if (is_access_fault) {
+			if (!strncmp(buf, KFENCE_SKIP_ARCH_FAULT_HANDLER, len))
+				goto found;
+		} else {
+			if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") ||
+			    !strncmp(buf, "__slab_free", len)) {
+				/*
+				 * In case of tail calls from any of the below
+				 * to any of the above.
+				 */
+				fallback = skipnr + 1;
+			}
+
+			/* Also the *_bulk() variants by only checking prefixes. */
+			if (str_has_prefix(buf, "kfree") ||
+			    str_has_prefix(buf, "kmem_cache_free") ||
+			    str_has_prefix(buf, "__kmalloc") ||
+			    str_has_prefix(buf, "kmem_cache_alloc"))
+				goto found;
+		}
+	}
+	if (fallback < num_entries)
+		return fallback;
+found:
+	skipnr++;
+	return skipnr < num_entries ? skipnr : 0;
+}
+
+static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadata *meta,
+			       bool show_alloc)
+{
+	const unsigned long *entries = show_alloc ? meta->alloc_stack : meta->free_stack;
+	const int nentries = show_alloc ? meta->num_alloc_stack : meta->num_free_stack;
+
+	if (nentries) {
+		/* Skip allocation/free internals stack. */
+		int i = get_stack_skipnr(entries, nentries, NULL);
+
+		/* stack_trace_seq_print() does not exist; open code our own. */
+		for (; i < nentries; i++)
+			seq_con_printf(seq, " %pS\n", (void *)entries[i]);
+	} else {
+		seq_con_printf(seq, " no %s stack\n", show_alloc ? "allocation" : "deallocation");
+	}
+}
+
+void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta)
+{
+	const int size = abs(meta->size);
+	const unsigned long start = meta->addr;
+	const struct kmem_cache *const cache = meta->cache;
+
+	lockdep_assert_held(&meta->lock);
+
+	if (meta->state == KFENCE_OBJECT_UNUSED) {
+		seq_con_printf(seq, "kfence-#%zd unused\n", meta - kfence_metadata);
+		return;
+	}
+
+	seq_con_printf(seq,
+		       "kfence-#%zd [0x" PTR_FMT "-0x" PTR_FMT
+		       ", size=%d, cache=%s] allocated in:\n",
+		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
+		       (cache && cache->name) ? cache->name : "<destroyed>");
+	kfence_print_stack(seq, meta, true);
+
+	if (meta->state == KFENCE_OBJECT_FREED) {
+		seq_con_printf(seq, "\nfreed in:\n");
+		kfence_print_stack(seq, meta, false);
+	}
+}
+
+/*
+ * Show bytes at @addr that are different from the expected canary values, up to
+ * @max_bytes.
+ */
+static void print_diff_canary(const u8 *addr, size_t max_bytes)
+{
+	const u8 *max_addr = min((const u8 *)PAGE_ALIGN((unsigned long)addr), addr + max_bytes);
+
+	pr_cont("[");
+	for (; addr < max_addr; addr++) {
+		if (*addr == KFENCE_CANARY_PATTERN(addr))
+			pr_cont(" .");
+		else if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+			pr_cont(" 0x%02x", *addr);
+		else /* Do not leak kernel memory in non-debug builds. */
+			pr_cont(" !");
+	}
+	pr_cont(" ]");
+}
+
+void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
+			 enum kfence_error_type type)
+{
+	unsigned long stack_entries[KFENCE_STACK_DEPTH] = { 0 };
+	int num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 1);
+	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries, &type);
+	const ptrdiff_t object_index = meta ? meta - kfence_metadata : -1;
+
+	/* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
+	if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
+		return;
+
+	if (meta)
+		lockdep_assert_held(&meta->lock);
+	/*
+	 * Because we may generate reports in printk-unfriendly parts of the
+	 * kernel, such as scheduler code, the use of printk() could deadlock.
+	 * Until such time that all printing code here is safe in all parts of
+	 * the kernel, accept the risk, and just get our message out (given the
+	 * system might already behave unpredictably due to the memory error).
+	 * As such, also disable lockdep to hide warnings, and avoid disabling
+	 * lockdep for the rest of the kernel.
+	 */
+	lockdep_off();
+
+	pr_err("==================================================================\n");
+	/* Print report header. */
+	switch (type) {
+	case KFENCE_ERROR_OOB:
+		pr_err("BUG: KFENCE: out-of-bounds in %pS\n\n", (void *)stack_entries[skipnr]);
+		pr_err("Out-of-bounds access at 0x" PTR_FMT " (%s of kfence-#%zd):\n",
+		       (void *)address, address < meta->addr ? "left" : "right", object_index);
+		break;
+	case KFENCE_ERROR_UAF:
+		pr_err("BUG: KFENCE: use-after-free in %pS\n\n", (void *)stack_entries[skipnr]);
+		pr_err("Use-after-free access at 0x" PTR_FMT " (in kfence-#%zd):\n",
+		       (void *)address, object_index);
+		break;
+	case KFENCE_ERROR_CORRUPTION:
+		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
+		pr_err("Corrupted memory at 0x" PTR_FMT " ", (void *)address);
+		print_diff_canary((u8 *)address, 16);
+		pr_cont(" (in kfence-#%zd):\n", object_index);
+		break;
+	case KFENCE_ERROR_INVALID:
+		pr_err("BUG: KFENCE: invalid access in %pS\n\n", (void *)stack_entries[skipnr]);
+		pr_err("Invalid access at 0x" PTR_FMT ":\n", (void *)address);
+		break;
+	case KFENCE_ERROR_INVALID_FREE:
+		pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[skipnr]);
+		pr_err("Invalid free of 0x" PTR_FMT " (in kfence-#%zd):\n", (void *)address,
+		       object_index);
+		break;
+	}
+
+	/* Print stack trace and object info. */
+	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
+
+	if (meta) {
+		pr_err("\n");
+		kfence_print_object(NULL, meta);
+	}
+
+	/* Print report footer. */
+	pr_err("\n");
+	dump_stack_print_info(KERN_DEFAULT);
+	pr_err("==================================================================\n");
+
+	lockdep_on();
+
+	if (panic_on_warn)
+		panic("panic_on_warn set ...\n");
+
+	/* We encountered a memory unsafety error, taint the kernel! */
+	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
+}
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-2-elver%40google.com.
