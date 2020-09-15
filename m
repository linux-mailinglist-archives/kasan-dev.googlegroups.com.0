Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUP7QL5QKGQETRUUOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FAFC26A62F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:23 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id hr13sf2051864pjb.3
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176081; cv=pass;
        d=google.com; s=arc-20160816;
        b=G/bjZQwIUb0sWI2OkTbBhXndC3NvOPGko2UXUIq9XQp13oqDRNpTQ3AynLzmQr4X3l
         2Ul4mVre1B+0Us9+k8zR2P7yQUjKkeuukLVd+p+VEjgaPDqZq6kPMqziJAbkdmYLzf1a
         CxdflUB18QGEt3NMRd3c1HLol3NUkV+/3+jtDjoSa2Ag6RwGLHOxNPGcN6dk7ZPk+psf
         jLAo7bz3UnavLqn/BLoAThmZtcg3hj9fVmv9vL/Yk0b8q/mYgttIuaMByBBjlrgVNZPJ
         62K/zFoaIbI1Gxiy7Uas9ULQHwoVNlCRypXAWngKxFh+0bxk9iHtxCVlXbu+016Cl7Gr
         QGhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YK1lScTh+Etbd0BNbfKbNl/fxwkx4vRyr77I7Qo2tKk=;
        b=QYmcS2MxfpErJFrgK8VnWvwurMIhtl7dkReKrViXhKh59sGpjx6uPBc/kNxg5/q1Ji
         lXzV1n0l5UAnzeMg7tUbA4ig/ezeQjfOfsjV33bH+CJ9d16XHvXvgX+CvQn5NvBA5t8H
         MTaXflnLY1mPS4yTe7lZkldHH6WcJxFGP4i+4K7TDuLC6hJM+wSZDCk69Vc0cnzYHk09
         QSYcpN+8K+lqpV9NNo+YLERYacriUGxF3AAVN2wbTiG4r29LzYH8qc4S5FtHIOCviO2L
         VODx+IUwzrs5jwChPaJHE70a/iInD9YlLrCpnXFxcKb0Nn+y5fObMC7GLa6g3cLpoPni
         26jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YX+XKlf0;
       spf=pass (google.com: domain of 3z79gxwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3z79gXwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YK1lScTh+Etbd0BNbfKbNl/fxwkx4vRyr77I7Qo2tKk=;
        b=a0Iob/ga9n/hI4hw38YVDtAIT4MehX9c6EKGV91G85gbfvT0ZTS9/2sJXPG4BvHHry
         goN039S9QyYA/xw5NkDcwS7TLrGAN90x8yEWfAgJzgxXKXJOKUTs9HdDyl6JNKk8T+VD
         bh9U9+bYQF5tD6iz6EHsVDNlZ2Jwp7v4uCj1a4aNGrMG7qkwHQdslMQ06cu/L0Hb0apz
         YFYrbwDdWTm5m8JKbFSpgE8cFNXnSkuP9qjjlbL8gfbAhngFr0JMYxhcO3cfABT8zrRz
         M/GxfJoZ6ynys9y8zdl0VPsmhawLcpdkyA/rysfEI6b1xKWqU6ixyZeNZ2cnVbrYaIbv
         2yjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YK1lScTh+Etbd0BNbfKbNl/fxwkx4vRyr77I7Qo2tKk=;
        b=nlBB7l/8gZncl+ggH+wv9XWvxjzaShfezS9454FCcuWbE7ZgkyRKasqmBJNqZOQbyK
         +FChwIT5zs/mR8e6Ww1cXRHgkECsd9YbOZbq1MN2IbBBhFJsSTrxo84+c1ZIZZ1bJy4B
         b5BBXcqq16M5lqh3JFGQnr7muJerghS1WObxcJwJIYnTeDXF62I65qMDfsn5Ii8By4vh
         /G40dxngz/IorChwNuBPrF29iLx9lH1D49azFZ00ljqdOdizToRyDPCYJTp8PwCB9PfC
         C2gYdnRIsE1APNV1485+0yQvhIPSLX0dMCK4fjrgNfCfYiRh/fZH73qWAub9On+mNGK2
         P/pg==
X-Gm-Message-State: AOAM531K5aiWG+9FC6yerO9H6uZnpuA/qhCRFBoRaX0Ek4NkyAy2d+3F
	4NakMy+6EE46puv/m45vGlE=
X-Google-Smtp-Source: ABdhPJzOnyYi0eYr8oZExmsU0L705mjK7zsYC4Pmex/+O4MrojFlWQEcPmal4FuRJZDQUx82DBXRcQ==
X-Received: by 2002:a17:902:326:b029:d1:e5e7:be04 with SMTP id 35-20020a1709020326b02900d1e5e7be04mr1747279pld.55.1600176081423;
        Tue, 15 Sep 2020 06:21:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d704:: with SMTP id y4ls6116679pju.3.canary-gmail;
 Tue, 15 Sep 2020 06:21:20 -0700 (PDT)
X-Received: by 2002:a17:90b:368e:: with SMTP id mj14mr3888478pjb.220.1600176080685;
        Tue, 15 Sep 2020 06:21:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176080; cv=none;
        d=google.com; s=arc-20160816;
        b=vhcOEhRzND5+wISduK3T8x35CJqdU9yGkKlyyN7eEuE+F6sd6Re8LswWnNOeRJZS05
         UTXmqdrtDcr3hnqQkFvJ2AsnkXgx1Gja0UUEOei/dQi4m1BnveSc9CKxRg939wPBks+F
         6tyBPapCkbeKrLlDEa9FPjCHfmlsNAj2iMdNdAYLm87QR2fg0GF+MNyCs46l/55Fed5X
         VX3ZzN+txKdM6em6SLvYuh2RxXdwSyGszbOMvDidNXRMPfcnv/PADZAMf+v8XXdCoN6V
         RrE/FpH7oYJAmS5aynF2IsIcdWp3eDi4Sk65XFgrdxmsdzTTGKKmTd1E8ufkJFBu787T
         uDSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mEwEXR2gCavtjq/sIohBdyoQVSXL94/GwEz2BKjsc+U=;
        b=FC8tfRQEYRz+5gR6smjZHGIzB6Iq3LsqXJRVy8NGtbdrW5EpsUb8yRTAYvdhaW+Bsm
         Hi+vb1Uoji3pacKRa/drcxT/InWdThlZRRmBMSVtuZBxlCU1fcwgu4vBwO5BP+t/OTTa
         UV/3T14BYHIP/k8DBNhP4L05jPQ3RmJxyKTwjhAWwxKMhDVuAKpfFaS0W50cwwfsu3wJ
         sVshdYcyEIEflIF0RxZy+A1zZc2IuwoEZhEP7auGnMtkUxFEQfQrqFZfv9oMjeIerdmW
         Pxceg7RO2iWrReZ6d9h1N0m1W4cWrvR5Dths3yXfo5/JGsU/YZ0yGAw5MJN9FmlxysHL
         hYuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YX+XKlf0;
       spf=pass (google.com: domain of 3z79gxwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3z79gXwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id w15si77538pfu.6.2020.09.15.06.21.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z79gxwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id t4so2090253qvr.21
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:20 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:f109:: with SMTP id i9mr1643861qvl.43.1600176079904;
 Tue, 15 Sep 2020 06:21:19 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:45 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-10-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 09/10] kfence, Documentation: add KFENCE documentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com, 
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org, 
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, vbabka@suse.cz, 
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YX+XKlf0;       spf=pass
 (google.com: domain of 3z79gxwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3z79gXwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Add KFENCE documentation in dev-tools/kfence.rst, and add to index.

Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Many clarifications based on comments from Andrey Konovalov.
* Document CONFIG_KFENCE_SAMPLE_INTERVAL=0 usage.
* Make use-cases between KASAN and KFENCE clearer.
* Be clearer about the fact the pool is fixed size.
* Update based on reporting changes.
* Explicitly mention max supported allocation size is PAGE_SIZE.
---
 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 291 +++++++++++++++++++++++++++++
 2 files changed, 292 insertions(+)
 create mode 100644 Documentation/dev-tools/kfence.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index f7809c7b1ba9..1b1cf4f5c9d9 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -22,6 +22,7 @@ whole; patches welcome!
    ubsan
    kmemleak
    kcsan
+   kfence
    gdb-kernel-debugging
    kgdb
    kselftest
diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
new file mode 100644
index 000000000000..efe86b1b1074
--- /dev/null
+++ b/Documentation/dev-tools/kfence.rst
@@ -0,0 +1,291 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+Kernel Electric-Fence (KFENCE)
+==============================
+
+Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
+error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
+invalid-free errors.
+
+KFENCE is designed to be enabled in production kernels, and has near zero
+performance overhead. Compared to KASAN, KFENCE trades performance for
+precision. The main motivation behind KFENCE's design, is that with enough
+total uptime KFENCE will detect bugs in code paths not typically exercised by
+non-production test workloads. One way to quickly achieve a large enough total
+uptime is when the tool is deployed across a large fleet of machines.
+
+Usage
+-----
+
+To enable KFENCE, configure the kernel with::
+
+    CONFIG_KFENCE=y
+
+To build a kernel with KFENCE support, but disabled by default (to enable, set
+``kfence.sample_interval`` to non-zero value), configure the kernel with::
+
+    CONFIG_KFENCE=y
+    CONFIG_KFENCE_SAMPLE_INTERVAL=0
+
+KFENCE provides several other configuration options to customize behaviour (see
+the respective help text in ``lib/Kconfig.kfence`` for more info).
+
+Tuning performance
+~~~~~~~~~~~~~~~~~~
+
+The most important parameter is KFENCE's sample interval, which can be set via
+the kernel boot parameter ``kfence.sample_interval`` in milliseconds. The
+sample interval determines the frequency with which heap allocations will be
+guarded by KFENCE. The default is configurable via the Kconfig option
+``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
+disables KFENCE.
+
+The KFENCE memory pool is of fixed size, and if the pool is exhausted, no
+further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` (default
+255), the number of available guarded objects can be controlled. Each object
+requires 2 pages, one for the object itself and the other one used as a guard
+page; object pages are interleaved with guard pages, and every object page is
+therefore surrounded by two guard pages.
+
+The total memory dedicated to the KFENCE memory pool can be computed as::
+
+    ( #objects + 1 ) * 2 * PAGE_SIZE
+
+Using the default config, and assuming a page size of 4 KiB, results in
+dedicating 2 MiB to the KFENCE memory pool.
+
+Error reports
+~~~~~~~~~~~~~
+
+A typical out-of-bounds access looks like this::
+
+    ==================================================================
+    BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0xa3/0x22b
+
+    Out-of-bounds access at 0xffffffffb672efff (left of kfence-#17):
+     test_out_of_bounds_read+0xa3/0x22b
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated in:
+     test_alloc+0xf3/0x25b
+     test_out_of_bounds_read+0x98/0x22b
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    ==================================================================
+
+The header of the report provides a short summary of the function involved in
+the access. It is followed by more detailed information about the access and
+its origin. Note that, real kernel addresses are only shown for
+``CONFIG_DEBUG_KERNEL=y`` builds.
+
+Use-after-free accesses are reported as::
+
+    ==================================================================
+    BUG: KFENCE: use-after-free in test_use_after_free_read+0xb3/0x143
+
+    Use-after-free access at 0xffffffffb673dfe0 (in kfence-#24):
+     test_use_after_free_read+0xb3/0x143
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated in:
+     test_alloc+0xf3/0x25b
+     test_use_after_free_read+0x76/0x143
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    freed in:
+     test_use_after_free_read+0xa8/0x143
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    ==================================================================
+
+KFENCE also reports on invalid frees, such as double-frees::
+
+    ==================================================================
+    BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
+
+    Invalid free of 0xffffffffb6741000:
+     test_double_free+0xdc/0x171
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated in:
+     test_alloc+0xf3/0x25b
+     test_double_free+0x76/0x171
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    freed in:
+     test_double_free+0xa8/0x171
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    ==================================================================
+
+KFENCE also uses pattern-based redzones on the other side of an object's guard
+page, to detect out-of-bounds writes on the unprotected side of the object.
+These are reported on frees::
+
+    ==================================================================
+    BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/0x184
+
+    Corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ] (in kfence-#69):
+     test_kmalloc_aligned_oob_write+0xef/0x184
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated in:
+     test_alloc+0xf3/0x25b
+     test_kmalloc_aligned_oob_write+0x57/0x184
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    ==================================================================
+
+For such errors, the address where the corruption as well as the invalidly
+written bytes (offset from the address) are shown; in this representation, '.'
+denote untouched bytes. In the example above ``0xac`` is the value written to
+the invalid address at offset 0, and the remaining '.' denote that no following
+bytes have been touched. Note that, real values are only shown for
+``CONFIG_DEBUG_KERNEL=y`` builds; to avoid information disclosure for non-debug
+builds, '!' is used instead to denote invalidly written bytes.
+
+And finally, KFENCE may also report on invalid accesses to any protected page
+where it was not possible to determine an associated object, e.g. if adjacent
+object pages had not yet been allocated::
+
+    ==================================================================
+    BUG: KFENCE: invalid access in test_invalid_access+0x26/0xe0
+
+    Invalid access at 0xffffffffb670b00a:
+     test_invalid_access+0x26/0xe0
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    CPU: 4 PID: 124 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    ==================================================================
+
+DebugFS interface
+~~~~~~~~~~~~~~~~~
+
+Some debugging information is exposed via debugfs:
+
+* The file ``/sys/kernel/debug/kfence/stats`` provides runtime statistics.
+
+* The file ``/sys/kernel/debug/kfence/objects`` provides a list of objects
+  allocated via KFENCE, including those already freed but protected.
+
+Implementation Details
+----------------------
+
+Guarded allocations are set up based on the sample interval. After expiration
+of the sample interval, the next allocation through the main allocator (SLAB or
+SLUB) returns a guarded allocation from the KFENCE object pool (allocation
+sizes up to PAGE_SIZE are supported). At this point, the timer is reset, and
+the next allocation is set up after the expiration of the interval. To "gate" a
+KFENCE allocation through the main allocator's fast-path without overhead,
+KFENCE relies on static branches via the static keys infrastructure. The static
+branch is toggled to redirect the allocation to KFENCE.
+
+KFENCE objects each reside on a dedicated page, at either the left or right
+page boundaries selected at random. The pages to the left and right of the
+object page are "guard pages", whose attributes are changed to a protected
+state, and cause page faults on any attempted access. Such page faults are then
+intercepted by KFENCE, which handles the fault gracefully by reporting an
+out-of-bounds access.
+
+To detect out-of-bounds writes to memory within the object's page itself,
+KFENCE also uses pattern-based redzones. For each object page, a redzone is set
+up for all non-object memory. For typical alignments, the redzone is only
+required on the unguarded side of an object. Because KFENCE must honor the
+cache's requested alignment, special alignments may result in unprotected gaps
+on either side of an object, all of which are redzoned.
+
+The following figure illustrates the page layout::
+
+    ---+-----------+-----------+-----------+-----------+-----------+---
+       | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
+       | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
+       | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
+       | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
+       | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
+       | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
+    ---+-----------+-----------+-----------+-----------+-----------+---
+
+Upon deallocation of a KFENCE object, the object's page is again protected and
+the object is marked as freed. Any further access to the object causes a fault
+and KFENCE reports a use-after-free access. Freed objects are inserted at the
+tail of KFENCE's freelist, so that the least recently freed objects are reused
+first, and the chances of detecting use-after-frees of recently freed objects
+is increased.
+
+Interface
+---------
+
+The following describes the functions which are used by allocators as well page
+handling code to set up and deal with KFENCE allocations.
+
+.. kernel-doc:: include/linux/kfence.h
+   :functions: is_kfence_address
+               kfence_shutdown_cache
+               kfence_alloc kfence_free
+               kfence_ksize kfence_object_start
+               kfence_handle_page_fault
+
+Related Tools
+-------------
+
+In userspace, a similar approach is taken by `GWP-ASan
+<http://llvm.org/docs/GwpAsan.html>`_. GWP-ASan also relies on guard pages and
+a sampling strategy to detect memory unsafety bugs at scale. KFENCE's design is
+directly influenced by GWP-ASan, and can be seen as its kernel sibling. Another
+similar but non-sampling approach, that also inspired the name "KFENCE", can be
+found in the userspace `Electric Fence Malloc Debugger
+<https://linux.die.net/man/3/efence>`_.
+
+In the kernel, several tools exist to debug memory access errors, and in
+particular KASAN can detect all bug classes that KFENCE can detect. While KASAN
+is more precise, relying on compiler instrumentation, this comes at a
+performance cost.
+
+It is worth highlighting that KASAN and KFENCE are complementary, with
+different target environments. For instance, KASAN is the better debugging-aid,
+where test cases or reproducers exists: due to the lower chance to detect the
+error, it would require more effort using KFENCE to debug. Deployments at scale
+that cannot afford to enable KASAN, however, would benefit from using KFENCE to
+discover bugs due to code paths not exercised by test cases or fuzzers.
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-10-elver%40google.com.
