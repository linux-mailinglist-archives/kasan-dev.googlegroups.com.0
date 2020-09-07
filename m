Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDPR3D5AKGQE5L44HDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3B8725FB94
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:33 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id c198sf3981903wme.5
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486093; cv=pass;
        d=google.com; s=arc-20160816;
        b=WMz/JtvlwL+ks8F4cgHkM7Tc60ZXtjNjA/05yJx7VPtx2I5FgyuYbfoPKA/idR+AIU
         g9mJc00LF7bq9YOc9aukAMWELXx9eVGri19sg3eNla7FaOwWMmflImxdzvndrZHYw4uu
         rR2reIjUYBlQ1HkHkzJZifp4qTlAtLh31r5bSFUTIX5hHrmhh4oVj9kdA4QHXyUVTXon
         i/rc4xA+RFRqcZX6DHQcPUmryP9t16qc+6NzyHqX7mmGI8/FA1cOiICQuLNEVADfN1pl
         lRqAPnvpxJyp4iVM1IVHKDLmXlgE5kA/Vh6l5HYeoOQ1T83htt6lhAk2CHT9+1VOaWju
         FlGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=diuHi2R2kCrqfENqiz7Aj7Ya2R962maiozsf1sv4Ha4=;
        b=LoS3Q1iXdXHmTIrHHMWwaJAZs0spLK3h2CGgoy+VTLyLPAy7sD+p3WPgrIrpSbe6cI
         v5xGsUWyQvN3o0ifpiaySu0iEegYj1p3xvpIWnBCr37hmLXwHotVrZIQEQ00TfvuRv83
         ssNfUlBR8pxn5VLMmVp6c6PFLMSmNRpstekJ/XOBEJyyPXili9GfGXtGqUSv7cV+LVy5
         YGFhTAjx1/Z5El8R7zYgOOeXr/GlOzWdjUS+kVL6tDAggPZdGNvqZ9MWuUcVRIIH1ZNu
         cz/YIZ5/59ZDur//uaqhusdWOQNPhfnOD7KEYNHT55eDHHMIpctEgnx/FPCcwmPGudVn
         43Hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ALL9RpQB;
       spf=pass (google.com: domain of 3jdhwxwukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jDhWXwUKCVc3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=diuHi2R2kCrqfENqiz7Aj7Ya2R962maiozsf1sv4Ha4=;
        b=YLhv8/vZIi65OMl5LFWUpZcVEKrniiDKsz+tDXKKVmXM3C2xw9JqyuhUlKB0/ArjZp
         tFhqAU6JDTUGxOUarDa4m111rhdp8MpVVhC8RVoV+z9LruMF0s9beNHBvsd6bRZ/EpL9
         ySxnIiByAzhmw9zLGmIWZMrBmLlTuyG+IkARBWomdKENou+53aqAhnZPih6JBr+cTjrM
         T3cQcThrJzGnCk6c2tAAWuOZZwTMleRTtrX/3uBfInBZZqmCAl8T5UxTD0tUMDL5Krbe
         hBOyJMt6LE6Z7d7GP2t2ziS1X86JdkAorAgdGHQyHWQgKqEpr6d0Fn8Dx+WxnYLdB5vs
         PNNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=diuHi2R2kCrqfENqiz7Aj7Ya2R962maiozsf1sv4Ha4=;
        b=jq1yqycfsnfnnTG3JNYqpHvTahCSmjJaFueab4PsLqprjxl0hXn/dJlJX1NOsClD74
         OL6jukWrXGResru0OFsax3kwR9iC1yrxHmrMp3lknUJMNvygb0eoqKw5vA2G/POmUF0q
         EStcQODmReUjtzBwftddnFR2nZMtarOY5dgsy6SbpQFMtw4HoQCciu9Muyo0pl3bdxqa
         1+oq/m55zYJQ7ZcUuocRYigFswzqkaBENP/+OAZujLk9IWp1KsbKcZsOZWqLWr29abCE
         IPvcZK3WLVYKGgxLQ0QboZmI77MVU6uch+mLLwV1Qj9sYJpQwLoD0/QzcSpNYSOnSB0b
         VhMQ==
X-Gm-Message-State: AOAM531DH03CNigO2tPZJtZD56NEs1rT30239OlTHDtYmuaXWYzMdcwb
	3aWJ1c/WbgF3tEt1TFMGaZ8=
X-Google-Smtp-Source: ABdhPJzI0JXEg8qtC9VMmN25T0LXwIfwyDqXbtgEJhyLhwnRHyu1Adsu/S/KTaBvxAgRSKnBaf3U1g==
X-Received: by 2002:a1c:a9c2:: with SMTP id s185mr21392326wme.100.1599486093400;
        Mon, 07 Sep 2020 06:41:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls9965359wrm.1.gmail; Mon, 07 Sep
 2020 06:41:32 -0700 (PDT)
X-Received: by 2002:adf:aad1:: with SMTP id i17mr23060802wrc.360.1599486092424;
        Mon, 07 Sep 2020 06:41:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486092; cv=none;
        d=google.com; s=arc-20160816;
        b=gL6wdQ25f/D5ZSScpOlS0ulmMZYMfDjbFxYmZDFwgn6i4UTFMXwu4KpjQLSTSmi2cJ
         TjsW39GuTlK8BwuOlBPBR1QJEHLrmmikgddwvyZYVd41BFBs73ad7sZGuGFpCXW+UYry
         QNakugjWmiIVekJ3b6k/2x7/3vgUBBUCocfgzUkkjU5H6SxA/Nzd18h8NQdcGQgQIU/K
         S/8eylQY3I32G52REGXCTxUOEkeDrkR31QGuoJeZDz6RaPy/uxmkQUUuVwwrBQ/GVU/S
         uTbJdcQcgyJNsETRLkCH1JqSnq3CqobqIY9jWPApiUhVjxKgN+3waIV1M0gyyqV6V5kK
         g2Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VRGvWOinGw0btNVyOH340+TVwWpL0hbTJw9JR94PpB4=;
        b=lm4v5q2EdwP4j7jJQAgqoSYOkdVonwzSml9Bn5jBHZlQZrpquYI7nzRyDBjON8Lbl0
         xcBaR96KAxOLaFefIaIB0KdNIi5TARyvmHII6tsa4gBXFUMrQvoUeVy/dnoxTTdPiKPW
         MUmczSqdU5EOuceObLJI6cFev5NCfj/k7dT/8hAoi9ZMGkTFLRdvvg9n77mbqmY73WII
         0+QQFHAujocgrjX6nqCEDhGFuesvZt01XrTUdM546BB+BSix0JQcehjQYfU4aBZ1iBfN
         sqrY5P1CquT7H6pkGQk+9b2kvAybpEXo/jOHZ+t9rD54dx+K55JA8F56wfncid1lolZm
         H8Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ALL9RpQB;
       spf=pass (google.com: domain of 3jdhwxwukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jDhWXwUKCVc3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y206si281292wmd.2.2020.09.07.06.41.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jdhwxwukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id y3so5707530wrl.21
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:32 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:3886:: with SMTP id f128mr20829871wma.121.1599486092008;
 Mon, 07 Sep 2020 06:41:32 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:54 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-10-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ALL9RpQB;       spf=pass
 (google.com: domain of 3jdhwxwukcvc3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jDhWXwUKCVc3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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
 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 285 +++++++++++++++++++++++++++++
 2 files changed, 286 insertions(+)
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
index 000000000000..254f4f089104
--- /dev/null
+++ b/Documentation/dev-tools/kfence.rst
@@ -0,0 +1,285 @@
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
+With the Kconfig option ``CONFIG_KFENCE_NUM_OBJECTS`` (default 255), the number
+of available guarded objects can be controlled. Each object requires 2 pages,
+one for the object itself and the other one used as a guard page; object pages
+are interleaved with guard pages, and every object page is therefore surrounded
+by two guard pages.
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
+     __kfence_alloc+0x42d/0x4c0
+     __kmalloc+0x133/0x200
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
+its origin.
+
+Use-after-free accesses are reported as::
+
+    ==================================================================
+    BUG: KFENCE: use-after-free in test_use_after_free_read+0xb3/0x143
+
+    Use-after-free access at 0xffffffffb673dfe0:
+     test_use_after_free_read+0xb3/0x143
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated in:
+     __kfence_alloc+0x277/0x4c0
+     __kmalloc+0x133/0x200
+     test_alloc+0xf3/0x25b
+     test_use_after_free_read+0x76/0x143
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+    freed in:
+     kfence_guarded_free+0x158/0x380
+     __kfence_free+0x38/0xc0
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
+     __kfence_alloc+0x42d/0x4c0
+     __kmalloc+0x133/0x200
+     test_alloc+0xf3/0x25b
+     test_double_free+0x76/0x171
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+    freed in:
+     kfence_guarded_free+0x158/0x380
+     __kfence_free+0x38/0xc0
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
+    Detected corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ]:
+     test_kmalloc_aligned_oob_write+0xef/0x184
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated in:
+     __kfence_alloc+0x277/0x4c0
+     __kmalloc+0x133/0x200
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
+For such errors, the address where the corruption as well as the corrupt bytes
+are shown.
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
+of the sample interval, a guarded allocation from the KFENCE object pool is
+returned to the main allocator (SLAB or SLUB). At this point, the timer is
+reset, and the next allocation is set up after the expiration of the interval.
+To "gate" a KFENCE allocation through the main allocator's fast-path without
+overhead, KFENCE relies on static branches via the static keys infrastructure.
+The static branch is toggled to redirect the allocation to KFENCE.
+
+KFENCE objects each reside on a dedicated page, at either the left or right
+page boundaries selected at random. The pages to the left and right of the
+object page are "guard pages", whose attributes are changed to a protected
+state, and cause page faults on any attempted access. Such page faults are then
+intercepted by KFENCE, which handles the fault gracefully by reporting an
+out-of-bounds access. The side opposite of an object's guard page is used as a
+pattern-based redzone, to detect out-of-bounds writes on the unprotected sed of
+the object on frees (for special alignment and size combinations, both sides of
+the object are redzoned).
+
+KFENCE also uses pattern-based redzones on the other side of an object's guard
+page, to detect out-of-bounds writes on the unprotected side of the object;
+these are reported on frees.
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
+performance cost. We want to highlight that KASAN and KFENCE are complementary,
+with different target environments. For instance, KASAN is the better
+debugging-aid, where a simple reproducer exists: due to the lower chance to
+detect the error, it would require more effort using KFENCE to debug.
+Deployments at scale, however, would benefit from using KFENCE to discover bugs
+due to code paths not exercised by test cases or fuzzers.
-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-10-elver%40google.com.
