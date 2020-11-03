Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VUQ36QKGQEDEMYSOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F382A4DAA
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:16 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id g20sf11116255plj.10
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426355; cv=pass;
        d=google.com; s=arc-20160816;
        b=svwzqI06smiJjN23h4fdUPqL4GhG6+Aktxpkk3EaB3/83k9LHwoAAZeaILMM5PKza1
         BEdZ3NXA7huenN2wYq1OhSoNQe+Fx5GMOT88fivWM9kDK5s/+DtrUO4UZCID/qJxpHbg
         O0K6gbniiLLhdtBPr4WPF2uKCrzNUdw1dibtPyAUB9YvvIAYvPeCFS9mqtE4gQcxPE5U
         gk61KRHQdRr9iK0oe3vtCvNMGMXNgIJRQjfindYFSJyMpAzYbMTbLteH0jxvp9IspB4S
         lOMYBMUV7H430HuYXsXs8iK1eKtijr33nFzuzhGTi0CBTF2Bzrvrt7KT/9Ocl4g9T1nr
         VhJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vEMlpR7x+LsJxoK8vQyFdXKqxD0e4dlq8PJ3kSkIX6k=;
        b=hAYMvlc7fZSWdCrJfnL9P3KljG2pneDZHC8isA+VvMGEBlF0hVb+zpi2NkqCQlssaU
         do3lxTIHKZkXz0CRBGXYIfmyfDIQGcXmdVYOxiH66kjAyeS5zfesTyTx1nNPcDuyS+f5
         QVvTJUmEngwzShtMP7dWzbs8y4fLEUSxWKiILrMnhrWRemk6DMQg+MLUSqlelgdWPmWK
         IdVJOzyHtUEGh09dRrCYlVO/fol0SdPirCtIrY9Gl2Dj9J7RrRbAcEWcV265CYUzXuFQ
         Q7CXJ9gpu81A6C3GKwhQ7W2/2YznFv/S8zSS5I90Tov5AnfrsMIoUwnAlr/wmfI5251G
         FfOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JZgHzLo8;
       spf=pass (google.com: domain of 3czqhxwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3cZqhXwUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vEMlpR7x+LsJxoK8vQyFdXKqxD0e4dlq8PJ3kSkIX6k=;
        b=cqonKnreUAlI4o9/Ew4Q3zsWLCMXFjzQkgmzbLDXPBXduNWv5PuI8DK5X0wyDfQ8Sa
         5QjkKmkswV2n1PSk9r4arzHyvhJck8W0PjEKbhk2LUsdaLktz+6tNWzcoPZ7fCv7ehoJ
         xfhdBSq5d+eQlquT0Sxeed4YODVjAFk55Lr7HE5ztBoWeiymFu87cPbK8IBxH/ZTN55Z
         v2eiaT0aakAVgf8HyXlCXOWkfcfM5F9PbToAIuoQjgIwSYh7WssfM5QAMAAxJsvsK5RE
         TAm1mDbbcETyjhLzHeCqua3UhdbRN9k+pG8ztPxIbsI7vrH2CfNWoDB3MaMiFARaIbmR
         Mhxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vEMlpR7x+LsJxoK8vQyFdXKqxD0e4dlq8PJ3kSkIX6k=;
        b=ZLQEGI33w84pzJ9ONVDX0CuLCP7NKzqLHk2jnh7ZM80JXbqCsQesBjDi7Hf7K3AZhg
         N4GF5UoeijLpT1ZfiSnBbwfYkO5545T9ok36IuoPwkbQLwrImZvmc7g7/bLl2KWCzIfn
         7LEABAKbbwzLYkt86SqO6PLw82pLXc2rQAcV4XXtU7VJySobfxyR0lKVq5J/jorZifYB
         +kFgVf/t1zEYmfRAgUPvStv8znzZ7pi6j2xxnAvjuD0ONLZ+nrT4cKcMaG7RJfmWQNgw
         wPfzuGc68LJsperigNXulTMm/+3gzEhxDBz1nFZHnGGZPWIilM0L0bCqGwHbvmxZ9xsZ
         QOKg==
X-Gm-Message-State: AOAM532JQZVymRkS4+wCfkKAAW//mmCYfsQ79KIQtUIP6BpAi7uWcCUs
	z/3r+UWQKuT5Ocz5289Euqs=
X-Google-Smtp-Source: ABdhPJw3yvwMknNpatXcdcoCx8YpuFmuKiG7RqKDfUqH2vtP5cENgeUu85m+8VCVxSggc/dR4xWieA==
X-Received: by 2002:a17:902:d695:b029:d6:a255:ae32 with SMTP id v21-20020a170902d695b02900d6a255ae32mr20188804ply.43.1604426354856;
        Tue, 03 Nov 2020 09:59:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls1645363pjq.0.gmail; Tue, 03
 Nov 2020 09:59:14 -0800 (PST)
X-Received: by 2002:a17:90a:f195:: with SMTP id bv21mr414263pjb.8.1604426354291;
        Tue, 03 Nov 2020 09:59:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426354; cv=none;
        d=google.com; s=arc-20160816;
        b=w4I61tZtuLz82Wan9vK8Hx/PWHdGxCNcztZbeNUG7bOmsYrtFmd3ghWUevFyJsLG5w
         bKgl6FnFpjxKZ2hl37sVd5ahVrqEVTJaytL3WlxJKdFUjgZ5aR6BM4ZBxLZCGO/KsaYm
         4ZQD8fHLn5fgh0eM9r+lPd8508939C0hISmqvXaz7aLMNCsToyOTYsqIn5OZcw5YY5cN
         YsdMOIf49lR2VkGziC+hW8UX0WjYJqbmv+2V/EKdTwAvYuBlcMXo5t0KmO+0qAVXG2sq
         jaF2ocxOxo6nSy8IUEhe90yXaV9rbVDSYSn64NPgpKlq8XzBNKpg8wbqF431zzLzhM8n
         hKVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fFwcA2UBgRV7sBLSj4BlqH41WXy2uDCLV2hs9+q1g7Q=;
        b=uOhuf+YpZZwc2xBZ6PutlCHwom1vCr/ORqiBLLIv3EqnN1IZc9zlTdo46x0VOkYNXR
         O9oFcoo8YH3ZUiXIyuwZAUqOh+w6sfNVUYX1Zr76sS7IS957eQ2yAKjLZ/3UL72Iy4q+
         1+KMJwASIkxH1uf3tbPxcEfXOcdRQZ34xNr9alF4eeBILgDJpbnIGuA4f60dQCN6qm/h
         YrHvgY4+RygxmaFxRzdyJ5TfABXk0HD3CERLwkPeJZifvEVRaagX1EGYMTvArqSYFPuf
         /jaWeKeQZBUQseIEER7z+ot55VFCSOGnpusmBYBamkx44NGURfdRncwdWqdIoQ8M96zl
         DcIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JZgHzLo8;
       spf=pass (google.com: domain of 3czqhxwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3cZqhXwUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id cl2si249607pjb.0.2020.11.03.09.59.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3czqhxwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id j17so7554731qvi.21
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:14 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:4f22:: with SMTP id fc2mr28977849qvb.28.1604426353306;
 Tue, 03 Nov 2020 09:59:13 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:39 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-8-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 7/9] kfence, Documentation: add KFENCE documentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JZgHzLo8;       spf=pass
 (google.com: domain of 3czqhxwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3cZqhXwUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v7:
* Suggestions by Jann Horn:
  * Add a note about huge tables.
  * Note about graceful handling of errors (and mention panic_on_warn).
  * More spelling/grammar fixes.
* Add __kfence_free() to public API.

v3:
* Re-introduce reference to Documentation/dev-tools/kfence.rst.

v2:
* Many clarifications based on comments from Andrey Konovalov.
* Document CONFIG_KFENCE_SAMPLE_INTERVAL=0 usage.
* Make use-cases between KASAN and KFENCE clearer.
* Be clearer about the fact the pool is fixed size.
* Update based on reporting changes.
* Explicitly mention max supported allocation size is PAGE_SIZE.
---
 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 297 +++++++++++++++++++++++++++++
 lib/Kconfig.kfence                 |   2 +
 3 files changed, 300 insertions(+)
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
index 000000000000..d7329f2caa5a
--- /dev/null
+++ b/Documentation/dev-tools/kfence.rst
@@ -0,0 +1,297 @@
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
+Note: On architectures that support huge pages, KFENCE will ensure that the
+pool is using pages of size ``PAGE_SIZE``. This will result in additional page
+tables being allocated.
+
+Error reports
+~~~~~~~~~~~~~
+
+A typical out-of-bounds access looks like this::
+
+    ==================================================================
+    BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0xa3/0x22b
+
+    Out-of-bounds access at 0xffffffffb672efff (1B left of kfence-#17):
+     test_out_of_bounds_read+0xa3/0x22b
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated by task 507:
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
+    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated by task 507:
+     test_alloc+0xf3/0x25b
+     test_use_after_free_read+0x76/0x143
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    freed by task 507:
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
+    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated by task 507:
+     test_alloc+0xf3/0x25b
+     test_double_free+0x76/0x171
+     kunit_try_run_case+0x51/0x85
+     kunit_generic_run_threadfn_adapter+0x16/0x30
+     kthread+0x137/0x160
+     ret_from_fork+0x22/0x30
+
+    freed by task 507:
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
+    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated by task 507:
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
+For such errors, the address where the corruption occurred as well as the
+invalidly written bytes (offset from the address) are shown; in this
+representation, '.' denote untouched bytes. In the example above ``0xac`` is
+the value written to the invalid address at offset 0, and the remaining '.'
+denote that no following bytes have been touched. Note that, real values are
+only shown for ``CONFIG_DEBUG_KERNEL=y`` builds; to avoid information
+disclosure for non-debug builds, '!' is used instead to denote invalidly
+written bytes.
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
+out-of-bounds access, and marking the page as accessible so that the faulting
+code can (wrongly) continue executing (set ``panic_on_warn`` to panic instead).
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
+The following describes the functions which are used by allocators as well as
+page handling code to set up and deal with KFENCE allocations.
+
+.. kernel-doc:: include/linux/kfence.h
+   :functions: is_kfence_address
+               kfence_shutdown_cache
+               kfence_alloc kfence_free __kfence_free
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
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index d2e3c6724226..d2173a3a423a 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -14,6 +14,8 @@ menuconfig KFENCE
 	  to have negligible cost to permit enabling it in production
 	  environments.
 
+	  See <file:Documentation/dev-tools/kfence.rst> for more details.
+
 	  Note that, KFENCE is not a substitute for explicit testing with tools
 	  such as KASAN. KFENCE can detect a subset of bugs that KASAN can
 	  detect, albeit at very different performance profiles. If you can
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-8-elver%40google.com.
