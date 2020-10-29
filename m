Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUB5P6AKGQETTCQ2QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E252729ECA2
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:18 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id e29sf413772lfb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977438; cv=pass;
        d=google.com; s=arc-20160816;
        b=uGi5d5FWuGxryAvP8nHwbaRorWfBjX+KbBRCzYwhdfmqyTfZpESv6ByyDQeLtgHHtW
         qyS4kzBQm5b9A06i9H727MMqQXa5H6gaDhkAm5KnsoNnaca1bKT3/6ypsM+OEcYObSm8
         C5DNdCiW7qI1YIb7YkYPVJH/oBn3SLpJezVJ2fRyX0EJVG3CwLl46Cu0Va47APm5rhUN
         maQ0wCO2VzhUL34SQKvjjyfd8cjEtYHqRzawzx/6W+L6yIKk+4WaC3xfh8+P0fuJ8jq1
         Qra2WvWDurebr+lPLnZsNmCZh06FzDQjRW5RUWCiRjq0abtQhnhSkF9Qt/mKA0DxK1G2
         jmrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sHT3MjoLJn+qAu6KiKNk9GkSuK5TUtGhtdX0r4IHFhU=;
        b=d+UF+Z/r5ysBtcesB7V+E48/NAV3iOfsO/iZhhlmyZXQNr1weCaEtJIzssccCLKwF7
         ZPgdTM0fR27ls1TglRbxP1Db96Kcjt4fdP0vSobMSrJvp9VNPvy8JHuZoT1I2MQbWewB
         Hqvc6Sy4Ib9LqnVB+dSKwUpn5+k1LU6I1hi8I0sMXVPQL6gRBi54IbLyjIAjFvLaydbA
         YMbKNVktrFWpTD5yQWoolhrn1iVuYm4cVtHukNLajwKWs05t6E6fQ4MeSxGR1AeFode0
         gSK6WcaAt21CxXevr79IkTVKMw3osESIxeFpxdrVQjoev07fKWMS/0EnvoJheFPunnka
         bBSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P7lmQ+JZ;
       spf=pass (google.com: domain of 33mcaxwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=33MCaXwUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sHT3MjoLJn+qAu6KiKNk9GkSuK5TUtGhtdX0r4IHFhU=;
        b=NILvc/PYNn5oXHC15EUSY4JDDXQRmgQH40+Cn2AzA1gxRzaebt/DFN/8Sn9PCCpyvh
         VzhKVjmBYEhWu4NgxLtchyvVhG5RHcgFZnY3jDiqwpL38HtvIrTpYpW6XuCtRQ/2z9i5
         amSENQrG0agvrzEkIFPTlIFshNvI96XGLUpINQgpKZS5MMCnrBEsDYqUcxy9qWu00b2Z
         RqWBsvWSYXcBtn0q9y/zgEUGOR1Uv5OC1ypV1Vo1JDsUiGBepH12qjwPOWZ1smcSsOJP
         jB/5rNb5uA6uxckH+jI8W4s/ud48GYDsE0rSPtxQgyK3gf+0+BUs1tkeD/MIOPQ0Z3sr
         4luA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sHT3MjoLJn+qAu6KiKNk9GkSuK5TUtGhtdX0r4IHFhU=;
        b=WYPWpIrFEBz/GTEMrYMNeZAdY9uxHoOyIuCSm7Xw6qpLip6G+Agq+T86KBjO/HJRTg
         R26K7fcYtwle6fhEXeh8RgRrU/wSFduYXNYt6q3glff+CQxfcx8KP8FFpNbjiy33uBq2
         4BjBRWLgux5sSP526UlPPbQ+hcYoVSt0TsT5fVBzp8x8RRV9LJV2KcYvPm4MAGKig5Pc
         j1iP5CkcfIJaTU2ai1zjuZ9bn+gdQpdIQCb2vw+CjmekL+O5FSjaPEo7+SY8JCtXfEwh
         WrByCzOydlpidNBGAPrNvwn/tF8YMG386ugBzTZSvFXEpngKvCijnXexPblM+ZuF/Q4j
         sS4A==
X-Gm-Message-State: AOAM532V91cwdNTCliyWEkYh8glYukX6MVfOTqo8bLXL1qjGj17X2SL9
	RM8qbzxBplvEiS6XRTCnZV0=
X-Google-Smtp-Source: ABdhPJw02KHKzbc0JiiCb7yaeNjCc65mqJWwdJoh46ijcFbLA/sw39O0gd0SMV9hSkdwuMCQYzqBAg==
X-Received: by 2002:a2e:9782:: with SMTP id y2mr1984308lji.110.1603977438474;
        Thu, 29 Oct 2020 06:17:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls1622323lfd.3.gmail; Thu, 29
 Oct 2020 06:17:17 -0700 (PDT)
X-Received: by 2002:a19:3f51:: with SMTP id m78mr1577786lfa.280.1603977437220;
        Thu, 29 Oct 2020 06:17:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977437; cv=none;
        d=google.com; s=arc-20160816;
        b=FkYOcyr6VUgviBLYMWYt8OHS5S+/xvy88PlRAsjePNs1qN+pBuhxC0v7xxMOyMcY3Q
         USjuZDGy+vruGyvjLuc9UT7ESqgKL6XuCX2xDuZyduQMbaqtxzw2gqgoxTwXhm93paTD
         OgDfr3aJhowBCD4CAWRVi0cTmxYMK50c5lJXaRPT4Dhsil8Tu+TCsKdP6HKPAh2m3bDm
         gbVClW1EgpR5tqRMdd2p2vFxkGkabh6w1vmHxzyj3xdJBpyjqReMrFSSe9zPYKbBnRLW
         Asyvx4QfKgwSEhz231hsrwpncFH0ag0x1VT/7EVOpbBRPUFcLF/YnPxBWJ0sASLVlyxg
         +LoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RwbyQhx2FDVpnqdar+PKeN5IqV3VGGUpJtBlI3DkhdY=;
        b=MzxWFjZX0lhcknua836m2Bp1UGHKqFZZ1o5Xa625cPr/vNUc5xl/R8gkJU7NMKaG9p
         bjYkDRuRPSWz06XCkaB7DvGI3qj7KaXlobms0lv7/q+nDDXS8vu/RSvECOI4c3+upHAe
         bBhjlCqfS0A1duWTvII91U/3+zXH4fChfZx/aeHN3a1Az+eHHsROl6awwzVCnG7Abblk
         mKNhy/C3oACORGpaPA+L5NROyc3ZXhg9hOozbRX1wKPWN1amSWVC0N54XWwv7nvCeugl
         l8YzjAYB+fEexaDMwcYpJ6uV9/5XhAK+UNRodts3t84QYtYD9AOoP1lNqtItDINvcVzU
         yNjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P7lmQ+JZ;
       spf=pass (google.com: domain of 33mcaxwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=33MCaXwUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id q11si63943lfo.8.2020.10.29.06.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:17:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33mcaxwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id m20so1264529wrb.21
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:17:17 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:2ec6:: with SMTP id u189mr4525514wmu.85.1603977436387;
 Thu, 29 Oct 2020 06:17:16 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:47 +0100
In-Reply-To: <20201029131649.182037-1-elver@google.com>
Message-Id: <20201029131649.182037-8-elver@google.com>
Mime-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 7/9] kfence, Documentation: add KFENCE documentation
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
 header.i=@google.com header.s=20161025 header.b=P7lmQ+JZ;       spf=pass
 (google.com: domain of 33mcaxwukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=33MCaXwUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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
 Documentation/dev-tools/kfence.rst | 291 +++++++++++++++++++++++++++++
 lib/Kconfig.kfence                 |   2 +
 3 files changed, 294 insertions(+)
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
index 000000000000..f0ee8db1bf87
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
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 639b48cc75d4..3c4066aca4fc 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-8-elver%40google.com.
