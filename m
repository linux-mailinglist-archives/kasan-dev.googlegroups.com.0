Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXVEVT6QKGQEYJ7UYGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 75AB52AE340
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:19 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id t77sf5027vkt.18
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046878; cv=pass;
        d=google.com; s=arc-20160816;
        b=ujk21PbuWZsPJnDpxzbCqIWi1RT5QIZ1lt0Ytf3n0L27CBllAfY/ATohvrA4BZdJRR
         Na7gCm7fevDep+HkDz19gOu/ncA9DzJBh9jneJHKj+NTfbhhO+pBS2cVbhSvVc+xE3wK
         CtwfgIRs+wcLOq69x9UHCaSXCM3C84PqyW7baaiUHLVYkNDV9IHtI48oCGj5E4AYyJa0
         hhqgY0HYHlAdo4SBwN2ixoXj+bJYy8mQJ2p9pcO4yiSdfoXRXuxpOQld+0lZfG8BjCu9
         EDsoYwvuC9+ntIuUh5tonTCsXWB9B5rVHz3e1KAFPSBhbMf19F21PAbYRQv1I2F1MJzH
         Lgcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vNcO54Bxv/lcIDHTkXGFaSumIhsPQCOUrbbxmk1yf8U=;
        b=tmrrChKOFK1Zxhz/sscXdry9t/rbQJzN4bHSQGtsCKuOYn0yqXyZVKOjBK+l1f8id/
         pXRYJYjIpam2OVpvgLkPjTICarZLVvBhQVI1LKibgMcH0rGwsgMC8k2GVwr1shFY8G46
         hLGBCPv6iDnaz02x1PjP6wZgCRtNeIxQL/U7hasVTIEbweBTrxBkLCCDWqlAPVgG8Zi2
         FZKwFVvpF+2vrdskqxtKa0mE3obitR9IJ8hH0RKpUqrTJS2gck+SPm9pcfNyBAV1O5TH
         rRGXJl1ONeIjqilDdXsMArM/dinYXoRvYiViZKVfzZ6i7kLM8MUmsge9o8Zr444sRF6c
         TgfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NtqZsgjs;
       spf=pass (google.com: domain of 3xrkrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3XRKrXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vNcO54Bxv/lcIDHTkXGFaSumIhsPQCOUrbbxmk1yf8U=;
        b=pcn9xxuLKId3zcOvqE0UhR8rhDCaw8mYq4RVoVBp5kRFQXj95qC3gEPwbW8TBvHUV7
         1CJJuGjWG5k6TQaPdN8/92avo1y6k246QXHCHN2a2PKcMtIMKza2dnswfLCN+H/L/byG
         1jMfkjOlJ5dcP3kQxCK1k2pCFKOUJTeOuoOCBJZhprL2qCEh4NrijnjiJ4Xrch7JAxR2
         DrWMyrFodS8ubmgl2BwjR6D5OcMTvHm/2RANuwC1jOH1c/WhZzN8Bkfs2K1N6aCVSw8b
         Z7k3dmrTyiPlAwFRvQWjDpmk1Nn1XGgwBMo02ioJXb4mNyVMdT5YJkdlnxwFoM98DN+s
         6jRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vNcO54Bxv/lcIDHTkXGFaSumIhsPQCOUrbbxmk1yf8U=;
        b=a3NaNEmg2+b88sb+ZZU1JW51ozEfjpVvyiFRBwoynCXdxras7EY6PfUYbAMZJbAhGL
         9kcz3iPbQJjh2vRabVwWYlVQOz1a8lVAeNMTnNUqMdDcCEAOq7MHNa+riz80mvUW0xtT
         7JVW8HIh5KlotcK9lTSATLcaKFmLGfESsIzRu1MSWBHIM+n4oDTdfJA5dt0sjGG2iTA5
         7lAgG4JPjPe/Ny5eg5HE3h06bS71TpH7BwKlGuZVUdW7TixLOPzKUszfXgaEglG0XbZJ
         7QMvdRX5xBjWYTt0wShNytW4DbfWCLPljZ9ysTdK5UEk5GMWfebbyKROM3BpeqakMAq5
         7K+Q==
X-Gm-Message-State: AOAM530Btj/5efhTHDphPF3EFOQHUYF09jG129vysXzstx1gmqjUnhAv
	jSUSz6pIIAuArPTbOlumaQo=
X-Google-Smtp-Source: ABdhPJw3nldGwHs0AnrAXd55u8VOlzGylf6Mn24+P3RBdU4NGSwhrn3wVxorscLVDw+VSvLlFSNMYw==
X-Received: by 2002:ab0:5e95:: with SMTP id y21mr11314906uag.21.1605046878540;
        Tue, 10 Nov 2020 14:21:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2046:: with SMTP id q6ls1672890vsr.3.gmail; Tue, 10
 Nov 2020 14:21:18 -0800 (PST)
X-Received: by 2002:a67:ec9a:: with SMTP id h26mr13540106vsp.34.1605046878104;
        Tue, 10 Nov 2020 14:21:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046878; cv=none;
        d=google.com; s=arc-20160816;
        b=pAjDIxET7L7tbc/rRzruSNgPndY96AnW4lVqbUqMZHokOFqwFHkyrznOIlFkeHUi9/
         MJlw52UxnDji/gif1NzCUyeuS0GNUIPy0tzq/ov3vPGksnFL9gwa0qZT695CMNRKKkEC
         6A5OLcdejgIz7reN1OrTWW3+8oeTixbZDXfquEsM/thJ7sy6/COQlaWCEAkZbj/owHJq
         r5FVadnzJmQ19xLEaC7Byb/U6hJSigLG7bXDiq5nu95oA9pQA5UTuPmNwl3VRtaVNTG9
         sUrF1NAujcI8hGa8QSxSeVA+Zgtq0zPKYux1b2g16HaRO5Ir6HdS3+p6inmaEHPEoc68
         UhVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hhAVeCS4JTcfsOdyr55ktLnnnel/q5W+4IYGph2ifVQ=;
        b=QpKBWNJYGAmMtirn5EWxIOdQ5TRoP8qirsFhucXVTc5l7UHkDrtdSz4Mf7FFd1akvZ
         zA0neSDouQWQl7n8f0dw7gIsBMkaSplWUMgVhx6KMgrqMiIOYERS/4galD2jL2EvX/TG
         4/OFYHt1i22zUDTDkoeWnsXrH/jBmSjnHmxkSuNldlJWHI2A2PmV3a3r7VhjUTZmr4EN
         LN8G9dlk6hso2/+ezgwblPCwY9GVVUpvQd1+dZQ3Vuxfh1pG08CUAptH6L6zj0gaJ+te
         /pqlKsvjJKF+CsJGo1Ga/9jXpoyBIlBVodFt23QagRwoQI9GM1gd32ewV40BDkJ+SGXZ
         LD9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NtqZsgjs;
       spf=pass (google.com: domain of 3xrkrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3XRKrXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id m17si16392vsk.0.2020.11.10.14.21.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xrkrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id m76so222692qke.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4673:: with SMTP id
 z19mr9694086qvv.60.1605046877787; Tue, 10 Nov 2020 14:21:17 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:24 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <6103d1aaacea96a94ca4632f78bcd801e4fbc9c4.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 20/20] kasan: update documentation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NtqZsgjs;       spf=pass
 (google.com: domain of 3xrkrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3XRKrXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change updates KASAN documentation to reflect the addition of boot
parameters and also reworks and clarifies some of the existing sections,
in particular: defines what a memory granule is, mentions quarantine,
makes Kunit section more readable.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 180 +++++++++++++++++++-----------
 1 file changed, 113 insertions(+), 67 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 422f8ee1bb17..f2da2b09e5c7 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -6,6 +6,7 @@ Overview
 
 KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
 find out-of-bound and use-after-free bugs. KASAN has three modes:
+
 1. generic KASAN (similar to userspace ASan),
 2. software tag-based KASAN (similar to userspace HWASan),
 3. hardware tag-based KASAN (based on hardware memory tagging).
@@ -39,23 +40,13 @@ CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
 The former produces smaller binary while the latter is 1.1 - 2 times faster.
 
 Both software KASAN modes work with both SLUB and SLAB memory allocators,
-hardware tag-based KASAN currently only support SLUB.
-For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
+while the hardware tag-based KASAN currently only support SLUB.
+
+For better error reports that include stack traces, enable CONFIG_STACKTRACE.
 
 To augment reports with last allocation and freeing stack of the physical page,
 it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
 
-To disable instrumentation for specific files or directories, add a line
-similar to the following to the respective kernel Makefile:
-
-- For a single file (e.g. main.o)::
-
-    KASAN_SANITIZE_main.o := n
-
-- For all files in one directory::
-
-    KASAN_SANITIZE := n
-
 Error reports
 ~~~~~~~~~~~~~
 
@@ -140,16 +131,20 @@ freed (in case of a use-after-free bug report). Next comes a description of
 the accessed slab object and information about the accessed memory page.
 
 In the last section the report shows memory state around the accessed address.
-Reading this part requires some understanding of how KASAN works.
-
-The state of each 8 aligned bytes of memory is encoded in one shadow byte.
-Those 8 bytes can be accessible, partially accessible, freed or be a redzone.
-We use the following encoding for each shadow byte: 0 means that all 8 bytes
-of the corresponding memory region are accessible; number N (1 <= N <= 7) means
-that the first N bytes are accessible, and other (8 - N) bytes are not;
-any negative value indicates that the entire 8-byte word is inaccessible.
-We use different negative values to distinguish between different kinds of
-inaccessible memory like redzones or freed memory (see mm/kasan/kasan.h).
+Internally KASAN tracks memory state separately for each memory granule, which
+is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
+memory state section of the report shows the state of one of the memory
+granules that surround the accessed address.
+
+For generic KASAN the size of each memory granule is 8. The state of each
+granule is encoded in one shadow byte. Those 8 bytes can be accessible,
+partially accessible, freed or be a part of a redzone. KASAN uses the following
+encoding for each shadow byte: 0 means that all 8 bytes of the corresponding
+memory region are accessible; number N (1 <= N <= 7) means that the first N
+bytes are accessible, and other (8 - N) bytes are not; any negative value
+indicates that the entire 8-byte word is inaccessible. KASAN uses different
+negative values to distinguish between different kinds of inaccessible memory
+like redzones or freed memory (see mm/kasan/kasan.h).
 
 In the report above the arrows point to the shadow byte 03, which means that
 the accessed address is partially accessible.
@@ -157,6 +152,55 @@ the accessed address is partially accessible.
 For tag-based KASAN this last report section shows the memory tags around the
 accessed address (see Implementation details section).
 
+Boot parameters
+~~~~~~~~~~~~~~~
+
+Hardware tag-based KASAN mode (see the section about different mode below) is
+intended for use in production as a security mitigation. Therefore it supports
+boot parameters that allow to disable KASAN competely or otherwise control
+particular KASAN features.
+
+The things that can be controlled are:
+
+1. Whether KASAN is enabled at all.
+2. Whether KASAN collects and saves alloc/free stacks.
+3. Whether KASAN panics on a detected bug or not.
+
+The ``kasam.mode`` boot parameter allows to choose one of three main modes:
+
+- ``kasan.mode=off`` - KASAN is disabled, no tag checks are performed
+- ``kasan.mode=prod`` - only essential production features are enabled
+- ``kasan.mode=full`` - all KASAN features are enabled
+
+The chosen mode provides default control values for the features mentioned
+above. However it's also possible to override the default values by providing:
+
+- ``kasan.stacktrace=off`` or ``=on`` - enable alloc/free stack collection
+                                        (default: ``on`` for ``mode=full``,
+                                         otherwise ``off``)
+- ``kasan.fault=report`` or ``=panic`` - only print KASAN report or also panic
+			                 (default: ``report``)
+
+If ``kasan.mode parameter`` is not provided, it defaults to ``full`` when
+``CONFIG_DEBUG_KERNEL`` is enabled, and to ``prod`` otherwise.
+
+For developers
+~~~~~~~~~~~~~~
+
+Software KASAN modes use compiler instrumentation to insert validity checks.
+Such instrumentation might be incompatible with some part of the kernel, and
+therefore needs to be disabled. To disable instrumentation for specific files
+or directories, add a line similar to the following to the respective kernel
+Makefile:
+
+- For a single file (e.g. main.o)::
+
+    KASAN_SANITIZE_main.o := n
+
+- For all files in one directory::
+
+    KASAN_SANITIZE := n
+
 
 Implementation details
 ----------------------
@@ -164,10 +208,10 @@ Implementation details
 Generic KASAN
 ~~~~~~~~~~~~~
 
-From a high level, our approach to memory error detection is similar to that
-of kmemcheck: use shadow memory to record whether each byte of memory is safe
-to access, and use compile-time instrumentation to insert checks of shadow
-memory on each memory access.
+From a high level perspective, KASAN's approach to memory error detection is
+similar to that of kmemcheck: use shadow memory to record whether each byte of
+memory is safe to access, and use compile-time instrumentation to insert checks
+of shadow memory on each memory access.
 
 Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (e.g. 16TB
 to cover 128TB on x86_64) and uses direct mapping with a scale and offset to
@@ -194,7 +238,10 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
+Generic KASAN is the only mode that delays the reuse of freed object via
+quarantine (see mm/kasan/quarantine.c for implementation).
+
+Generic KASAN prints up to two call_rcu() call stacks in reports, the last one
 and the second to last.
 
 Software tag-based KASAN
@@ -302,15 +349,15 @@ therefore be wasteful. Furthermore, to ensure that different mappings
 use different shadow pages, mappings would have to be aligned to
 ``KASAN_GRANULE_SIZE * PAGE_SIZE``.
 
-Instead, we share backing space across multiple mappings. We allocate
+Instead, KASAN shares backing space across multiple mappings. It allocates
 a backing page when a mapping in vmalloc space uses a particular page
 of the shadow region. This page can be shared by other vmalloc
 mappings later on.
 
-We hook in to the vmap infrastructure to lazily clean up unused shadow
+KASAN hooks in to the vmap infrastructure to lazily clean up unused shadow
 memory.
 
-To avoid the difficulties around swapping mappings around, we expect
+To avoid the difficulties around swapping mappings around, KASAN expects
 that the part of the shadow region that covers the vmalloc space will
 not be covered by the early shadow page, but will be left
 unmapped. This will require changes in arch-specific code.
@@ -321,24 +368,31 @@ architectures that do not have a fixed module region.
 CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
 --------------------------------------------------
 
-``CONFIG_KASAN_KUNIT_TEST`` utilizes the KUnit Test Framework for testing.
-This means each test focuses on a small unit of functionality and
-there are a few ways these tests can be run.
+KASAN tests consist on two parts:
+
+1. Tests that are integrated with the KUnit Test Framework. Enabled with
+``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
+automatically in a few different ways, see the instructions below.
 
-Each test will print the KASAN report if an error is detected and then
-print the number of the test and the status of the test:
+2. Tests that are currently incompatible with Kunit. Enabled with
+``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
+only be verified manually, by loading the kernel module and inspecting the
+kernel log for KASAN reports.
 
-pass::
+Each KUNIT-compatible KASAN test prints a KASAN report if an error is detected.
+Then the test prints its number and status.
+
+When a test passes::
 
         ok 28 - kmalloc_double_kzfree
 
-or, if kmalloc failed::
+When a test fails due to a failed ``kmalloc``::
 
         # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
         Expected ptr is not null, but is
         not ok 4 - kmalloc_large_oob_right
 
-or, if a KASAN report was expected, but not found::
+When a test fails due to a missing KASAN report::
 
         # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
         Expected kasan_data->report_expected == kasan_data->report_found, but
@@ -346,46 +400,38 @@ or, if a KASAN report was expected, but not found::
         kasan_data->report_found == 0
         not ok 28 - kmalloc_double_kzfree
 
-All test statuses are tracked as they run and an overall status will
-be printed at the end::
+At the end the cumulative status of all KASAN tests is printed. On success::
 
         ok 1 - kasan
 
-or::
+Or, if one of the tests failed::
 
         not ok 1 - kasan
 
-(1) Loadable Module
-~~~~~~~~~~~~~~~~~~~~
+
+There are a few ways to run Kunit-compatible KASAN tests.
+
+1. Loadable module
+~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
-a loadable module and run on any architecture that supports KASAN
-using something like insmod or modprobe. The module is called ``test_kasan``.
+a loadable module and run on any architecture that supports KASAN by loading
+the module with insmod or modprobe. The module is called ``test_kasan``.
 
-(2) Built-In
-~~~~~~~~~~~~~
+2. Built-In
+~~~~~~~~~~~
 
 With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
-on any architecure that supports KASAN. These and any other KUnit
-tests enabled will run and print the results at boot as a late-init
-call.
+on any architecure that supports KASAN. These and any other KUnit tests enabled
+will run and print the results at boot as a late-init call.
 
-(3) Using kunit_tool
-~~~~~~~~~~~~~~~~~~~~~
+3. Using kunit_tool
+~~~~~~~~~~~~~~~~~~~
 
-With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, we can also
-use kunit_tool to see the results of these along with other KUnit
-tests in a more readable way. This will not print the KASAN reports
-of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
-information on kunit_tool.
+With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
+possible use ``kunit_tool`` to see the results of these and other KUnit tests
+in a more readable way. This will not print the KASAN reports of the tests that
+passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
+for more up-to-date information on ``kunit_tool``.
 
 .. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
-
-``CONFIG_TEST_KASAN_MODULE`` is a set of KASAN tests that could not be
-converted to KUnit. These tests can be run only as a module with
-``CONFIG_TEST_KASAN_MODULE`` built as a loadable module and
-``CONFIG_KASAN`` built-in. The type of error expected and the
-function being run is printed before the expression expected to give
-an error. Then the error is printed, if found, and that test
-should be interpretted to pass only if the error was the one expected
-by the test.
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6103d1aaacea96a94ca4632f78bcd801e4fbc9c4.1605046662.git.andreyknvl%40google.com.
