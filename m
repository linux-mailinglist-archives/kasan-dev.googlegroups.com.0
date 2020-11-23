Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3FQ6D6QKGQET3GRVNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D620C2C157C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:40 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id b185sf6517053lfg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162540; cv=pass;
        d=google.com; s=arc-20160816;
        b=kRVgwG2MvJKDxQ/y8VjVwhg6fXpqO1K92nhf/+iPnBaxzaRcf1r9UP35BQT4M4ybz2
         VA6Js5SodcPmoPmUQRUfn6bXY56usdRcFdeYL1EjIvk80mPRc2ygti9whK18kf3YE/IT
         zH5z42bsEirab40D9qjWzlBqryeBhb5xNlmmP03obM6pQDFxpJzx5DUwD++4YfctQtyO
         gCJUJDcdfk+6rFVp3Y9JEDIOfzKMkGeY4HyZoHeQFRAhJtPCwDNSh9e7k/xZdtXVJDfo
         v4vzqIcvLOQGJd+ZKcd4oBrQ95bNvZNGJ1P3OZE9gWHg0e/Odu40K93gcQGk787sTHgq
         iNig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0Jm6DPz+HJYqxI9Zs0VySN4NBNWDEoXvoTaBmXXqaHQ=;
        b=DOyP8JzGwiFWqP5KoHkyEmbJbuA50cD8xWc8jN31iolDevO6f7EfYdEfYS9CYgJV+4
         I4H7BSRhEqnGPgcty6EYGfFTMyHaaZXZoso0h9qZKNJdh37mryJsgjmic/Crou3GY5Tq
         Crnan1NF7yuDPYgXtWftmV8u29EJVqRBrPu7J52Iowg5MNwNC8ADsNP3oq5LO8twJ56I
         u34f0WFN8eSBZ8lPyNzH2XlVOG0qsV5LdhpRP7pGRKyTNismeKV994DIWQf9cmfcMeYl
         3qBEuAP6+AYiMmHSp0nBAIVvuKfYSEFt1/iesiwN7o5uhyO0j/OVgmYl9argEvuM0JpS
         PNnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uqQ8B6Ep;
       spf=pass (google.com: domain of 3ahi8xwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ahi8XwoKCY8t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0Jm6DPz+HJYqxI9Zs0VySN4NBNWDEoXvoTaBmXXqaHQ=;
        b=rp2Du+E6Z177AA4zM/sJoYtygB8zjPxOIPOaCiAwNw/9aIAyoo5ZmL05+sEkDPQxyC
         0GSNLT2oB56uCUFAApiYpwq1O69Ga4wQlHG3XtsVYzdohcyuUPJfcsGSnOUB047+BgZK
         oZPOKW6SYCaut0ky8Ygkd3uppHqPAY3rLmltg44BIn8/AHRA4nBBRfYB/C5CHKxRdUWU
         tz9TSwV7H9G8oDvsxVFa7JKyUd5Q8V+Hejk/GWuI6n7lg5vvZY8GBE+MJbAsDOQ+6IfF
         gaMd78WDd9eibPhVOLoEzoqGJajpRhNgU9gzbwfXRMQYCuStODe4PXIbpDbE3Xu3zRp1
         0ZwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Jm6DPz+HJYqxI9Zs0VySN4NBNWDEoXvoTaBmXXqaHQ=;
        b=WST4BPz2pj0OP/RdBJkMQUj0x8IO1z690Pm0nLW02WF6mesVrUQOAMtlC2845vnczI
         6FjTkIvlhLbEvBPN5MdBlBV/s67OTmK95vDRUAxHrD1ZBHHgwUOL0gokFQ/JMPracfn/
         tUfVJvY9TQHYhHq2o8qI8yKZms/xz8itqok01F1P5fk4Uc29b/HheGChv+AOtBYTettt
         YWZtgNt3ZW/t3TRa0H65KDg0o/n9NWmI4gmbCWVtMC4US4ZPORH8XLJAZ40ERU3ELu+F
         FHXcJCAFPqdwtMUudhdkN0TJ5R4fyLhqP6URdOua8md8SAvmu5GGkTCnX0qvKKtxjJJP
         ywBw==
X-Gm-Message-State: AOAM53064VeR0pTXAvGtOmGOlpXApph6elpVCOp5t84aBVW+hNSWiVjJ
	O87ZLH2hIiUcARInbrVnwhI=
X-Google-Smtp-Source: ABdhPJwSeSOk+PJBGgtN+yOL25uvplkK3X8TaEHUKfDZ0P5wQ0wTjIdaTtsSRTmHuM+NdwhF5cMJFg==
X-Received: by 2002:a2e:9dd0:: with SMTP id x16mr467905ljj.406.1606162540427;
        Mon, 23 Nov 2020 12:15:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls5186049lfa.1.gmail; Mon, 23 Nov
 2020 12:15:39 -0800 (PST)
X-Received: by 2002:a19:4b45:: with SMTP id y66mr315330lfa.482.1606162539472;
        Mon, 23 Nov 2020 12:15:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162539; cv=none;
        d=google.com; s=arc-20160816;
        b=aB1IKJZwnN9V76cTpXUZRHLbn6//V48XUGqKQs4mJ6sBfEA1gsEWd0NsBlfAGcOZI+
         ScgqtLnDjxTaRpiXi4aJWhpmPA/jr+jeNSt7+TMOaQ/8YaZmsQsQhDn9zP2NCpHTcsb8
         W/OTMlEjbVJT3z/mIZtAdYFLw2dVYW2IjR3ojun6jaJOzBcmOAiI6mRDySRqC1COUZPE
         diD2d6RMFXrGM32VNm+y4/jw4T0Hu/vgnxYywBoECZAnsS+DHW3Go4J1kwo0IJcs4kbK
         Ew+fn4VRLopi5NaLbI9Uc8dTTxzv+qBXzw3tOoYSo6yb6EaOgYZpwIXzx+iVQTKs1Axw
         eIUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TwVlqrzbK9OEiBxZdI+rhahWnVEZAm2Aq662xuQkBRk=;
        b=JhwmBEufXP0eAEF8WrVemFFQrS4rSacquakH5o/MFUC9/g4t0ymVq00vw2KOYT0jH4
         EzSd8s+MvTRvsjrFpO7g5pW1zwxpJX6Lh95Y82QiJ6WuY+dgMdbp06m2TS1Nq2wE0Msz
         klz5iIcHuyye41wTOoqXQI4OjKn3WYM52r6QHFyJ6dwjjMhGlYWh5RHZUYH4CKL/9fw5
         /yrZxGbuw/ygejhOeoyFJ8293fiATpjQ4pTvo1KlxxGiLpUfWsktJeYFZXCMc5DpFQaW
         +0QO9AZ/kdaXLIZp3vTliaRoU+3QUFe/fTPLMFWw95xk7//p+HR3SL1b1ry43Itkr6pR
         wpxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uqQ8B6Ep;
       spf=pass (google.com: domain of 3ahi8xwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ahi8XwoKCY8t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id m18si404829lfr.11.2020.11.23.12.15.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ahi8xwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g72so155442wme.6
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf09:: with SMTP id
 l9mr646052wmg.54.1606162538948; Mon, 23 Nov 2020 12:15:38 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:49 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <748daf013e17d925b0fe00c1c3b5dce726dd2430.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 19/19] kasan: update documentation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uqQ8B6Ep;       spf=pass
 (google.com: domain of 3ahi8xwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ahi8XwoKCY8t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ib1f83e91be273264b25f42b04448ac96b858849f
---
 Documentation/dev-tools/kasan.rst | 186 +++++++++++++++++++-----------
 1 file changed, 116 insertions(+), 70 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index ffbae8ce5748..0d5d77919b1a 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -4,8 +4,9 @@ The Kernel Address Sanitizer (KASAN)
 Overview
 --------
 
-KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
-find out-of-bound and use-after-free bugs. KASAN has three modes:
+KernelAddressSANitizer (KASAN) is a dynamic memory safety error detector
+designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
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
 
@@ -140,22 +131,75 @@ freed (in case of a use-after-free bug report). Next comes a description of
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
 
 For tag-based KASAN this last report section shows the memory tags around the
-accessed address (see Implementation details section).
+accessed address (see `Implementation details`_ section).
+
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
+The ``kasan.mode`` boot parameter allows to choose one of three main modes:
+
+- ``kasan.mode=off`` - KASAN is disabled, no tag checks are performed
+- ``kasan.mode=prod`` - only essential production features are enabled
+- ``kasan.mode=full`` - all KASAN features are enabled
+
+The chosen mode provides default control values for the features mentioned
+above. However it's also possible to override the default values by providing:
+
+- ``kasan.stacktrace=off`` or ``=on`` - enable alloc/free stack collection
+					(default: ``on`` for ``mode=full``,
+					 otherwise ``off``)
+- ``kasan.fault=report`` or ``=panic`` - only print KASAN report or also panic
+					 (default: ``report``)
+
+If ``kasan.mode`` parameter is not provided, it defaults to ``full`` when
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
 
 
 Implementation details
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
@@ -304,15 +351,15 @@ therefore be wasteful. Furthermore, to ensure that different mappings
 use different shadow pages, mappings would have to be aligned to
 ``KASAN_GRANULE_SIZE * PAGE_SIZE``.
 
-Instead, we share backing space across multiple mappings. We allocate
+Instead, KASAN shares backing space across multiple mappings. It allocates
 a backing page when a mapping in vmalloc space uses a particular page
 of the shadow region. This page can be shared by other vmalloc
 mappings later on.
 
-We hook in to the vmap infrastructure to lazily clean up unused shadow
+KASAN hooks into the vmap infrastructure to lazily clean up unused shadow
 memory.
 
-To avoid the difficulties around swapping mappings around, we expect
+To avoid the difficulties around swapping mappings around, KASAN expects
 that the part of the shadow region that covers the vmalloc space will
 not be covered by the early shadow page, but will be left
 unmapped. This will require changes in arch-specific code.
@@ -323,24 +370,31 @@ architectures that do not have a fixed module region.
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
+2. Tests that are currently incompatible with KUnit. Enabled with
+``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
+only be verified manually, by loading the kernel module and inspecting the
+kernel log for KASAN reports.
 
-pass::
+Each KUnit-compatible KASAN test prints a KASAN report if an error is detected.
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
@@ -348,46 +402,38 @@ or, if a KASAN report was expected, but not found::
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
+There are a few ways to run KUnit-compatible KASAN tests.
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/748daf013e17d925b0fe00c1c3b5dce726dd2430.1606162397.git.andreyknvl%40google.com.
