Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUPORT6QKGQEVQKJHDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 23D8A2A7153
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:50 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id s10sf103613lfi.15
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532049; cv=pass;
        d=google.com; s=arc-20160816;
        b=wZYy5cFUmOrIb9+o//gR4Qg1swbXIBfhRJ1NnIZ3WbIG7TpXeHENebz/Ek6Le7fSWY
         TOLQnXvdBqUEXCU+U1TQXyb5FWATIevkfUXzmGaUGRKvdQ5vd/KHmKDlr5JI9cRP0RCd
         RfK0DMXwMBijM3NSN9R3nGk47OQtUPEFk+Nk1O8WlnWlGVPDSBi3u6wHSrrtzf+986gh
         RXR1bYhNl4pLK/FN7jch4qG5ECa8kpvAkG7HEbxeC7FroBtvKt7tZpJgHPoKpSQZXo3W
         H80yEu62dR74azYC4g0OKxyWEf3jlHqI86gcCLd3Nyq2JImhcHAo7L9dSNV/0/VDD7ff
         /V6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=H/XdFYFtfR1q+HVEx0LCrIwjM1v0upjLar05CbNyiDE=;
        b=PdioZAmeQuLE0GXjQnBhmHrk5QQAIUGGAm/Z+3SePXJsr1LIwMhzGC+mvv7NczKbbh
         50u7ncf68hB7FgNKR8MmdwKZNqFSf6k+gZxoOYyqcGFDwfBrS/ZwBqz7wxTOJ7OBwOnu
         VthepBKvWehtu9NzZyXArHFcnJnqzkaG7ZMca+mDRYiXcRFr1qkRXt024Qqw6//YgkGI
         /Fa7oCCEYr0cJ0EtiqCMNpvyUKU/G8EtYMqiRm5MtRVK8VqjaeCA3b43HVz+2QdU05K8
         SLeztdosEwRuNhILeZ8W39pH2eeMm9mtgSEVCeeRgCkrLnUCBEEEz0pDzUmZZRf8xXnp
         y/ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VtBS5tip;
       spf=pass (google.com: domain of 3tzejxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3TzejXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H/XdFYFtfR1q+HVEx0LCrIwjM1v0upjLar05CbNyiDE=;
        b=YXTjQXIvZc96zx+gd9wJzJFqn0QvyweYV2Bxg/9C8Gh19kwpADNd3v189UFdTfYRDT
         IFlKpgcYZQqTXVL3tnArTDDWSNdjOiPl/nxwEhJ241X1szBxl92eBhBjhSYY4RHUIemJ
         kJEQmI/nXA4nd7X1y3m37fueTlITwzuD5VWcOBaBB3QxfyHN8ASdjR52QQe9kjemIdV+
         8Csaz1aQJxZMMFUu+BOTfEJQGjTlBQl1Fpn7qmAPPSGy3kJdWAqK6jnrFRP+xN9cB6qI
         cFjo+b7K4dTxPh8g1BFkbJMjVesBVftRmy5Sd9C6oXRgPAAYwpcM0e7TB4AXQx0Q0oDA
         7w7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H/XdFYFtfR1q+HVEx0LCrIwjM1v0upjLar05CbNyiDE=;
        b=ip+iRwGhTQskTDO4OLo+ot7KJy6QgCTbQayCZnpMJBhwFHC5/SOIqAtXr6mEjB1k16
         noBe/EwC8b6Lo5VbU3vvNPz8AquDzpGumknz4A++iGs8Obb4Jg7Xlgj38PMaI06UWuuJ
         ndi23ZEA2rJdCczBkt3LDmgOqNBFTxwzvVNxSdhYspoEiXxTlUtLwX8TOG9eh6eY/Rnl
         A0KdtnLBX8qZ+QUpIsRFzUhsa9FUFClDdRr04/OB5n/cNJERhyLHc12ec5jp3PdcKrI/
         zb1emdMc45tAZpTPznMizk2jOcnnyUaiwzYkNiNPPxoG1dElwmtMcWf+xdziacD/KZ/c
         LrTg==
X-Gm-Message-State: AOAM5319onRzkPlnxlG0Skq5ckR4AgWgYUSsFoSl8/GRjHgW3L/0jO1X
	fJg36NLjztw2z5v7b1Axk1E=
X-Google-Smtp-Source: ABdhPJxJzomnh9LrSFwaLIjpv9bypVyGdnEEFV5QAmJKrQV0qe03mvs/JouCdLtKh+RV5FMk2zbmQw==
X-Received: by 2002:a05:6512:6ce:: with SMTP id u14mr19061lff.269.1604532049711;
        Wed, 04 Nov 2020 15:20:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:998f:: with SMTP id w15ls671460lji.4.gmail; Wed, 04 Nov
 2020 15:20:48 -0800 (PST)
X-Received: by 2002:a2e:89ca:: with SMTP id c10mr122949ljk.322.1604532048629;
        Wed, 04 Nov 2020 15:20:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532048; cv=none;
        d=google.com; s=arc-20160816;
        b=B4nZDhowxv43HQCNV+yKH4WVSAS2fOs6Lockazrx5eg49agHfB2eg4gVRkUF9Mkybh
         syxbB9pFQkI+QgNo65nbWKdizyEcLOJZOhmztqYqcZDSPraNPdTn/PGLyNtwTuN1q7Z1
         FaVLtoM88hE8VUxaHkn1wD7oOOKyvhMW/Su1BGG1Lzt4+thlq+wzR9xPnNPRHtKQAzwy
         5CFlNqamEOULfmfdb7Z9kpJ3ju3FMS605lvrbLJuX1GbVV/DXXv9BsNXgXx/7+DImEFi
         R/DY0HBZmIXyLTB5YqPvnHtA7LCoRL1kRhkm8ucN1Qso9tw8/+m0CVTK+BINYc/W3Fs2
         A5uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=b9SnV6dyF/NNz3ylZbPzVHyY+ZwsvRStMTdcsqRrxIk=;
        b=tSh/okQqDevK73lP+Xx+RLCFpIaoEfRQ4Fy8g/aCj5huP3/zfV8FW4oieeny3o3jAD
         uJXNoetlMWxvFlzXtaSW5LNskodkf+UWkUaUkUYBt5ehr+gmQcRr/jI7YsWzeNSOn7OV
         ZWExZOcGbMHr+wOh3vl1zw/nsbTmPHW4ByFSLGy53ispOJmD+qBNrSJuI1Y/GlVyZSnQ
         w6EGzl1RLPCx+9KO4MQfeZm460S9n8MLTDP5NP4qJpbk1SrK0fd96DBB/bZTjqMc45+5
         j1fjbQCEGL1EQWcyPMoyYxqL3gCr7H/RlkW/AZmxbEMSv2SIoELR/xrk/B85TWZ7kTRy
         XtvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VtBS5tip;
       spf=pass (google.com: domain of 3tzejxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3TzejXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v24si116714lfo.5.2020.11.04.15.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tzejxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id t201so30806wmt.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7418:: with SMTP id
 p24mr102064wmc.36.1604532047923; Wed, 04 Nov 2020 15:20:47 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:57 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <8c7ee6f573ec10f8f5b2ee32b7f649d479691349.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 42/43] kasan: add documentation for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VtBS5tip;       spf=pass
 (google.com: domain of 3tzejxwokcu4q3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3TzejXwoKCU4q3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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

Add documentation for hardware tag-based KASAN mode and also add some
clarifications for software tag-based mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
---
 Documentation/dev-tools/kasan.rst | 78 ++++++++++++++++++++++---------
 1 file changed, 57 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index edca4be5e405..422f8ee1bb17 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -5,12 +5,14 @@ Overview
 --------
 
 KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
-find out-of-bound and use-after-free bugs. KASAN has two modes: generic KASAN
-(similar to userspace ASan) and software tag-based KASAN (similar to userspace
-HWASan).
+find out-of-bound and use-after-free bugs. KASAN has three modes:
+1. generic KASAN (similar to userspace ASan),
+2. software tag-based KASAN (similar to userspace HWASan),
+3. hardware tag-based KASAN (based on hardware memory tagging).
 
-KASAN uses compile-time instrumentation to insert validity checks before every
-memory access, and therefore requires a compiler version that supports that.
+Software KASAN modes (1 and 2) use compile-time instrumentation to insert
+validity checks before every memory access, and therefore require a compiler
+version that supports that.
 
 Generic KASAN is supported in both GCC and Clang. With GCC it requires version
 8.3.0 or later. Any supported Clang version is compatible, but detection of
@@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures, and tag-based KASAN modes are supported only for arm64.
 
 Usage
 -----
@@ -28,14 +30,16 @@ To enable KASAN configure kernel with::
 
 	  CONFIG_KASAN = y
 
-and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN) and
-CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN).
+and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
+CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
+CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
 
-You also need to choose between CONFIG_KASAN_OUTLINE and CONFIG_KASAN_INLINE.
-Outline and inline are compiler instrumentation types. The former produces
-smaller binary while the latter is 1.1 - 2 times faster.
+For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
+CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
+The former produces smaller binary while the latter is 1.1 - 2 times faster.
 
-Both KASAN modes work with both SLUB and SLAB memory allocators.
+Both software KASAN modes work with both SLUB and SLAB memory allocators,
+hardware tag-based KASAN currently only support SLUB.
 For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
 
 To augment reports with last allocation and freeing stack of the physical page,
@@ -196,17 +200,24 @@ and the second to last.
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
-store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
-uses shadow memory to store memory tags associated with each 16-byte memory
+Software tag-based KASAN requires software memory tagging support in the form
+of HWASan-like compiler instrumentation (see HWASan documentation for details).
+
+Software tag-based KASAN is currently only implemented for arm64 architecture.
+
+Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
+to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
+it uses shadow memory to store memory tags associated with each 16-byte memory
 cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
 
-On each memory allocation tag-based KASAN generates a random tag, tags the
-allocated memory with this tag, and embeds this tag into the returned pointer.
+On each memory allocation software tag-based KASAN generates a random tag, tags
+the allocated memory with this tag, and embeds this tag into the returned
+pointer.
+
 Software tag-based KASAN uses compile-time instrumentation to insert checks
 before each memory access. These checks make sure that tag of the memory that
 is being accessed is equal to tag of the pointer that is used to access this
-memory. In case of a tag mismatch tag-based KASAN prints a bug report.
+memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
 
 Software tag-based KASAN also has two instrumentation modes (outline, that
 emits callbacks to check memory accesses; and inline, that performs the shadow
@@ -215,9 +226,34 @@ simply printed from the function that performs the access check. With inline
 instrumentation a brk instruction is emitted by the compiler, and a dedicated
 brk handler is used to print bug reports.
 
-A potential expansion of this mode is a hardware tag-based mode, which would
-use hardware memory tagging support instead of compiler instrumentation and
-manual shadow memory manipulation.
+Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Software tag-based KASAN currently only supports tagging of slab memory.
+
+Hardware tag-based KASAN
+~~~~~~~~~~~~~~~~~~~~~~~~
+
+Hardware tag-based KASAN is similar to the software mode in concept, but uses
+hardware memory tagging support instead of compiler instrumentation and
+shadow memory.
+
+Hardware tag-based KASAN is currently only implemented for arm64 architecture
+and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
+Instruction Set Architecture, and Top Byte Ignore (TBI).
+
+Special arm64 instructions are used to assign memory tags for each allocation.
+Same tags are assigned to pointers to those allocations. On every memory
+access, hardware makes sure that tag of the memory that is being accessed is
+equal to tag of the pointer that is used to access this memory. In case of a
+tag mismatch a fault is generated and a report is printed.
+
+Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Hardware tag-based KASAN currently only supports tagging of slab memory.
 
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8c7ee6f573ec10f8f5b2ee32b7f649d479691349.1604531793.git.andreyknvl%40google.com.
