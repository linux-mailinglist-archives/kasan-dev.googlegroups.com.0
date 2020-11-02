Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3G4QD6QKGQEUBFVNHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DF272A2F2E
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:06:05 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id i15sf8289404qti.7
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:06:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333164; cv=pass;
        d=google.com; s=arc-20160816;
        b=0w/VKg8m+GNCvOD7GNGtRNLMJFxkkozDQrySJRgTSoZYkk0O2UzzV/L5DPSlFBJc+T
         YsR6+oopBG4kZhagzX6pRXLMNnBoY8JaTW/ff9Rgzqm9yonB06qfBqJMq1Vf0vHnWhc1
         pvR1ksKgDt76qLthLgphqKHmLQEhTEzqMzpc8qFoUYpIae1gXVsqORTJokuNngX9cvdQ
         pE8KbDNTKN4FOCWoWBzaA27JdZhJaXuIc6AIsKEO9pT76V+QF5dyepXvqcCGxNlBNdMX
         xIB9UtuzhQJyKcAWGxCEcH7UTxjmDNlHY77YYTF+Ufju1DJUSMKcf84aqIyWAIpzU+YH
         jUCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pF/JzUKldSckDDtVY4MHPyWKFQFFM6dJF1Xx1uDJfp8=;
        b=vFtv0nPJ/elExMjTR+FsFMtR7QSsRs8StjdoKAx6CuTezhq3g5P//mzyea31+JIAbQ
         fQWB5gmCHflEBABj55BRdWr1aOa8Y4i9j4PPvSGkYEcFtkz4/I1mJDv456NoGSPY/XjK
         AzKp4w3dTGOrgJwZgwp0hM7T7Z7eJevjSntBp2jze7swjZTITYpwwodTN3x/oNGtVDN7
         sK8EqYW4yNZjtSkDEep7axjFDoFKNYVldAigNn4H5q0CJIdNEw9a2ykWoyHDihy86ezf
         R3wCxdLtcnfXZ3hoIecmrLaLbh4kpiHyz8cfRzAW2b09OTsX3ftX0RWXtyLECv+OIcBz
         jFAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SPOwEKxi;
       spf=pass (google.com: domain of 3ay6gxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ay6gXwoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pF/JzUKldSckDDtVY4MHPyWKFQFFM6dJF1Xx1uDJfp8=;
        b=i9O+8imAfcVzQeq7GJD6ddZKysDZE1czBY6pqUK8n4NJSsq3aocIioaAXTgQnr+x0v
         ecA4mTStfsqbC1QZgOfRMZA7K86dNrZCF8tuY3UQV0kzX4E7N7F+ByCgi0i5XWX1OwJK
         n2jyaMQAfRvP5Yl9rkGIrJB04K/H7OibmioyYb7ocZtmeMDUB4ZWuy/N9Bnqm9699vOI
         5r6Yh2Lkbkbc8/HSHhzImvaClRuO2h9s2bAqyKnVGfubbx1WeKq5aftzgoOV3nzApkXv
         iQrU/2bSFm9N44VLoEtMnTYkvbTreEz9uEFx4e9TvtZg0Sx+Mzqhqu+jjTIm940/DeW6
         f65Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pF/JzUKldSckDDtVY4MHPyWKFQFFM6dJF1Xx1uDJfp8=;
        b=ArlJof9Hl8puWn7N+AombqB7s2nxQsuivnmFw4ERuv7Tnx1mZE7oQ8LOGaAYny/lsx
         1b1b+CdrYSvnPpMwKbg8zq5V4DOI7n0sii07+9+8ws2g4zAGuAZ7t4zOM14SfAul13NG
         uw2M1McMHF2atJS1WpwX/gkiGfDRnCHbbaDpQ/Hd4Pkx43uUwC9RMOUO+My+q0EDubHa
         14TbZGhHuQXH4D+V+mcWIKg10Qg/x//z4EUanTtC3IS/utaY1fKgClqv9imk2IQqAlBP
         2q8UWU0eHxxF+Q7bvrDhPT4jaiwgE5EzJZrczB3mtFGehv2QyBhAUMkD8PSSuZiCY4Rj
         wnJA==
X-Gm-Message-State: AOAM533VqekXHqRsliQIxClHRTCUZA9ClYUG8dFKgF2PJMYM78dR3Fmf
	oltb4E0sv2ha4rLaA9cjU8A=
X-Google-Smtp-Source: ABdhPJyT6Wav+2vT1q8wpzXs3sv23ZYjtRrETt8t4i+lYN/YBpHjbqFlucIVfReUTc6JaXRAwdImDg==
X-Received: by 2002:a05:620a:4141:: with SMTP id k1mr16050578qko.60.1604333164211;
        Mon, 02 Nov 2020 08:06:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8744:: with SMTP id j65ls7075208qkd.1.gmail; Mon, 02 Nov
 2020 08:06:03 -0800 (PST)
X-Received: by 2002:a37:a9cd:: with SMTP id s196mr15754189qke.30.1604333163593;
        Mon, 02 Nov 2020 08:06:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333163; cv=none;
        d=google.com; s=arc-20160816;
        b=BLEBuJizvaDYu2cOdc/wbdVr5sOQNZRBd8crFXvyOLTi4OJm756lHR4ZBMipXOpRIv
         dBaaWT7S98nsWs9NucVExAr7z5uUCr3EocMMwzdaPcjceR7uBbZ8B2UdUYcoFMI94vrF
         W4zdJWvL4YBh573Cj3TJhFvA8BQgjd3+SnuxQ63zTORjvLi26H/ku+KO3Q5v5OgSj8dv
         zwdSSi7ono/X9/B5tx1msxxILvGfw8V5dNyZCEcbS4LbGf8ZPiQXoumqZhGlK0XtrfI6
         Are3Tslxox6pyQi4TqJ5kVWxG0V9CbOttlpTd5DRFfFZMLTtUOwtn1F+YrTTqj9RotuV
         C8FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m61njPxPjXbU7KpGf2VpyrS3MAG/f/HeOixCOkKzSfs=;
        b=ylCK9hMNoiNEcUdFZX6imEYL2twmgs1ho4UyGNKVAssqH+IUGJymup0iQ3WC+deoJh
         zOb10BFJG5D5hqpSBRSRfphk6ETl29y+15mPBeDEgu2xPM2gslQ8BZS1XpqC/3FjmLWg
         oO026kez4qNCRjMnP1TKRp6I8vTmlCJahwpjPwvxQ1to3Q9UNVzCn5NccSuvifV3Rqmt
         tnpgOB+e+OSxo/edF9uJb2AXqlzsUZOyYXnJcToJSDxuVn8LJu6nu42vVQBRJNIDYZ39
         boG6T1C2fTPPepOOtsruZlaCN35JxYdiNBzZgPcvv90pmE1aMjbF3rzYYZwR5kEIpP6U
         ngpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SPOwEKxi;
       spf=pass (google.com: domain of 3ay6gxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ay6gXwoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id o11si897394qtq.5.2020.11.02.08.06.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:06:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ay6gxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id y14so8289155qtw.19
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:06:03 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b525:: with SMTP id
 d37mr22911256qve.31.1604333163190; Mon, 02 Nov 2020 08:06:03 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:20 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <2948a9756e2659c5a5e9e94ad7519a9b9c88ed85.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 40/41] kasan: add documentation for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SPOwEKxi;       spf=pass
 (google.com: domain of 3ay6gxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ay6gXwoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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
index b6db715830f9..5bfafecfc033 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2948a9756e2659c5a5e9e94ad7519a9b9c88ed85.1604333009.git.andreyknvl%40google.com.
