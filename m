Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEUMXT6QKGQE7SDJOKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 24C652B2833
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:55 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id 91sf4478123wrk.17
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305875; cv=pass;
        d=google.com; s=arc-20160816;
        b=CrZQjYv0SQ+KHpEtghhypWJ4/fcDIE1fW4t8sQzYPemJqIQ8/PVvwaJK7O2bLpxYlP
         XzKsIfqTau/yc7VcGeLk31uPt8NWJQWChWYKiMDw2U6Lt5KIMcMjSpbTFgyP2q8nrjkV
         eOTQ8BlSn2cNya23yu3fkz+kbu9GLxX0FVTJhuKn7YUXUHv4remABxl8K87SFrFB+eLK
         av/dILZonTHmHscMMQwLw1QOr/o7crBugkyvNSdqFX1gDsUhGtNZnMGaWkg9ar4rPF5E
         iy6h7LxMTMXmu81IDtM7G/Rfhly8wkCT3WF0lihf3bhLttsFjbznVk2m0Dm8zJV4n0Y6
         0ung==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hVdRKIMcU+wOShr8FzETK6fcDqRNqXVgrq4gr2w685c=;
        b=Ul97hmNfhBrMlBCdWA09JdfLK3atw5bWl1Jy3xgETMX6gEpVNvgMzaaBXTEPBEQEzB
         SeYOcfqdNcAZDBYtIPexHFfw2nFBcOPZUPPdacLjoGyIz0vYkKlliGGPJJ1/g6D+WOMA
         fN6cASNws2GALdgnBf9oTa8znPA4k+aQbeHBjA9IY3DL0f27omU8JC+VXIyxrcT/uxdN
         ApPitUwSZjfVLy6PbolOASAkfBu1VFG6/NCdZExM68L7GD/Q9UgWm5MfA3CMbiGgjDfi
         c/Hk4PvXRvHNGyQUoVfPyvKwQvv+n4U7fbK9I/JEy7Dfh+4keaQdBia43V9QJ20pb2BK
         GQAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="KwNXJYg/";
       spf=pass (google.com: domain of 3eqavxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3EQavXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hVdRKIMcU+wOShr8FzETK6fcDqRNqXVgrq4gr2w685c=;
        b=lCf+ih8zLSEUPCAAWsu5jUO3tEGDguzBcyshVP7u6fH4Tf6bbgkN/7EbOs6VdICkpg
         XhIEQTRZShNZgoGSIZIqHb95Wzt3zXK8SAmjcvejMzPU/GlUOomYc9k+5QlINC9ccNrj
         W8eRxI3HZ6wTIMFMonzrPdWLoGkwVxDyhHoVYdSgS169HLHdHBcLvo0ByZl9+YGXIJZJ
         OvDRS18m6mPwSwxmjT0NMx2HCQz72143FHOUDoH1Lqk+DVIIAZBcdvRGsoUm4h7f4NcE
         Q1WEOExvpvgf2J9zsroi7LaIEIxCgP7APne8s4NsEaUwf2jXoMyGY3JGuTb3R6ZqM9L7
         xmvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hVdRKIMcU+wOShr8FzETK6fcDqRNqXVgrq4gr2w685c=;
        b=LjkwPgIN1B0BG1ByostGFmaAi5rl5wvtBTSfXcOigkb27ZgQVZELKTm6M/e7fLxoNa
         1/RopBcjsw/Xhce9x+c0pDxAbmhkPfTrqdnoFibjEn8TwiBrlV30fFCrqcRV6ivqhXBN
         tcdq/fbomjVUXB6eRM51w5SP50EeCsZnEfxiQf1wfUD41kBqOjz2C4fgwVVz8Sqw+A0d
         X+22dRMo9P9LdBL6tDD3a5OOBF1eNHLM684n9AAS5AAl8x4wsjIPMzgHNMvjS+mbHwW0
         MDq8DYuC5/iCkvnyzn/j212Rmhgk2bER87Q/N0ot7Qb7zOM0LL7fLFNiBrGseJMe20+P
         x6PA==
X-Gm-Message-State: AOAM533yyJZU3zj8JLdfM7NJu4javhANtoz8wcqlpXuoUnblVx2tXnQG
	EqfD0DcxQTK1sj9hwa0KWBw=
X-Google-Smtp-Source: ABdhPJzyIhhPJl5fsU2azNuuOWbaM7BepyyhjuyRgJ5j0Gbh+apE0g8yIrHzustk1QV62hPLONrRAQ==
X-Received: by 2002:a5d:6688:: with SMTP id l8mr6372707wru.360.1605305874824;
        Fri, 13 Nov 2020 14:17:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls3719535wmb.2.canary-gmail; Fri,
 13 Nov 2020 14:17:54 -0800 (PST)
X-Received: by 2002:a1c:e482:: with SMTP id b124mr4705665wmh.25.1605305873989;
        Fri, 13 Nov 2020 14:17:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305873; cv=none;
        d=google.com; s=arc-20160816;
        b=B9QfN80bjKbk7s258SeIwV8W480HUebW2IWnAxyiJjruLeQbwQqf32X4A1DVJXJky/
         04WpHlX85oOPY/OIGAt6/cAtWPL4LlMaf4psYrlNUaqeM5Y1AOuTTW35MQbogMZM49u/
         WsmIb4ZrGB6JVbfISkd8d/ae6yE0zugPGgkJ8pbLpzvsF+mEgANe+0nrWYTTYh1C2LqB
         8vTcq7sjoIJqX8TIJ7GvHgDdGG7pnNnP+x0EnOxSB1NhOsXEwv3KaoIYpnXbTi+G18Hh
         OAZxQAyA3LQth9kuAujaZJWjHNdTI1cj82FcJL5sSHmgRlNRx7LB9M9zwA4DnmYa0fGS
         cczw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6nAr1IcCAzl2tMgDp4OlBjDX0TewlK5sxrsfllyCaVM=;
        b=Z4tcPsWCHRu3RfSqOB0rTfpkickqDXQMW/KsS1f2kaIW+noHcMNL9jk+SwElqVIcRK
         u79LkpVukE9EAIh9onvpOeaIBc95KlB8D3vati5h88uiSVA1orDZRHmA55NgW6jFbnue
         mbduTQnNy25u7E9KPn0ix9BI+mOdtQisyqHD6q38KclmmBE0F2E9IwxrTS/y6vuWw7bd
         y2pA1BknaYnLtTK5hZQwDA/mj5CGJpabXjU5uS7dyO+RhfvESopuHbgXYGLGKj3jPnW/
         AAQuCK/qYManuWtqTaohhguNvW0XH8wL7MO85n7uzmLfELKHLlnuiKBm5BxxpexZLlSD
         BAAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="KwNXJYg/";
       spf=pass (google.com: domain of 3eqavxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3EQavXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id t1si310775wmi.0.2020.11.13.14.17.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3eqavxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r15so4659680wrn.15
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c3d2:: with SMTP id
 t18mr4684770wmj.112.1605305873647; Fri, 13 Nov 2020 14:17:53 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:09 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <f10443693b4dfd63477519e5f2e4fdc439c8c3c8.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 41/42] kasan: add documentation for hardware tag-based mode
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
 header.i=@google.com header.s=20161025 header.b="KwNXJYg/";       spf=pass
 (google.com: domain of 3eqavxwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3EQavXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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
 Documentation/dev-tools/kasan.rst | 80 +++++++++++++++++++++++--------
 1 file changed, 59 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2d55d788971c..ffbae8ce5748 100644
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
 
 Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
-and riscv architectures, and tag-based KASAN is supported only for arm64.
+and riscv architectures, and tag-based KASAN modes are supported only for arm64.
 
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
@@ -215,9 +226,36 @@ simply printed from the function that performs the access check. With inline
 instrumentation a brk instruction is emitted by the compiler, and a dedicated
 brk handler is used to print bug reports.
 
-A potential expansion of this mode is a hardware tag-based mode, which would
-use hardware memory tagging support instead of compiler instrumentation and
-manual shadow memory manipulation.
+Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Software tag-based KASAN currently only supports tagging of
+kmem_cache_alloc/kmalloc and page_alloc memory.
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
+Hardware tag-based KASAN currently only supports tagging of
+kmem_cache_alloc/kmalloc and page_alloc memory.
 
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f10443693b4dfd63477519e5f2e4fdc439c8c3c8.1605305705.git.andreyknvl%40google.com.
