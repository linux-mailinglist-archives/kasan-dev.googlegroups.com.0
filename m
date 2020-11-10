Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYVAVT6QKGQETKGW6YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id AE7CE2AE2EA
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:51 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id j10sf9473732iog.22
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046370; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qg6ZhCMjtksQ3H6ErPhrj2xgQ8UcOVfkAUkdwwIWeN0Gaak3R47y6X7rx6a47CfBlg
         o1AZYvh3Kjxn30pNLJX+ic1yNRun9BfU13uVEUbzA5yYHOdjBiaduMw60odJtqh82QhK
         fNUvwfKxukBQbxsBOMtofSZu0oV3ZsUZFP35Y4EKgabY/bclqAt1376AZHLkPGh+iBGd
         v+3GHV/pZRDsP8JpZRQDtNbfX0FEDCmwViJrFDcn8A+c4CkNSuy7/EF4vD4cxu+P92Uq
         cjvw8wSQKRRTsydWRfVFYxOvvgI1FSMm+FdbZCBYwWopQRdPBaBXUFgfkTdbwUY74qob
         9RRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tE4UoOz1mGSKFPHa0HAFnUXkV2luwTAxSF+O/U/Daik=;
        b=YMFy01/2/tbK9XkFyR+jmHcp5CnsBAnTSBl0hnhXt2lwKhPI4xm5nSERYSlLvGUotB
         nPj5Mrf5oSm+uNxcRCmnFHU2BvGtl2if7XcWEJR5LIkC38iakg8Se57uaJPqF9SlI60B
         O1lpv3pogD41y1K8r0wqFnfKv/LYoRPnYO6Asv7Q6ke3z9iP/XXulf+VDiP95yntvIFR
         Sq35AbqQ7XAv599oP6QcE2ov+KjohG9REXVM4uZIj7ZOmE9+zsXMMbpzCtLGMqnRrXWV
         lHeEvAaVoMP/LexFPkuDgdlQzAnDEB7zG+2WpRJKXKIAeSpucux1s+ebV02C3tkrGzdu
         9YXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aGwre+RP;
       spf=pass (google.com: domain of 3yrcrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YRCrXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tE4UoOz1mGSKFPHa0HAFnUXkV2luwTAxSF+O/U/Daik=;
        b=cRDqk/n50zw9ttfsz3SllicXer57xUV2seLZFd/kedaoWdpNfDlXLmuY7jiQNeK8rd
         s+N+h4L/1M0FXXwafx6knnsnHKrw6xOsh3JX8rAECo5+yplKxCnwm7/dpKTg7V8SCcXu
         b+tLMlp0os6RVQ0AYYn87FFeksbn38Xamst/zYgqeBSZdFZMlFY7uQp9a2DWkUxRCR13
         SG1f8fjmH9veAElwhkyN0g5T2zXk/hrYydBIJynWKCEh597BNNUJNIG/V0vS1c/ue9N9
         1XivhsVqElhqsJ1fthgF7r5XiZ80iKYAP1Blng3+D0n09XUrxUliCmg7b9J41s9aQFDP
         ae6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tE4UoOz1mGSKFPHa0HAFnUXkV2luwTAxSF+O/U/Daik=;
        b=dI1SHvqP/XZS9dNJBebPH8F6A97gwxMvhWVM6L+G8h1Es3H67uQDelg9kGUAvGqS8G
         Am5fjgWxaHPn7ZE6ONCNkeOXJ6HLuWrmOgoJcqRdJSSYAiDdndfRshBvqaThg6Ax9xlz
         gZqwfWjfY4PiteUn4xMcfqbg241l4ZaoVSinAcyqfWqcQ3e4X2UBuq5KYuYoKYLqf9/0
         aMKA7l4Rox78BsKjGrB0BCXpF/Fjd3to7PIqumtLtHH45aD+/p4dcKUcERvGoYYAytiT
         /zmnzGGHNEcoTgFuqZXqmGNhoD5gdVAegoPp2ry8kKX33Z6yNl3IJSe1lHtJtouk5aXn
         1yHw==
X-Gm-Message-State: AOAM531bilWco1RRyN4vI1fBCVyMc3GmQEkX19pwDhwTzJxh+qEmwcy7
	oQWy7QzMScp/Z5QN5uU1wB8=
X-Google-Smtp-Source: ABdhPJxqA3mNwRmDXRazoqen04DiX4h3gwDtdUOSGUoeKzNsAIFc/HEXXNYAtk7ypBLnYmaCSm+zDg==
X-Received: by 2002:a6b:f416:: with SMTP id i22mr15857945iog.161.1605046370684;
        Tue, 10 Nov 2020 14:12:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:d516:: with SMTP id e22ls1932067iom.5.gmail; Tue, 10 Nov
 2020 14:12:50 -0800 (PST)
X-Received: by 2002:a6b:7a02:: with SMTP id h2mr16008914iom.171.1605046370259;
        Tue, 10 Nov 2020 14:12:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046370; cv=none;
        d=google.com; s=arc-20160816;
        b=JBurTI0PZJITdzpHXAmavaUXv/bCzvC6mOHWkfwd5jDGDbR1I78OxPWZ+JLI/eMouc
         limHc3DhMDxeKtiIvbFF2FaYJTDz75dphFLzeAyFxXOjBP5JagIw5M2tvmA2MGhOkfBk
         etJCP7Mx0cmDqHKIqQtHi7MyYpCZbgE1q+DNX9S0EEooQVV9uwdN44RFZYD1gfiYhPii
         mV602yJxab8IUIc/W7VNzMJo1aNz+jF9tJE0RNqANrmPCG4Qt5C6Pz7IwX5lCbBoqMnL
         RDbhCwCXKylet1Sp1+OLE29cfGFJlGTzV9WNoYe7lc6a6cahSlPcmy5gR+r9EiD0URZw
         kYvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ler15gO3h2+8cf9drTK7+V6jTLCucggCDNqJ8LVS/NE=;
        b=flqqlM+/ADHygd2reY1/dJUkQ1NiFYvFrRU85noVWSZYZ9YQcPmm/jYiuPUCBs+LS8
         zZYAipZcz9S8pA2CYgZWqxpOQMTxUc81gRS6DhP2oSI+lgqdMZeuHhwRINzCxWTIdsOz
         xt2Iq1X8KAdnP1u/dBRiUB5kJVyJF03F3lhGZ/ZHBJ5el+xn8MddegJsid5ycNFQywUg
         9iRW2JpPgLklcZoYEQhVIzhIm6BLYzwEIG5HQMvU8SxwCYVMcAFnfRIzrk2NRfYM4xMy
         e2Dg0KQgw9+gP9rc9ernHOqtgT/Vkhyf3eq8ANEmenV8cfUAOkPYZjVfHg9pQZmDHyhV
         BxGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aGwre+RP;
       spf=pass (google.com: domain of 3yrcrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YRCrXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id y16si5578ilk.4.2020.11.10.14.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yrcrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id b191so191439qkc.10
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:45d2:: with SMTP id
 v18mr21145853qvt.45.1605046369606; Tue, 10 Nov 2020 14:12:49 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:40 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <e9077072bcdd4ccaecb1c84105f54bac5dc6f182.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 43/44] kasan: add documentation for hardware tag-based mode
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
 header.i=@google.com header.s=20161025 header.b=aGwre+RP;       spf=pass
 (google.com: domain of 3yrcrxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YRCrXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9077072bcdd4ccaecb1c84105f54bac5dc6f182.1605046192.git.andreyknvl%40google.com.
