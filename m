Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHNO6D6QKGQENEXSGDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C9EFC2C1563
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:10:05 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id q17sf108943wmc.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:10:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162205; cv=pass;
        d=google.com; s=arc-20160816;
        b=NgWXoSTI66ey5BYbtR1JqiLx6sOtt3shjsdDPHx6My+a2fdTZfE4kCNrd/CbsrflNP
         orOCkPbL8VxzHfLZh4fZkq66iFFN9dwkiEXQdWKacxNA9zl3XL4GM7CEMzRg8P8bhf9B
         6GWFjhRJqB3bgjyRDnimF05VHaQ/YK0ejTplGc5MCGGOJd1CaUvvrSkhzHX/f49u5031
         zDCG0TE9jgd6fkF4MHZgsv1vJifvynAB5LXIv+SpVjUc6o8Unv7ZNdfoXyp6sbKxfX8Z
         Z78VoQWaUYdtNbyE0ePsUAmrIjRwyOABZ7m5COou+7B+fFmr1y+MA282sSv3+D4nCh+v
         jHXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=rFPn0LgjUWOOoEc0xeE9OmjxejDG3KasrL6fAH8EPYY=;
        b=gtZy6s8BMJLmH6Ygk6ALw7232Ddrfx3+bzu3VCNoLzIfOgZhKYsR82PdPs5qeE0f3g
         Q4GaJsZYCZPNSHSjytadsAEPOm06FcIhdsybIsQrxV0g0GW91kJPLfKuhIj6ZJpUzThH
         QmOyg3oavWJhR1jb8OFXX+8A2dp2dCa7Db6aFtLLeJ5K5Xv2UiVUJpDCHbxJY1ZgELX1
         MOwPjulD4Tf0BNATsNpFwDQVdqODFpTqsgjuPZsL3CoxJeqg32TK2/slhLj0zfjo6gvp
         dj613KRAfyEJTvtXfQP+N2GFGxhH4zSdGgkEo7KeG/OoQcIYbtp+xtoespmvWArmsSNw
         UJdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CUnuQ1rc;
       spf=pass (google.com: domain of 3hbe8xwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HBe8XwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rFPn0LgjUWOOoEc0xeE9OmjxejDG3KasrL6fAH8EPYY=;
        b=Ao9MhE+W6TKwXsYsTanK+m08WgonW7r+kNYjytge4tEt6fRlmn5lcPV79PsnfGcJjD
         Vcg9S0MIFC06RpbCl5LHzf1k5fwf7lKCM6LJ52uxaz6bCWF9j6VqqC3J7pj92tb57q/z
         +8OzMun+sSvtZ8XE2CSIHFPPooQzqxCVOe+/UW6KIOkiHq8Rb7d3xkGAPeTFzEwTcyDl
         3Bja92QmD+3eQnrz8fQZlzIyrkuW04Rj5XcWR9jssbisaYS9QHU4w03HMNEVTSb3hq/P
         NNjYGDaWf/mrlTE4z5YeaalIuI8kRkYifr+g7olDPCOFV8P/U8PeKJkOi75DEe2AghGb
         G4cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rFPn0LgjUWOOoEc0xeE9OmjxejDG3KasrL6fAH8EPYY=;
        b=FMPzT8cDzdDoXG6RQ7o3CW9spaWdUCh9F3ZqrKyTUk6EcMV3UADsYfr7WClIRxQtLV
         V5qrMJ+4tB5sRWPp5XMVS7tpEsWkD6/SPWJZsDqb5sUNlmJ9PSMP6PmAh93v/cctLTVM
         +73XCApsR98v00KKO2fjDXCMtTXrBad2ZyEYtAWtCiyeul1BQHjTHyX1K/dvEY9j+kEP
         QBBxroKOZSiR3uDEn1Vs9QeD9CVI+FBZJd2az6NLf99yAjdWB/YRdNGXVtWmQEY3QuxC
         E6Ey31Zk2mYXQ/IaQxtFGpb4wtU7x6jeEjmL92mVfOKu8gXu1dUzLeAGS53xrlMCfiOe
         Y2Kg==
X-Gm-Message-State: AOAM530B3u2ip0Fj/9WcKGAePB2DkzOcmdQs0A28SNa4MsTbvYgCNUeh
	zsU3TUU9v9oVPSby9JMZSBE=
X-Google-Smtp-Source: ABdhPJyjd5QY2qQNHSZ6HguVIso7aN1h0ao1OFhAoetrCPaGfNoG4M/IV1dzPOigJ6VOzFI28u1CBg==
X-Received: by 2002:adf:df86:: with SMTP id z6mr1477892wrl.57.1606162205551;
        Mon, 23 Nov 2020 12:10:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls8967417wrp.1.gmail; Mon, 23 Nov
 2020 12:10:04 -0800 (PST)
X-Received: by 2002:a5d:690a:: with SMTP id t10mr1451986wru.203.1606162204829;
        Mon, 23 Nov 2020 12:10:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162204; cv=none;
        d=google.com; s=arc-20160816;
        b=bhsulb9gIcFwzstrruDK/QtrlWRevwBKjQX185H8+6lgJ37PK41VPUmW6UXJqQ6KR8
         zsheAeyDvEepHsbnI8qPh/jxZjt+TeVr2nDTvA6XbPZvxZ/0FEoNNcmblH8WOgYgcFHr
         dOt4fXycLG9JFMKyzKwpIXc3p/StnEl4g7tiQWbGjSsmxCrmOOOOQ1UqimiTp/i2l/XR
         nHhiBUtfhGJWGr50tkHTRTGF6dNNpCkv8zsphYN7BxnXnIBAg0imYePo1yfsnxtwROGj
         CRucfcn4cH2QZwQ71lLIpfOtmrZX4LsMpkSoGgMDybfrES9vYrwrogMZoXElpVwY5X+S
         4+JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TO3EiNiPW3ajIGGCuCUB1KG01MDOhW4FKGu08Zilufo=;
        b=uh3tlmT40eYEj7dTkf6AE9JL9dEnAJlu/x0XSv0QjFlkUjFZkA9CR7K2Ax5068LFIn
         9XetJ/96HnZ4Qi36TWz8RidB59I8XNqAf/fFQjbNMpuN8unoBotqTskxqMnEBPtyM9KB
         hdQo2CXoVyr1Fwi/gr/0grNVJJZq4VY4dABOtMAWFRa9RBUaYrrI7zTszseG+1hBBNco
         sB33QMWnUGPCphmNqyknaVZEcaCG6Ir7VlmSiUVmxbcmBM/bmk1gtozv8Ikb1+fjPVDV
         zR0cmlOsdns4ALAiPVAmONr2OYFpsAylshgLvLSYEA7ul7poyON0hBfg1VEh/gBQxUK6
         XMLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CUnuQ1rc;
       spf=pass (google.com: domain of 3hbe8xwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HBe8XwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c20si17255wmd.2.2020.11.23.12.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:10:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hbe8xwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u9so107173wmb.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:10:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4909:: with SMTP id
 w9mr587797wma.15.1606162204374; Mon, 23 Nov 2020 12:10:04 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:05 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <20ed1d387685e89fc31be068f890f070ef9fd5d5.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 41/42] kasan: add documentation for hardware tag-based mode
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
 header.i=@google.com header.s=20161025 header.b=CUnuQ1rc;       spf=pass
 (google.com: domain of 3hbe8xwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HBe8XwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20ed1d387685e89fc31be068f890f070ef9fd5d5.1606161801.git.andreyknvl%40google.com.
