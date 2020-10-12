Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIUBSP6AKGQEXMU442Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 51C8128C319
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:28 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id j13sf13041149pgp.11
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535587; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fc95+OlLPepT4ShTDCHcKVG3oFOlGRTdapSIkpHmxrmOkV4+DKm+nS3WOsHuV3dPUr
         sWrHdufCMlZqbdfVKJD72FPRmU7JIRwmqCorC+62Exoz9/6FKUFlWnSrUi/5DiLprvJA
         GZBKLDw+joCm2GZynOY+AeIG9UaKmUObV7jpxuIY7rft9GZ89S9RZNYmHEu1AQqxYTXa
         tD+azkc7etayXBUA3+oa0hOZsXWUcotef2OeCGpgCK6q/+2Nq7XXPb2qrXRnFll4yGtI
         HlwNSLEN61imUlm1oyBhmAsQ0+NyVszL9iUYPAbgIiZYKggOT/olNbh8akuIdvdyF0vC
         t3zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xxJvMYEg6pfpSbr2ecysogRxoY7jyZOclUrBE2Assq8=;
        b=M5V+2pDRRsyKZ9idrGfD5s0Cr+g9EGV4bLuklHtW+a7MegWw1GnEQQGegyKC4ckKoX
         tArJTNgNbA0MpLErTYvDWYldqo7IaEI5JU2lXUA0mPZX3V2rAhhEJfXHl9K+ACP9yBYo
         49TVqjTQKal+wsYC/vsD2rQpwpaWps7Ota/FL7EScQ9U2uhbshRIRRGaKJZF0A5TXmwn
         7/f9w2x+igVW9xMv59fE5YG15KeMTOkT8Tw5G7aMXXbrPyA326kQgpyenifRhxx1xlos
         PbnZEV8BnPXwfX4+Y2s6IQo37MEcXbvbzqNl7DMqzCFe+aQiJ+DruSITOvzpdqq4ldkC
         EYaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uRhsz1DA;
       spf=pass (google.com: domain of 3occexwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ocCEXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xxJvMYEg6pfpSbr2ecysogRxoY7jyZOclUrBE2Assq8=;
        b=FYdsH5tAcmvmg0xKMoumKLGe6Fui6RRKYTAEJL4B8Ai7aWgBCpR9RA6k+3fGC0w65i
         DdmtQ+C81rwgpXbnh7fzZzbax4HZ36y5tOJTqzXRxl9DFMbIWAx6sq9QchMI754uDuTu
         yqnojH3bgmNMIb1tuL+KDU+E3+AZLSR9Z0ERSwZkpy9onJCqEEotjQyK33vSchIWZ6bv
         XxOTsdbtoSdaWhNlW/ho6qnKaerVmdXn5rYBVWP/VGMvBerBosYned0te5q28Oy3/OVm
         k8dDsYvQ7Loi5xqlhhYIQOlTXGt4+9DeyrfOHmAREc+JPlkd+EWwbGXIQGdcAq39yIne
         hWxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xxJvMYEg6pfpSbr2ecysogRxoY7jyZOclUrBE2Assq8=;
        b=RvXRjYDCFz5uKZaGt+Wb8Mvj01MeOckhdC+IWUsM6xRjLKLQJ5z3/LXLU76aO2pDY+
         13pE4vlaYjUe3le2PTllQs0MJM5o8COeT8TSGuV2Y5qmzrl9gzjFOsYaPyx1ERi61qAz
         6249AFyCyXvAcLIglBD6V0PiqvZEiirH/Bp1NYs5WMPxICY0r+Tt3Xh0oYVszxdz7R9b
         zfWe/cLu1jyle19WEQYVKPhFa6sSo0ZkyMwWmTzN3moiLWXGIoodJs8bQ8a/rim6+UJM
         fsAfeRlWjvtU9y0oleMTR8R+kho4PeeWXs3CxyhQX6hP6bXDo2Qaiy3TBno8besEalnX
         Bo7A==
X-Gm-Message-State: AOAM533D1plm62PcTes7FUnE1YKaGpcP19dBUJRRyPOnow5k8WmLD2Ra
	e3AjHuZy4S7wZbGvmsKRXCo=
X-Google-Smtp-Source: ABdhPJw7WRhPfOs0B5/HI4/rKTTR5FZkvxwvrnovgYYY7HBfOmTRsRVYDlFJcLLFMvu21mtnkw72UA==
X-Received: by 2002:a65:628f:: with SMTP id f15mr15121864pgv.168.1602535587016;
        Mon, 12 Oct 2020 13:46:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4486:: with SMTP id t6ls9986794pjg.0.canary-gmail;
 Mon, 12 Oct 2020 13:46:26 -0700 (PDT)
X-Received: by 2002:a17:90a:ba06:: with SMTP id s6mr22509604pjr.13.1602535586448;
        Mon, 12 Oct 2020 13:46:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535586; cv=none;
        d=google.com; s=arc-20160816;
        b=zJZiTYid3Rmkxpo+sP76KJadRBRi7quY02pvirmtfnN05Ph/EtKqlRkaHCL34JJIAK
         Oxymob3MUT5Y9yBx8C41vHB9UHM8BNDjVKqHHNvYXX+LJt/FBneXOlc7iK6983q/eAeB
         2u+T5arzyp74PqzYfpFa0zpSwSjyobmV0Keg/zovDk20+mHApEyr72V7csM2OrYNI7q4
         TN5nVNa256PwDjrui3tK6/CYHxFLIRZY3ARRMp2jZ/yOwMtdmrJnnZ7S3v4n2jEf++57
         qcSuM01NtHBRd6x2sHxPaqJxT9JyWAbcnMJjy1ZH9S/vPAnWs+cPNr/YVOgWhmAs3GZ9
         HxCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mXt6DEHJBh08bT8AIz/MENs2tletQLWrl6oHjktxJQo=;
        b=N05e6hpBWGBetmsqbMujiVj/U7Sy1B9I8CJBR4bjhSdykrIdYMCr/OFchEo3sSkbA+
         OhFyPn5guAmjKuQKVgupQk7lwME+X7W26p5tNlm7jenW0BW5VBH89cRZ7Q0S15G0KQLg
         m0iqkUKeTKLkXvGvpQQjv6MbplkTSK/tfxWGoFQAeAtQhq5sRTiw13FIQVQjplYpZE9g
         G4bFFJdw4WPhGesaHoQ8y3QnvHAYXYiY77uypJh23R+tsV3FbJtwwKTrzUK51/Lqsslg
         xpr3AMvN3xCj4r8x8ks9isUHVLeZkUOKEHe8VrHYUdOjmTwfPs5bfmUjE8rPXwTYihCd
         WqVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uRhsz1DA;
       spf=pass (google.com: domain of 3occexwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ocCEXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id n8si1286533pfd.4.2020.10.12.13.46.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3occexwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id m11so3833141qvt.11
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:26 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4a91:: with SMTP id
 h17mr7161247qvx.41.1602535585496; Mon, 12 Oct 2020 13:46:25 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:45 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <456c419555a262461ff45670dea6d09605bd6a68.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 39/40] kasan: add documentation for hardware tag-based mode
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
 header.i=@google.com header.s=20161025 header.b=uRhsz1DA;       spf=pass
 (google.com: domain of 3occexwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ocCEXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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
index a3030fc6afe5..d2d47c82a7b9 100644
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
 8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
@@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/456c419555a262461ff45670dea6d09605bd6a68.1602535397.git.andreyknvl%40google.com.
