Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUWE3H5QKGQEZNMJFZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C28280B2B
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:18 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id a12sf121606wrg.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593938; cv=pass;
        d=google.com; s=arc-20160816;
        b=0BV5Ep9+FS5KvvXJsUcBMIx8l7IYIfu8NiPemTQhB4oMJX3TzQ+3Q8gRJpK7CQuv5P
         zQ47+5JxVHp2O60QxNjm947WqXBKEXz9YJtbvlcKq5estEvErO+s0DtqpsQR9S4JSzns
         sqIo/APXWqjE+CVMijmUeipkbXfnGM4kHORbYDV1ij1JVW7o+fr22lOOwtp98Lw+2EdG
         y+ciDfGbDN2kjknsOBRa8TaVqRz0bXUvmZa0vKwXl6ibQrFik3M1kzROerRzXDMwLrHU
         s8L+n7ZrZWvAqra6qeYm1PIBD6lwhefVskG8jeYhETS6roFj5o2XrbmyBTMtTE9nKB+F
         +wHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=h3xtx9zz9REpSzdsncOnKr92VQvGl9AvTKlYAHve/CM=;
        b=kcvroIKFnwx/MeuFaLSg6WAObBb5c/BdG8eBWNKyGTiYD0qM9XlJE+qiLSI82fbRvj
         o+S1L+ksKEN3JPjuwi6anEMKoFvSUfLtA0oTTqlOTyNCGRjiBFcBHxI4LJQ92MPrzESa
         lwcm5WcCpXBxYCsd3shn91r2MMS3D1Lgc3lLlKSVZWed6donF3gYt20i5DFCk7s4I3Nj
         dm3sHQbg+rajdd8e8sijbhUHD3oDigyY0A4WZZW4OdyyhwktuGdswcx+iUhEA/sxClWy
         HdAuVQeJopvOeoXOpYct0+LnhMOQcur6xs5ayx8Ae9YY00Cbw0ytWz1ZOkeQw56BdwVR
         DzzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T+Mb0qxi;
       spf=pass (google.com: domain of 3uwj2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UWJ2XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=h3xtx9zz9REpSzdsncOnKr92VQvGl9AvTKlYAHve/CM=;
        b=JEm32ZDE35M9kutTABvEDCsm2aE4NhE5WXt/S3qU73xxL0brm3c+Z6Yep8+W2Ev0DS
         uDHeAQ/0zURo31m9rnX8OBeKFGIAM7Sj40hOkdh6tHTLzcAaWPUqX0avMCxNr2vknOIt
         gLEIY7xo6mKy97ay0PLo//TcuxjIZiqNBeQhTp7VGCYvpMaZU4JfBQaVW59wCdWGhcOP
         DHITw+76qcPdLcxkQCPxvr3inNS16rwZSmscNQ/yVSYgT6LpE7WOigQy4jCafwqWm12s
         M0ukbYibXr7UlukOMOaLETBUaIsgRjeGND+ALcfkyMU8UON8BK/5uZ7dV3L5TYm9VPh1
         ejRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h3xtx9zz9REpSzdsncOnKr92VQvGl9AvTKlYAHve/CM=;
        b=CrL05L0MHEDHIUwUgntPKQhb4rNHq0rlTcqmYwroST1kL0ODlVq/1erKzwaUwgp8wj
         SCRiGuSzP1SMuoBY9oWuV4znopioALa4VbIUdO2fUUHWaHhxLFDydOn8g98oGkqVms0h
         hqtpszAGHdQ0kPljXm7LPaLUn23uY8wAk5+8PIBkt7WMf7VSIak3gyaBGUavjPAdwqD9
         JWQ8FHzpm8T+HIBUnczxERdnk7yLiTSJZl1ew5wNNVhcgFi/BdcHwNCN7q/vPTIGXwMQ
         JHJU4YzESmJiYlzkgvoW8HlXnNAOebkdYJVnvbTYZelLoS38IXCQ0GaFfdkLaPOlTs4Y
         tw3g==
X-Gm-Message-State: AOAM530OZgpeWQ8Imn/c/dvNx0zmW2n3Tp7LeX1453cBqTUNKAQpZ3JP
	D5zdErYcixOszFDDsbEvQcQ=
X-Google-Smtp-Source: ABdhPJwAyZpnJ+asNqyhTcnc/7xB4DXhmHSs6wyUOEtrNO9DUqTMB9mBRmXlRkUATJFMBWrz8hxZ0g==
X-Received: by 2002:adf:fd12:: with SMTP id e18mr11735171wrr.96.1601593938578;
        Thu, 01 Oct 2020 16:12:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls3660379wmi.3.gmail; Thu, 01 Oct
 2020 16:12:17 -0700 (PDT)
X-Received: by 2002:a1c:8115:: with SMTP id c21mr2313447wmd.153.1601593937787;
        Thu, 01 Oct 2020 16:12:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593937; cv=none;
        d=google.com; s=arc-20160816;
        b=QwiCShiUIAmnm84s3/k8iWh6eAeE1u2QlrfCZfYgKTrUqKw68r02ptYp3FWcAa9MWJ
         X+sGLt3ycBqZ/QktHpm9wQ+9yBt2O04qKurIdfDuIN7pw1d4xCclp6fYg3UN7eDZ/No5
         PrLlBDY6OSixoVBF48vjSj3kJjL0StAC3pdFXx614CB0dAUfGmPKDoc1GVH+JEl+J0OR
         PwNxgH8ts4cfLLreGhYgBj1JaMxRsuIwuB+0ZqEZvl/I0/3uehJso+oanNO+ma2+BG9W
         xA6AUhjSLdAqF2YA0OGRusnfTnOGbivihNHpu2jLcBo3kmP4N7Y7FasIlumPVcjhiWdK
         AC+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6U1yc3gv5wM9kLNMd9jEohPOntXTZSbqzeYsD504LQo=;
        b=vaFYUGi7kcripmsQ6Knvxm0j+lJx/IxhezRsDbKObOAWjYKXp7ajvjpgXjXbniAQ+z
         zon8oZBDSZaL3dUE0xGBKy8sSsHOMN8TfKYF/YMnsvc0E7kxc5hNIdjrpoH0jHNGRF13
         0nN1RGaSXCdBQ8sxJY1HdcTHWgM0Y2eSz0Dm6m0928IrAKMKn9JqUZFniaFDAm4s/SiL
         tAtEVhanVJOAp1pJk7fG4y3mAL8jC4/nd/EEWE0f+jC8IR0wJ1w253+RdYoUygEw80Mh
         qpqio9TP2fFYjZ5FqOXkA2tQhJoO/Gok6Q9otDjR5R2MFP9oGWHGcjBZASeAtbfWtcti
         Z8bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T+Mb0qxi;
       spf=pass (google.com: domain of 3uwj2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UWJ2XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z11si258659wrp.4.2020.10.01.16.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:12:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uwj2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id l26so39001wmg.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:12:17 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:23c9:: with SMTP id
 j192mr2411869wmj.6.1601593937356; Thu, 01 Oct 2020 16:12:17 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:40 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <356d693f2b332627f0b42c5940c525c96e6efa0c.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 39/39] kasan: add documentation for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T+Mb0qxi;       spf=pass
 (google.com: domain of 3uwj2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UWJ2XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/356d693f2b332627f0b42c5940c525c96e6efa0c.1601593784.git.andreyknvl%40google.com.
