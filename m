Return-Path: <kasan-dev+bncBAABBPULXCHAMGQEPUDRXMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 49A87481FC5
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:17:19 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id eg23-20020a056402289700b003f80a27ca2bsf17589130edb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:17:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891839; cv=pass;
        d=google.com; s=arc-20160816;
        b=HE921lj3zAcb48jJP2sPkkfY56opamMqqTNkEegFCQOoVHyYqMJKhQJRFX87b8IxyO
         hQcSCKLMMJzzgwGCDYUdg/5CnCvSBDBhRcYgXtnOPks4FCju8vul+k/O5oYYEQqZXmnR
         WaJhRSSv1GbsDaYG+VlX/qgDSufVWoxPc4IIZyqXYePLD5wRu5sYWAgnZduloAEbbGis
         zZ1edb6Muk653u/7UVlvukuJ5WTelvEK8A9Qb5PYTyVWE5y09wkcpjgShKgrlMy/HEYO
         2o1YR9Yk+SXBaTgOaLdhditDqSjjEYvljcrJca7qqqSoJohrv9/BkFdskBoHUBs3fcOi
         TqFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ShzdpxAMmrshnjSlOfzS7kla0A33feFWwz/piLXZQZ8=;
        b=dqKzD65DCTc4FcoOxrQ9GXMBiXM9AH+19wDjgu4NIhXOSC5DY1k5rRjNwdgAI+y3fx
         F5gKA0JyQ8lLu+XI73pPC1jbIOLerH9FqpgyupqMZ6oEMR74tsxvwMx3zkHuF6VLiUwp
         K4oJlD0dWWIxP+Rj4GocCaS6kNNiDB3P9S93SYrYIMpQKtGTSIBG5ZfxuS3yydiPjMxC
         tTtyLsIIIXAUCoAipdhKsxcmrgfDbwJcGv6qssxXrLwntHDCyEKuFz11Wn+zgb/WxzTV
         gofmIvlesjrQPOYDHssBDeLdKXWdoluGYwM5BgMJlIcefcMomQKTAugKaf9iIzro1/Yn
         8dOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="e/+XOYIR";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ShzdpxAMmrshnjSlOfzS7kla0A33feFWwz/piLXZQZ8=;
        b=WbGZ9Lf5/dCBDEVI8FqP90odUyfn9q6Ed4gRBWEMxh7iD83/gfa/b2KRLkPune91Bh
         mUzhvEBxBzg7h1kncpwePyLKmzgM1ShAhes0bjPyUhUQhr1wJqq/lNPC5ADwVgBVBq8o
         edib8GGeQJbhPOdkwNUm37uzeCriWKTFK0J+AC+kr3auc0aNQk7CEVSF59Ug8AXuMib2
         Fse5gcJD2nBY1qpO5yxNI1FWSBMgVnuhLJGj70Y9khLh0fCV0qxdbauvBsD6heMf6l0e
         724GyzC8ei/zhRvXOcXbadYnbvpBKuguPaReim+tnGU689rrr9g6YMLCzzIDvUAUZc4/
         oPHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ShzdpxAMmrshnjSlOfzS7kla0A33feFWwz/piLXZQZ8=;
        b=qyJKfab0DpW2TKW+RsZr+d7wsCGRsAWblFNrLiuIrwWJ5uHfIVs57GUAtyc+Jgl4iX
         zlCmKcyLpWph1y8T8LCAtTNMnKx0fF26Sm6NpPh8N1rfAyfJ4zWxjVpr/rHiU6dZKgpV
         DZlX/AD3SH78sdad67F5AWGnch90oDomOkSuEjKry3/zdD0Qht2wWv5Z5GPVJ8vSPRAp
         tVELdW0tZxAW7JyxGsdlVDm4pD8VEGq71QluUoiPAlN+Aet5m/qtkaGa5hQzUhWYf+OH
         encHcCpvJTHzZ7eqa5Fdpwlws1s9ThduUBJ6ItaDTBUqJGyYcQqg2lGDI7aC03muq5pT
         vr2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RdK/Zbok4k2Nqd0pJgY6F6vz9HfIKkpGSXx3n7i4nPzR7NSan
	ggXm8BC1ptcDFLNT+Z/VnrA=
X-Google-Smtp-Source: ABdhPJyB4RS/7TAqOqR4uPjX6vZv342nadqPJfzWWW4xlVrw2eDOkDbXLRMA6humEVysGQQW5RN9Xg==
X-Received: by 2002:a05:6402:12c5:: with SMTP id k5mr32429090edx.296.1640891839018;
        Thu, 30 Dec 2021 11:17:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e87:: with SMTP id hs7ls8515003ejc.9.gmail; Thu, 30
 Dec 2021 11:17:18 -0800 (PST)
X-Received: by 2002:a17:907:6ea2:: with SMTP id sh34mr26930184ejc.509.1640891838233;
        Thu, 30 Dec 2021 11:17:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891838; cv=none;
        d=google.com; s=arc-20160816;
        b=QCuFWL3XvHPnKlsiSEm0otl0gFcltQKfSNDwW5DDthY/vjWRVPW2usDtqAUsOLm52F
         dr2VDF7bi/qS/Q69d1rSrnFjTB08r0TCfEZkEfgZ5OyjMXOUAdrmMuXpjH6boucSwG+F
         Da8AkG69KfJI4weQCOfXTDdIcClinh7FzmN28HDUGhc5V8ReA/KQVfsjfG/D9XCgMvCu
         w/uAxAht/uyk2kyxP0am5pvmYhkvHvt5nP6X8iGXpyHnZLPDfztoDOpqtCaDDg5qir++
         Zdj8w2CLjTviHxYTr2xQMyr5szDPhMJU8zp0D5P5rV1lwICK4ILr7BOw+4hLA3PkY4jV
         l+mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV0M9szKvSlfXhwybxJe1jA9V5abexpCELFOGxjWDjg=;
        b=KCDgzRA7S8131Ff5ZAvyhiRrK48+VxtsQDjNZpiMBsz+rPkG5p2iBPmo4aku/xHQTH
         Do7rOc3NkKVzwpltp9kUzla/OXxO6VmwROgpkyQDUE+OXTqaoecFP/yaXKxe1u9cpSA7
         PERiCDaxKiJWNDsnfBXh/6dhQg5DVxtzPuQbUOZ5sidMjn5zgijSVwjpJLyR5R8ocISs
         l5UHANm4ms7EltXh5I7QHir7Lq0IR010cpUmqyO+DMmD6xRCN44J/tneNd49hhI3w+Qe
         4GTefZ53hP17wckjG1Ad7Gw2+msmDh45hyXrjcIJXqYy79YGohzxEa/F8ArHQUd4TKs4
         B8/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="e/+XOYIR";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id bo19si941732edb.2.2021.12.30.11.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:17:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 38/39] kasan: documentation updates
Date: Thu, 30 Dec 2021 20:17:13 +0100
Message-Id: <b47e56f00c2619a4033e10d5bb7c99cbf8288cfa.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="e/+XOYIR";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Update KASAN documentation:

- Bump Clang version requirement for HW_TAGS as ARM64_MTE depends on
  AS_HAS_LSE_ATOMICS as of commit 2decad92f4731 ("arm64: mte: Ensure
  TIF_MTE_ASYNC_FAULT is set atomically"), which requires Clang 12.
- Add description of the new kasan.vmalloc command line flag.
- Mention that SW_TAGS and HW_TAGS modes now support vmalloc tagging.
- Explicitly say that the "Shadow memory" section is only applicable
  to software KASAN modes.
- Mention that shadow-based KASAN_VMALLOC is supported on arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 17 +++++++++++------
 1 file changed, 11 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 8089c559d339..7614a1fc30fa 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -30,7 +30,7 @@ Software tag-based KASAN mode is only supported in Clang.
 
 The hardware KASAN mode (#3) relies on hardware to perform the checks but
 still requires a compiler version that supports memory tagging instructions.
-This mode is supported in GCC 10+ and Clang 11+.
+This mode is supported in GCC 10+ and Clang 12+.
 
 Both software KASAN modes work with SLUB and SLAB memory allocators,
 while the hardware tag-based KASAN currently only supports SLUB.
@@ -206,6 +206,9 @@ additional boot parameters that allow disabling KASAN or controlling features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
+  allocations (default: ``on``).
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
@@ -279,8 +282,8 @@ Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Software tag-based KASAN currently only supports tagging of slab, page_alloc,
+and vmalloc memory.
 
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
@@ -303,8 +306,8 @@ Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Hardware tag-based KASAN currently only supports tagging of slab, page_alloc,
+and VM_ALLOC-based vmalloc memory.
 
 If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
 will not be enabled. In this case, all KASAN boot parameters are ignored.
@@ -319,6 +322,8 @@ checking gets disabled.
 Shadow memory
 -------------
 
+The contents of this section are only applicable to software KASAN modes.
+
 The kernel maps memory in several different parts of the address space.
 The range of kernel virtual addresses is large: there is not enough real
 memory to support a real shadow region for every address that could be
@@ -349,7 +354,7 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently, this is supported on x86,
-riscv, s390, and powerpc.
+arm64, riscv, s390, and powerpc.
 
 This works by hooking into vmalloc and vmap and dynamically
 allocating real shadow memory to back the mappings.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b47e56f00c2619a4033e10d5bb7c99cbf8288cfa.1640891329.git.andreyknvl%40google.com.
