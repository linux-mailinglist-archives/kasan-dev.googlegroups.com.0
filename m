Return-Path: <kasan-dev+bncBAABBZMJXKGQMGQECT5GP2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A3D346AAE2
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:47:18 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id z8-20020a056512370800b0041bf49128a9sf1865998lfr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:47:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827238; cv=pass;
        d=google.com; s=arc-20160816;
        b=U2Or5k1SiuMAsae4mJPDdQD8oeYUzHtnu9ZdBlqdor1wNzky+u53Mi+4kkYqdy4Y8k
         00Ci+8Bl/GQ1Q0V6bSbGUPjta+CYjpPcOfXxGPvg/jXTWB1BNa8DR7QOhWUr2r33mQJ0
         WVC6UKjCYNxxCLk1paGtnHr2mJHMxuEDv/ZW/fPHsOCnPHFn2X9JZnu2WLLhgKVIYg09
         TNZ+jApIwBS/nG4shdAdLiPEvo97tSEQlEoVrt44/lNGC9HfKWHrvz+7GPxoPOmroPzc
         BhnH8ceed0gGlOynT1nawF9vSA0OC463EZGVS75XgD6C8YNkoDEIDWPcmDeXq83NFsWv
         nsgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TX5ffTFhAxJggg234yAbnMCLldgjQRDu/wyliBOpaho=;
        b=k7DmzeMLDBEGwcWafvohotFuz1uAFgEYhQ/vryHTUIBHzMfILyyG+JNkNwYqFTs9oW
         9nnzYMpZTvmMY177D653KfaQiMAbAnhKKudr36iDoaU2S/JZ1KN3Ca/toORuixuVCuZy
         6h2Qf7kPFnpVx/pW5Sc/h4jUwvjwxMCvf6CYtbQbO4+YDEDYJfIG2MZwHb8VQE2tYanr
         XkG76WwejTsbti5jMnK6iGGHVBTpDOfnigcYasQUdGVVt3oQ8oKCCkAhXw/HKbx6NnE/
         s2tCLpN2JWZnfgj0enl2HKy2D5Bdu+7hmOrJ0msE0beAMEEOQGGqaPYZZmxe8Xdk40kP
         dn+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AbHNSooV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TX5ffTFhAxJggg234yAbnMCLldgjQRDu/wyliBOpaho=;
        b=hkJF1qNPpIpkHCYU8b4gAYrHaVfHZba/i1RXXbCSORigRkHkxlokBH+9e641pzx2pr
         tx0/gIMmcKqzjPGnZf4xdd5h+Um7gS01XRbzED1PFHWSWXEEnNhwwl8ZQXpDUm72mpT2
         Wk4BxTtUBDkmPp7RelQ1pMQ351C/OGn57tLjWhcsmbvTILfjTAUw81dSACxwnnRp2AXp
         OvdFeQRooSPsFUkkk6PCQLzTEtgerAO9/y/haLbJ7TLYsQjV9tQoYJjRSltl1G1ObFgV
         Ykfgrn6vtPuLS2tSnVxkRdcXIFlI8lnpWUx7l4YgJtvvwe3tVRx5jWsrwM3iRHt/8N4U
         ikYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TX5ffTFhAxJggg234yAbnMCLldgjQRDu/wyliBOpaho=;
        b=4mztbTAJVcYiJj+7JJInArYj9j6sPSfGydsVY9SqEffQHjY6HfQp/I6ng7vXVIzqTM
         J+UfYkCWPRaYvL7rgRup7Ts25FQO4V35CDIySg9BRwfyxoWuNLTu+OsZpKNW28DMdu1p
         K2hAPtLE1Dd5G9V2ZBwnCSZd64lYBD/r/EJH7QGMd7d1pGzryIlE4I90F4ZOGlDWzIwp
         hEmUVL7Zv9IyjA8fAvqtZnXx7UyqcttZE7jlFMQSIwlwAq4O9CGI3ZuosOB2EKEnqxzo
         f/dj2/GYwCSjfustR2/2QW6Zm1jZrCZjl6mokE3IJ6XtKZGPNij57JnOhkTcjDt1SjSF
         etYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HgyUJJybVNsd2m+NkT0VvLDv8JaLOHXs5zRJCvxD1IlUOdPqO
	pNPfuA6Hys/p+lGr0ktGZYQ=
X-Google-Smtp-Source: ABdhPJxfspHm5nOObBbCDG1kJfZREXB0epZAl9dU2ED+vIO7wpATwpXNWxMsjpEDQUnUj5luMG35pQ==
X-Received: by 2002:a05:6512:130e:: with SMTP id x14mr38021932lfu.366.1638827237970;
        Mon, 06 Dec 2021 13:47:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls2824114ljn.3.gmail; Mon, 06 Dec
 2021 13:47:17 -0800 (PST)
X-Received: by 2002:a2e:9617:: with SMTP id v23mr37426528ljh.363.1638827237013;
        Mon, 06 Dec 2021 13:47:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827237; cv=none;
        d=google.com; s=arc-20160816;
        b=dX2plZfdq33bXTkk7VXL9Xi89gyUBjYWbj0blfv1j9AIWb2uzO3MoREz5JrSdYCwbT
         ki4/diZUF21SCuMzU3l+yUC6l26tWBz/O26bNECUo3PxGuq0B1RiNzAB3+dMkwgZYpcO
         KaLYrCQSD+6IjqUAJt79nJkBRXv7sVRxSdlrfRDZyjDl0SBvWzj3WXSuuq9Q1dNPu8vN
         boFKjFOPw0PhEWNgcwcG0w0TRR1sLBwbgwti8tZju5a78ypdNYib8v4g/f7obm0zluch
         2XtyVZ9vVuQxzdB34vRXjnfcF2fUTT5KpGCb+QqF5qXF4k0ZjUUmiFuJhzvq6XoodiwY
         S25A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV0M9szKvSlfXhwybxJe1jA9V5abexpCELFOGxjWDjg=;
        b=Q/9X5SZ8G4k2TYnBdhAXjc0Iap3KKFnzhtwhw3OpttQDm2t92dYoWJFcMydKCASANj
         3q04yk44Zj4Ja33/nSb+HclMUkh8UsPPHBIaW+igJxpxDui3mL6vfi3s1MKaUcpKqGwE
         sBko+BKh0KW5IkF/vJyqPT6+YhcjwE0xL3ObHA6ETgEsPtNDxD8S8umcclosjpn75SPu
         S6kYIWWyL2Rw70MpHf6vlfGbgoDFG6lmPa36HI1vL/vePxIAVgmRe8iGx2lUkzwCDHfy
         9Zqj7MIC6BpuqiDyy4qTrnvFkM8iYRlYZAa/3HZlBBihDQJrHT03yzw6+YnbJGAvNmfc
         cBDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AbHNSooV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id c15si858172lfv.8.2021.12.06.13.47.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:47:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 33/34] kasan: documentation updates
Date: Mon,  6 Dec 2021 22:44:10 +0100
Message-Id: <e6d60d5748b8e1907be8f26ac20944c41119bf0e.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AbHNSooV;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e6d60d5748b8e1907be8f26ac20944c41119bf0e.1638825394.git.andreyknvl%40google.com.
