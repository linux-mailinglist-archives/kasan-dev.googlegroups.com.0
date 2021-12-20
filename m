Return-Path: <kasan-dev+bncBAABBOX3QOHAMGQELUKINNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 00BEB47B5B8
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:03:39 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id ay40-20020a05600c1e2800b003458b72e865sf1018104wmb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:03:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037818; cv=pass;
        d=google.com; s=arc-20160816;
        b=05VLdkTs8+lui73VJ1VSTIWeUzWYff5Xjsjfuxd3cvduULObfcISC5Ho3p3nl3RBsD
         2c35WMLi6nQqMQszt+palfvoQwFbDX7gFrJVl/SQ2ERTa0ZU8idSK5OWm91T02G6XI8y
         zMR9Jx6bsUARb5/pILlomIkJQZZVbV35C1RuSefLRkPHNAvKvzKYjrmI89q4+ZlutvFo
         sxV7O2v5R6fLauCmNclgy+LT2iGLZx+U+LLAVIU/7G/2nXLIZRWCISHFlYns7icVIgY0
         IIghotwSbTvayRoS233BpRcFJATPGP0i1kUvhZ9am0INGgGhUwiSR/tJdti6RRtFc7ZK
         kp2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z+w+2Xp/aG2XYVwXj+jpUmRMrhqGM+uf6OksYmwtUdo=;
        b=kcx/upFFhWQpZlYxIZTWfBVJyxTcRT5JjGjkMMau7MrJltqLiYuLeRD//pm1KdsN2x
         Srt3/wDEPDV7YiUUwipi45Nfz7ADJBtNy3QOUYwNe/v6QaFs93WrWRj2dnMZzTxr3ATR
         IDfMaTLbjK2Hbg0DjQifC9xvMU26vHDZOvOYnNp4+DBBeM8wj/nvjjGQIv4dv8ZZDFAr
         BdiV74TT+xYK9dpmOfhyRXsoxaLzIjOf7LYaqa4Nk0wz9lro8VaN2c8asx7NZ8eaw7OW
         3dBmxzIkK0jt1ducc7JKP3fG1qxzrUTAK9PA+HwVrbVEQ3sGLmGJgJFrooVtxCtyTyIB
         ohGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vvlwzFi0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+w+2Xp/aG2XYVwXj+jpUmRMrhqGM+uf6OksYmwtUdo=;
        b=E81Oj3l1nFUC5k8D6xlJRv7ArBfT40coKGDm+vrkO3blY030wDP1eMUn9XQN+Lq2hQ
         Dz5fL7VlwzqlM+9LylVC78rinKlsy1JSt2jaFbeF0C+oIwHjw+hvHlvAMS2QTGrgSsf/
         D2RUkeqwZpn8OkzIyrtDD43pQdMHAj7BwUWrOTsSBq34Xa1OTOCQeBRHMQTHtpcGbdhW
         4tbCjhGGaic89GiLC7bMHlUPsPDcfvdOD9rPyX6XRB/uTEfM3nloNyRnRcc2QmqLvIQj
         LJ/uqVehc+1fa1bJoSGladjpkgcCCaVi2JrOENUKY43GRwy1iwhkrpRhVSmqmgGxM8oB
         3Y9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+w+2Xp/aG2XYVwXj+jpUmRMrhqGM+uf6OksYmwtUdo=;
        b=hKIXJkYv1lAWKv3LoUr6FBwtfMSzP3SX69crsAB15VlbgjaPdxrAfwfyRViMMuagW8
         1h9NeGzPsCqwGz2QFOdQGAcMhXvqxflr2/aFTIrKCiL3CGzQLgnVgRozVk0pKhBlNwO3
         4/y7fzcnRf63sKGgTjSuAoBjcIkrYkP2oc+WPHoFjSgUzjWImg6DBTzXLmAw7R8nU7KT
         zCYYXSYY24E3IH780WlfKUZDpy14Ou8qG3NYj6IO0zVqAB35dL+2Hhc86mlpTrz7fKUA
         dQKE6vAKR30Aiq9zhU/2mUhCONoGJkueF4yhRjQY+lcdACd/V8VxWi3lqEJ295KG6A4A
         w/rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qnEavxCkxW6eyAlZcvu6UhGSrOMkKwtf6sFiXafX2aNG0wHNi
	RG6uV8cwGfZ3dFCdtcj1UvM=
X-Google-Smtp-Source: ABdhPJy9KJodQSmXxSHwfOrLu9bRZh6Somsf81azJBmXLRJ7jHyAeM7WxjZyuEzNgb4bAsTSQ6KFXA==
X-Received: by 2002:a05:600c:2119:: with SMTP id u25mr43138wml.93.1640037818737;
        Mon, 20 Dec 2021 14:03:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1078513wrb.2.gmail; Mon, 20 Dec
 2021 14:03:38 -0800 (PST)
X-Received: by 2002:a5d:51c9:: with SMTP id n9mr111136wrv.694.1640037818159;
        Mon, 20 Dec 2021 14:03:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037818; cv=none;
        d=google.com; s=arc-20160816;
        b=AJiMH2unLPZMe3/qyAX8gDS7i70L8qkC1hQsYJQeLfyiKBuTVU/HhnZ+AMQ9eGa3/q
         g1TeQkzdBTKcXXlEkL7PBCyciLnHFz7PNcHVSitJeMHZSZQ3KOmmHml3exu3F+g8mtu7
         5fA5dhE1wd3HL48b6ifg0GFQfeNw98KTWn20NSImJib/LcTieo1pg6zlzleCGV3RUJi8
         o7tMBGO0WlSBGSwmUl9UuYQiDB+v+mYcchZBK9VM1Jfy1dtT8iQmaZmoqIBFn3sKwb/T
         LfQbL+A/b408EL+KD8/1jJQwaccHdzEl2L+lMWw2j8x6cfvkQZjnEzg2HjWoLE9Plf64
         LM3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV0M9szKvSlfXhwybxJe1jA9V5abexpCELFOGxjWDjg=;
        b=eF+i7FoQJAYgQXrAPkSIht2xha6gd8SwOUHEJeIhv0b7IUuIcP/O85OhGYA9hsA9mQ
         0YhlCvqCX7ctxCgzcl61RsnynLwZLPM5QiMwxnYT57tl5dKusQtcTkh4qp0QuSkgqfVP
         vhbSNXvb2u6aGOl8tHydWeBwu07lKTXhvcm0CN57X7buDzZfk8wp+zveNb+HKDozeOAX
         OtyUhW9xm4WiapoAqO527l4Aba3NGI92nZIjxKHMIriRudSStNF5wW5tPLaI3QBGUHah
         XdPKxq5ytm89p40Y4A4+P20+jofXmJ6egPxaGpnPwWmNabSo2DIN6NmKH/Y9euQdoYKf
         p9qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vvlwzFi0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id z16si33151wmp.1.2021.12.20.14.03.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:03:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 38/39] kasan: documentation updates
Date: Mon, 20 Dec 2021 23:03:32 +0100
Message-Id: <31a7f02f6dadc14825220862b63d204f3970f173.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vvlwzFi0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/31a7f02f6dadc14825220862b63d204f3970f173.1640036051.git.andreyknvl%40google.com.
