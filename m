Return-Path: <kasan-dev+bncBAABB3PZQOHAMGQE4ZH6DGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F75747B586
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:14 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id w10-20020a50d78a000000b003f82342a95asf6558920edi.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037614; cv=pass;
        d=google.com; s=arc-20160816;
        b=e2eAxdvCKCoyde40D98zOTAKxkN5ylWjC0d/XYc5g9fxrHibh6hGrvrNzqWMi2WYho
         1CKiL6oiuBpSOmDD/9jq0KqtuRxzuJWIwnPxXe2ZZwmu+1xo1qi2PQnx8D4MyKg2a+XX
         zs9uMeUm0Dw1hCFdlb6gY4duNxUQNgJLda4CWq70Vd7780fKJYCuTDC7tDKE0jvM5x5B
         re7C7Fak6uEsQysF4un0OZ/O1hP6VOWlQUZhcC67UFuGBziFQPgM0pzySqOCvlh9zc0A
         9t/zyLVOBBV2RUyk3h8i4IUtEOlDvWojtDdC8YmHN+xhIry24PDPDtPI9wTPQojh1DCn
         5Ivw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o0VDGio5878fRQD0/EKtCOll2EIcUD0rDEZKUTFIPpI=;
        b=BeLJFuu+ZwDl75+QT9QVeiZgSQh2xWVH1GMmdpvhCrNQVODyS/s1w0iiK7fp2owM5J
         lmTQa4PoDNbR5DkhEHyvU5TYaxOgaHGQMZiQiYIADwphb0OlCmPZFbpQoYadJPt/ik9Q
         XOSa442chQf4iu/yinpkpYvbWGMkoo1mpfI47XpNZluJLM8T4xDiioPGx1tzzJTAP9yj
         cdQERHPxlXd75Bev9BD4Nro8vbw8kH6X9pVEKp99rXvxHr9vY6Crj77spFHGJHaHlFY7
         Hm04r/E/w/GB5ff7Zyl//FejGNxnBwRPRQg9D24QzeoJEXnb1qLV8Vm5E6gy4bBeRNXT
         dlgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NoALNQTC;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o0VDGio5878fRQD0/EKtCOll2EIcUD0rDEZKUTFIPpI=;
        b=bk7s26lMHbHjroC5KDwTPDeboOCwZ6cCs30t0OR0FOQ5x+Q/82Z+ErpkdA4I1e/TIA
         HzI20gF1ZNRhKn9QHaV4b4btplZ3O38nbkdkzFBNZLIxbND7kiNJt4o8mdCJc79xU2es
         mP3W85wCLHVHHRB5fmi7/F/vhuEHVuGyGHfNmrL6GxbMlZ4hYpX8lS2EZS6smeXVsA8z
         ANLl6ocdii8jlOwbW+qpLUV3rFj6qGUBiXR39J4+KeRo9g0sBtuGDjnBrHhEw1N4XIWi
         8zPcslcQVUkyWgjcOsDK4hU11/deuMLOkuSnVbhNVSCPxI/nSAx1zg4Wf+WnR/cFGk5e
         4ZDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o0VDGio5878fRQD0/EKtCOll2EIcUD0rDEZKUTFIPpI=;
        b=5osWh+o8CZkwBrH2TAJyR6/0azoeC0glVFs9CuEaa9Lcm4gI9ZGZcTjVbxDhLsHBu8
         jinPw+qc8SJzMXv7kWmqTqWFdI5g34MNinI6I8mL810nuVTDWbu42bQKbZqCgqCMwMXK
         YUEbSjv40s/uLpGfPk6l7gm/HB4hF7zmXgafbs+nhz1WaZm2wMdrhmVzsCLyy+DHdt/U
         K/oFdeVudhdtGGLwOMitGDV2fImy5keQY+/NkshrUh9cM6dfMCf3oxWQ9dJ9i8LOfSQH
         pgmax1OOrjubBTy0GUdKLhE6Y1GlOO7sKNXWajnpLky7C30SPM461JWfplgM1SlG0Lkf
         L4xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LH5eYRxaWY/cWnHuhALWN4EGstg4dH94Fd+U5KYFTRUvmtz+a
	+vwwv7c5BdeLrhzNSwQP6d0=
X-Google-Smtp-Source: ABdhPJw75cr5cVklgMIh0dc/cjP5tWI4rIJ6jhhr6punCACutmgp6tdyCExmmYZwRMBPHufHOCtGZw==
X-Received: by 2002:a17:907:e8c:: with SMTP id ho12mr121913ejc.689.1640037613919;
        Mon, 20 Dec 2021 14:00:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3f98:: with SMTP id hr24ls1457562ejc.5.gmail; Mon,
 20 Dec 2021 14:00:13 -0800 (PST)
X-Received: by 2002:a17:907:6093:: with SMTP id ht19mr168636ejc.286.1640037613218;
        Mon, 20 Dec 2021 14:00:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037613; cv=none;
        d=google.com; s=arc-20160816;
        b=bjUuzFmYOmAQ21vcldeW0CFj1YBsTjd+g6/A7PpdDgUb1InJDhB5AsDKjhTwUNtW/z
         qIhwFmzOyQC2VN4o/OLCS+FwevNTEBs3iLARSPd6uhC4/eJuBU89bmBq82+POYk2MNnZ
         D2X0BBAbTJTX6IGo1fATkiJkJ+5Sgo08OX2NI243886xAL6dPyjp9eMDqU+apL6Uf36/
         4irK54q7BL37FLBJpPdZ/gPwLR3fmMoP/nGuJC2lsBRx+Alw7zwN+7JliKGbg3FE624s
         Wk7zjhGOn5xFjybUDRctV4C0LtVLOzF/YPs2Q9AXjjWxqooKhZZqoZJZaOXwYUCysDeU
         tuxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=28nrHGgMyGK55v/Rjfsypuf+W8Mz9cvlkAPr7bWxb48=;
        b=LIqF6H2sOvxD+ET25CiYqzsC3mNx+kuTvpo27gN7YZiw7RzAsss4LIcS0WdNNjT1cw
         HUPlHZ45tuVnfZWYTVPBoVBNRLy7krZ3+KkUOwpTT+FcNJ7H3WHxTmKfV8fOgBsSIzPb
         UuWAZ9gNV6k+Ufl2pFG2461maWWHikoV7AtDUw3LUKQ27YB+2SFJJv7BJsCzWqGEYHOV
         t8nY1SiH5E8V/y6dPhkxM5qB4gwTzbBPn3BOffC5jHh6MA9+EKTnF+hHSFsVKhzMTzLC
         kvehMTDnPINz3CWcai2I/Vh2kwkgZCaRL6oQ15zrBumccut95OnuvtjajldK2Epll61j
         l5sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NoALNQTC;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id g16si102243edz.1.2021.12.20.14.00.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 15/39] kasan: clean up metadata byte definitions
Date: Mon, 20 Dec 2021 22:59:30 +0100
Message-Id: <593b113a7fe3363b1945565341e1cd5978493acb.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NoALNQTC;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Most of the metadata byte values are only used for Generic KASAN.

Remove KASAN_KMALLOC_FREETRACK definition for !CONFIG_KASAN_GENERIC
case, and put it along with other metadata values for the Generic
mode under a corresponding ifdef.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/kasan.h | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c17fa8d26ffe..952cd6f9ca46 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -71,15 +71,16 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
-#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
-#define KASAN_KMALLOC_FREETRACK KASAN_TAG_INVALID
 #endif
 
+#ifdef CONFIG_KASAN_GENERIC
+
+#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
 #define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
@@ -110,6 +111,8 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_ABI_VERSION 1
 #endif
 
+#endif /* CONFIG_KASAN_GENERIC */
+
 /* Metadata layout customization. */
 #define META_BYTES_PER_BLOCK 1
 #define META_BLOCKS_PER_ROW 16
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/593b113a7fe3363b1945565341e1cd5978493acb.1640036051.git.andreyknvl%40google.com.
