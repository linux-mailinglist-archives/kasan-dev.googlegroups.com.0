Return-Path: <kasan-dev+bncBAABBBMLSKWAMGQEAMVWPHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0522081BE4E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:35:51 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50e67cb7ab4sf105761e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:35:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703183750; cv=pass;
        d=google.com; s=arc-20160816;
        b=mkZIh8Vqp00rYnH51lahW9pT1gQuC8q6acpkvBF4NwTSOcRL+rItzlDRZuKWjB6le4
         +B9yHe4DsX4bNK3L4Eny3Cvsyoack/5owZi1FvIEymHcb+Bzzh3DASp26v3VS1wTgujX
         g3jrEoQmzGnTWqyOUOFTilzo6Ai5TOXrotrTJ+ebl+HnTqY1uyb5d5xooLeEh1Xnhtfj
         fT5eTupBaqP0yRYErYmM1ivf3suAb+56df4lL2ihWymgvPeZeumrUnmgPYk6tehBfQYQ
         2EHlfG0iEGPeqtuWekge7oYf67g2OyJjKoxhcOmrXL7p243YT4tteZufazi0Oy2KfpxV
         9BxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OvbOkv3h/ghKv8hbYMwtWHqWwb+lD7clXX7c9ip3GB0=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=m0nF2oG+xoXk25uQE/uySQ273ljemONkKF02B318u6tnlf8Tk9+XTsXFI3LVXDDzD4
         krL7UYpk48B35A4Nsp71W8oK0PY/zc5TNMO7ZOYgTX1gwKaCaCBCufKBUHZuFPqQHsUJ
         SSefHsMPb3w6coBebU9X7YpEfH+W2dvlUy/mjk7XCdso70m2ez90A22JyMGLnEwkjpjt
         yBJbxKR7fD8Oqv4YPiTQ9vIj0uj+8cwmgH2mrdjEeYZ3bBvbNTnyeEH7EB3U54bqQ5U1
         jA71lX0TDCks78UtbTeSZ1pj6SXx/ArCqbO/4Dokt5dyH6OCqDN2bnpbiIAZUHRlXZ6B
         VcKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tbPj3uPo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.182 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703183750; x=1703788550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OvbOkv3h/ghKv8hbYMwtWHqWwb+lD7clXX7c9ip3GB0=;
        b=l1Sv7fAkROmSn6FV2KpDtdGX0cEc4nn01udV3NK+jId3eanM7tAPUwJthRU63jIo05
         i33TgBnwWpfu4i/EWqIrkJ41VPXmc/NejftFM4fyM3IXWtRAIEY6yF+7zJGqwEiXJVsq
         8Uxdo4QMOxUnn4L38LEEgdUystqCqB+v2yCvp9XHKBKDJgaD9Ud+2qaNzkx1AHW3lyg1
         RZcr9KrqD7EhB5Gge6VVmvqsTXX9ORnnabnKuY5oklqRY1ABDXHxRiEa6ePgzZeRZIlc
         LZgcvMQljGppSFgO9Avf+8oADtqukIZTlXpuzYqaXfPAkNHXjKD2n93d2L7Cj8mIjs0C
         Oyew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703183750; x=1703788550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OvbOkv3h/ghKv8hbYMwtWHqWwb+lD7clXX7c9ip3GB0=;
        b=MWX89lEZUeXTsLj26qv99U0cOsXhZZVrJuZxCgJHZz2oaA3u8BLg7dZLVhNPgeO7OL
         W/kKYiXNmVZf5X11IPe7GqMQNjALT2yLoFZg2/9qR6BgWoIZqGliBtSgkUG0N+xjFLMH
         FKYuLb107AhPnYsvh6YErfDqE2FEXjlojZjaNjk5zg8FN8dLq4Uwuw0Sm1gmCBbB0D6W
         MIhIONMs2nAjo+2ENBsOXAqqhuLy74EqCrgAXL8OWynJ3CDmrX7tyE0vFb73tWgpiizY
         h+X9DQCMH74vURDWb18wQFpn2jngMuKTpL8MyeWjEt439dNvEa/IBcDIuroqDw7dFSnw
         GUrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx1ywMIabYSqS2nbkBJrh8ZCwWG/PH42nJr+0qR4RMgdch7tQjx
	mre1ATwAnmoO8b6mDPrKidw=
X-Google-Smtp-Source: AGHT+IHmTPJr6WpTZgZanCXXx7ZqPlbTh5h9u5Xm1el7y/jWs68RBk8inG3a/Fz0m5YMKCVpIvlTiQ==
X-Received: by 2002:ac2:51a7:0:b0:50e:3b91:999e with SMTP id f7-20020ac251a7000000b0050e3b91999emr24424lfk.104.1703183750108;
        Thu, 21 Dec 2023 10:35:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e24:b0:50a:aa99:28a8 with SMTP id
 i36-20020a0565123e2400b0050aaa9928a8ls297388lfv.0.-pod-prod-01-eu; Thu, 21
 Dec 2023 10:35:48 -0800 (PST)
X-Received: by 2002:ac2:4907:0:b0:50c:4ea:64f4 with SMTP id n7-20020ac24907000000b0050c04ea64f4mr34327lfi.70.1703183748168;
        Thu, 21 Dec 2023 10:35:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703183748; cv=none;
        d=google.com; s=arc-20160816;
        b=mkaoQ8DeFtOnH8tLdccKMPBGUiQjG5cTcHbwQp9PP0Aoi5lUb9h1yrShE4M7RkjSGL
         xt2wlGc89BREt5oNEpeNf1zeW60mlC71yhyqRdHVvkweVfU6LpA4chUDwTt77jc0qaPG
         RvWBWEKfo8a588N87SBZyYDm24lqc1mHOGZjdw3tDvb5BQBaAiDz11PV+t4/FX/Gd0Mt
         o0h/74AteeH9+GNJI70wr7+g3yfWcBlYlwwnD0WVFChigAht40syvJKsnAJcrl6As4vz
         eJ+W1ELG+kEXyUIsBRDvLGA7HL51HPovdvrRLs6leIafJv5d29zxssOU9l7qSlqsALmk
         Hx/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DILt3p53uNIRMlyKqLmSfi67XoCveJqLdgVMwZq9yXA=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=er8Ey0IaYJf3vVrS4eZLvnyinDuttmlbmE3syz3xFbSX/cIs54tZprMl7+3gl55DNv
         ROM6n+q0qIdqY70m51eWe5PyOHLoiaOaPNSYu3bFlw7pNyWpLL0m6A7LQBWPn7PtgZS/
         q4zZmurapwczeRATtpKxGBWeZ95sMLGkIRK4XOYAJ/+l9pfCsOc5cEcdfdfhXFnkkYeB
         9IXg4/LmcLs0IwhjKOj9sCrIBIrzDe8FRKo37GU4PH+nb14ngXwqy2VM7x+GwFuqDG6l
         POVPvQFmePzYo6t7iFC144i8UCdjecUR6nZGuNvs+f9xjhbf/g30zIhfg3YSxVNhQZJz
         299w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tbPj3uPo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.182 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [91.218.175.182])
        by gmr-mx.google.com with ESMTPS id bi5-20020a0565120e8500b0050e5c71125dsi78910lfb.9.2023.12.21.10.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 10:35:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.182 as permitted sender) client-ip=91.218.175.182;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>,
	Juntong Deng <juntong.deng@outlook.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 1/4] kasan: clean up kasan_cache_create
Date: Thu, 21 Dec 2023 19:35:37 +0100
Message-Id: <20231221183540.168428-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tbPj3uPo;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.182
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

Reorganize the code to avoid nested if/else checks to improve the
readability.

Also drop the confusing comments about KMALLOC_MAX_SIZE checks: they
are relevant for both SLUB and SLAB (originally, the comments likely
confused KMALLOC_MAX_SIZE with KMALLOC_MAX_CACHE_SIZE).

Fixes: a5989d4ed40c ("kasan: improve free meta storage in Generic KASAN")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 67 +++++++++++++++++++++++++++-------------------
 1 file changed, 39 insertions(+), 28 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 54e20b2bc3e1..769e43e05d0b 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -381,16 +381,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 
 	ok_size = *size;
 
-	/* Add alloc meta into redzone. */
+	/* Add alloc meta into the redzone. */
 	cache->kasan_info.alloc_meta_offset = *size;
 	*size += sizeof(struct kasan_alloc_meta);
 
-	/*
-	 * If alloc meta doesn't fit, don't add it.
-	 * This can only happen with SLAB, as it has KMALLOC_MAX_SIZE equal
-	 * to KMALLOC_MAX_CACHE_SIZE and doesn't fall back to page_alloc for
-	 * larger sizes.
-	 */
+	/* If alloc meta doesn't fit, don't add it. */
 	if (*size > KMALLOC_MAX_SIZE) {
 		cache->kasan_info.alloc_meta_offset = 0;
 		*size = ok_size;
@@ -401,36 +396,52 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	orig_alloc_meta_offset = cache->kasan_info.alloc_meta_offset;
 
 	/*
-	 * Add free meta into redzone when it's not possible to store
+	 * Store free meta in the redzone when it's not possible to store
 	 * it in the object. This is the case when:
 	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
 	 *    be touched after it was freed, or
 	 * 2. Object has a constructor, which means it's expected to
-	 *    retain its content until the next allocation, or
-	 * 3. Object is too small and SLUB DEBUG is enabled. Avoid
-	 *    free meta that exceeds the object size corrupts the
-	 *    SLUB DEBUG metadata.
-	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
-	 * If the object is smaller than the free meta and SLUB DEBUG
-	 * is not enabled, it is still possible to store part of the
-	 * free meta in the object.
+	 *    retain its content until the next allocation.
 	 */
 	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
 		cache->kasan_info.free_meta_offset = *size;
 		*size += sizeof(struct kasan_free_meta);
-	} else if (cache->object_size < sizeof(struct kasan_free_meta)) {
-		if (__slub_debug_enabled()) {
-			cache->kasan_info.free_meta_offset = *size;
-			*size += sizeof(struct kasan_free_meta);
-		} else {
-			rem_free_meta_size = sizeof(struct kasan_free_meta) -
-									cache->object_size;
-			*size += rem_free_meta_size;
-			if (cache->kasan_info.alloc_meta_offset != 0)
-				cache->kasan_info.alloc_meta_offset += rem_free_meta_size;
-		}
+		goto free_meta_added;
+	}
+
+	/*
+	 * Otherwise, if the object is large enough to contain free meta,
+	 * store it within the object.
+	 */
+	if (sizeof(struct kasan_free_meta) <= cache->object_size) {
+		/* cache->kasan_info.free_meta_offset = 0 is implied. */
+		goto free_meta_added;
 	}
 
+	/*
+	 * For smaller objects, store the beginning of free meta within the
+	 * object and the end in the redzone. And thus shift the location of
+	 * alloc meta to free up space for free meta.
+	 * This is only possible when slub_debug is disabled, as otherwise
+	 * the end of free meta will overlap with slub_debug metadata.
+	 */
+	if (!__slub_debug_enabled()) {
+		rem_free_meta_size = sizeof(struct kasan_free_meta) -
+							cache->object_size;
+		*size += rem_free_meta_size;
+		if (cache->kasan_info.alloc_meta_offset != 0)
+			cache->kasan_info.alloc_meta_offset += rem_free_meta_size;
+		goto free_meta_added;
+	}
+
+	/*
+	 * If the object is small and slub_debug is enabled, store free meta
+	 * in the redzone after alloc meta.
+	 */
+	cache->kasan_info.free_meta_offset = *size;
+	*size += sizeof(struct kasan_free_meta);
+
+free_meta_added:
 	/* If free meta doesn't fit, don't add it. */
 	if (*size > KMALLOC_MAX_SIZE) {
 		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
@@ -440,7 +451,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 
 	/* Calculate size with optimal redzone. */
 	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
-	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
+	/* Limit it with KMALLOC_MAX_SIZE. */
 	if (optimal_size > KMALLOC_MAX_SIZE)
 		optimal_size = KMALLOC_MAX_SIZE;
 	/* Use optimal size if the size with added metas is not large enough. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221183540.168428-1-andrey.konovalov%40linux.dev.
