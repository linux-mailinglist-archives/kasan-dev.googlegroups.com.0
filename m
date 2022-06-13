Return-Path: <kasan-dev+bncBAABBYFWT2KQMGQEUU6YX4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5882E549ECF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:17:37 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id a29-20020a194f5d000000b004790a4ba4bdsf3507205lfk.11
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151457; cv=pass;
        d=google.com; s=arc-20160816;
        b=o5KQN31qIkCK2e+S9YA/DJpTmg6pIJ/HLYUgti9BxEmwRGHEUb5ggfNKj0KmTA14CV
         UYo/sls8O+bFanKG6Q/gPghzp2BzTUyCZs0m9JeM49OJQ80Wunmlw0O4P/ljB6yHuHVW
         ibn3RunTbM2r06vHHXbeHpu68e0MHL+/cGx5ZwGsppEIBFd+y/4IQKevppYo/ZHrdKTw
         u4Pt3fyTSuNgkw7iHEm4B5L8i2S0Iawh9iDNZCyvphT0C/nXi8Si73WD16vGD/U9rTWj
         RFG8xmc/6GnZnEoD8T0ki68tFyU6wDwJy+85xf6bZdiCTrjIUxhtCNjFEHbEBNVeHj8P
         alfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=C+likx6Gr7btWYXeaF1xfPaBFosGntCJsByI/zFhppM=;
        b=WflZ6nN6/4LLv82B0DWiWa5kGrvQzrgnAaX0n12ztkPEftRv2o6BSOS4mZ9VTybo0R
         Rj2VGr2zh4R/XlnknPINnnJBIk0QOTWs2N2PIcqis9yKt+sT3ZQG77jVLvmVJu452rXq
         9UVNb+ljFJQZYXv3GkQqY6iMTs//WtX+ufoSllNtjOWboP0Qn0n3ECUezua9E9zBsvl7
         +EU2Iyd5zTd0XCML+QGdkdsHC2o9DMdCagHA2t7Up6q7EzNCcgSgwpCrAmbmjf8DEBBg
         jwnzJETQ7OXtD+7lR1apiMlHkBsE66H/yX0oObZ874iH8hMR9fOGyyI6HogB+Q4T9RbT
         QqTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W7OMMObI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C+likx6Gr7btWYXeaF1xfPaBFosGntCJsByI/zFhppM=;
        b=fDvPlRoejUl5lwdfKyV/7kq/p1TAmpUOk/IHpy3ixMqdpEeIb++qK12jVmutTkDx18
         msBnBFungr06p2thX+xX4NYcPVwUdswuW62i0wSUd7nOQ8DjcPqmOGziTBZR6XQV4frL
         r6eKNeOYvPPHIMVPUsvGk3iuBUORBTv3x1YR7P1TJQh41+3ocbQqU/sKKfWDEUyMpxyW
         5A/0gsVmOxOI5Oa1kUFufs6inr+zC/zhWHfrAipLS1lQcOytPtN4UgPKUOQ+oR3Mdd7k
         hefonGbpyxYS/Oh8q6BGwEi4L9lbNNQOxeBnz+HKDEQ/FJEjR3VeXXDE3l/O/jCLiF/e
         HOew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C+likx6Gr7btWYXeaF1xfPaBFosGntCJsByI/zFhppM=;
        b=D58REbmEAR1NIKEWpbjXBufzZm0KkKMhCf/0wbRqpKLnlGZE8UapWBv2/cGMJxwdad
         J5agxIF3GjcABefzDzSvd0YaXkqZitRWaJReM+QvaCkc8+Y2Wn67X8q8g0bVUkMRrU4B
         8kiBzQAB2MSlLgLgZHDXJN/U6ZiA4UXcOI/IVCB3G1Lq/SnS3FyYXY0mxy3whvde2hOx
         u0DV2D/wMlqc4dfDmyPKyRKolYwjKCE10iT4n/kL8Qg4SxIXufgvKfiGdOGFvggL1SBn
         C9iyyx9yTiTkU8pTQLQXdp1Zq7TuR1T/GqsGktsUJxXFzt/CRWQh44yLf7TZtDV4/mOc
         SdEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9UxqVTss/CvMqKwQJfAsRd7V9OrWQZB723Hh6cKTA9iTdWFnVv
	ZVpD9uWcgdWb5d3EoLLeeeY=
X-Google-Smtp-Source: AGRyM1t/309zQv9IhiTjpOGcTyHy0WnQH7M/ZeYo4mybDHeX50c7AUeryLg2i/pkQVX+2L5kNkwVHA==
X-Received: by 2002:a05:6512:239c:b0:478:efa9:9533 with SMTP id c28-20020a056512239c00b00478efa99533mr871269lfv.661.1655151456849;
        Mon, 13 Jun 2022 13:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als185784lfa.2.gmail; Mon, 13 Jun 2022
 13:17:36 -0700 (PDT)
X-Received: by 2002:a05:6512:230c:b0:47c:4e4:9485 with SMTP id o12-20020a056512230c00b0047c04e49485mr913062lfu.452.1655151456199;
        Mon, 13 Jun 2022 13:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151456; cv=none;
        d=google.com; s=arc-20160816;
        b=vbAZsJgWCadDRTAGY+lXUPE5d+IzPHEtWdbtQK92LAPSQ/X6HmgaNjPzV5hanMuh7b
         Q0XSyi/bfxURDTr9iluG/RqShriZaVh7lbMc0zFVls4BXQri9Wr3TWtzZ0M6DFITST0q
         rz29pAFdWGRmWEwHDY+H3EbsXJR/GHgFXdH70Eu0pa70DAz1Pfp/vsfkL6K2/Z6U5dZn
         NO/DBxcRfu9A0hTlhN1ov5PqOtzKACIH8uoUndwNnGBTWT3WlWtYRClC5vKynb4/oJj6
         C40iqEUAlDJIKX6gKH2Zsbv2xJmE9xg6fD06c5Kqs8eR+btTvXDba1NOBsyLwCndrLyz
         PQMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yMpcVjLCf9jqLKxVClgu+qWUo0HLupVHHXi+5F8746E=;
        b=dzJMXuzQZ+nKgLIcbHqilGAg4/ihxLNb9IdYb4VEmXIiRIi73ZP3Og0X9n4l0oMcwY
         Z66S8UhWsturISf9yZGghCrQvrHOVFdz3SoexmOIRl538IbEnC+TxMYqDmbk8cTT0HBn
         +BjCFEVT69h5xJOCambh0FGrFgdAWXQJHvBm4jUZzGj8ADLUpkmlBP8U5mx4rli3vEOo
         T527HOngfhJyt4LrXZww7CwT4UfTo2JaDPLABcSmUT0d38VWXZN5ZDxU5KnjGS/ufIAF
         6Mc8Vo/TMkyQm0TzEWUbh7A/l4rCRc55YCprxuMXll2mbLXnctzTVL+5+YB+KcGYXCeo
         KMwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W7OMMObI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b00478a62b07b8si311555lfv.5.2022.06.13.13.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 15/32] kasan: only define kasan_never_merge for Generic mode
Date: Mon, 13 Jun 2022 22:14:06 +0200
Message-Id: <fe532f89a33b691ab0cef40f4b6506960e75a3d7.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=W7OMMObI;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

KASAN prevents merging of slab caches whose objects have per-object
metadata stored in redzones.

As now only the Generic mode uses per-object metadata, define
kasan_never_merge() only for this mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 18 ++++++------------
 mm/kasan/common.c     |  8 --------
 mm/kasan/generic.c    |  8 ++++++++
 3 files changed, 14 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 027df7599573..9743d4b3a918 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -103,14 +103,6 @@ struct kasan_cache {
 	bool is_kmalloc;
 };
 
-slab_flags_t __kasan_never_merge(void);
-static __always_inline slab_flags_t kasan_never_merge(void)
-{
-	if (kasan_enabled())
-		return __kasan_never_merge();
-	return 0;
-}
-
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -261,10 +253,6 @@ static __always_inline bool kasan_check_byte(const void *addr)
 
 #else /* CONFIG_KASAN */
 
-static inline slab_flags_t kasan_never_merge(void)
-{
-	return 0;
-}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
@@ -325,6 +313,7 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 #ifdef CONFIG_KASAN_GENERIC
 
 size_t kasan_metadata_size(struct kmem_cache *cache);
+slab_flags_t kasan_never_merge(void);
 
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
@@ -338,6 +327,11 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache)
 {
 	return 0;
 }
+/* And thus nothing prevents cache merging. */
+static inline slab_flags_t kasan_never_merge(void)
+{
+	return 0;
+}
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a0ddbf02aa6d..f8ef40fa31e3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -88,14 +88,6 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-/* Only allow cache merging when no per-object metadata is present. */
-slab_flags_t __kasan_never_merge(void)
-{
-	if (kasan_requires_meta())
-		return SLAB_KASAN;
-	return 0;
-}
-
 void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 {
 	u8 tag;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 806ab92032c3..25333bf3c99f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,14 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+/* Only allow cache merging when no per-object metadata is present. */
+slab_flags_t kasan_never_merge(void)
+{
+	if (!kasan_requires_meta())
+		return 0;
+	return SLAB_KASAN;
+}
+
 /*
  * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
  * For larger allocations larger redzones are used.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe532f89a33b691ab0cef40f4b6506960e75a3d7.1655150842.git.andreyknvl%40google.com.
