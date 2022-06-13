Return-Path: <kasan-dev+bncBAABBH5WT2KQMGQEOD6NQPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D5EA549EBF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:16:32 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id u5-20020a056512128500b00479784f526csf3480483lfs.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:16:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151392; cv=pass;
        d=google.com; s=arc-20160816;
        b=tff/HWNSMUom4OxBVnsI/ATQIW3OBLbhTYpzodB04Gmh690zBHOmpn8az3dyo150Z3
         JuYu8OGseNhgRJdRCRIREE+Vqqrk/rKUNzdultfMi0YlUAgSGq+NFJzWAThOKypoJzyy
         YCFbVZhrg0eJBFNAtkJF3NXbp5v4shOmK+ASWvfbImdfOERc6QKOSg7SU9W1hjcXqZ4k
         5iRuml6nbj9UouX25dIlJTtqIfEIfWYmXMjz9TmaY/3puP1iA5Oxo74F6dJaNuMqpSp1
         r6pb90DSStFUdmOQLYaWzNPfCe4ErrmWgU5wVTb7WmWFgRQfVbnq4Tz/Yv2L+XOOoAlV
         MyeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MAy5vxOZ57DKmNXsSIJu38bQXQLBoWhmf12J6g2+aNI=;
        b=F67dqKWr5wmC5+JPOLz7lrEuMfPxo6KA2fRBQ5bA7j+HxCeDpvUcRFBCVApWsmDza0
         i/LF3JoO/6K2CAzPBzcNbLw3Z1bvk1EqpjJ/EVdHdyLZ2d2qyWOGIiGwm67WJeqPyXKk
         kXX/WmmtaZLrVbgnFgUTFSTk/kbRRy9TDSnUkKfdV4USCEnWHgzOr3Ov3FKbuFUkPFcp
         A7JhM14Tmz53VsV8GWeVhsSBWenbDBwdkmhYaXArBBb1yb1BEu2SYAVs1cJr1X9G6xob
         TOVtmuwZCgSAVENXgIcvl0SLr/lfQBVEmh2nWNsy4pCVGwjMaYZf0R5piGOdiEHS1I5x
         8tBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tkqmGQlV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MAy5vxOZ57DKmNXsSIJu38bQXQLBoWhmf12J6g2+aNI=;
        b=B7z+LIM5NAf3i0C5nrmjbBJSLP6HGCT//vMVdmsimYE1PUovJeYVMIA7vwzy6DmLgy
         qWZ+66CULM2Ii2rDCSmXF4qzVQ7aVa7lqhowqvY/+ItPm5RlTMc8JofrSveZcb8JBXh1
         AOkUKxP3sP/WOqM5MutPfCgcU9uYDs2ebHLkl9UFj8BFIVGyDhfJrXCGyJkYVKboYByW
         HJS8yTaoPCRHlGZy0QFwZ7Si0cdhVQeGCzxZEJyoGidjEUkEYwAzzODaXBYn3cCwViRd
         k36e4dtZ2sAESSflwngUZ0Mesy3b+va9x7TmZp2h/qIVyl+ZYsww+Z4vAoYpFAkV9WLm
         T0yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MAy5vxOZ57DKmNXsSIJu38bQXQLBoWhmf12J6g2+aNI=;
        b=WX05M9zP5hR+Pj4tHtdi/eVpTpZHHsqw8nHZx4GeFOT13l8xUNPJlmQ1gQSavPjlOf
         DzNKyLmbRUcshPzL/CRgl4CWOjTPAo/Pbh/ts6RBYmZWWmmfMkvn46ly4vN7HELHPm+T
         p3ZXZ00/zsRWuB1giPvvjzM2L6ghp343oNSW52xxlCFeONbQcsayrFMvbWSxe/ld4Ehi
         yNxqFOV8duMDxmExMgjiRP+Gs5COha/Yzyu2AQgJwY+m46z2qgZVej04AbufZWijBhHw
         h4eApHassHnK7pU/bBfFi8RJdOobCITjKD7lWh2F5UafvlV8yGgN3GajqHjqWeJuYg7B
         KE6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9T37kGiZHDCoLf2gnqVQlZ+F7QNDfAuVgIxAtp0G0oHwwdleSK
	fa0GC+PVjBMD3c1WszT4ot8=
X-Google-Smtp-Source: AGRyM1uq4l81YhoS64PkbsRwvBqDYT54iKfNYr6rsXiRGAIwExYqH495F7L33snC1gJ2R9cR80QDIg==
X-Received: by 2002:a05:651c:54d:b0:255:bd25:3d9e with SMTP id q13-20020a05651c054d00b00255bd253d9emr654992ljp.94.1655151392020;
        Mon, 13 Jun 2022 13:16:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6e03:0:b0:255:996c:87db with SMTP id j3-20020a2e6e03000000b00255996c87dbls457166ljc.8.gmail;
 Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
X-Received: by 2002:a2e:508:0:b0:255:66fb:9fce with SMTP id 8-20020a2e0508000000b0025566fb9fcemr616696ljf.171.1655151391187;
        Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151391; cv=none;
        d=google.com; s=arc-20160816;
        b=OLw5Gv0O2nh2nxwpXH1r7iyWns0me3NZKAucHmfnPnYS9I/uc7Ozlu7DP4wF4xZf1C
         H3FqcXBNe5K8LTLSJRpJCY/74ryLfupnO1W7Epa/L6CN6TblNiCU0JNgkDLL+h/TE7B4
         OygdWuRvU+adLfHzXV0yFTQ0Ph717ufCPE3UCRYeQvJUFEDJAMRP6F42lMyk8M5mE7UP
         HtYhMRC9KWjW77hiqD8Fo8PbEHRleUYDtzlvLh4cgEz/yA1eCkAD1Zrue0xB6sh1VhfN
         Fk7uuD/z8WhRarmVtzLMMwAMlrzg02a/bQ3U7AfhF7pCsEZNCS8VcrNwqlJtUCIVn7eI
         ZPeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=d1nMQkX323PpKYmvfsU+42+pLQR/Ix0WXYjxZevQJDs=;
        b=eyN8W74qMZIJWJRDBpboMdHS6RS0dxHXzpD7vxLzAxnJyAQ9vuyRsLvy4DA27INOy4
         6+OyQsfMSVjHh47DDw8fFIhCDxhHLvFiZpzZhwBux/95Ao8BOipLR8PIDaTyf4LAhfs0
         vhWQE8Cu8YbF9w7PCClJ9stb4R73WdRo2MS1tVz8riiw22Rs6iEVLn8sMopXkHQ0M+c2
         DUTTOzXZXsF5zBKEvMo8eDGcm4za4QFfybqtrb0flZvbZ7GpvJtnb50BRgpDJBMt8Jh8
         iJL1CuWJmzxrxLI/60onJSMk03Irwhj5tUY3hR2qaR5aMCntThepFJMw457WBGxTBc7v
         wyMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tkqmGQlV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o17-20020a056512051100b004793442a7f0si262632lfb.6.2022.06.13.13.16.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH 10/32] kasan: move kasan_get_*_meta to generic.c
Date: Mon, 13 Jun 2022 22:14:01 +0200
Message-Id: <cb77ebceeb6da2a721989ec2031dac2186f8b7b4.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tkqmGQlV;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move the implementations of kasan_get_alloc/free_meta() to generic.c,
as the common KASAN code does not use these functions anymore.

Also drop kasan_reset_tag() from the implementation, as the Generic
mode does not tag pointers.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 19 -------------------
 mm/kasan/generic.c | 17 +++++++++++++++++
 mm/kasan/kasan.h   | 14 +++++++-------
 3 files changed, 24 insertions(+), 26 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f0ee1c1b4b3c..226eaa714da2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -228,25 +228,6 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
 		 sizeof(struct kasan_free_meta) : 0);
 }
 
-struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-					      const void *object)
-{
-	if (!cache->kasan_info.alloc_meta_offset)
-		return NULL;
-	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
-}
-
-#ifdef CONFIG_KASAN_GENERIC
-struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
-					    const void *object)
-{
-	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
-	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
-		return NULL;
-	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
-}
-#endif
-
 void __kasan_poison_slab(struct slab *slab)
 {
 	struct page *page = slab_page(slab);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5462ddbc21e6..fa654cb96a0d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,23 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+					      const void *object)
+{
+	if (!cache->kasan_info.alloc_meta_offset)
+		return NULL;
+	return (void *)object + cache->kasan_info.alloc_meta_offset;
+}
+
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+					    const void *object)
+{
+	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
+	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
+		return NULL;
+	return (void *)object + cache->kasan_info.free_meta_offset;
+}
+
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 751c3b17749a..ff7a1597aa51 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -208,13 +208,6 @@ struct kunit_kasan_status {
 };
 #endif
 
-struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-						const void *object);
-#ifdef CONFIG_KASAN_GENERIC
-struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
-						const void *object);
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -280,6 +273,13 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
 
+#ifdef CONFIG_KASAN_GENERIC
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+						const void *object);
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+						const void *object);
+#endif
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb77ebceeb6da2a721989ec2031dac2186f8b7b4.1655150842.git.andreyknvl%40google.com.
