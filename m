Return-Path: <kasan-dev+bncBAABBX5VT2KQMGQELO4YGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A220549EB1
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:15:28 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id l2-20020a170906078200b006fed42bfeacsf2166196ejc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:15:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151328; cv=pass;
        d=google.com; s=arc-20160816;
        b=nXMPUTitnz6WnUjikX8/HGZa0JAWthgP/IXQdb07ypCZbY2c7SgfzkUzkSLIw/09dX
         o0RFv/Et/4HYfyGTYLoJWZg5BUzA4MqoLI0ZIGuLBiPnUF/s5T5puK4odnIHGqKGCtDb
         vemgNamSs3PLnbFMMkO+77JFTBpKo0mn3O3GYDigC+JZYu/gPYn8fv+58IKjqRtrj/kt
         aCocixk0yeb8scWWYlwSGkROrFw1GyIs8TyxDHS8WpYQkaRoiTKp0OrjfwsitW1RGTrv
         ZZpj5FnlWu3hDYqrFnT/9ZzelWJi4e7zeZy+R26FVfXSBfkJzwqsIBxmUpKs5ElvDG5E
         ofog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2WtrnGKm7LnUtt1bpZBhHXYf6k1JZ4xSJRQwroI5euw=;
        b=xVPjfwDX3z93OqIIxvKbIRwqz99BHboeyWKjuZVcCPttVmDXEnN1Pxnc3rfDrUudmN
         40/650p4o57k9+2d+yLP5ndxlszELsWfH5ewnnFTXlUyi1sBlB7e6I6+EDjiyWESybDC
         k2KWFwtSbSFUfsA3gOnyJwYeX8+zD6VHnl+NqT0HqMpDOvx8IP+bz4FQv9qupWKOCOft
         TZ0Cd7XvJcfROg7hiCJ8jfSss3HErYRfOZmQPckQ2p9sM9SmNcqE1uvbgccMYTzOiYY1
         E1TzDK7n3sq/srTHS2RRnAdhPNVP3gpNwp4k6qAY7lZFst4juwKLNQmsGM38TXbxvQXV
         gZ7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oRiXY173;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2WtrnGKm7LnUtt1bpZBhHXYf6k1JZ4xSJRQwroI5euw=;
        b=CyGMvER35buWZk6ASR0HrX2G1hrpclGAY7JvgRwJ2/1MfFWKNpBOJylnKEQldiXzZc
         sAyePgZmkdBvoSEaI10tfxBDSqO4s/Zs2l7LRtOCEjmhSHQ7IkJnKlsofjtXoAH+Hhdl
         aeUAODQ8NfWCtUIA9WiEuvTUUqN6ACKdECZInU/fnLOQGaOLzIOom2xpj1AVhMbBanpt
         ADylqjuq+0cIYxiAen8juI/SpQ+UTzc/zKcBBdUPYO2BeHZ5xmKRr/8BI+SqVlzpFV5s
         xfx6KL3O+c09cJqhIGceF6xYPn++aPo7klwX/QRyc2uHCIVnmaWtK2+ymBv4yNvvSSJ9
         KhkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2WtrnGKm7LnUtt1bpZBhHXYf6k1JZ4xSJRQwroI5euw=;
        b=sZbQfhRis8cL2HmLeQ/iAu2hV8AspnXQbGh4MCBGtRNjSLhwGpd5FowAU5JeNT8d31
         15V+GCZa8MH/wEpLXFLhj9byhnyRAq4Z/MIx2B8gkbvBGGX2XdEDLnnnQXJOBNWf2uZS
         o61r+c7v4UIKqe75RPxXDHg+MAhJ/a8aX1S1YEJnJf31AkqPdhKcrh9gZygeexGBe4Ia
         oEfIk+B0tEwB9lYsEeBavA3SV47pmaqkMCtXdTB/xCbh35XYZ3gr73ObEsdJ4nERR52d
         tpbg6STyql9yFg34F6LzOOdW6KEAQp0N+pTL38wgFGuTI3XlLKUdwE8SD1fB10TMhfRB
         6+yQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532q+6Go8OS7936rvdlP0obeFRfN7/3pYY7iDzjl5XoQPjWxJgh7
	oqtuqVxuQd1y+CvCF6Wh6y0=
X-Google-Smtp-Source: ABdhPJxv5SHUE1EmDda97Fqw4CpGnct8tdRFY3gtM3IiNpzeSQTUzrg+XQ8DLwLxuf46bSxLspNqrw==
X-Received: by 2002:a17:906:51c6:b0:712:2a1a:afc8 with SMTP id v6-20020a17090651c600b007122a1aafc8mr1310740ejk.649.1655151327961;
        Mon, 13 Jun 2022 13:15:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:c19:b0:704:582e:9858 with SMTP id
 ga25-20020a1709070c1900b00704582e9858ls143497ejc.1.gmail; Mon, 13 Jun 2022
 13:15:27 -0700 (PDT)
X-Received: by 2002:a17:907:8b06:b0:711:e7f6:1728 with SMTP id sz6-20020a1709078b0600b00711e7f61728mr1304763ejc.32.1655151327250;
        Mon, 13 Jun 2022 13:15:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151327; cv=none;
        d=google.com; s=arc-20160816;
        b=z/FRyQsf7aZSG4Gtn+5ScTVfkNcQdd59PfGioYBgCw60aRH06b7FHDAqVqprw24QaZ
         Qdvl3lC0xSN6V7BqIu0KWN8M+1r7MhLYtQAwW2Jb5z8mx33OTWpnQT0BeWV5lCXSyP0+
         rdvBOdgJ2o9jev9Yt8eEQ9qgsXQV8Y3olU936saV5X08UE+bdAKG7F5ZK+548ZKpVcdI
         njBiCORwSAzhOGkvSzBIPGmWAYjCSie+0uDl6Ij9G29w76LrjvsQELHj6srQkqtHX5DZ
         aKOEFTAo0sRzAJCQlnbD9/lW3Ti//fXYsjDYnd7eexx0Yi+FrZlsaUE4hLYFfVf8lIaL
         EOTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AJyI1q6f80wQzyJSQxJLFHolqTP9cxvpgBekekTg5FA=;
        b=hBs1B+1Zy6Uiysxm9qXQCv3qKHJatl+QUdNMBLubj7+xRi3jB3sStOkfX02HsY1Ypf
         7/7DOt7HZf4fGWlJchAEOztnFpT24O4EsAgX1QnjxLlfgLX8XX2xjHZrn5VucSO36c46
         /jG/l7TJNFsE/A8GGiPCaIfzH3REoyIlyXc6FFdUh3SBAzi53jF+KmI1eBMhye4UVOia
         P2wTiSRSC6z3+IELVWrDNbGlPbfP7Y1A8gqCS67s76sU6VsMQYUhaIgBN8R5sjeeyzdK
         uJbV24UBvUSdCVrMeONIPoMaPoctfmgHlEyaaKYAaRcdidBINiJbD0GW1CDqk1wODdRv
         Vk7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oRiXY173;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id y27-20020a17090668db00b007104df95c8bsi353194ejr.2.2022.06.13.13.15.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:15:27 -0700 (PDT)
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
Subject: [PATCH 05/32] kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
Date: Mon, 13 Jun 2022 22:13:56 +0200
Message-Id: <cfc1744f4a5eb6f50eddee53238af1a2fb4e8583.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oRiXY173;       spf=pass
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

Drop CONFIG_KASAN_TAGS_IDENTIFY and related code to simplify making
changes to the reporting code.

The dropped functionality will be restored in the following patches in
this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan      |  8 --------
 mm/kasan/kasan.h       | 12 +-----------
 mm/kasan/report_tags.c | 28 ----------------------------
 mm/kasan/tags.c        | 21 ++-------------------
 4 files changed, 3 insertions(+), 66 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f0973da583e0..ca09b1cf8ee9 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -167,14 +167,6 @@ config KASAN_STACK
 	  as well, as it adds inline-style instrumentation that is run
 	  unconditionally.
 
-config KASAN_TAGS_IDENTIFY
-	bool "Memory corruption type identification"
-	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
-	help
-	  Enables best-effort identification of the bug types (use-after-free
-	  or out-of-bounds) at the cost of increased memory consumption.
-	  Only applicable for the tag-based KASAN modes.
-
 config KASAN_VMALLOC
 	bool "Check accesses to vmalloc allocations"
 	depends on HAVE_ARCH_KASAN_VMALLOC
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 610057e651d2..aa6b43936f8d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -168,23 +168,13 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
-#define KASAN_NR_FREE_STACKS 5
-#else
-#define KASAN_NR_FREE_STACKS 1
-#endif
-
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Generic mode stores free track in kasan_free_meta. */
 #ifdef CONFIG_KASAN_GENERIC
 	depot_stack_handle_t aux_stack[2];
 #else
-	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
-#endif
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
-	u8 free_track_idx;
+	struct kasan_track free_track;
 #endif
 };
 
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index e25d2166e813..35cf3cae4aa4 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -5,37 +5,9 @@
  */
 
 #include "kasan.h"
-#include "../slab.h"
 
 const char *kasan_get_bug_type(struct kasan_report_info *info)
 {
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	struct kasan_alloc_meta *alloc_meta;
-	struct kmem_cache *cache;
-	struct slab *slab;
-	const void *addr;
-	void *object;
-	u8 tag;
-	int i;
-
-	tag = get_tag(info->access_addr);
-	addr = kasan_reset_tag(info->access_addr);
-	slab = kasan_addr_to_slab(addr);
-	if (slab) {
-		cache = slab->slab_cache;
-		object = nearest_obj(cache, slab, (void *)addr);
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-
-		if (alloc_meta) {
-			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-				if (alloc_meta->free_pointer_tag[i] == tag)
-					return "use-after-free";
-			}
-		}
-		return "out-of-bounds";
-	}
-#endif
-
 	/*
 	 * If access_size is a negative number, then it has reason to be
 	 * defined as out-of-bounds bug type.
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 1ba3c8399f72..e0e5de8ce834 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -30,39 +30,22 @@ void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
-	u8 idx = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return;
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	idx = alloc_meta->free_track_idx;
-	alloc_meta->free_pointer_tag[idx] = tag;
-	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
-#endif
-
-	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
+	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
-	int i = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return NULL;
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-		if (alloc_meta->free_pointer_tag[i] == tag)
-			break;
-	}
-	if (i == KASAN_NR_FREE_STACKS)
-		i = alloc_meta->free_track_idx;
-#endif
-
-	return &alloc_meta->free_track[i];
+	return &alloc_meta->free_track;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfc1744f4a5eb6f50eddee53238af1a2fb4e8583.1655150842.git.andreyknvl%40google.com.
