Return-Path: <kasan-dev+bncBAABB37M26LAMGQEFXAKGCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AE04578EC3
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:10:24 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id bg37-20020a05651c0ba500b0025d68341139sf2276442ljb.10
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189423; cv=pass;
        d=google.com; s=arc-20160816;
        b=ctDThPjfLmCNQiKXO3be6eUBe8HMC6djXFZYKI3adet/bNQr7C1gFUkaWzkSHvU3fl
         CN/rheFm1sha6DatcwaT/xrzEiHQukD3UIY7G4LBu8T+w/uQOj3T7Y02XI7wAvbMF1cz
         1+34UKO1ZKx2QgZGkOkZeOC1HL6dk+diun8eTFBoDZ949XjXb4Wo1KsdIVBZBdR4kVMZ
         VqBCeP4vas7BBAR50t/By/ROQ7Mw1Z3iKqE169rQEMdKHjiTzZJM5d2IRY8X83S0gpTM
         wE8zcecoK/H05F/xLiN5438TbVcxfL4BqtW7gIq89YF3oIepD9cBSoeG6XIr2dZ9aVjl
         Ox+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T5izri6ljBzeK8hXYdoOgIkio3h/j0Vda1zaCNeZQzk=;
        b=IhkDJEa5OVfdqvzKh28zzB6VukZHP0AGIBqCFGFLD6DOq7UUeI6TURFtl/SFqxc2b8
         aHqc+pSxJpiLrE8FNZVz5wNVCx42armPK9/GXeRbGumwowjz3hToJGF2btM27uthii/O
         UaHvekg1HY+xVoVdEnp1Hv71bNJnGm5lT+Tg2hrf4QdmaZmm8F2F6bwVBLLYV7xFNrr4
         vTr5rpUeaCbQoE3COLaILbCacs/zZsdDXDc5X2MTFbiA23T9uFBUigQA0JJOi6xQ9HTH
         cOGrxf+0VRDRqNIVT9ME7uvrBotjnSCHSjTYB6MsW1Xe89mdb8rL8cMJlsACoaCfHzJS
         ugSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KuLkwH5O;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T5izri6ljBzeK8hXYdoOgIkio3h/j0Vda1zaCNeZQzk=;
        b=oJlGoMhjtlKX6EaMltH8rN9yaykXsOy0MCzUfXkk2k8upia9nJUJeDQ6MBwglbwTcA
         FUiaF835bBUP6dcAIlYXHvPvC5HFTDxQ9Bj+VsA6JSLdaDotTJo2t6RZbqwCnGZLfRBv
         2XObsfHHSZUFh5AHm7+ds7DY5/2q48AIa6oMHD3gK/53jS/ojLG9R8RN27Ji2InUQ/G6
         aP8bU+oD8PUmTQ/+UI37nXRWSR1EG9KcAT/dKBhtWF1IwAix0LyQJ24lkPPshfvSKe4S
         S0VoQHfrwpILyBCadZgjhaaslG7B8nw9sn02mibDqWdVUUojs1VKkrYONre5vcFjsPKS
         ZSCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T5izri6ljBzeK8hXYdoOgIkio3h/j0Vda1zaCNeZQzk=;
        b=wWInZbyQSDO3Q1o62VoTXzbrE62Gq/2kwfYCWPfD6jHxq6n1WOdYDRdCX7bu2+7k7Y
         C57LifMPwx0qPLz1vkEXFNfbazoFrTQ6AIGS87Gh/tmIZuhHb75AYmbaF2kdND41oEc4
         euFCp6H6fps0Sw3ZMLe2SP1R0bnOhwot7BfgVs/vpnWtSc+hNqDQFsyjDdYYIGpxcf9C
         hAM+yJG7dkZDUrtT+B32tNhiRdPm75+W3IxbbhOg/nBu/GQxL3ruYXt8i6ovEhFAbU+M
         7ak+8S6sbIUx31fiwQT1xq9kdMOKHZixfVlIE6cvAk7+dDkvy6ivwG3H1hPSIG5c9QOE
         +Xcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+39WzvBeymOyxjex+cv0a/UhFCU+uEFcSHbpyRbNEgNjdLJARZ
	RLfogm0ZgbLfkOLpR86t2JQ=
X-Google-Smtp-Source: AGRyM1uLFZ5fdF+e0DVte2yAx0szWB4nUHINjkFzUWD+G8Gf87Z3i3ZjyOqnNvNM4YjLJzINtjZ1lA==
X-Received: by 2002:a2e:312:0:b0:25b:dc9f:9e7e with SMTP id 18-20020a2e0312000000b0025bdc9f9e7emr13949336ljd.57.1658189423706;
        Mon, 18 Jul 2022 17:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:154c:b0:25d:6f75:eea with SMTP id
 y12-20020a05651c154c00b0025d6f750eeals115537ljp.8.-pod-prod-gmail; Mon, 18
 Jul 2022 17:10:23 -0700 (PDT)
X-Received: by 2002:a2e:80d6:0:b0:25d:62aa:2b11 with SMTP id r22-20020a2e80d6000000b0025d62aa2b11mr14228086ljg.375.1658189422905;
        Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189422; cv=none;
        d=google.com; s=arc-20160816;
        b=cbML4K9SnHk5gqRdkaKDyeo/HwG3yLtAQfwwV/AuVcNSwh74LzOqV9rXnWMElntfgb
         eGy7y77TPjesmENGa1jc8KG1pqejjTZfxQJ4+A+o6QSEKDZqbhaAtOPupTQiiS4R0JDC
         hoeRe9foNQvZME6rGmIVgGF3LtFic6oq/RzmlyTj5qJTKLhogUdJN1b7Ug64QQiZXN1r
         52xTpEe7PR+WwmtEYnQtQyEgvW2DBnhZ3MNiOtn22NY3TESF9BsvsOv/aXz1bFRYYLpI
         n/RFT6fLbR91NWIy1roURaxB89PWX+fnWL5yzoTBFLbya+leWmSNYAeM6BER8q/g81Rv
         Fq/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=btqlB1PcyI2oEVK30B4u2+ZtYIXUDjtBMu4es4RldM8=;
        b=h1Sk4qwguj9XfCH4/1jVjKrobImZ9EDsXjPm01altREqAzP6eebkehumgoou1kMflw
         +lGpTtMcjm4cuc1sfRYAiwVug8KpbRmWXw0ORU3LBq+ELo4H7l6aZqbHR/IzU8oAND7O
         SWBv/yVRW4k8siL+Ez6Zcugpe2Yr8KDIQt/XA+3X5d2wT2knWT3evo6+Xzs6O18ml8uO
         OrRO+0plRuo6UTpH/nzKr3qEMcil2BKRTGicTHqRG7UM5QPz/W2uBQloLiyp8mVPkH5f
         GCnHdZB8x+3DxD94K7ncjWjaMqxjvRrVYqq05w9gn4feqfEvL+KAi8fISyIiHlEdPKA3
         eNTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KuLkwH5O;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id g7-20020a056512118700b00489d2421c05si402565lfr.4.2022.07.18.17.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
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
Subject: [PATCH mm v2 05/33] kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
Date: Tue, 19 Jul 2022 02:09:45 +0200
Message-Id: <19d1c6e68d66fc261bec30b9a2cf4f533df6e5c9.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KuLkwH5O;       spf=pass
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

Reviewed-by: Marco Elver <elver@google.com>
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
index d401fb770f67..15c718782c1f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -169,23 +169,13 @@ struct kasan_track {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/19d1c6e68d66fc261bec30b9a2cf4f533df6e5c9.1658189199.git.andreyknvl%40google.com.
