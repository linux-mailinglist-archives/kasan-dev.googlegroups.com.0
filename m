Return-Path: <kasan-dev+bncBD7JD3WYY4BBBU5RZSCQMGQEQ7U5CZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 31C5C394F9B
	for <lists+kasan-dev@lfdr.de>; Sun, 30 May 2021 06:47:17 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id z13-20020a056808064db02901eea2bd1806sf3433296oih.7
        for <lists+kasan-dev@lfdr.de>; Sat, 29 May 2021 21:47:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622350035; cv=pass;
        d=google.com; s=arc-20160816;
        b=k+dhrt1BGBlp+1JaxwnKxagb5Ibk+5BkIENRsjxvB+FI9VvP9oMLl4G7EuZbrFlKw3
         YPK7DnuM0ZWzFKuBwCqgHF+YFizH7+GvX6OMalLWF/raINDineLfMFzOLNnqSW+2FycW
         IZfS2mcil/yLKym10M0ApWArUpP0vp03OXht/xAKG1l6mVs9wezy7cmQlLzY4vfpVdhY
         OnAr7Vpb3zccq14wwDHAVsO6SgugsfxdJQ49CyrH4OQr+f4yjDEWfCjJWES34lSnbnvz
         gHoJwwumW6YZPMJAnM8usVVdLB/TGR66HpCIsjQmLiHg5w+Jxbb8O72psHGL7N/G1Ap0
         ayZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=570S2hdkTNTzz4rLfGRiPJL2c2JOfPNkf1EMwCMwWP4=;
        b=JPHyXA/U0OD1z94M57keurY6iwzTsdi3JHQ8BYdO04HPxwuscTC+JxwdVAFb8TiFCm
         blnCf+67ZrQrc+/07oBRRD1t3jpC4qLNfxYzizJZkL5rUp1oT/UYH7ghi4ViYhPFuZmA
         2LwhCBKf2NyxDdjRj3dnLHndm6PbxsD1ZcZ5/YniH05KJzdnib+WJ2jdfPqOrYFc4t1F
         JTFIEkbKOIYR6GRMB4XJZm9wn+y2XiWS4nz7IgwVpvokaZsqtZwRBQgetuClm0XDb6BX
         GOIxACMrYF1WV9utSXolp/9VYhGusBKWnjmg4WS7g7lCErjMJtDgfL1itQ8XG0ZE3GsQ
         LjCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tuhSD2Zs;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=570S2hdkTNTzz4rLfGRiPJL2c2JOfPNkf1EMwCMwWP4=;
        b=pLyOvxnAVgPiuMg3bpn8q4D73ha5+6CQTI0mW58CflvHVQ6v/R03EB8RybTnQNy/Qh
         z4LLz4SRLOmTRt9XZdLRC/+qLZnDs6/VIMrAS3ahZITElOl+2xnAmyYyvz05sTbg6B3e
         dxftf9L7rV7G58qf2jkXCgf11xSl4BCMQR8OEXY72pRKKWPk7pp2KH1ks+whJAX5B9HY
         g+R7sKqOFhoC3a4qCfb+Tk9YeVqBhTLm/vodCUGuQUGNYh10aq5EyqerIOKcxBptdfnE
         eUhVWOnb165NZqavPCmpqTT3TOufj9C7HAtodnGHzl5GBf/MDsPrYFJtKeFEOJbs4kd4
         v0fg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=570S2hdkTNTzz4rLfGRiPJL2c2JOfPNkf1EMwCMwWP4=;
        b=AOYqnXw6mOtlYHRPoZxA4Hgjfc7jEoN8P1ZABxGmOJ+hy+Z3SxCQIzJ50NOKseoDWa
         MU3POYYiKLMccCGl8cn1ppmM+pothFMwlGE0fNIFaPtx1t8JBmkvoguci3eDif5ov8Sl
         DY4lG9TB6VXUeQR8/JjtaMFFQyBQSNg2Ewya966S3dYFdrEOs9W0yeqKx3wrp4s4VRRN
         EeUk39VUgNdj07StFvkXaf+8F4Dy6JiiJIDt/sxMdD++O4MWGLAvUcJuzuqHG9VJSN91
         T4zZW8ykMUdlUESJexRpItXvmPXWKCAeTkDV6eLrqhHEi1pi9CMbc9AiVtT2M5g2ENAL
         BgXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=570S2hdkTNTzz4rLfGRiPJL2c2JOfPNkf1EMwCMwWP4=;
        b=jKuHIKUIrcA8umm/gNnBUGj7KD1FdyNLVhrR0wogl+Dixlk1QIsHhqFuA1XEWkbaNs
         CAJ82w1EdedXNLe+3BCqCl/ECRlZgEghqn2EPmQIkKPQowZ0j98EK9zj8Z+y7A6wkIM+
         xrxKrOZzVBazz6KCaAKM7VKX8aBXM6m0UA4pjvVcf5+YgkuB6aHg7FiVkho//jIQeid1
         I3Gd2XnYZ5J3bC9Kosl/CXInQvY0ivFssgL81DZ1IljL1NQVaqVcDfRlx5HQeLGepoWr
         O73NB4TRkTTciv03csFq0hpTyyT1ltNMWud52ql3K6DRFiS/Vh44m2iaHua/Q+9S29/h
         SCdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lBvBsaTaKAfpX3ha92xPlCP6b3KSP27731NCmNNUymrsqYjzr
	YRZ/A8m6sVPvs+d6wQibUkc=
X-Google-Smtp-Source: ABdhPJxqNLY32bFy7LemUsk7tTSK6Rku8dHSi3qbB5JsjGvAkJmcNqhwvx9SH5YQwaOVZjmaDEf3+w==
X-Received: by 2002:aca:488f:: with SMTP id v137mr10435215oia.173.1622350035766;
        Sat, 29 May 2021 21:47:15 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4705:: with SMTP id k5ls3225957oik.3.gmail; Sat, 29 May
 2021 21:47:15 -0700 (PDT)
X-Received: by 2002:aca:de0a:: with SMTP id v10mr960140oig.161.1622350035357;
        Sat, 29 May 2021 21:47:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622350035; cv=none;
        d=google.com; s=arc-20160816;
        b=RjmE3KLtcT0dk+V3pFYwx3kE7YbjE/+xRLk2mXSDpMXaWRBOmA2d9KXU85/gZbLFWk
         MwHoZ7H0bTMauGQFQMBkOjmQo45NjK473bLgrMnCZEDScnJncPp6qhVG6UqKEMSYJTIz
         TPu8zaPojca1AzyeH3Qd5oMZLecZxTtImJ2zmf9PERIsbXDEcHlp+vjHZ7hxbBkhHZrU
         L1bY9yzhzBTxiGk+aInnmeG8ETb8WTFzkeqpWhv/5Eeg/39etpEQ2TOkj/Cs4OXhAAR6
         8Z90ctiBzanFUW6ySorf/pHyPKTzfUX36ZfPlZyh/jx5D4Ng9I2UJd0S8VfPDLhdFt69
         o2kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=iF5+piAFy1H+gDGG26ovo/7bII1xMjc8kc5KVtIH7A0=;
        b=T9O4z8YKTQCHgq+9J+7uUqmDxA9SdAG28qQNegk3V2Knyv4Ib6/c8o9DqUY/Wr1md/
         Jmzh5hzbgwi+ZpWFn4MAUKP7xzpvpy7ll9LPyOFsZa468qTAe5dT8IfD4vdNduzVhut4
         mGXrcTJwC7JUdsjrBMJ23UNFvV9uTCOYPHNUF74k4DQI9lMMCc4icwpVe/b14nOBCuPM
         cr3ZlX49wQHTmpAfCoQna8Gv8GRodcbpgnrVun8jMSqZJ+8/TAzvNRpYKecpSoH0gkW/
         ACG5myA3pF0ajrfZtRyN8mEaBDkLTUFX/s6LX9QVLrvdemysixIUSZppL22CYeRT8C3y
         Zk8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tuhSD2Zs;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id c4si1586194oto.0.2021.05.29.21.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 May 2021 21:47:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id t21so3568456plo.2
        for <kasan-dev@googlegroups.com>; Sat, 29 May 2021 21:47:15 -0700 (PDT)
X-Received: by 2002:a17:90a:4404:: with SMTP id s4mr12768266pjg.218.1622350034746;
        Sat, 29 May 2021 21:47:14 -0700 (PDT)
Received: from localhost.localdomain (61-230-18-203.dynamic-ip.hinet.net. [61.230.18.203])
        by smtp.gmail.com with ESMTPSA id t1sm7471108pjo.33.2021.05.29.21.47.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 May 2021 21:47:14 -0700 (PDT)
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Kuan-Ying Lee <kylee0686026@gmail.com>
Subject: [PATCH 1/1] kasan: add memory corruption identification for hardware tag-based mode
Date: Sun, 30 May 2021 12:47:08 +0800
Message-Id: <20210530044708.7155-2-kylee0686026@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20210530044708.7155-1-kylee0686026@gmail.com>
References: <20210530044708.7155-1-kylee0686026@gmail.com>
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=tuhSD2Zs;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Add memory corruption identification at bug report for hardware tag-based
mode. The report shows whether it is "use-after-free" or "out-of-bound"
error instead of "invalid-access" error. This will make it easier for
programmers to see the memory corruption problem.

We extend the slab to store five old free pointer tag and free backtrace,
we can check if the tagged address is in the slab record and make a good
guess if the object is more like "use-after-free" or "out-of-bound".
therefore every slab memory corruption can be identified whether it's
"use-after-free" or "out-of-bound".

Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
---
 lib/Kconfig.kasan         |  8 ++++++++
 mm/kasan/hw_tags.c        | 25 ++++++++++++++++++++++---
 mm/kasan/kasan.h          |  4 ++--
 mm/kasan/report_hw_tags.c | 28 ++++++++++++++++++++++++++++
 4 files changed, 60 insertions(+), 5 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..f7e666b23058 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -163,6 +163,14 @@ config KASAN_SW_TAGS_IDENTIFY
 	  (use-after-free or out-of-bounds) at the cost of increased
 	  memory consumption.
 
+config KASAN_HW_TAGS_IDENTIFY
+	bool "Enable memory corruption identification"
+	depends on KASAN_HW_TAGS
+	help
+	  This option enables best-effort identification of bug type
+	  (use-after-free or out-of-bounds) at the cost of increased
+	  memory consumption.
+
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
 	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 4004388b4e4b..b1c6bb116600 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -220,22 +220,41 @@ void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
+	u8 idx = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
+	if (!alloc_meta)
+		return;
+
+#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
+	idx = alloc_meta->free_track_idx;
+	alloc_meta->free_pointer_tag[idx] = tag;
+	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
+#endif
+
+	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
+	int i = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return NULL;
 
-	return &alloc_meta->free_track[0];
+#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
+	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+		if (alloc_meta->free_pointer_tag[i] == tag)
+			break;
+	}
+	if (i == KASAN_NR_FREE_STACKS)
+		i = alloc_meta->free_track_idx;
+#endif
+
+	return &alloc_meta->free_track[i];
 }
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..41b47f456130 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,7 +153,7 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
@@ -170,7 +170,7 @@ struct kasan_alloc_meta {
 #else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
 #endif
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
 	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
 	u8 free_track_idx;
 #endif
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index 42b2168755d6..d77109b85a09 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -14,9 +14,37 @@
 #include <linux/types.h>
 
 #include "kasan.h"
+#include "../slab.h"
 
 const char *kasan_get_bug_type(struct kasan_access_info *info)
 {
+#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
+	struct kasan_alloc_meta *alloc_meta;
+	struct kmem_cache *cache;
+	struct page *page;
+	const void *addr;
+	void *object;
+	u8 tag;
+	int i;
+
+	tag = get_tag(info->access_addr);
+	addr = kasan_reset_tag(info->access_addr);
+	page = kasan_addr_to_page(addr);
+	if (page && PageSlab(page)) {
+		cache = page->slab_cache;
+		object = nearest_obj(cache, page, (void *)addr);
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+
+		if (alloc_meta) {
+			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+				if (alloc_meta->free_pointer_tag[i] == tag)
+					return "use-after-free";
+			}
+		}
+		return "out-of-bounds";
+	}
+
+#endif
 	return "invalid-access";
 }
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210530044708.7155-2-kylee0686026%40gmail.com.
