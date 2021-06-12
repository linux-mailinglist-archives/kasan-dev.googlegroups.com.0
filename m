Return-Path: <kasan-dev+bncBD7JD3WYY4BBBHX3SCDAMGQEHUVT23A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id C351C3A4CE8
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 06:52:47 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id i184-20020a1fd1c10000b02902356b2351basf2723674vkg.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 21:52:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623473566; cv=pass;
        d=google.com; s=arc-20160816;
        b=M2Ed7bnBtH1Eabn4y1yjR0dNFAhvMHBQuKHvyv6N46hWr/zj6ldnm87s9A6014NO59
         rZiIbEufBLZnYTE0tr98iJQGnaviw2UkHNkOD5S6YubRflvNy5QJJRv9tHkcgFdBGdqS
         I2oz/pSIXSdgkfq2DZnGXf/16Qz2cLMzDsnXvjg5pwFcQRfMv4kuuEuLGRuyArx2Gq56
         o3p2mhn3462stHWtzYnwE5wxon5h6lPpqxCTXK1gAY2C9YKLbhQn2t8ThlZF4NSYyd8k
         7/ULcYPT5JNZOXhdzyRQPvdZ7Aos5hn1n2ItatUivZ9XRlxcI7P4u0736mAHFI/nnimk
         ZoEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ysmMgqn+dxqHkUNFbwm6gCzVn3IhElbjyZRQ+15qyMc=;
        b=llj/y4QArYFOI/2dWPMWUlQKdkspyA/SSNB9pNUJcslkt2nndIqNXiypybrjPsER3T
         IBpvLSvFquO7jZmoMCqfO6hEYgy55wJs3sS733bxsxFV3i2VVsxxd8ZCBa69IbhLl9R6
         aZuDH6lkAgGr6vKXbGv3jpKsYlKXWE57KnKAlzLsT/I8kBQtynnoefxrgz7c5xjFHmBZ
         BQlYONQyxYwtpg+RkahS/mg+Tsog+3seWqsv/9VV4Tzye2F5VaTPCOG9z1b2+1w1b7EI
         aL8mNtA3Q98X4cWMtUX/BQi2dIBpO6f3lLX+g7Kzugv+/F28JDMIL0qtx85sc/DHcbHb
         lVkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Xfi5pFS5;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ysmMgqn+dxqHkUNFbwm6gCzVn3IhElbjyZRQ+15qyMc=;
        b=RMIFcaYvKt2NZTJdRttNcuaAkQW6GYOLMM6WJpPc9nKjRicIvfeuAFb3200fopG9Uc
         HT4L/rtR54dY2MLp8x4bFjAaLzcEKhGyE3cdUFB12FpzCxwICHoi6Xw+9l0ot79m7ifo
         SMsKNUHpOb/0gOOpagqjH+M7cVaCcM9cMhC65bMOZnOysKTsJlUZ0V+PiSHbJYEwVVMM
         SHjFVdRjaXoV3VPCktGzcH4ijCEoPkLxHnXxFXhpwXU45d64zlgQ6GBbI4guZ/vJosgr
         W0fpFdvheHd+xuOZXP8gL5xXgHhbZ1/2dCyklwALBuHCKWe8PA8FMCaIwBdco8Wetg91
         TJcw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ysmMgqn+dxqHkUNFbwm6gCzVn3IhElbjyZRQ+15qyMc=;
        b=lYGI//Df9wid7obYxYRLIcI73lOZMo+TrqKsezXHkhG4n+ODmqJzwp+vLiExh1oH22
         ks391U7aciEADhdwHADdt/klZZ/6L6zLmveZh+qyBMNUli64NL4fYSVAci3kyi1iO0eq
         PgdVJh73hPzCyeHkdI/xjh99XOgnKZZZl6i37BNfETNkUUWa6rqAamvuy9sR9B6AeiFG
         omgvEAhg7uYBnfqhSs7zxnOA5n0b+mjQsGf1gPSezTvMahx6B8781Htjp8SlD56wJOpg
         5o5IcYfNb+3P6xQ1WrVdhurrIchUL2L6kkFajRI6YOAJnpZIOWQpYt6zHs6Zjbkvs3Vv
         7Jqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ysmMgqn+dxqHkUNFbwm6gCzVn3IhElbjyZRQ+15qyMc=;
        b=EcxTZYgbuhLMFXPzBEykLLaebQylrTKBKFkza+nfTS3WMbrPLvcgLxEAfNeicW2rOD
         AYHLoxrGROFYaaVPV66wzyLjQ4cTmIJe4F+IsZf045o2r9tWxzsZPicdk2OGkyU9HFou
         VL3WiYYymyUmtoKYAppNGIHzBKYh7h8u4JFGk9Zd9dzB2zvXqnZb9cDQFLYsfyPJWja9
         REVqnLJf/VtjfNEJRJlEngZ2yys14biKwzWaAHFgdQLN4nDqIWJgcjh2TBvcTLJkByJD
         cDEQaJ4XqRbogJjkc9bvLj2Tw5O1/FmExhLf0YoSn+JMFm1TQMLCeDPUoDJ19D6JAM5H
         TkYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Yfp1ZaEaz6hGRgSp/1WQ7fZcuFe0fm/BairUL5lWnzorstM/n
	YmihOOl1TQfG28x6GQlW6E0=
X-Google-Smtp-Source: ABdhPJyrX/b1PQmzERMhDf1ftAGW/H66MZNmhNgLZOtUAnmJ/yCsUCLiUhU8LzZ1hIDw+Gx3eucQpA==
X-Received: by 2002:ac5:c9b5:: with SMTP id f21mr11253826vkm.23.1623473566738;
        Fri, 11 Jun 2021 21:52:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:c704:: with SMTP id x4ls1144501vkf.4.gmail; Fri, 11 Jun
 2021 21:52:46 -0700 (PDT)
X-Received: by 2002:a1f:9106:: with SMTP id t6mr11407238vkd.19.1623473566315;
        Fri, 11 Jun 2021 21:52:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623473566; cv=none;
        d=google.com; s=arc-20160816;
        b=0CEhST9MVFZoRQMu7swDmxFudE/hi5tfZ+viCtzPM7+ATa33ziJHSzkqn25eo+ZQN3
         d7zvIMM8scgsGDTPzzG3a4Xx06LtXxQPtP40C0BVh7IetDSLXj/Y8s22sWyPND5T3QF9
         2liFGRHi2+am9H7lczMjEUSuSDcsUEfCoQZhXK7bp6W75ecRjfYVWUrWwBV76OJq0CIS
         pii+Vkxx/U+N8aoobEndGIyEqQ/3hkLtTY3hLO61ay8uZoIFeYxQxMJe1lE13u6Za1na
         Kxd8U3ACnNrBuPy1C9QcapB9fTVQpBo0JsTIWOq//S2gGyPzygrU3kOwhqYytJUQbGn6
         LVag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=j92rbW58nMKVCYwSujbaWen32AsKLCNI08XRkv0EOjw=;
        b=YibpeLFzazrVId98sQxDl8lZ2cIUr+L3uv/kxWyJJBo4YCNeON8YdgfY7tXz4aEfE6
         U4WgMe44LUFypzPObm3zkJCkacBkZQmp0QBiQq2ARzJg7itlS5w1JePHhugbrEYH7sJ7
         O43aMn7gwhJ/f63+4ZYUGL935cS0LMWfrQ8bSaGkC30Qc9x0NiDFfNgPXz6nNSLd4UTm
         cRJNrDmXD50Rj2gkSY1wsnJp6c74v6OVJrswCG7UKwtEEmBr3cEZX6Md88L8BfaadESQ
         jkdz8yodFyzp4Q0fNAiBv4TBa2P6bvpo7FXm20CG8alLXR3+tJTK0ZKGxqC3MuVG92am
         t99g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Xfi5pFS5;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 8si811323vko.4.2021.06.11.21.52.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 21:52:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id x73so6099065pfc.8
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 21:52:46 -0700 (PDT)
X-Received: by 2002:aa7:8892:0:b029:2f5:33fc:1073 with SMTP id z18-20020aa788920000b02902f533fc1073mr11510790pfe.79.1623473565850;
        Fri, 11 Jun 2021 21:52:45 -0700 (PDT)
Received: from lee-virtual-machine.localdomain (61-230-42-225.dynamic-ip.hinet.net. [61.230.42.225])
        by smtp.gmail.com with ESMTPSA id m1sm6076572pgd.78.2021.06.11.21.52.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jun 2021 21:52:45 -0700 (PDT)
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Kuan-Ying Lee <kylee0686026@gmail.com>,
	Marco Elver <elver@google.com>
Subject: [PATCH v2 1/3] kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to CONFIG_KASAN_TAGS_IDENTIFY
Date: Sat, 12 Jun 2021 12:51:54 +0800
Message-Id: <20210612045156.44763-2-kylee0686026@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210612045156.44763-1-kylee0686026@gmail.com>
References: <20210612045156.44763-1-kylee0686026@gmail.com>
MIME-Version: 1.0
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Xfi5pFS5;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42a
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

This patch renames CONFIG_KASAN_SW_TAGS_IDENTIFY to
CONFIG_KASAN_TAGS_IDENTIFY in order to be compatible
with hardware tag-based mode.

Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 lib/Kconfig.kasan         | 2 +-
 mm/kasan/kasan.h          | 4 ++--
 mm/kasan/report_sw_tags.c | 2 +-
 mm/kasan/sw_tags.c        | 4 ++--
 4 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..6f5d48832139 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -155,7 +155,7 @@ config KASAN_STACK
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
 
-config KASAN_SW_TAGS_IDENTIFY
+config KASAN_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
 	depends on KASAN_SW_TAGS
 	help
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..b0fc9a1eb7e3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,7 +153,7 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
@@ -170,7 +170,7 @@ struct kasan_alloc_meta {
 #else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
 #endif
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
 	u8 free_track_idx;
 #endif
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 3d20d3451d9e..821a14a19a92 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -31,7 +31,7 @@
 
 const char *kasan_get_bug_type(struct kasan_access_info *info)
 {
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
 	struct page *page;
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 9362938abbfa..dd05e6c801fa 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -177,7 +177,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	if (!alloc_meta)
 		return;
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	idx = alloc_meta->free_track_idx;
 	alloc_meta->free_pointer_tag[idx] = tag;
 	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
@@ -196,7 +196,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	if (!alloc_meta)
 		return NULL;
 
-#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
 	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
 		if (alloc_meta->free_pointer_tag[i] == tag)
 			break;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210612045156.44763-2-kylee0686026%40gmail.com.
