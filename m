Return-Path: <kasan-dev+bncBDY7XDHKR4OBBBOWXSDAMGQEIKZK4OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A0ECF3ADE33
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:48:22 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id w4-20020a17090a4f44b029016bab19a594sf12016911pjl.4
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:48:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624189701; cv=pass;
        d=google.com; s=arc-20160816;
        b=TUeUTVyLzyBltd6/AdB+D5C3ii5hoJBoWMSMrq4MDbaK2mOikJg/nOp4Gt5TZgwF8Z
         SYNb8Od/VMIgtlRqPt7jTMsBHCq2VU2kBBkZcCDAwW4oxhRGThr+jM48LDCZCUW7wHft
         WNpkAQLyaaTl1sDucoh5yNJmOl94WV7hN16/XvjoqCL3KWN/ITtEi3UY18AbHw/0wlsn
         XJNV//9K95VUBOq2syWYQnS/WXQelmymoMBziY7vZ4j77TqVRIv1EjE5QjYpmKlx0NpR
         7/yziyQpTUBNUxtr0GCLjIgBYwKXxofWxZ7hKCi4223a3I34kgqThHqJgDhavVPV1EZB
         fA3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2S/ZhSencVMysEf7DXylm8brwZHZgi3acp4xbpSfqtk=;
        b=zisnvKv2Ugv2iibUgCJzG2WJYDDSiSJMrS3ah9L/rc1YTMaq/VQgNBvNhiUSW23R6p
         Ue6XDaODcT65YZ8nu/+ULdGE2ZTAbHue6roLralQHTqPV65N4KXKfvvV8iAQTelWr4Yd
         aB+oP8JUMXAlI5WDYzg8HV9ZZoIh9NJhN/DpiNvF01QB7XiqVJlbcfmI1e2wqDZuOdqf
         6gf80MHZUQLaMLHBogAjd97CZmkkrpbqjO6++0jiqEJkJVk+DQQIvriS5pID6EScqiAx
         ophKPQAsBd2LJQ9NjObewOLAEh08ZJ/q192jYjg2DRchSHkt2M+U4E60IIrBY7szJ691
         aBsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2S/ZhSencVMysEf7DXylm8brwZHZgi3acp4xbpSfqtk=;
        b=imcNWPKPzxc92LKAi80TttJR6Iv/hqrXL2M5tKWhLC2MPhtSg00o29Hl67wohafYHl
         cETBibTL3YitLyA+cNgqHpzH4Uz55YMxDkqFYQoCNfJtxKht6PXrgXyxMWMcr3QHUsS5
         80TuSUHLc9qD7ejzIZMpxf9yZX7KWxiloI79qrn6+tlDgt5+Jh3VRY4HJlEpDe7ZFB24
         aFv0coKiXXyB3mbHI0b/Buk6A4oLD5u3Qsu7GnA1fEEj+KMEgbIBxs55RjQ3Rfrz3mYR
         YkVrHNVveW4sekp5jeLuFMEWuT/LtR89bf4BnPtiIsgRzcZ3VjsOUQ+cpuCQzozQzx0K
         Qg2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2S/ZhSencVMysEf7DXylm8brwZHZgi3acp4xbpSfqtk=;
        b=uT0hR8fQGirtdN9A8HFePl+/iHii9fa8ND4u0I8Wa9LKmTc8JYYgHHNzO3bHHrcbw7
         JSdadSCV9pkhtyMtnXbdyHIen/xKMYigR+mICVS7FgMEofzIJHVAibqiOZZnvfMSXkng
         d+hTTCe+pG0J28D6qjxLP+1aipF8RnZa6oY+nP264Nx8eWq00WlP1xny+yZ2Kela5h4V
         NWU36sveHDAvo8G1oV5U6fBqyogsWydL/p8Nun6yRYDtuMNfvxKgG1TSKS70RQnr+V5s
         wA+nqrYKZjypAzpVH3XMC8//AwFiioKXnpKspd0e7S7Y1dzp1cmZ+eT/pigHOAhIx/nZ
         G31g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GWEvKd38YIGxBJltW2nGGcetRCR20IEo65IJAphR2S0b5WUhU
	29jviHEaRy/98UvqiDNvwcc=
X-Google-Smtp-Source: ABdhPJxXWk4Ok+2CR92wIEAO+RTZ0vDpnqRe4vfaOxYr6HzZ/7HyFwtOV1dYDlpTr4HC2pXrTMmTHA==
X-Received: by 2002:a62:1d0e:0:b029:2d8:30a3:687f with SMTP id d14-20020a621d0e0000b02902d830a3687fmr14196305pfd.17.1624189701144;
        Sun, 20 Jun 2021 04:48:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ea4f:: with SMTP id l15ls1221771pgk.11.gmail; Sun, 20
 Jun 2021 04:48:20 -0700 (PDT)
X-Received: by 2002:a05:6a00:b42:b029:301:739b:e2dc with SMTP id p2-20020a056a000b42b0290301739be2dcmr6944891pfo.38.1624189700650;
        Sun, 20 Jun 2021 04:48:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624189700; cv=none;
        d=google.com; s=arc-20160816;
        b=uCWQxWx8yLZtfm96/zE5QzV4a1KC9AHHwaK2+iZ6D8d6j6uf9aufcAOdWc1sB3u1IF
         GXbyKIzZfLZanERUKAcXGcHkYJIXxrdR4YexHncgqhPR1TpinqZO4N506ygbYYSOo83y
         qEHYDVnvWv83PzGK9MpCk0G+W6WFBcun0FCfSAsqrzbYRCBWqGH+MkSR9dbmu2a0Zp9p
         VssTTvYPhd7hxhvWI6tAa24inn8/E2ysqEiWtcldRSiMQEYhWd/Qp+H08rPMpgdi1n/w
         Z+lu8YQM+jU2EC5vab2SkL/9+dQiEswC+6/A/tsi4fFsE7S9J/Q82AnrAyTTpH+gwkWX
         sG7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=18mTP/LkSLET0xVhE/FDQdVvS1FPd1r29rfq0CWfN9M=;
        b=BnRJTpd44c/FtWh/05tIL88DZ/fFPvteZKIYFJ2CW/X6kTo8vdutH7JK0EP8bTaXrq
         CUf+mvQP/jb1Q8ailAqKKGKU1/Li73UgZHs4BBZPWKUABGsijymO0ZBZqazmovOhMd1Q
         uO1ndwkAQZwY4w2mTuNrbLOm3l2ocYLx0V+GY167HPqLfKBKdp0eVgCbClaRlKYK1o2o
         MyEMDMCvIge9cRLoItqJSUf23uka2Qa7jQeIF/mPyqeo18RIV/Xl+HKMkDRamWgfGU7D
         A60qCbLVedrKuHWJJ1cm1PRs/wWvYmW3mNNbaAg8GFlmlE5/nPrjjOr1MT7K3KbGQlaW
         9l5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id z18si496560pfc.5.2021.06.20.04.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:48:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 5200c755631c4cbaae55cad4ffd2324d-20210620
X-UUID: 5200c755631c4cbaae55cad4ffd2324d-20210620
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1585456589; Sun, 20 Jun 2021 19:48:15 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sun, 20 Jun 2021 19:48:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 20 Jun 2021 19:48:07 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 1/3] kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to CONFIG_KASAN_TAGS_IDENTIFY
Date: Sun, 20 Jun 2021 19:47:54 +0800
Message-ID: <20210620114756.31304-2-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
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
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210620114756.31304-2-Kuan-Ying.Lee%40mediatek.com.
