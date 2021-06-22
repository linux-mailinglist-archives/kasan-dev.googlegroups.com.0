Return-Path: <kasan-dev+bncBD4L7DEGYINBBSOHY2DAMGQEA65GICI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id BD9443AFF95
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 10:48:10 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id i3-20020a05620a1503b02903b24f00c97fsf11587455qkk.21
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 01:48:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624351689; cv=pass;
        d=google.com; s=arc-20160816;
        b=R7mvK1nHZGMT3UEYhci2rYIJ7wXaoj2mFzO4Fl2YzIVlkfTa2rR7JKj7Gf7/9CZxiU
         DzT7pVFU53t5PHnKJ0HqPKBIUxb/evv/a9G0mEic2TwsZNMCkzyKj6qyeSGW7BlEYYvQ
         agYf2Dit2mFvI6AoqhaiBVA1jF0AIow/1wBwAFPUK7fCoi5RwKM+XMCCsJMzwgm7Wxc0
         t+qnoc5ayP98CofQDN4LNVr6WmA2bm5vBHhU5/MUPFprel3bUDyAmLcUAYG0SdfzWwtf
         QViN4kJWTVTg9jcEavn4pvDM1WG+eu5cnNU1PX0jKduD4laCLEM7STdmeMYNfwYVBcb7
         WWDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=UuTvtrJa1APVAdUMi1ryMHTJYIPdJIfad6FD8h4gOTQ=;
        b=KRIPil3cYBlULxmsBi2lwvvV/pm/wlMpjfGbBH53Dj7WsrDBr/XpTn8f2cQ2CyzOI6
         Sxqf2Mvq2vgauwFPs41RAlVEU+mSd1QcjH9uKLLAS9jiZ5C8BB8Zg1HlAw2JXs5Q6Z2n
         HAXaZ+2LrgO7Y5qPC7m7bmUmmL7n6bB7pzpyzPF6dUFZDu2Xj05WBFWgNXPqtoKjICf4
         q7ZBWlbqOeVIoYdXONzJzdruB2jrKCllYuXda7u+qOphBwE/7C80WcE69/PCyfbg+uw8
         b9o3gAcsR5RHEqeGzbCiCLQ6YqFSLt5JWDQIjeJkWi58UoSms8mYY4ZVDqvR9O8EOybX
         hk4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UuTvtrJa1APVAdUMi1ryMHTJYIPdJIfad6FD8h4gOTQ=;
        b=fMgOiIqxDkOmknk1XzL5eRY4nMN7sjvKo7mGHM0lO/g3mc1ZeAGFZhlHl8jK1nBMPp
         GqnTx3EfZCEPv9EPji5VrS90+P3d7VI1SR0XFOL5OUryw9Vfxy3HcQ2VfewcMCRV1yt3
         o9LE3eWgbxz+ww3aPstg68tJoQvWUi78o/Wo9ZxsvPwpZbjVQwtR+lO5t5b4QjQO9yam
         Bh2L6htckzVogPYay8+cPvDYiUNAP3k62f1wNVe1vuC+GjH0xUfPJKRMjWyOGK/GpDRV
         mNt1QR0B6543yBeM5y+gYQ9KRAUjHRdzL7A6Y+NVK/sbcOQG2EGGW1aI5TdWno1ifKNY
         7F7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UuTvtrJa1APVAdUMi1ryMHTJYIPdJIfad6FD8h4gOTQ=;
        b=aD4k7p7a6NwMPtffsvZo7ezPicQ6TAmitFn8Kmoi4iDMfiWxYC/OmPtzABLjZWwqie
         yu0jbS6kqXmwvQVO1rrCjMrGbGRjuyiiKOvAJuocITnVZEo6X+jw4I7ajPXl8JFxRuy5
         sor0Ov2Fp1kjFplZ6JxWhxVO6kp89H6DVcKY4iJXAa9np/1nbSoFJDX0+G8CVm6NjYgY
         80kENcXFETTm1khmFAzQ11z67ie3hRVGXtpo/OhxE4Ut5oTdrLxidHgYJTh01zJUOhnq
         qCCasQcRRTOrquSgPx5makD8JowNlYySZYogEiHUsUhen/IDknRTwtv+Hyi7+lRMhc5B
         j2hA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530igD+oIWNTetckgMFo2MOVtADgJkKFDLF91UQuXwIzpY1cBNgS
	Nu/4E9JqE0IfHiq2ZIgkbxU=
X-Google-Smtp-Source: ABdhPJxlHV+TAmNZzgrVaqW5/bw3T7FD4FAd3nRKYnk4az0BYRNRKC9bXfRgl/xwrtUJigGX7MxKtg==
X-Received: by 2002:a25:9942:: with SMTP id n2mr3255837ybo.230.1624351689697;
        Tue, 22 Jun 2021 01:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2b08:: with SMTP id r8ls10672482ybr.9.gmail; Tue, 22 Jun
 2021 01:48:09 -0700 (PDT)
X-Received: by 2002:a25:b9c3:: with SMTP id y3mr3253675ybj.480.1624351689221;
        Tue, 22 Jun 2021 01:48:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624351689; cv=none;
        d=google.com; s=arc-20160816;
        b=s2sTpgoto8dvmE3r9KozZs9W0TgeijzJ0TNMhO2m2wmfPmklDg/LF6l3MrjQFqR3rx
         A5VgkgWVAqMOAevcRaUEOwVgdSOtgMxjk00jFT5QfkyDeXD7QlpaAVSaquxpR10HWVcc
         pKnXPAuFjfHOMJMVyJPd1XHR4EFSo4jhFjPB3mRS1vA8u0mxFIWPS2RxJMBW1nzJa1hB
         y1dvpBRu8nNM5aTzmkEkOe0L2KUbVA3mQ3dm5n+j22stcw3vYAqtS0PPmuxsoPINR3RS
         mL7FiQALMjyxxbbiST1SwDpe7Ac3XOpUN8dBql5d41jfm3VaP5k2ta9z2Wq8oGHNI90Q
         40TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=7ffkn4BmCjJV20OcrRmGR2s/B+hvRUgEw8F8k3r20NY=;
        b=CEuAYjxgTSSsg4Vg85618CRSxr+u3zt+biyrg5nLQLli4xIqXkWDTG0ukk1Dstz7c1
         iDRtrFQwD7qo43KJXjRIXjkuIMom1Mdc1qzAoSscfQ8/2D1Ie0sQJSx12jUaN1rji/5c
         Yo3AykT1lGkvMtLqt4BLEHMXZYwItNz5QKHtpHRspKVt4kdRormqktXSP8CM57O2tJd1
         u9akSs+Ps+gDEdJO7VkPKrhrtN1bMy6H9kBVWf88gD1U5GV9TqGZ6RNG/f1TkQZBHMAq
         ZlxELRBbOuth9JvAtcoTTBylLles02Y/jtvuTYq4HB5aXYsWvr7OUUWmBbEXfTiTpc/i
         6Zbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id r9si180440ybb.1.2021.06.22.01.48.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Jun 2021 01:48:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b95d6c1b4f8a44b7b4dd24d4e16b1eae-20210622
X-UUID: b95d6c1b4f8a44b7b4dd24d4e16b1eae-20210622
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1243209495; Tue, 22 Jun 2021 16:47:59 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 22 Jun 2021 16:47:58 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 22 Jun 2021 16:47:57 +0800
From: <yee.lee@mediatek.com>
To: <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Yee Lee <yee.lee@mediatek.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KASAN" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH] kasan: [v2]unpoison use memzero to init unaligned object
Date: Tue, 22 Jun 2021 16:47:20 +0800
Message-ID: <20210622084723.27637-1-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
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

From: Yee Lee <yee.lee@mediatek.com>

Follows the discussion: https://patchwork.kernel.org/project/linux-mediatek/list/?series=504439

This patch Add memzero_explict to initialize unaligned object.

Based on the integrateion of initialization in kasan_unpoison(). The hwtag instructions, constrained with its granularity, has to overwrite the data btyes in unaligned objects. This would cause issue when it works with SLUB debug redzoning.

In this patch, an additional initalizaing path is added for the unaligned objects. It contains memzero_explict() to clear out the data and disables its init flag for the following hwtag actions.

In lab test, this path is executed about 1.1%(941/80854) within the overall kasan_unpoison during a non-debug booting process.

Lab test: QEMU5.2 (+mte) / linux kernel 5.13-rc7

Signed-off-by: Yee Lee <yee.lee@mediatek.com>
---
 mm/kasan/kasan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d8faa64614b7..edc11bcc3ff3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -389,7 +389,7 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 		return;
 	if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
 		init = false;
-		memset((void *)addr, 0, size);
+		memzero_explicit((void *)addr, size);
 	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210622084723.27637-1-yee.lee%40mediatek.com.
