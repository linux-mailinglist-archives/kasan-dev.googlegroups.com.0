Return-Path: <kasan-dev+bncBAABBSUJXCHAMGQE7NMAI4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D159481F86
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:15 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id a13-20020a05651c210d00b0022e1dc44d53sf411915ljq.17
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891595; cv=pass;
        d=google.com; s=arc-20160816;
        b=cot53aaPX9gqIx4IO/YIWHEfVXZ/QBkBt90c47HSW7EfVubCcRG0+JLz+ir3v5CEoD
         hBU12SjX+93DryJcviDTH056hf4gQGS61t6bxEYx89LXAn7dx2UhulI7yAMMruwX64ei
         aKQMXg1N0D/CRJmmAyd+mEpxKbspCdj4P4Oc2t2WthXKHIRd0+6sTKMqC/IJidSQdIod
         ZgWZ5BhsL3zsDWnvmr4ZEdTB38I0d+JJwFpLOBt53nKOV17nO4IG2BHn15il2xxIAu2f
         WFMFRevzAlssU1HQNUAmQFd2DCWdamsa+j25ELxAwVzFM1fr/ApD/uO0pf749fnVtDTh
         2SkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Nt3VOK4QrOR1A7PxLe76QqBiZe+7NSqQzyw7FocRY+8=;
        b=zG2ngzWz6XK8n/HK3FOimCaEhR685gFA4RbUpGV93sijTInGMGh4x4cv0SDPxWo8nH
         0upFluIkq99DU75O+dMwWZ934f/tTCdSBFdzVvEeECrHUyzIb/hm97fHaRxWeus2E3GQ
         o16uOkzW0DnQowm5Cu1PxwRIo2n4qy8fgGidvgLMgf4gZyBAFvJPqrWxqOW7l5K9Zz2l
         1IkfVLqLL4XSP9vnQrX0xS7Fd/NFahIQYmW36bXbq/06D0lUTmoP2S+jeLAcFu0w/rKd
         1sfX9xOEyyUi0WEWfxgeCJST98SkYGiYteAE+Yh1Uym8uqQ0sKJkuGuyfE2JGNavz8AV
         l+9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=j2KQaFmp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nt3VOK4QrOR1A7PxLe76QqBiZe+7NSqQzyw7FocRY+8=;
        b=nQgBcr6uOzi2C8DU6KY6tq1Tc4wOSfTxPONEaZcQekduLQdLU2UaXq/vdiJE9Jmslw
         ObmH+i3pSPKl5IoQ2qXJrSOOSnJaGemBVYRhdyGeJOy8jFUgSzoXTBYDDSpZE+ejCAWb
         HfqV2sR5ikiCiY0Cq/4yQLJqYHpRAKkin0Vw8JUQdcmzC3IV3Ta2s53XmVVo0KmANJqE
         CweC2dmRFdyjbYEYxX79939DzPYJHJ3FLnm5bA+nKEvj5/AD5TxcrtqtfTdT8jTVfMVD
         BmJ0l78MNo5wPbtB423Uhl6dU15ytMrPiTGC6MfU0lZRhxvSX2ZTN13Jy3yPTPGK4Gn3
         +rug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nt3VOK4QrOR1A7PxLe76QqBiZe+7NSqQzyw7FocRY+8=;
        b=nLzb+LjI2pmvDz4zW8toAmB1/xGtMg8tBwsOeblNWPLNUpg1Q/1so/Sbd6jQd7hxD6
         EvXMBFhNUhCK6rXzdQD/bgqjA5Ht9u287fqBQjIQjeNwy7KVSTOrAfS6FW289p5DgkMr
         J+rw6LRCYwoWx66XaVnvZfLyOy4phTyxyvbh5oQYnNJVOzgUkJTwDhHfmKP0UwAFlQsM
         jZslN4w/jLURZXL7qayQVs+n1BKj88kClzt8n2/hqXUibUwJ6eV3s4KnB0ChGt7bJLaU
         eLmBX4Uyjt3XlOQkM/CQ3pun9yRlAYtoYRM15I56sAQylNAGj0rpSxvSJCg2Pw//dJLN
         SX2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NsgfeCilHWioYpAXnJm4HDazxvSfxLt0/Q0/quKAGJw+7SoSa
	MIYmr1iPEtwSQqKuC/nOYJk=
X-Google-Smtp-Source: ABdhPJznoH03pxSn9raDPnfmHAd2zEdLx5ShRdzlg8STztYaa4b4hzXREMbRemF6PME33eQPGiyj4g==
X-Received: by 2002:a05:6512:261f:: with SMTP id bt31mr12787253lfb.400.1640891594887;
        Thu, 30 Dec 2021 11:13:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c6:: with SMTP id s6ls1950040ljg.4.gmail; Thu, 30 Dec
 2021 11:13:14 -0800 (PST)
X-Received: by 2002:a2e:9019:: with SMTP id h25mr27386126ljg.257.1640891594071;
        Thu, 30 Dec 2021 11:13:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891594; cv=none;
        d=google.com; s=arc-20160816;
        b=AWEnT09XDdGEDSiQZDWWIn3hA9LcJiqfxFAsFbo8vmAC4IEp7mWvtiOJrKvXc1qoYj
         9G7wBe/Rzquyob+VUzAbi/gb1bNSjK/xRLd2M/qnZ2aDIXgGAQiMy9PDxXdpdc+eNZpF
         WlrqTXikK2WfiTnt45ILv88muPBxenKUzkSx6y3XfAedHiycaCrITZA4+wNAqMRz6y7O
         WQJ9lET2zwYpeiOVvDGTPyOP/NUu490PFzXXcJjuj0HTuR0/GOxYJ6y/XcQk8FdhNFrt
         a3C1Yflw7aINnNHObYFdCPyx5BqszeDJTdgJE16cT/0FIfzZa4GSYLT7Ircp94xNO8Ni
         MOng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TniNgsonCV7N4x8CfBP962yTwJ3ZQbzv223ievd0EoQ=;
        b=RcPIwYb6IjPH4kxy0WW1FZMhtpbAP/xk+SsDppBkl07Iw4NB39vJMfTXsuHDlRJLsC
         fcMmUrwTiYOM5LaxlUAgst953UNF48gcZArZa6aPavozzuymiy1f3u5X/UZc5ON9x4qB
         gL4dB+JgBrv0YUJPQ5CdLqyCF+1WsKvHxL7UC3937pEaQYF0bEQ917cfYPWmc4qy/pdL
         eYOP0/uEoBsn67L+aPMTX1YU6QfKdYUkFgf4VTfZEHkSMEzq3j/HomLLq8FT2n9COzkS
         jVlfFHABV4szcG0YjzjD9id3OeGxE6qQ7qX3PHocs3ZPsoU4EhB+34K51A7/8RoIdpkg
         SghA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=j2KQaFmp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id g42si1293252lfv.2.2021.12.30.11.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 08/39] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
Date: Thu, 30 Dec 2021 20:12:10 +0100
Message-Id: <e29f04fb2b152838a22702799ba554da80a96564.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=j2KQaFmp;       spf=pass
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

__GFP_ZEROTAGS should only be effective if memory is being zeroed.
Currently, hardware tag-based KASAN violates this requirement.

Fix by including an initialization check along with checking for
__GFP_ZEROTAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/hw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0b8225add2e4..c643740b8599 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	 * page_alloc.c.
 	 */
 	bool init = !want_init_on_free() && want_init_on_alloc(flags);
+	bool init_tags = init && (flags & __GFP_ZEROTAGS);
 
 	if (flags & __GFP_SKIP_KASAN_POISON)
 		SetPageSkipKASanPoison(page);
 
-	if (flags & __GFP_ZEROTAGS) {
+	if (init_tags) {
 		int i;
 
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e29f04fb2b152838a22702799ba554da80a96564.1640891329.git.andreyknvl%40google.com.
