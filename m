Return-Path: <kasan-dev+bncBDY7XDHKR4OBB75SVGEAMGQEEOPYNMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id E08993DFDB6
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 11:10:24 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id g10-20020ac8768a0000b029023c90fba3dcsf759465qtr.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 02:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628068224; cv=pass;
        d=google.com; s=arc-20160816;
        b=wMvLpLPO49Zcm23/+d6MXySQtZA1xtVgH0z+DzY4bmTfGANATcdqvy2ZpxUsZEWYYd
         5rP7Ad4qgB3cycL2jQlf/kj4NBLBIbY+JhsT64bJnCUCaoHMHgr7Fav5PDdi2di0bZwz
         EJT5ec6s2vgsECo3zzUnIeu7X3XF+XfAfV/GWlktn5AwNkMegHvirWVdo3njtItXhZ4j
         +G62oliwN6DdoGYu3drhdp6g2WemOAlbRbQyY9vSoVyKzQL1HrRLw5Lg9T3ihGIQoHbf
         1+jgcnbU6p4SqROn+F2gzJEe9ixH/4OrBHg1uDOaBWcU9rRGtdYCoCeDatKtyni/r8El
         fLyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=J6HBiV7PK0qw2piPEdZVbhHNMYLdx+a4qbQ9NEWIHuk=;
        b=bU8FIVx3ZPWzXcaOlaU3xBNQDog1L2FDPn0jUqCZF/MVVCcqnz7C2xJZj4ypezjl/k
         Vhu5JGnNoq0v7h7mrcEcGgeMef+Ngf4mzZa8+UhX0oXPd7nbfx/Cgz9SOkCC22wwmun6
         IvxIaaWmkWhx0rCdBr/VH276FK2R8D0CRQR6rv1FCodmYsF+tQ3y+anIiPW31TqRkvub
         lsntWWeBTELBYbzzoSvex/DaX630GPnKINkAVoVQcegEcWGYqe7LaNE/EMDnRF9ea4a5
         A+W7tpDWuIHmqO3Nthyq0nGcAdOExj1ogyQoK0hGqO3abbEX9WhDVjfIdRaRCIJj8yKb
         DEVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J6HBiV7PK0qw2piPEdZVbhHNMYLdx+a4qbQ9NEWIHuk=;
        b=P5gu9rHxUQCYXkqOa2HNesH0qV+hXYh9qpUQNAp1jnk4hpBjiIII7aqQICJKtyKDc0
         4EvEdS/siaExpT0tRtPONMo8DpmtkYCl6nvqu8vuAeSnLGna5nk0gIMh8WJx5ecimIJF
         XilNLqSmg11XvuRcBNsayyfAaldnjblCxYqsEGL07hCydc72sbDbra7JNfzxyuP82g+9
         1bIybc7/4kSWTkNLfMCwGlYXa9D5tqtQktKc50aYvJF07rdfjPspbMz9J5lAS/C0ymnj
         5Xet72MAg7zBNAt+SOdgCfyUuHZADfuLVekvnLpGbCoDOoSbytwoUJ7di0womo5d8rva
         apcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J6HBiV7PK0qw2piPEdZVbhHNMYLdx+a4qbQ9NEWIHuk=;
        b=A4h2dP0yWFbIy0YRkXmNcUfhPVEQ3mwFXvS76KHn+0d6bhIhntlxZFB+l4mJLAa+YZ
         V7wCIdtA2bUc5oBjGhKb+t12SEOa7O7RXzNMP6f2QKTvD3Rufi8LB7B/OO2HfCITaEes
         qyAb9Z+wiXUUlCZckVDXMuVo+g1YUL0BFCHnYf0XOF6jsnkKwn/TFNtV2rkyNscdNEhs
         rZdnUzF2P7Qt+WlxVFdUU2vXUe2uE+IS6zwdfm3xaB1yI2tCYGQ3YGr2fBxJUIRgM446
         ebThPfjgwH2+Me49l3Th3amjNk3QctfLRVfRIW9F3OkbBtT7fbl0yOd+BLKXCbPdqm2X
         UtCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331GiknvsrtNbvGT2chqlsNfvHS0vLQW66piRLpEeeiFH5H5mzw
	wrkhM79BseVz4vMK3kko7Lo=
X-Google-Smtp-Source: ABdhPJxpFpSE2omHHaUDLXqbQuf1jKUSm9A8vxszcqOs4GSBcPaAWJacP2qNasjkhFQYdD7kleoM7w==
X-Received: by 2002:ad4:54ae:: with SMTP id r14mr26204387qvy.1.1628068224070;
        Wed, 04 Aug 2021 02:10:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a24c:: with SMTP id l73ls1108551qke.6.gmail; Wed, 04 Aug
 2021 02:10:23 -0700 (PDT)
X-Received: by 2002:a37:87c5:: with SMTP id j188mr24014565qkd.317.1628068223629;
        Wed, 04 Aug 2021 02:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628068223; cv=none;
        d=google.com; s=arc-20160816;
        b=ma0PsR9eN+0+6ugpEHrNyar7OE5JV9ijTkoW37DuQe/CB4lkoGhSxWdpWyV8mruRqs
         bQiPZ1FooPwE4iZMZBhrhMXd1x2dhxQm2OiQjK5tu+SUWxi/drtPzF+2ndLVeF67jx6q
         G+RMjlMITZ2GuUz2nMirgCFwdGhKHapP3HwrHV7ABm/IGfmcp5gg/U9ySm9emXcwQXcg
         Hdw1AWLsa7RlbvQ2vwP8NTvyNYCryGbGFQm58tLe26U/zT/KuxEmHI3obH2mH/oqfZf0
         b1m/yS6hEqFzUXi9QZ2FR4g5KkoF6jcMaW8FwF0WaFYPRlzZWKnM898oHMcWqkoGXTY0
         hxPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=1k9KEHgTww6/GAfefvfTZzdnOImvLWHYJMW8jtdaTqI=;
        b=AicQb52V2n8ojVGt5CRfOP1CdZCEU3RaRB7ahXaw1lLXeS00H54kIbMAjYCGtk3pow
         ZPNmFlQflmO9MByOyM6tTtb8jPzj6XOKN0H/gLSe+juLu6vekVh+S6TQY59r3lPQbJel
         wVEfRoZixpVLTa1DDTrJ1gI+ISMErCI5Cbodq56DHycIVMB7f27RyXjZ7QGchLVxU38O
         PVhSyrAxoDnXlBnK3/0qj5Diphh6m4sbIU58/1Q+7nss+o1WzUqMoOnWfBYO8lgxF9I6
         I9sTtINCRDMPSPAv007UVNfgXHSfFo5BTqCyG07Atx2mRnS7wSCR1E9K+VbvKZnatGyK
         pfOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id v31si61988qtc.4.2021.08.04.02.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 02:10:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 70d6da78d4a94c559c99d936885b3c4d-20210804
X-UUID: 70d6da78d4a94c559c99d936885b3c4d-20210804
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 954435666; Wed, 04 Aug 2021 17:10:19 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 17:10:18 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 17:10:18 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 2/2] kasan, slub: reset tag when printing address
Date: Wed, 4 Aug 2021 17:09:57 +0800
Message-ID: <20210804090957.12393-3-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com>
References: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

The address still includes the tags when it is printed.
With hardware tag-based kasan enabled, we will get a
false positive KASAN issue when we access metadata.

Reset the tag before we access the metadata.

Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing metadata")
Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Reviewed-by: Marco Elver <elver@google.com>
---
 mm/slub.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b6c5205252eb..f77d8cd79ef7 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -576,8 +576,8 @@ static void print_section(char *level, char *text, u8 *addr,
 			  unsigned int length)
 {
 	metadata_access_enable();
-	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
-			16, 1, addr, length, 1);
+	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
+			16, 1, kasan_reset_tag((void *)addr), length, 1);
 	metadata_access_disable();
 }
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210804090957.12393-3-Kuan-Ying.Lee%40mediatek.com.
