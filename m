Return-Path: <kasan-dev+bncBD4L7DEGYINBB6GP5OKQMGQE4NP5PRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C7D255C0BF
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 13:37:29 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id n19-20020a056602341300b0066850b49e09sf7063814ioz.12
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656416248; cv=pass;
        d=google.com; s=arc-20160816;
        b=qcbMg0rWwxS3ypQsKx//Rf42/u8MVkcH8hpPnyHvyvZ0pDDa+tpOurjWLjd6EYtwne
         33NzlnykjHscaMvZ6ezm6ZiCzmTiGpdkj85g5qHaGpZlKfedUGXS4bbP5aUSIJG0lcPN
         IO2Wx/0ihiV6icYnnrG6pLP0AGXygNfsK+Ug93B9vHxXqO4/lP5zC4CIEXUmhKwsrgf6
         iHAH78uFgkqmRSzViOi/0WkVW8Rr1XM0wkiBniZrkogsA30ucHkXysQ7eD/fQXFjSObo
         eyulVOVicHGszDIByL35hfKdo2La4uf48twhHo3nJK3VEKuU3C4tQ+PfibP8dfErC6lP
         Jf0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NKSUf2vItpJt/SdgRIWUo/HLfzlIq6QnLuCOw7D8p4Q=;
        b=Rgr6vLb1Qk7RlWWeZC3wbsqwnennpJsIUXYvQ9lAIdLHhF8KmgMaYKXQ/h7Uwkx5a+
         JWHXSE53WOio90YBB+a6t6AWI2x4j1DHUbgglH6d/1kv+/7LVR39Uv6sbyxiqpnovxl2
         Atmr2dQ+hqmTSCgtmcElIOmPiBwoHqUS42Zbq2nCPJgQ3OA7wR6E+5ynAw0h3BnJcEQ4
         Y0hxfpjOi3hofm4aOwWqBaRQel7sIiv9nKMm+wsUIXPdFLrhO12Y0prvV1eDXYsk09gJ
         nS49EraQ+8Q07OmxH5RRstAXk0TLZMa2vDGbSyVmUWLH6gSZ4e4oV9DGPDyYQ1Ld5+cE
         B3GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NKSUf2vItpJt/SdgRIWUo/HLfzlIq6QnLuCOw7D8p4Q=;
        b=n5TF6YTd+DhQKbn1oAgS4K92jpHsCGRZGWk99Nh7FLy7aC3yJ4tOfB6RyFG0BmM6+m
         g8/zbghXE81x07HttmjzgK527iNmRc1Pz2ncV10cGUrGZOoLJ5d8aS7y1MMaBk6hJG/S
         2+m+BFgSZpMPm2HJlk9gUHis2TXtWnALa6LWgq2ajJ9E+2ggjwDhwPzvlvRbNoAbI9Bl
         fYHHnP7s9j9Qn3duZ1KgkdfVqmAcmqkgWZ9TKlkAWvTMhIYxYb88MvKlZ5wfzP1MhnDd
         R11PJXBiDZGgdU7npHNt7eekMpj0mL/LT9GBAqCBFRi7WkjRgu08KMDhYuKotMij+DHH
         8zNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NKSUf2vItpJt/SdgRIWUo/HLfzlIq6QnLuCOw7D8p4Q=;
        b=76aC1kR09OzmmlSTZCnKvbWsBV1sQzkPvaWbec0yAgdZaVoBdJBB0rhrJ//kiMuYBD
         QtSUZo7Zh5IJ9lJPHbEyvor4eINPO1/hdB9b3s/xsIFhT2mmtl0ZkyBwWJGVekmvHa+a
         cGVvJF2OPRYeBC6BAGJRBGSswsFWmT3nQyj/gm+UrANVZ8pWLLRCURQAVh640N8zg9ib
         2zK9kzadQxLxXUSCP4Zb8lkGUD/euu6/QSFN6o0G+1tdZCg28uAi5N6ur1mA925R+3Kj
         x1zMN41x10ayFuwwJxwCwM1OmRgJJYF2pFNrp2sEVE05JtlkzLIZc9xAs5kfnHHUtcaD
         Uszg==
X-Gm-Message-State: AJIora9mmbadY3RoKv/GJ9Y8X4Lkz3K5MadGxKAFLgNEbZm2OOPA7Kc4
	nXFVdhn8SP2pHTc4qqssKWs=
X-Google-Smtp-Source: AGRyM1u1rgyly8iD3Orp8MG6bMePN2bqnjdLVUF4Z+BXuVu48YT2MhJqxnteNR57qOHc9duRDuz4iw==
X-Received: by 2002:a02:a70f:0:b0:339:de0d:4ed6 with SMTP id k15-20020a02a70f000000b00339de0d4ed6mr10775691jam.292.1656416248124;
        Tue, 28 Jun 2022 04:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3010:b0:319:c97e:f47d with SMTP id
 r16-20020a056638301000b00319c97ef47dls5490001jak.1.gmail; Tue, 28 Jun 2022
 04:37:27 -0700 (PDT)
X-Received: by 2002:a05:6638:371e:b0:331:bc34:c3b1 with SMTP id k30-20020a056638371e00b00331bc34c3b1mr10835709jav.68.1656416247714;
        Tue, 28 Jun 2022 04:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656416247; cv=none;
        d=google.com; s=arc-20160816;
        b=g+LQzs44esNdFGUKWYkMdrNHAiMu25OelHRZEmAEWThsk0jDenuKchndn0rpv2vezK
         1tXe/mF8FlB1kiCsuY9kXiGVbJdGq+kfP7nMUnPfTcx9UUbHfpJUh+VqgrlTvwQ0KuT4
         nsITQfX+CH0U2sfuR5HZQikeLSnjood9TrTwFgMH4Aq7sRxslH/dC6lI4DoFQMCfR5ls
         WzGJUXyVgAUZUgsmPZrXzS+sAWvzSKjlPAJHlFrH3kiZE/zRqsDNMURB/SNAfnCR+PbC
         T5cA3Pw1uWkw4f6/fYGuVj2Ty6t6D/GJsuYGRtPjYX06O+lcWm84EsVPxkG07AEjFQx6
         8XLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=7zXu0ktyw7BMrjs+/PsBz2fQRMG/j+JasIZ/NDWZBX0=;
        b=odR026shBaIri/zC0rKWW9kyKVmnt8S/J3QLrFJhqn5i6HZUPzoQ9uAJFiHSbGPWWM
         1qIGNo9dcaxEfEXr/huxzathW/u+VDZ8zijKBdQzlGi2UtlB90uPetkhxq3ISDgiPV0d
         EVPgRPXwCxclk6danHaIsfaS0/kuATiMo9p8ux2lurm1iX2re1vCKVS/26rQZGZdoSC1
         +1nHYbRDtXyjwXRhkWQb0I61kG+dYvNNH5UN9ekebpCIeB1RO83RGGA0+J+6Gsk+RsT7
         cpBe7buYnUdj/0kTVozBtfaqNt+8nc5/1sPs2bw/GHwYw26iwseY4hlTfXI6Ad4+nCfj
         zQgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id u10-20020a92ccca000000b002d3c49040dasi442584ilq.5.2022.06.28.04.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jun 2022 04:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 8e40239068524747978adcd657543054-20220628
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.7,REQID:1512ee53-7e3a-4674-9147-26b4153cb159,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-META: VersionHash:87442a2,CLOUDID:2d2cfe85-57f0-47ca-ba27-fe8c57fbf305,C
	OID:IGNORED,Recheck:0,SF:nil,TC:nil,Content:0,EDM:-3,IP:nil,URL:0,File:nil
	,QS:nil,BEC:nil,COL:0
X-UUID: 8e40239068524747978adcd657543054-20220628
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1902182933; Tue, 28 Jun 2022 19:37:19 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Tue, 28 Jun 2022 19:37:18 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 28 Jun 2022 19:37:18 +0800
From: "yee.lee via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>
CC: <catalin.marinas@arm.com>, Yee Lee <yee.lee@mediatek.com>, "Alexander
 Potapenko" <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, "open list:KFENCE"
	<kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Subject: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early allocated pool
Date: Tue, 28 Jun 2022 19:37:11 +0800
Message-ID: <20220628113714.7792-2-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220628113714.7792-1-yee.lee@mediatek.com>
References: <20220628113714.7792-1-yee.lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: <yee.lee@mediatek.com>
Reply-To: <yee.lee@mediatek.com>
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

This patch solves two issues.

(1) The pool allocated by memblock needs to unregister from
kmemleak scanning. Apply kmemleak_ignore_phys to replace the
original kmemleak_free as its address now is stored in the phys tree.

(2) The pool late allocated by page-alloc doesn't need to unregister.
Move out the freeing operation from its call path.

Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Yee Lee <yee.lee@mediatek.com>
---
 mm/kfence/core.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4e7cd4c8e687..32a4a75e820c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)
 		addr += 2 * PAGE_SIZE;
 	}
 
-	/*
-	 * The pool is live and will never be deallocated from this point on.
-	 * Remove the pool object from the kmemleak object tree, as it would
-	 * otherwise overlap with allocations returned by kfence_alloc(), which
-	 * are registered with kmemleak through the slab post-alloc hook.
-	 */
-	kmemleak_free(__kfence_pool);
-
 	return 0;
 }
 
@@ -620,8 +612,16 @@ static bool __init kfence_init_pool_early(void)
 
 	addr = kfence_init_pool();
 
-	if (!addr)
+	if (!addr) {
+		/*
+		 * The pool is live and will never be deallocated from this point on.
+		 * Ignore the pool object from the kmemleak phys object tree, as it would
+		 * otherwise overlap with allocations returned by kfence_alloc(), which
+		 * are registered with kmemleak through the slab post-alloc hook.
+		 */
+		kmemleak_ignore_phys(__pa(__kfence_pool));
 		return true;
+	}
 
 	/*
 	 * Only release unprotected pages, and do not try to go back and change
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628113714.7792-2-yee.lee%40mediatek.com.
