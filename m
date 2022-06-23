Return-Path: <kasan-dev+bncBD4L7DEGYINBBZEY2GKQMGQEIZHYEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F055557899
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jun 2022 13:20:06 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id o22-20020a637316000000b0040d238478aesf2463217pgc.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jun 2022 04:20:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655983204; cv=pass;
        d=google.com; s=arc-20160816;
        b=sxtN878ByBkz9DnSx7WgCf4pXh6hdEgBttEeZbOHJBd5WiF4EMazHoK7utGa44k3tm
         ZJO1sxU6fzKSxddzhotKrGbdmPglIJOrDBY/1SdDvD68JLyOaohAMDJAI8sjpGvzuLiA
         zVtqzVY4NsNCP/Llhbjq9lIR47c464sh7uwOHB5LXu/Y/9nBcXVxPagYzy74nYqg+Z1K
         F5nJ8bHeKBgFbIzV/VBTJnxkYzTQb8OlyPVhgqBt+89qAx4uGTFWvXRPZcwbOX2TG3ft
         EVvSAHNFacvPKXhIjwM4olM5pXOFzxHwCtb7gWvaqD5OIJSCCtFsiJwp0zC9jvTlBJeS
         xocA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eRHMGH8N4Dr95WCjHIatlaos6gkDTPGIfcJ4IzsB/tU=;
        b=Uoa7OttlVbwXNln4zEyaUKREJNPWlipb/soBl0q8H2dtn5Z8Q6dOHhtQCckPNoKODC
         RROID0cOSYk1h6qjLex6jgGoqKB9sB7Hx+JdR4TkV8fW4lTN9mzXItZ7+HOC5ga3kozv
         8/ziiseOQRcqDFVTlMOfMz6PTbuSkRETogXK5i2K8Nu3ADFyfJZPfsRqBqOWs7XhuT7P
         yLGA5IwCc+JVZqhfVyVwSPLHxy02a5mF9IfozfEn964pG2AvO3sCMP2ZoxURhCg1VtnT
         tYg13+pNypmVA47MOvT7X7G4V+ATpmDhXPNfM+VzLYlDMzZ3eKUq99KvxkzTuKn9a1rm
         l5ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eRHMGH8N4Dr95WCjHIatlaos6gkDTPGIfcJ4IzsB/tU=;
        b=YWesevX7I6iZTIJBwFMQnS+PJEaooIQcBG2qowMEc1GUApE7/3ixWopP//CNBzMWzW
         +du7FgRGMHbiWOS5uIJ8THd7ecqJH0a4DbEkdgh88VyGP4voBlinpNvkn096gED6Z0J/
         kkKJL1/oLnSpghIH6obLchS0canRtQuhNUuJOsUPkTL1Fl703n6XqZWc9wI6rRGv73Oj
         VVGzMZZAKfDx30oV/xUUF3HTq+Em67xyWB+S+e3nUCvBqCzu1vr1GITGbGxOwmQJB4sW
         yUgiLfvqA4oO2IyABCQncxAa+EO8nBzk2enmIQIj0aOMAXcGrJjnnBONYKdfKl+U//cv
         VcNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eRHMGH8N4Dr95WCjHIatlaos6gkDTPGIfcJ4IzsB/tU=;
        b=si4qo+WNQj8UKT1C+sW9JYYoiXG9PpfGYKS87Mqy/PCSGqfQP3nXdv/v46W7/r3gnG
         FPk84OrPdZ4eaviP312fDEvjrjekeTIne/0enR2/4k+FcG8BPrd0t7bb+Jm9NHXXlYJY
         TawGMu3kWpiASiLtGwNOr8moKsAK+o+g2EwpmD+6NGX2RBW2M+s6PpPpP9he4F0VEGRh
         Qt6OyqXkWSbrvyhpCLwwqX4q+w4JqHfWPbG7QjA9sZKZT49WL2uGcYzvzVtgUx60Nj97
         9OgeeoxrkDwpy58QH2tgzc3pBJahaZJE4AhIkSGTTBERVXo0iSsm4u68ojRU5y+NcjVG
         j/Hg==
X-Gm-Message-State: AJIora9FRK3KgZItWZyqTNqRnSTxUP/pr9XyP2z3ZbuAL4yxYooZOtB+
	yLmzUoWoCUuTVv3o17QFsoQ=
X-Google-Smtp-Source: AGRyM1upSacP5FYGkkhu0PSgktqM/6cI1kR+PmQ9XXGDkwgWUwlK06I1VSCYYxZJT5jqOv4XaVSWpA==
X-Received: by 2002:a17:90b:33ca:b0:1ec:c617:9660 with SMTP id lk10-20020a17090b33ca00b001ecc6179660mr3559502pjb.95.1655983204644;
        Thu, 23 Jun 2022 04:20:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1a0b:0:b0:3fd:9834:5d21 with SMTP id a11-20020a631a0b000000b003fd98345d21ls7662355pga.9.gmail;
 Thu, 23 Jun 2022 04:20:04 -0700 (PDT)
X-Received: by 2002:a05:6a00:3498:b0:525:448a:de0 with SMTP id cp24-20020a056a00349800b00525448a0de0mr8593231pfb.85.1655983203895;
        Thu, 23 Jun 2022 04:20:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655983203; cv=none;
        d=google.com; s=arc-20160816;
        b=Ymc3fu2DFvYsnUZ+eJWrFmsP0nDvtuvmBvjfXTwTN/Kk6NpUYJukWBpeXoAmV1RWg0
         nkut2C8CG5Ntqhl61TAQm+E8nWkDKu69Pj/U/H2FFkhtkDgfeO0rDvucrOuD6EP/bH5l
         wkEdkZAl1LNnoshLARu7AoZhWw5R7E8sXF7C3NkgtYe5CkRISyeHRYIjiwCHFvhTf2kO
         plYTYpCUFmjiyIoU6GGkkhdFDVuEv/YFnIcJAUqLrNsYhLHpngTOvUGw7k0TGY9b/o1a
         36FnGbJfGsU6MAA3txtiFbCrEtWbmZ4LLYtrzz59IUu4BiAzdA1DSJGiZgb2Hsfjhuq+
         ZXdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=sm76w41pAm8PnOIyccnGOO5LV1X4Kpl21+W+/cD3KqE=;
        b=PsO2LMIoYKL6VwoZEgz+cKE5sE/zTrzCg4fE7jpxsQAdhjrudaMN8qw63plnEO3RVi
         uL9gujZcqF7mntHnAwVtIAsBqbiE8CwRYgxGhgkOYLjKHv2Jp7oB46344E4vXOEp6L2/
         hh31GpSoQKkfUyXUWjMvwQt8IwX8Hpl9OyQ1V3NpAPJ54836N3dHgukWnwIU+6kmfJKF
         TLH7luBMLjv4nFIMjQuQHqlxnqfjIEe21/MLHlC6jjbAZQOi+iv3N73g1aW8pLfGy+Xn
         IlTAAoOmJ2UU6D5s1ypmTEs6dc8p444UVvHIl3d2l18Hwj7JqiGPq4JQCE4Qa5Mhr6sK
         l1sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id f21-20020a656295000000b0040d0bd431fbsi264544pgv.1.2022.06.23.04.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Jun 2022 04:20:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 06e9682c6e8d481e918fcc6f966e18f5-20220623
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.6,REQID:af011d69-7248-4d7d-be3e-479c78a82b58,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-META: VersionHash:b14ad71,CLOUDID:a6c3dc2d-1756-4fa3-be7f-474a6e4be921,C
	OID:IGNORED,Recheck:0,SF:nil,TC:nil,Content:0,EDM:-3,IP:nil,URL:0,File:nil
	,QS:nil,BEC:nil,COL:0
X-UUID: 06e9682c6e8d481e918fcc6f966e18f5-20220623
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2122228748; Thu, 23 Jun 2022 19:19:55 +0800
Received: from mtkmbs11n2.mediatek.inc (172.21.101.187) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Thu, 23 Jun 2022 19:19:54 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs11n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Thu, 23 Jun 2022 19:19:54 +0800
From: "yee.lee via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>
CC: Yee Lee <yee.lee@mediatek.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH 1/1] mm: kfence: skip kmemleak alloc in kfence_pool
Date: Thu, 23 Jun 2022 19:19:35 +0800
Message-ID: <20220623111937.6491-2-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220623111937.6491-1-yee.lee@mediatek.com>
References: <20220623111937.6491-1-yee.lee@mediatek.com>
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

Use MEMBLOCK_ALLOC_NOLEAKTRACE to skip kmemleak registration when
the kfence pool is allocated from memblock. And the kmemleak_free
later can be removed too.

Signed-off-by: Yee Lee <yee.lee@mediatek.com>

---
 mm/kfence/core.c | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4e7cd4c8e687..0d33d83f5244 100644
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
 
@@ -831,8 +823,14 @@ void __init kfence_alloc_pool(void)
 {
 	if (!kfence_sample_interval)
 		return;
-
-	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	/*
+	 * The pool is live and will never be deallocated from this point on.
+	 * Skip the pool object from the kmemleak object allocation, as it would
+	 * otherwise overlap with allocations returned by kfence_alloc(), which
+	 * are registered with kmemleak through the slab post-alloc hook.
+	 */
+	__kfence_pool = memblock_alloc_try_nid(KFENCE_POOL_SIZE, PAGE_SIZE,
+		 MEMBLOCK_LOW_LIMIT, MEMBLOCK_ALLOC_NOLEAKTRACE, NUMA_NO_NODE);
 
 	if (!__kfence_pool)
 		pr_err("failed to allocate pool\n");
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220623111937.6491-2-yee.lee%40mediatek.com.
