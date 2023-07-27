Return-Path: <kasan-dev+bncBAABB2EKQ6TAMGQEIF5DILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F002B764347
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 03:16:25 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-345f9c1176esf2316945ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jul 2023 18:16:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690420584; cv=pass;
        d=google.com; s=arc-20160816;
        b=MCDNU0eXEjYWeC+KNA7FeXjDfBXKcLWo7U7H2rbL07wMaUWkDSVd4swcqh7r4Tda3t
         XMZgQ2KzlOYFywdkaj9QudGDl1p6/d+hf+sOxMX2aZNZ5NN1UBa+jMikm4lc4p3HpoQr
         CMeiMftBUaQqVikCvgaoXeGv1cQVlQnMZ08Ar2yosDHB/wSmO5qXKlPMfkCdoKXaZl1C
         hCB3gNA//WDycZ71TgnAtdy0tX5VesT3oat3PEoBo93GfedpV1JJ7e+A2HjsgakjZXb2
         cK8pPE3dE7pd5Lj/Bc7kRmV5VJF+KUtwEbIsj8AQ5SI6lOW9ymQkZPdpxSQwoygtzDMM
         O7nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ClgNeiFjuy/ZcuAlA/jQSJxQumT/kuSYj1kJfxFSLmM=;
        fh=p+2efxOrsjtKfHqLXl2Yl/PWOJT0MqeZo5k3po+L8gM=;
        b=jmMWAJcf14QmzHWkPViWm5fXRzl9pKB0fw/GexrXxGTGAsKF0hyiqG94oQIISGLcJ8
         JtHrOOGVvvcW4b+NGPy+uDLpJ8r76m3N0fvyoSl8oxFONOTCsKyxJPggRuA0eYXyvkPk
         CGfVigQvA+3FejP9MxyRaj6CpSTePDm8JeZlbldVyJMs4sx4c9iPI/ISLo5d7Xdsu5gD
         25gBMkiPCXqNHXoLyzNbqlwrB7kY/5yHvV176KMBJ9FAeTYnj0TZeajnOaBeTv3RUYfj
         o0v6rekb+TuZXk2MPK+HON+RoJknqPZDZX03XOHgbKjACEZDp1xyQBB0XtH34Js/yvCi
         NEuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690420584; x=1691025384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ClgNeiFjuy/ZcuAlA/jQSJxQumT/kuSYj1kJfxFSLmM=;
        b=UEw6NMo5mOgIjlkELFVoD61aqaofvL9W58T2dSAMhZrNN2mD2tX0cFR4i1KbZanaN1
         RT1oDULnr2o4yeJH2fA7X/pS6Lu4KtIZQ5OdCCh69MhqZQyCGSe3q2o61kystOMwPFwZ
         VAjTgvgiecrAIEA3DYDU3dPjqqypQ1XFna4acgcof0i3WkjJGO2ETulKI9f3CuXV5md9
         hu8sSocVLfDShKxZSnZ052dhpYtA3nBwC+cc5ZAkHNNduWQhBI9Wlj4MLK6K9P8hmjHN
         qCvK2vMwVAFWIpQwIQTBEupN/h+AyMbzrbbwljkJbMIUe3w+7hlxGY/DPdLMPmudAT6D
         rFIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690420584; x=1691025384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ClgNeiFjuy/ZcuAlA/jQSJxQumT/kuSYj1kJfxFSLmM=;
        b=FPIO6GDyOIxTxz3bfMRXaU0qP2OOhmYi4XG9lKuGD/xt6usbD72bOs3K4f6ESdomEU
         WHILN8woCQ4xIrpBBmR+eVcwzW/Zjor5FCCz7AonNgQBDVkPU+lUQ+u2vp+heNGBV2Cg
         oSjhMnp+Q0XWvLasK+Y0jtZm0tisdZ6EvHflpD3pFaP9syLJJn5aFGYXBovfvNpcRIIp
         mX9boOZggXFcJQE6IuoE6p3BUAAACSsMUCbjDuHgq4X6yz0FMQrymkolT9XmoWqjYohm
         Jf2+TFyyFYCr5WpoWW3BlN+x6eVbuIfxRoyiCeRJhv1UXB6DTPT0XdQ+LydSwsRnQ5Ry
         e5bA==
X-Gm-Message-State: ABy/qLYN5jO1jEV7k61bOahA3sC2BtYsu4Gd+wt8YmILvYem4i4vDkVz
	ZNQXPXg5RvqKUF4cmzHIGBw=
X-Google-Smtp-Source: APBJJlGnLJFFKjjjFSlPbAyar6SYwSdg1nFq1zcS6uYv7zflgxuyCe0ufQo+y3THwPCrsfUKoSAXpw==
X-Received: by 2002:a05:6e02:1d9c:b0:348:e4a7:7bff with SMTP id h28-20020a056e021d9c00b00348e4a77bffmr4520166ila.21.1690420584609;
        Wed, 26 Jul 2023 18:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7b11:0:b0:348:738d:f1f with SMTP id w17-20020a927b11000000b00348738d0f1fls71998ilc.0.-pod-prod-03-us;
 Wed, 26 Jul 2023 18:16:24 -0700 (PDT)
X-Received: by 2002:a5d:84d8:0:b0:76c:56fb:3c59 with SMTP id z24-20020a5d84d8000000b0076c56fb3c59mr4170284ior.10.1690420584027;
        Wed, 26 Jul 2023 18:16:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690420584; cv=none;
        d=google.com; s=arc-20160816;
        b=PLzj16JRmZpFl4yy80YHS2EA0OVifpR6aDWBLjI3MgIOkj2VDLnjyLaBjUHdMGXYjA
         wddhi90N+yYferu1CQJTZ4LaNPjIY2nEDrtOd782olA+6eiQg7oQcR+Tsva2jRFGlJTn
         /3kZDSWGmxEoVWuSfvj2hg1TnAd2tkQ5n2lg0dWSHnCTLYCBiqGb+EB6UQy4iuaNFfZR
         5i91+v3JcGl3Jil7fqKgs374KJ6IOmwgGmgXmEi5TqhvF1vis8bYxBrtILaa29+6xxsd
         HGxB6x6EFcdkmm7Kxrv1ZITxvgwuiVcJGPmuq4ElfzDWK2gopdDdWinJMHZ5/9Ix6h9r
         DvIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wdDnXuOYCY6a9cM1iZrK6XAJpPM+qYFvR+jg6Bi7Xzc=;
        fh=v9wYe9VT0TbAN61FdyevhEThUjofuva2Dd+9j50U/es=;
        b=wQOebN8lfvDdeRdBhYuiPQUizVO2FMqRaCEmWNGhMlJ/qsptUeyj9Pax/qGqDS5OEJ
         xtGhMkGGXZRhpSeNp0aM1pB3upd+B5185TDQ1OQmMX8xfs0VDgu3W5gUWcKS6y2YOOlq
         7gAB1Ef5EVlwJAMPvEhIB5y4JUFmO8pCBDQ1gFz1RPJgle7lAYemOPTeaEF2maSxJNdu
         JLeXigu46bhWTkOggsX3k10uoTkzp3goMFEAlxOcXChaIwo4Jl30Ty8DLaCEfsn0mjR2
         rSalsU3AAq+FlRLbqDb9x4Q+OUzZe18K/fl+EOh31ir0gxDcbWRtcyZc1fH+zImWnepc
         O/8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id k17-20020a0566022d9100b007836de802c0si29616iow.1.2023.07.26.18.16.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jul 2023 18:16:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemm600020.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4RBCSL0RfCztRjs;
	Thu, 27 Jul 2023 09:13:06 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27; Thu, 27 Jul 2023 09:16:20 +0800
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>, <akpm@linux-foundation.org>,
	<wangkefeng.wang@huawei.com>, <sunnanyong@huawei.com>, ZhangPeng
	<zhangpeng362@huawei.com>
Subject: [PATCH 3/3] mm: kmsan: use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN
Date: Thu, 27 Jul 2023 09:16:12 +0800
Message-ID: <20230727011612.2721843-4-zhangpeng362@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20230727011612.2721843-1-zhangpeng362@huawei.com>
References: <20230727011612.2721843-1-zhangpeng362@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: zhangpeng362@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Zhang <zhangpeng362@huawei.com>
Reply-To: Peng Zhang <zhangpeng362@huawei.com>
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

From: ZhangPeng <zhangpeng362@huawei.com>

Use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN to improve code
readability. No functional modification involved.

Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
---
 mm/kmsan/shadow.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 966994268a01..87318f9170f1 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -281,8 +281,8 @@ void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
 	struct page *page;
 	u64 size;
 
-	start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
-	size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
+	start = (void *)PAGE_ALIGN_DOWN((u64)start);
+	size = PAGE_ALIGN((u64)end - (u64)start);
 	shadow = memblock_alloc(size, PAGE_SIZE);
 	origin = memblock_alloc(size, PAGE_SIZE);
 	for (u64 addr = 0; addr < size; addr += PAGE_SIZE) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230727011612.2721843-4-zhangpeng362%40huawei.com.
