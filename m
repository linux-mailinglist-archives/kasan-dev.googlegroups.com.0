Return-Path: <kasan-dev+bncBAABB2MKQ6TAMGQEG2TSLFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E07A8764348
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 03:16:26 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-565cd3f645bsf605982eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jul 2023 18:16:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690420585; cv=pass;
        d=google.com; s=arc-20160816;
        b=bG5xL/R2DC5pUtWKmLsHA70Xf122MiZ7hr7Y1Whxzg0pk1CbuOowizcU7Ae/IoD9GA
         3J1sGSSqI448rEUUl+n5+KqppnV9NjzhChN71hKe5YOUEn2/t705BVpEl11NHk+rGF5e
         R2tIjgiH4Crtk4tkfwpQ6rkQ3HECDFoHh1iLoU9+cyRWKvfoFZ/p715bojiPgarmPJd3
         ZKN6AXjwgaYdgHOzn6y1j2diuqmpqbnguK2RO1KXyMGtXAzlOyecrNhJg0J5hzfvendk
         +lTK3XOkg0kZ2KwydFWBp4zqU4bAz3yb2IOVZ79H+gOyDBrlyac3p5u8TkJmA1wnoDwq
         mc3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fyEhgtLwV9Xon3XTU5o6hz+wsPQ1yOSZ0L/DklYnxLM=;
        fh=p+2efxOrsjtKfHqLXl2Yl/PWOJT0MqeZo5k3po+L8gM=;
        b=MCXdmjeIxFQV2SkTEqtm2OQSuyZB9dUbuu0HSn6nE3pPNNQ0uLL7QyUWY3y0SufU5k
         r0uqpqWjEC6gYovlvRBmqxelcD/w9qNCiLXaU8FrEeNtkThvlIkdUmZPx//6yaiJBx6u
         P20GZvXd5lQ3RDj/Bfg4VuREOrS2FLAlyFt+y+S6oYn/fM45yn4OeTZc4zj8IJzNrn1O
         jzw6wxLvb+rXC6rKOZCJd1IjIrTbTi1r1AkzMT7AJVHS6KDd6x2bVnuPFLjSkSWSIeNM
         Opr14R50Wrs8KkCuxViVpS0IRGOxgrOd2LXkajAH6MBAMd6TLXcruojHfqXwAzvq2WEs
         keCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690420585; x=1691025385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fyEhgtLwV9Xon3XTU5o6hz+wsPQ1yOSZ0L/DklYnxLM=;
        b=jO+g6IporgCi7aByDElBOA63rdS5H4trTPWa+n2OOsTCSvXMuLXbJGQGNq5vazRV4b
         jjli0Bz9lRMuFkUmJtFULkLfYoyCcOxiZOpAA57Hg+YaKotvLtwq3owBuqcD/a+ID5qG
         DlEz1TvMymFWAAUzKdP5EgaCE9ZcVgoDZ/mV4ISXdO89wOByTU7TL6Xz487yBuwEBe0E
         NB62x5kc0j9opxMSDlUV0yuJi+xC59Y13qm6x777p5cwkXqw/FMhJgnoyuauuuQ651Xd
         d+OWPbsfUhIn2BRyihpCyoqe4Wra1qK3u7gzqEeEotN/rQn2GJ+sta8gAp6Cajgnmg3J
         D4Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690420585; x=1691025385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fyEhgtLwV9Xon3XTU5o6hz+wsPQ1yOSZ0L/DklYnxLM=;
        b=IbsY6nnvcf6rHS38mGghRgv2psow/8UJdVugjM2Fnw3ziOH9gR4b4D5mb/C0nvEmLb
         z+L0FM+JoUi0gLbSXmZtf0EsZe8IwnlVbzY3Kcmsb6MZCivF9dvggy2iUGI5gsPU19cI
         cgjwnhYpGJy8LsdBaLKGDrlEIgFIZ2AcgvQpFOs/74KH7zqGdVr80Ui/AxkAC587slmP
         Ucbg4H+le0BRn3v/nmHq3GY2BfHAvF+9GHoBuHfQDu8v63sB+J+QswwsjK8rl6D3OJDk
         whu9T1HX4bcTLaHKjV3fFe/OyJQR80B75FjiGTYiS7SW0R/8ubHZO/smqwulaH/vCSjB
         4sGA==
X-Gm-Message-State: ABy/qLaFWNuRoEk+WBp3M7vU7FCmCR4Vlb2yOdY6ggz05ilXruFds/Ca
	+CDpOsPc5Fd99z2zjNGZThQ=
X-Google-Smtp-Source: APBJJlHsOToHkEK6VzqNykmYajN99R9FcwTPqt4jEgAeXJi+1OsP4wOJNjGdY+olw1ss1pPocOqirA==
X-Received: by 2002:a05:6870:e243:b0:19e:fa1f:fc2f with SMTP id d3-20020a056870e24300b0019efa1ffc2fmr1208896oac.38.1690420585300;
        Wed, 26 Jul 2023 18:16:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6121:b0:1ac:e9c5:77c3 with SMTP id
 s33-20020a056870612100b001ace9c577c3ls32018oae.1.-pod-prod-06-us; Wed, 26 Jul
 2023 18:16:23 -0700 (PDT)
X-Received: by 2002:a05:6808:617:b0:3a3:e638:78d2 with SMTP id y23-20020a056808061700b003a3e63878d2mr1067880oih.12.1690420582810;
        Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690420582; cv=none;
        d=google.com; s=arc-20160816;
        b=rTmuk037xc0qcrQNP50VcoR7EQxQd6eM7mlYqZxh6i1atw4/aATtnkz1iDpWBlFwvO
         kcOSVyCMd3BD4WbsFlXFXRvsZ4T2PQ3kw/TaCBYwj3y/fscaDanYNgJbIITkZxz5wEXr
         gpR4ggPss5F7cwmJOEfY+ef5IdS8UWwEBGQjR7G3k6Xfga4S+qj/0HvnvmdCv3tASTcm
         cRf9t/1wI4YkgpS/B/zXvMJjCuwmxGkhyheGtnkyp7yeiSE0VaEcYYWRqT+xVgIOMEg/
         X1C96rFyZLQGyhLv4Ldnn/X8EPnpqNaPPVUW1mAid54nSi3HGQ2Bvni2o5QCdXJfEVDA
         mLIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xYd37JbWctprMIsLniMzviaBXc8Tl5tX0ObDbsc5gGU=;
        fh=v9wYe9VT0TbAN61FdyevhEThUjofuva2Dd+9j50U/es=;
        b=kEFsWoWL+opWk5flupGQrG30nFz/qYAnXFkLWwJ3wT7IW8TDRJ0qp6oV4GUygW6u1n
         kDNg6lbvuOsaGk79Au3Dvbm8K81x2qYp0Ghh838zPa2rClGrCDBFpPW7r43TA5vAfZIj
         ONM2rYs/3/T2oQneN4dMs3fXRmmxOSRS/z18AHTcRxZkxVWcUQZRbGJbKM7PD2QDp9fJ
         TYgkjPE6bl9YmjyIpIbRv8VEH158d6pgtJHPnqgEmj9LBTqXS8nIkgdJjMBZ6Yr3wpIY
         +4Xsnhzc3UC9LuNpl7A1NTSTYc0OE7POdFpsybOdoJ2IbgM3+7kvR9xGh7SSBYFl8f54
         wKFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id 188-20020a020ac5000000b0042681c2d789si30487jaw.5.2023.07.26.18.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemm600020.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4RBCVF1DzZzTm6Y;
	Thu, 27 Jul 2023 09:14:45 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27; Thu, 27 Jul 2023 09:16:19 +0800
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>, <akpm@linux-foundation.org>,
	<wangkefeng.wang@huawei.com>, <sunnanyong@huawei.com>, ZhangPeng
	<zhangpeng362@huawei.com>
Subject: [PATCH 2/3] mm: kmsan: use helper macro offset_in_page()
Date: Thu, 27 Jul 2023 09:16:11 +0800
Message-ID: <20230727011612.2721843-3-zhangpeng362@huawei.com>
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
 (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as
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

Use helper macro offset_in_page() to improve code readability. No
functional modification involved.

Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
---
 mm/kmsan/hooks.c  | 2 +-
 mm/kmsan/shadow.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 4e3c3e60ba97..5d6e2dee5692 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -339,7 +339,7 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
 	 * internal KMSAN checks.
 	 */
 	while (size > 0) {
-		page_offset = addr % PAGE_SIZE;
+		page_offset = offset_in_page(addr);
 		to_go = min(PAGE_SIZE - page_offset, (u64)size);
 		kmsan_handle_dma_page((void *)addr, to_go, dir);
 		addr += to_go;
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index c7de991f6d7f..966994268a01 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -145,7 +145,7 @@ void *kmsan_get_metadata(void *address, bool is_origin)
 		return NULL;
 	if (!page_has_metadata(page))
 		return NULL;
-	off = addr % PAGE_SIZE;
+	off = offset_in_page(addr);
 
 	return (is_origin ? origin_ptr_for(page) : shadow_ptr_for(page)) + off;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230727011612.2721843-3-zhangpeng362%40huawei.com.
