Return-Path: <kasan-dev+bncBCRKFI7J2AJRBDXQTOKAMGQEJEM2V7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1336F52E25B
	for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 04:08:15 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id q6-20020a056e0215c600b002c2c4091914sf4183473ilu.14
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 19:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653012494; cv=pass;
        d=google.com; s=arc-20160816;
        b=sV4VPGfNHYyVi9TfL92G7jo3umoAEpVVPEfXDGCJFjU2SQs0o46lBmr0nW0JXjzCt3
         Hy0bvoK4qYR6BEPSympGTQC6pRyixFVpMn7WDRPT1VZ2ZCbWOwKhd9h4o+sQU6i5SOPt
         N1m5HP9oDshotoNf5yMx7ykbzcBUPnJVPFJsPvlFVZ40nZdU4cgLComwUzVNEY+Gq7WW
         cQUGjbUQyCvgTtkG8S3FPmC7uCXMh1fPaFymXshVKCGOvecOJoWNr1PHHL5ZfaYzTvCh
         glezLltxxjmi8tGEZi9NMUeFPO2y7Hg5CEQtFD7TmyvcoPMc6vYVB/BG3o179G3oF3D4
         MMpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=XCaCB2FBMZugz88TOeVLqMyYJPNmIQucZSdajtsz/NA=;
        b=wA746umdOlLDpYL5LUE3EWl9y56uSHSP9jDR76o23BFMNORqHbxRodmzOm75q5b/AR
         QJtpX9FVSO4TunUVnmFb5Te1fqKkPTcjpR8swWYWrU+ySRMj2S8pZRyHkb5+rCgkIevc
         Pf47JMuxKlcHWkNpJi2XWzHTib0DdWYXYguqF57v1BN8nx+tBN6LoVef5kmQWlGfRke2
         y+bBVV33ECbtEnNQKW4N41sGfRNM6VwKlAjV7uhFu/LOJIhm5MdgGLASI9xVOfO+WWWI
         zjnL5LW2zttThU+MmBEgEoNOQzx6Vo2r8d8eITDEYOd9ceDrv6qt+dx2iEXmHXxmECHT
         kbiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XCaCB2FBMZugz88TOeVLqMyYJPNmIQucZSdajtsz/NA=;
        b=n+iDMTg8PE6fHrD/j7e8TrnXkr1jbbQII5Yxow/2LC2k1yT28mMub4D9zrsptonPJ+
         vyEMROeuQGKg0dafHhF8/sdqCYKCldzN/TetmI22aWxXuQ7HFrs2l5C/MaBH81bGASh8
         PzZma2rZJbJ/N+KU2a6aDhrQcNtcFQnrcppOAqxzrO4IE1gzrb5BoKCMpJlVWkRp2nQQ
         5CSRJ/EjT17km73KtV/cwcXT8aqOUKKYV3QgdiqFSrSUEydPzuNJlGu7c/EQFFdR4vvr
         Kzt8F1QW934Rh384kjsk/i9qStVFAKcDUy2cE1xqbc40NNDEN4aXGTMJPKVCrOWTREND
         edNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XCaCB2FBMZugz88TOeVLqMyYJPNmIQucZSdajtsz/NA=;
        b=zi9mx8Sf7R1FAlAA97cvzAvXwIHIaOOX0hVoFb1M3lA25+/slLLVhescKzlO/vY188
         pOq+I1KQDL05O+Gy932QUYZhJx5icWcQSIdRc1M5TIQhdXOK22YutiiroZ51W1CApP39
         NM9rVDu9S8hJWTtCunVq457RV4S+GkKvP1bjKDrYN41JEZmr1fyDs0FutPY1SsuzquKg
         cdZ3S80mCRiA1ACaNc220uJkyGAUF+ITxTvjGn+5vhby1uGg2MOMQ6CjxZ+NHqP/xA1A
         3jYXu1V/Vz1fW+cH0eC42DP398V2chAsO3NXoTfqVEQw92GtQZE+qt2gngrnKONc53a5
         iC8g==
X-Gm-Message-State: AOAM531HIseWBJg4oud5cRjJR34Poh+HVc54z2HAJK2CTHFdJ7AoV5Rr
	Rn+AnDYo9VOHq4V3mwCRD0g=
X-Google-Smtp-Source: ABdhPJw84PIw4/baRG/XDWJn1u/80cDfTE2l9/TlsB/Gsd9fL0CyqEs4M4zLBhpfhI24irX9cLGyTg==
X-Received: by 2002:a6b:ed06:0:b0:649:d35f:852c with SMTP id n6-20020a6bed06000000b00649d35f852cmr3880321iog.186.1653012494339;
        Thu, 19 May 2022 19:08:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a82:b0:2d1:10c8:10cf with SMTP id
 k2-20020a056e021a8200b002d110c810cfls763912ilv.11.gmail; Thu, 19 May 2022
 19:08:13 -0700 (PDT)
X-Received: by 2002:a05:6e02:1bc3:b0:2d1:32b7:97ef with SMTP id x3-20020a056e021bc300b002d132b797efmr4208531ilv.166.1653012493878;
        Thu, 19 May 2022 19:08:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653012493; cv=none;
        d=google.com; s=arc-20160816;
        b=PdZCI+zGGDxDSPeiw9SHSJStcAx6pTu6dlTcjxw+J2HvKuwAscNl4Tka5j49pNeH+6
         XjqedQAMd40kweOND2p5xKp2A13wlfLoGItQX+VDAQ8Eg+XTUPpHFDAya1+burBeNppx
         aONwF5ZdojSyxlzBNqJI6nFfx1C9jhYLiLU+u8b8YEZ19vMIWuNzWlb3MvyVt6ln9TKy
         OYKgOQAVCXkFSYx2uXoQkg1ZTgkGTCaho9BaBHhXL+n/ezR6xDTlA48S9Tzhbqv0PiAC
         SrlOJ3/CjY/+tE/SlXkliXzzLw36WsW/7c7kBONx5BBBVOuLp6qa8Jbl67mhfM6fitW0
         o93Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=8iXOkphluPt+9RVDFc2DABzEKIc5ur3K8HWyvlOCY1M=;
        b=m+os1JVJnB0qlxr9Lkz3gjueS1YBLB8NHqxpfJJgR/4kBSwSBGRqpkHbqiVKWuJlU2
         TGrZ1/DgAX5egA1YTcpL4ntv3KI+ynf4cl0uyBe1wEri3h5TODznlB5PMzXBk1yuO0Qf
         207axDpCxVq2+kq6Ub7VLQn08h0KJ8hqYqYSuCk/+vMSTxstQXYUNHgODXkNyWaHjqXp
         ezA/ysvpCufsVTqycDjxmEDNadC/W7eX0rlR8uuKJ2bmGdxxEBHt261wG3RIDv4wu5Y5
         kS9e/Nhvy4dOWhdOcMo2Rs10uL+HSCcB8RzGr2NNPOiyfOfISokDMdD7xPaB9UN9wXCR
         jdbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id q17-20020a5d8511000000b006495f98f57asi184221ion.1.2022.05.19.19.08.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 May 2022 19:08:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500020.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4L496M2hPbzQkM9;
	Fri, 20 May 2022 10:05:15 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500020.china.huawei.com (7.185.36.49) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Fri, 20 May 2022 10:08:11 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Fri, 20 May 2022 10:08:10 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>
CC: Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH] mm: kfence: Use PAGE_ALIGNED helper
Date: Fri, 20 May 2022 10:18:33 +0800
Message-ID: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.35.3
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

Use PAGE_ALIGNED macro instead of IS_ALIGNED and passing PAGE_SIZE.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/kfence/kfence_test.c | 5 ++---
 1 file changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 96206a4ee9ab..a97bffe0cc3e 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -296,10 +296,9 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 
 			if (policy == ALLOCATE_ANY)
 				return alloc;
-			if (policy == ALLOCATE_LEFT && IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
+			if (policy == ALLOCATE_LEFT && PAGE_ALIGNED(alloc))
 				return alloc;
-			if (policy == ALLOCATE_RIGHT &&
-			    !IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
+			if (policy == ALLOCATE_RIGHT && !PAGE_ALIGNED(alloc))
 				return alloc;
 		} else if (policy == ALLOCATE_NONE)
 			return alloc;
-- 
2.35.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220520021833.121405-1-wangkefeng.wang%40huawei.com.
