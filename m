Return-Path: <kasan-dev+bncBAABB6VVUP2QKGQED2Z7ZNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EDB01BD1CB
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Apr 2020 03:40:11 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id i15sf875018iog.15
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 18:40:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588124410; cv=pass;
        d=google.com; s=arc-20160816;
        b=rx1uaiD/+LpkcRgloIU9h82CwjjVDvKTJwAuKpgVqa3ghPbwz/WjmvCUb3WyFDx8+J
         WzLnmMEoFoHefY5kBpPVKeCRiZVAqxa5k4B04XtDt41EbST9RlsmFJpuUY27CTg2DyxS
         Z70d3D9kJrpHaNJHmHI8+ZtCdBuct5f9v9paHEdUy/Q/l5CHSB1uY/MHfAyGCa/gqkNj
         ePvJ/9ViroNmJxRmsy2OFg08f4g0iimA3VFLcQg/M1zws5nVBh63k5p59/6PvgqUWRo1
         vjq4t61XrdQdPwaw/35AKsapRlc+moDd/klTOk76MSHqsCSVZ5ApSJvxRWV2uEZRJZmZ
         AePA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ekbC8zVV9XJfCeY2BzyBKoMnGxB/+phqxks91NpLOUc=;
        b=mdEBDqcpssdiUC26fEwVUWlKCZpacsJkWSnw8o82xzbdyXZSfh9rPuROG/ysIL4J/H
         msk54lOJOCW16299WfuDUkcjmHUSl1I/0eiks/e0BAJCnI+uEmPPWTo0/Zh+ccUnhUCG
         oyqrUqxB2rMTNDEPjNm0Hp9tTERe21SnXzNgiOb+T7JHnqbuy6CeAEes7kmZ40zl9LRJ
         oeLPB5YOc5Fqebvnn6NE9+IJPzgw9YgOWeDtXja8NK11KKaMjl19crQElG/CQZNV9lAx
         V/6+e9A9xSd6wr8BtdexZSBYo2W5elR5LQA8kxL1NRLTuqX3Y7Ew78eiyeuzUGLxS0VU
         QSYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhengbin13@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=zhengbin13@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ekbC8zVV9XJfCeY2BzyBKoMnGxB/+phqxks91NpLOUc=;
        b=Yp+530H6qKOI9nF5S0dbbd0QhnZ2p1W9zjRFbumKemsdc0in+aRXX8D7sf2FQRJaLV
         nXVc2GDetEfBD6+chu4GTa51DPdZSPChB9hmHWUHQ0H0lo+94iAEfz/RmTkTSuA55KOU
         pBVIto6Y++2l1E0KFbPg15q/a3f27pTTu9Cs9utdhcvI30T0MTze4HPstWUeZXSvxokP
         EyOfhHj2VCkBFuiI3StOZK3ZbZ3c9ANYoWL2cdJ0lXZOyCFfqJjLVGe1IVO+CQzojHJ8
         26DSL224IFL2pBnZ4EU3g2wHqRDlfydu8gSauwJSDAIulR+yNoB0gClj7diHYW5e5ij6
         K8Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ekbC8zVV9XJfCeY2BzyBKoMnGxB/+phqxks91NpLOUc=;
        b=jWtcEy9ZEj7dQfgl4YP94CelXRMfxQuGj5S0BgTtWjxZvRDL8lNvfb31w6ZYM6p3hh
         Gp1hAjswxyb/f2kzP/t66l0fjyIixQhck8QVI9mpy1wWL0SgrHNTlS8qG83kt3oXALTJ
         yPIRTLD8k4cs01eG6ssgAsCx+sllQAhpHHfhAiKjGLLYaBlT7unFRtpNBXRxc/o2y+EN
         HxqACs43YexWvrINb7ZEQJygnQinly1Ou9lLEUrzZlZFugxIGSZmIZhD26+XbTOGH8Kk
         ACucDoo4nzdSIIsP1TkgLGdIxq6K4jOEY+e8f5NF/QuEnKr9FjhbYmkp0sjH+3R+DqO2
         hq4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYET9vp6ryzC+EplNnPTzL3W3toQFkpuKLX0+7gxmQFAsL7xVP3
	yw2iZfrjkzgcDI7mbm3T3QQ=
X-Google-Smtp-Source: APiQypKrgDTyoDmBnM7QalYvszvUVcwgKkLMfT9bCkY7ZDAd4T0Di+0ZSVIG0ZEH1HRaLBNGTX82AA==
X-Received: by 2002:a6b:b955:: with SMTP id j82mr29188855iof.54.1588124410335;
        Tue, 28 Apr 2020 18:40:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5fd5:: with SMTP id i82ls11401832ill.0.gmail; Tue, 28
 Apr 2020 18:40:10 -0700 (PDT)
X-Received: by 2002:a05:6e02:5c5:: with SMTP id l5mr21259889ils.170.1588124409991;
        Tue, 28 Apr 2020 18:40:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588124409; cv=none;
        d=google.com; s=arc-20160816;
        b=pSsUF83Y2/e5928ObF3vjug9UZ9CEoiIQxCPeu0i7li/yApemdu9FVAHCVnwyF/FJz
         2NKJ5m+opsACTqL/TptUnuL/0DUzddIBG6qxFsOwWed7E9s4Ta9LHjTuR4VB6Vd/itQZ
         fybN1oKBSkfA2gQpqtrZOm6tW8mK0C53DolfrBco8sYZ1felVN3a7DOyvOFB60YrJugi
         ZENqyQfWHPM5KiO7QdP1NI23OTFkF0WuxtAayCgm49AxKWkrCn1QJLXZaqBjidKr16uR
         cBayFPN/mNb+Xy2qeouHV0ldNypNNd/v4xOCIkn5KySeiXY9NtovG0hIC3Wz5zr+15eI
         QUEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=S3Gj2CX8Y68uytqyFb6mJOcphU/qt2RDEn/kab+udP0=;
        b=p/UbUxoscMU9VUlR/o+QPm+x20nqoPPDJsa1eEwE/u0bGKRNgeGMsEhhlGBS/wvrm6
         xUcfpmk6B9hiGxuHGlZlYhNoT4HPZBRA/ABFuwg1smc3s2fIK5II4sb1ouA2/bhiHncS
         Ta3P4nglZrlBhhDvwW3569Llo+4l9MuJ2cqbwO539m/KTdsnja+ATXF6qe+xNwUKfvcF
         KqTkHrq/EV4kOyRFMhmVSuGkfLnsFOjRQaSkfqVFidoRWmIqS246efKWDM3Z+h9cI/KP
         5GYvegZbmxyCFBlWlLHPEWSTcmlz/CnU3MmfbJ21xbTsXWXfR9LNN3loyWQiEmCQdG5+
         Nwcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhengbin13@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=zhengbin13@huawei.com
Received: from huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id x4si37482iof.0.2020.04.28.18.40.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Apr 2020 18:40:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhengbin13@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from DGGEMS414-HUB.china.huawei.com (unknown [172.30.72.58])
	by Forcepoint Email with ESMTP id 6ACD64896C78B919BDD5;
	Wed, 29 Apr 2020 09:40:07 +0800 (CST)
Received: from huawei.com (10.90.53.225) by DGGEMS414-HUB.china.huawei.com
 (10.3.19.214) with Microsoft SMTP Server id 14.3.487.0; Wed, 29 Apr 2020
 09:40:01 +0800
From: Zheng Bin <zhengbin13@huawei.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>
CC: <zhengbin13@huawei.com>
Subject: [PATCH] lib/test_kasan.c: make symbol 'kasan_int_result','kasan_ptr_result' static
Date: Wed, 29 Apr 2020 09:47:10 +0800
Message-ID: <20200429014710.45582-1-zhengbin13@huawei.com>
X-Mailer: git-send-email 2.26.0.106.g9fadedd
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.90.53.225]
X-CFilter-Loop: Reflected
X-Original-Sender: zhengbin13@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhengbin13@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=zhengbin13@huawei.com
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

Fix sparse warnings:

lib/test_kasan.c:31:5: warning: symbol 'kasan_int_result' was not declared. Should it be static?
lib/test_kasan.c:32:6: warning: symbol 'kasan_ptr_result' was not declared. Should it be static?

Reported-by: Hulk Robot <hulkci@huawei.com>
Signed-off-by: Zheng Bin <zhengbin13@huawei.com>
---
 lib/test_kasan.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index dc2c6a51d11a..06512d9a01a1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -28,8 +28,8 @@
  * are not eliminated as dead code.
  */

-int kasan_int_result;
-void *kasan_ptr_result;
+static int kasan_int_result;
+static void *kasan_ptr_result;

 /*
  * Note: test functions are marked noinline so that their names appear in
--
2.26.0.106.g9fadedd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200429014710.45582-1-zhengbin13%40huawei.com.
