Return-Path: <kasan-dev+bncBAABB6FV4T2AKGQEHRBR3JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A50EE1AD4A4
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 04:56:57 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id z2sf883221oid.13
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Apr 2020 19:56:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587092216; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPcV0Ag0mCXwtEz3TX3DcOW6JowjKUfUzHjO9Sftb3094KxTs7UwzDVclxLsiRMICG
         PZM/v/c9ioMsSJRwi0sAo+bMk9Zd6FXbO0/boivAh6DnwivLjr2yqFONoEStusSeGke2
         SlvzO3UsQqZi4uhYTmIlZqcGeKrVsb4XjYLF3npMFzMZm9U4qVz6G8Y5kZuh/ndmjTxU
         M2KDDWdSPXC05jwim3vm8B9TlVlXe+aPAWgrQcKyfuMrKX4HdLwRBU5odBYTWgyD1C1W
         9LZkPZQLkVt9pLGX7V8vze35DzPcgZ0+Zy2SacA2xDp5P6LwzyfbY9JVh/NENfakrfef
         VDZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=UxbnD3+mAHHZdCqsZnfS20qsLky8xddICxwcGJJUjU0=;
        b=pPlEFNq41JCrFz2MdZn7m0+4MI/1iKNI9kVM+CUAz/yX5OI6JGNfFzyRdET9U0NiTK
         Xwki1/W2R8V6nTCpinoc8LtTuZ5nDTrd6hNkrDYurLIIvjKhmok8UWLcTKhhMVDWHDA+
         Nr2WXdYm1bhG6E/SYqT75QgVfdZUVx4T3Y7AkjEHkrDu+bnYQEBxDYb09bx1+WhlHafz
         TnZbNR37UG+iNURWLltQF3URTI6IJNEOdlyFcdTWDRIP17d3ZwNnt5a26Aq2EKrMsvnS
         l1AuJHjYGAx/XUApTjWd2pgBiQAslz+gKMBnjteEmMgOE+1tW2nX3GXlaWMk9rLw0UPP
         btbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of weiyongjun1@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=weiyongjun1@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UxbnD3+mAHHZdCqsZnfS20qsLky8xddICxwcGJJUjU0=;
        b=a32V3sKL5weqrSqGTcoeVtaGu+noMfxbPS3y8DMYAkMFXYGCedl+OQwCCYXWEmCtqa
         koYNiBUJ3lRigen6+gj9whbZiiAf8tUM8Jm6bfkyBI7ePU4rn8HQAc06ey0nD90E0UR1
         BUhS6FeC/JEvL0H0wjJ9HwgsvgRXmYNx05ORNgj1OupcZvpcFEdh/3w0ECZ05ojYiwod
         IgO3CXOEXcUh7kIA0LCzWej4VLGmQ7hWSAHNGli1WNL0hMiEOdDppPO3XaKTycmgfUKF
         pEbUWdHr4H6ihmPLmrfD+xV6DLSahd7k5OYcbt86zpZp8uqTnViLKyJ7DRPY3HZ8wgqN
         gdtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UxbnD3+mAHHZdCqsZnfS20qsLky8xddICxwcGJJUjU0=;
        b=jytto26tn/emVwwpYBMRskrsiQgc8ktJdC3tM+kX/bAi6h4PYgXipbP8iJ3/ZQkvDx
         mViv1MCM5Ne4eT4yMA3nIeHDnS9BZWoQ+sAD81o0t5acZzGWFxFonqvY+oCHrSZCKPHB
         dt83QCT/Rs1dObODfnINV3HuWPJpX2Nn3EuUr7ofSru1s/6JtRk6aGmDnmpDHoPAAhxE
         1x0hQWcILvtXzr1kL0Xb3lB0BEzirLJnHIytJL4rCf5chsujr2tyt5u7eE3PjQVMOJsJ
         WEkwk5O8uUr9/022pnhuazp3FUWMQAkrn+PKVNTVPeaDljJHB+OnRzL0Q9O/xDmbEbkF
         lyKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaXDIIkdUSAJ/JoXWuVVhorpjqXH5j2URwlY2TB2wTe4S/gAl7G
	FS9plkotU3ZRE9lw2H4XKAI=
X-Google-Smtp-Source: APiQypKxj3mKdnJktMdQ8VL5zPxhCh/e6q5O6ZEAx6D3CYDbe9qHrSBES7KZNy1IQ2RIgiYns3Mmrg==
X-Received: by 2002:a4a:e1af:: with SMTP id 15mr883739ooy.40.1587092216586;
        Thu, 16 Apr 2020 19:56:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:d03:: with SMTP id 3ls108736oti.5.gmail; Thu, 16 Apr
 2020 19:56:56 -0700 (PDT)
X-Received: by 2002:a9d:3b7:: with SMTP id f52mr943496otf.4.1587092216169;
        Thu, 16 Apr 2020 19:56:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587092216; cv=none;
        d=google.com; s=arc-20160816;
        b=yqCQVh1I3rNss9oDBwdRc4fdx1lLjaRxoRJVNfZtemwwygMR+3TH1mMzPp+h1dKCbL
         OvXFkgPQ5/gnl9Nqputs/zzZ9rTrzWUt+2xmJpu4Jzk2KjytaS9upYfMFpxC2gimdOL8
         2L8/i/J4OGhzlENbCQGwjDsGLhQKyvdEWZNlhSuGBCCrIWzjUq3vUbEZzEJDXlpzFPo6
         naQZykW5bJXrl0TVa7Bf/ZZCR39AUugs7mI3e4yWlT0Uftj15YcR9P7wtkIvMjXfkjWp
         rbeFPfTiO80PHUvIoShzM5MSTYvI3hHi3aezzbk0cWv5y117LIyULnj3TBWEYPargOdf
         S2FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=CdNU4sDmBAMI2AjyfH/OTA7n8O4QJ0Wn8XM7v1KWlOk=;
        b=i9FAXdP9N8vf4e0fC94QP8lKQwdbE30Em0s4MH/wfLVEFw1mUziGCSmFMDiDTCShbo
         qXv7SiMZJtYvuuxdV/kgYxjxltTMoeXcMTrVgJwK4I6KbJ+DlvoW8UdKOgj3Rd6G6Reu
         KoL6tzjNTEq1/BGizf4pxRWtUs7CoGfBeK4HcL1gmL7L0qADWSsECExii7ekjliq9Ta5
         tRpuirU1OzkRCgWYohZ0MoTQDk0/U9M8Zi9SRW6EsUyFTLR/FkraQwxq9QUHMy8k2vmi
         LKVXIGyUp8a9Bydj4+tn6BP2VSSLQUIRjkcxTqpFbjlAVyAHRUGUhDeXGkTZV+ZgSyQO
         IN6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of weiyongjun1@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=weiyongjun1@huawei.com
Received: from huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id w6si1121239oti.2.2020.04.16.19.56.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Apr 2020 19:56:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of weiyongjun1@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from DGGEMS414-HUB.china.huawei.com (unknown [172.30.72.60])
	by Forcepoint Email with ESMTP id 6BF7ABC77059A6E3C900;
	Fri, 17 Apr 2020 10:56:51 +0800 (CST)
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 DGGEMS414-HUB.china.huawei.com (10.3.19.214) with Microsoft SMTP Server id
 14.3.487.0; Fri, 17 Apr 2020 10:56:45 +0800
From: Wei Yongjun <weiyongjun1@huawei.com>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: Wei Yongjun <weiyongjun1@huawei.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kernel-janitors@vger.kernel.org>
Subject: [PATCH -next] kcsan: Use GFP_ATOMIC under spin lock
Date: Fri, 17 Apr 2020 02:58:37 +0000
Message-ID: <20200417025837.49780-1-weiyongjun1@huawei.com>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-CFilter-Loop: Reflected
X-Original-Sender: weiyongjun1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of weiyongjun1@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=weiyongjun1@huawei.com
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

A spin lock is taken here so we should use GFP_ATOMIC.

Signed-off-by: Wei Yongjun <weiyongjun1@huawei.com>
---
 kernel/kcsan/debugfs.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 1a08664a7fab..023e49c58d55 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -230,7 +230,7 @@ static ssize_t insert_report_filterlist(const char *func)
 		/* initial allocation */
 		report_filterlist.addrs =
 			kmalloc_array(report_filterlist.size,
-				      sizeof(unsigned long), GFP_KERNEL);
+				      sizeof(unsigned long), GFP_ATOMIC);
 		if (report_filterlist.addrs == NULL) {
 			ret = -ENOMEM;
 			goto out;
@@ -240,7 +240,7 @@ static ssize_t insert_report_filterlist(const char *func)
 		size_t new_size = report_filterlist.size * 2;
 		unsigned long *new_addrs =
 			krealloc(report_filterlist.addrs,
-				 new_size * sizeof(unsigned long), GFP_KERNEL);
+				 new_size * sizeof(unsigned long), GFP_ATOMIC);
 
 		if (new_addrs == NULL) {
 			/* leave filterlist itself untouched */





-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200417025837.49780-1-weiyongjun1%40huawei.com.
