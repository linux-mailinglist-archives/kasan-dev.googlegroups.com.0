Return-Path: <kasan-dev+bncBAABBHOGUGIQMGQECDMAJWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BE54D4D2A7A
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 09:19:42 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id y7-20020a056e02128700b002c62013aaa6sf911595ilq.3
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 00:19:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646813981; cv=pass;
        d=google.com; s=arc-20160816;
        b=e8c+v2xSSai4tAJwbl7CQVZkeKrLQ5vaHGJT9dHw4hwaxTevcnB2P7UkQYKeorGb4Q
         IF12rOYvkz+qqr9kycoSklGT0aKnZKS02he0iMJkp6R+Mri8yTuntw5A/fGyDzNaeuW7
         r/idrIpSlgAnF7/sZBr/JYw3h9r2WY/G9EilxaIIikgbWKeJsg1bCadHlo2cq3wioEKo
         kCvSzZUGL2LCqy/isegQ79btZg1l3pKeV2y2uKnBGS40tX/9q4XAKMO/FU7mVrYU42Yh
         Yu3DXn9Zy9i/dW1pj2TCMEMwCvtBHFSzirgL3emBygfBEaKmnYDorlj7xspyexeSe+tX
         LiDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=yD3uqzURULJVFKdHPX4g7SRCnc+g5uW1P1hzGcyIWkg=;
        b=q3JN21STY6BkZSW+elUEfElWRhPL2VqFuxUFnvbP8agDccp5kJYuxnHvVc1UNOcRFp
         PUxVzVTxFrNoezBaGkHtdA6ZpANx+cRnp+PAlng5h+jeSpKfpHZDkBAyA+RNUBfK/9IZ
         MGXcVjY2yCUdM3z6K5n8cg3FfEH7ONYl7kIAuaj6yfq7M/3uDUWgfQB/j0i9PcwTGQ/x
         H30tZla5B+w0Oww1EGX2cCnGtlOZ5uz2zR7AABg7pM+3L83gud7VQv3ikWcM7xw4KQaK
         fVTySYN/UTuM/1KDLdPPN+rLNHtjAMTor5eorqnTY1QSHdmK6s4+3WT5jhCLIQ515FaM
         zfcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yD3uqzURULJVFKdHPX4g7SRCnc+g5uW1P1hzGcyIWkg=;
        b=EAYkbQiyBBKVjzpkHCIKXE+EPwPDI37hXYXT9pO7OBZpuwY0VV5OolBQWY4/VHPPFd
         Xnn/8syP2APFEwgf4qeVzhnG9DLI/7ohWzxsO7jDyn9s8MbK62qitUBQumQK/6lDKCRO
         aXv/gSSucUYrHSgL9slWokPV2i7R83HO6ksvIi87NbNDepfD5mWTw3M+MK//3D5uTaQs
         4QCT7a0LoRzZVDCVWSw2Rhw8GNecXTLwgOBmyj+8NOoW8uAY6VN6H9SB9CFPwbskuUOm
         Yr/ru1Jn1Jk/MIr1jmWvjABItdPtHE+f4D8bGCONl2oBHeMwNVNB6u32793GQgzQ8Nzj
         75fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yD3uqzURULJVFKdHPX4g7SRCnc+g5uW1P1hzGcyIWkg=;
        b=JJ+anIN0cjRl9Gnl24UjpfgL8cGLrFsWGYmbBpRcRe3zT880KR7/9ADwEWKuPr6rgb
         ngcEHlhoRaP+9ZNln8q3SpoX+TUwIK10uwP+DDZi2JOXm8dWjiu58oEasLRC/SkRJFAP
         zLIXq96f+spRkjUm1dRcemsiKf+13R2CnJPT0T6WCaHgR84ooXgyWvKzJANn57/kHJa5
         NMd02f7AZ/tx5bB2ONqUonMZXeOFfXUMonuscEDt/k+gjwDRCBilOwQFXFbWELpgzlhM
         Yxkyaj3CTCa1h30SWvWgajqGwOgslQjE36rtcM3BQ2Jxcu93wrsW2SbXE6kJVkPUdsVA
         h97g==
X-Gm-Message-State: AOAM531TSMt9DblKkgJoJMyUbLZMipgPke5jcYaZJh5e4BRjkeSDZyY7
	QgQrM3lDm/mR5/yQLp7kuQw=
X-Google-Smtp-Source: ABdhPJwmXhZbjpuG5lZ87Cy8PeYy8MzST/kF6ec/1It/2OMKkuhKkyAAxlIUyR+3ayjMY/0rLq9/7w==
X-Received: by 2002:a05:6602:2f0b:b0:644:c875:116b with SMTP id q11-20020a0566022f0b00b00644c875116bmr17736699iow.115.1646813981570;
        Wed, 09 Mar 2022 00:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:bf04:0:b0:2c6:207c:345b with SMTP id z4-20020a92bf04000000b002c6207c345bls232578ilh.8.gmail;
 Wed, 09 Mar 2022 00:19:41 -0800 (PST)
X-Received: by 2002:a05:6e02:5c2:b0:2c6:4416:d086 with SMTP id l2-20020a056e0205c200b002c64416d086mr11836413ils.300.1646813981228;
        Wed, 09 Mar 2022 00:19:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646813981; cv=none;
        d=google.com; s=arc-20160816;
        b=ha9+5CLZLwF5oO2r7ZprDdTjiMWd5MFPXNzo4Lo7aM2HgLNnKdszIJ31+GZkAq/0Uc
         tF6ZNN1uUyGWKoju9RrbKRDcTCAj19A84UmY+pdfeJID3Bk3QuBFFb9y0WJdYepAC5yA
         /N4p6W/nzZjdpd3oag9cmvM8WOl+3lEGhPblqkWHp8ebTF5NZgfXcvklGmTXvUag/r7L
         FBtPTGuhghE1KOkx4M6MQIepm8GczEgu/D2fh3Kxq0ao8IYeeYHVFlnre4ovXOI25Y+V
         uyicCrL0DWks78qHsdaHEWIjGz0/+1mXbRLSlPuHTXv45V+ZrChGhBA3a4qpS4GyKflV
         ER4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=rw9Z+e9I4TYyqesWWroad5S0QCqUIaBMcYPA3dm12Qo=;
        b=O6cXRnWMHSHGIYrfGTyy+GBHgf0KFPH5SH2iyT43wpHeLgx9zBCvWP2YOVmrycWqLT
         hmf77bnu8KEnidYlUWAITPYKLxCzFRhXf0NfM01KS34HHoZeDQTjjnUXcdXYstkgUyph
         J1EZvtvN/5sGl0gSqvPd4T0oqZnnBxdf3JIiUB5JPCX9yjQz5X4lJukfWsLLqK9vlWNT
         gxn/e4SxegCkKncD5QZE+n9G/hNKOxGuDnKeM9v2BnMlNkPZaHC/kXIggp1d7jCBxIe7
         py3aD/M+skuciHJelrDhlJ/6TmKwv1jGmjcw9yc9dAae01kfEC+IfD0+x851n+TTUg0I
         lKDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id i5-20020a056602134500b006411847597bsi45096iov.1.2022.03.09.00.19.41
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Mar 2022 00:19:41 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from kwepemi500010.china.huawei.com (unknown [172.30.72.56])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4KD4lK3VNGz9sSn;
	Wed,  9 Mar 2022 16:15:57 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500010.china.huawei.com (7.221.188.191) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:38 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:37 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH v2 2/3] kunit: make kunit_test_timeout compatible with comment
Date: Wed, 9 Mar 2022 08:37:52 +0000
Message-ID: <20220309083753.1561921-3-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220309083753.1561921-1-liupeng256@huawei.com>
References: <20220309083753.1561921-1-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Liu <liupeng256@huawei.com>
Reply-To: Peng Liu <liupeng256@huawei.com>
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

In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
represent 5min. However, it is wrong when dealing with arm64 whose
default HZ = 250, or some other situations. Use msecs_to_jiffies to
fix this, and kunit_test_timeout will work as desired.

Fixes: 5f3e06208920 ("kunit: test: add support for test abort")
Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 lib/kunit/try-catch.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
index 6b3d4db94077..f7825991d576 100644
--- a/lib/kunit/try-catch.c
+++ b/lib/kunit/try-catch.c
@@ -52,7 +52,7 @@ static unsigned long kunit_test_timeout(void)
 	 * If tests timeout due to exceeding sysctl_hung_task_timeout_secs,
 	 * the task will be killed and an oops generated.
 	 */
-	return 300 * MSEC_PER_SEC; /* 5 min */
+	return 300 * msecs_to_jiffies(MSEC_PER_SEC); /* 5 min */
 }
 
 void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-3-liupeng256%40huawei.com.
