Return-Path: <kasan-dev+bncBCKYTRUVTMKBBE5QWGMQMGQEZYYDUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 556665E62A3
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 14:41:56 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id k12-20020a92c24c000000b002f18edda397sf5426968ilo.13
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 05:41:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663850515; cv=pass;
        d=google.com; s=arc-20160816;
        b=bDkAftItv/JSQNoZOX57gsHg/2sJhcRA0a72nwWCnQTVsWNwpLLdYfXaubPjPbXuoJ
         XOOjmWD+SqcH6ljxAsOYYq5/SOlVHkyR3VatuDSdr8iukq4+B9swwN+2j1oAGZOE176V
         VWWjIkFU5+3RFKHgZnlNocmC+cYEFBwmACct779ZD3H4M2q5tNF+rxDeavjOQCqoew/W
         0jmmJ+6/IJnCyfMFd784eUeCnEUClX/SAwlYO2MdpXjnK/Vydzqz9wvzN5EHX3fYViSU
         0KFRve4q0A6PCOTPzx9lx/JousBpsrO1uQ+HXav4f4P13HbN02NytN4Y395qrhg6lhdX
         mKPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=V4f1d6huFnfRAll594euCf71mFUJBplEhNH1UndpWFk=;
        b=PXW0YXpp8wmJ1bV63VGwQJxQgOzdoPCo12AVKyd8VIRCBOYiLWFgerf4mdQV6t44Yf
         ajHnbTm+LKYYSfViwrDBvbZ/y+trG1ZEUUumP+u8Xml1kcbwXIj4EdWdv6O/c2jYFDEZ
         +gBZVsF5vo7iwbXtoRnCoNY+mc/Le4g5WRwtehnCPzKCqs1Eg20SlGedAouExwjkmH0u
         SoZ0go0h8ppl8W+KLvLmeShKjNbp9uePtl05hjXgz9iz3vw52iHMdBTNGkfkydhK/s8r
         gMvXvjqP7/OXdl6uxQ/R2y87/p6Cncv3zifeugkTO33Gm3i2AcyODY9LS9aMreHZ/ao2
         3sBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date;
        bh=V4f1d6huFnfRAll594euCf71mFUJBplEhNH1UndpWFk=;
        b=C2obXyIIIRI+l1SbyBDxc2PDGHlrwZaQRuEsx2ojFtB13YsjAyjml+01eSnPpcYnxZ
         N9UwT6ZP+nZuKOI5WTPC+2brLTgiMxU7Al6Mi9zvCqbtbONiGnp3RD0Zq/au03pi1De6
         6QiV1lqUALgCgpOrd+7Ye9KYajIODJnc+3oiZGLw+ymUR0pVip2Gev13m+RBgPp19z6S
         n2EsW9BqcyAcSzurpbs8LBIbdQXvohiaS5S8hZYcV2FBlU+XfQ1SHPim/IDHuOzlHIub
         mDYSSaMi8QheIxD0Q57C2f902RPhcb/eBppb2nTPMkMzWly0qu4JY/aqwy4E7azRVYaZ
         OO0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date;
        bh=V4f1d6huFnfRAll594euCf71mFUJBplEhNH1UndpWFk=;
        b=GGPvqu8Yh+FdImlk8nJNOaIEzd8hc9MzYWkZwqnBjy3qduLkJ8WnDLHc708J/EyhlF
         ioa/+xUWfiAFPB/Bl1NQl9NDuc/PfSJmOwUe4E+F/oyYCKTOFU3+WxgCiD92Y8SDtbB9
         t5yBSqK2TCNNRl3z4q8GGfhu/7zTYRwsHvV2xi+NUodaesaFG2XRlckqgggHo31gsA0n
         HVnjE2c+k0Ybc3BjPlEIWkQs7FUZbKiqR/IKx3oyAGnD9CoY3NXVqrZ2QSB6KObdzeey
         ljprVf8hkwEEK4S3HrKpuR/Jc9UNWs5daXQ1gKviNA+CCJXGsaDgEyeDpy12bo3WqvHx
         uYJg==
X-Gm-Message-State: ACrzQf1bD5Ec1VqIxu8kNTTJTpr7Vz8aRsrtwUH1+xdBGvPfLWEcxCUq
	VaFKUvbhi1kGeo4LJKa8mVE=
X-Google-Smtp-Source: AMsMyM6LmLqCuC2hZUMcjKmV/hjai5J/FiH1SW+SywMu6pKY3G/PUciKneJByRVVkWPkxMY1HR4FIg==
X-Received: by 2002:a6b:5f03:0:b0:6a3:fe20:a4e5 with SMTP id t3-20020a6b5f03000000b006a3fe20a4e5mr699564iob.65.1663850515113;
        Thu, 22 Sep 2022 05:41:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:dd0b:0:b0:6a0:f347:9f3a with SMTP id t11-20020a5edd0b000000b006a0f3479f3als1616123iop.5.-pod-prod-gmail;
 Thu, 22 Sep 2022 05:41:54 -0700 (PDT)
X-Received: by 2002:a05:6602:1595:b0:6a1:cfa8:bff5 with SMTP id e21-20020a056602159500b006a1cfa8bff5mr1386984iow.94.1663850514732;
        Thu, 22 Sep 2022 05:41:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663850514; cv=none;
        d=google.com; s=arc-20160816;
        b=lyba12ojEBXN1F8TAy6nXeb9hUbcZMcIJKeCfxlVnUo3uJy8R1V54bAwmIJpTi7wXe
         t9he4Ir5hAFo0Qs46nzyK6TSRAg/C6xA2DlBEGse8SgMA8OHGV3o1aNyAOoBgRGfIG3Z
         jiDIowwJ9hc6RmkZs1yBD2sG20/PDYh+neulvxUQjPag43VPh7GInh17QFnRVvEOv/LX
         plruxPZGRREeUg8BpKBgf1/YYc+SFuCwovRhx/lk0/+ahLe3EmCYT4vmjXA3Vo+LHuJj
         YF2LV+CsZY+05lH2wRn7SWe6nhncBJCQ24y4XV723tf78M0k9ZV/fy56Y5ndFvkvSV26
         1yRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=5u5xjVsojzjDjNvTTKdIN/l6yQTCxwsIKHIwij7TPYo=;
        b=spSY5Va94FOf3Qvor80DNz4cMoxMyv2tzr3oxkr8qVk4X4NFvKM3FXtHTASvXa627p
         PRSIbwAp3sP1aHSxfKFL25egKRxig7blPAIhH8zsBHs+jb7S7gvMy8ZfEsrylTgrROtR
         ksaQk5waxEwxImkVFgbwRuFA1sUoDh+MjlJdtJYbUQqxfbm58QupOYEmLLqM/oRNzWiJ
         SeR7fi3VMEGTS/P+FO727EnlOuE+ayCDS+1+WrlkHnPUf3UStVZ/4ZaDzzsXszpC2QBw
         TOXBAaP+vhFghblGMl3jMpUGSJ+/MBM/EmBcbW4ajL6PnxW0CthWuZ6STGUNhy9qGnWf
         fvpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id a20-20020a056602209400b00688ede7086dsi204858ioa.3.2022.09.22.05.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Sep 2022 05:41:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500022.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4MYFDg0TGfzWgy7;
	Thu, 22 Sep 2022 20:37:55 +0800 (CST)
Received: from dggpemm500013.china.huawei.com (7.185.36.172) by
 dggpemm500022.china.huawei.com (7.185.36.162) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 22 Sep 2022 20:41:52 +0800
Received: from ubuntu1804.huawei.com (10.67.175.36) by
 dggpemm500013.china.huawei.com (7.185.36.172) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 22 Sep 2022 20:41:52 +0800
From: "'Chen Zhongjin' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: <dvyukov@google.com>, <andreyknvl@gmail.com>, <akpm@linux-foundation.org>,
	<elver@google.com>, <bigeasy@linutronix.de>, <nogikh@google.com>,
	<liu3101@purdue.edu>, <chenzhongjin@huawei.com>
Subject: [PATCH -next v2] kcov: Switch to use list_for_each_entry() helper
Date: Thu, 22 Sep 2022 20:38:10 +0800
Message-ID: <20220922123810.227015-1-chenzhongjin@huawei.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.175.36]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500013.china.huawei.com (7.185.36.172)
X-CFilter-Loop: Reflected
X-Original-Sender: chenzhongjin@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Chen Zhongjin <chenzhongjin@huawei.com>
Reply-To: Chen Zhongjin <chenzhongjin@huawei.com>
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

Use list_for_each_entry() helper instead of list_for_each() and
list_entry() to simplify code a bit.

Signed-off-by: Chen Zhongjin <chenzhongjin@huawei.com>
---
v1 -> v2:
- Forgot to change pos as area, fix it.
---
 kernel/kcov.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index e19c84b02452..6c94913dc3a6 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -133,10 +133,8 @@ static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle)
 static struct kcov_remote_area *kcov_remote_area_get(unsigned int size)
 {
 	struct kcov_remote_area *area;
-	struct list_head *pos;
 
-	list_for_each(pos, &kcov_remote_areas) {
-		area = list_entry(pos, struct kcov_remote_area, list);
+	list_for_each_entry(area, &kcov_remote_areas, list) {
 		if (area->size == size) {
 			list_del(&area->list);
 			return area;
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220922123810.227015-1-chenzhongjin%40huawei.com.
