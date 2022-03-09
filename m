Return-Path: <kasan-dev+bncBAABBG6GUGIQMGQEROQ27HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id CB3AD4D2A78
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 09:19:40 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id c12-20020a170902848c00b0015025f53e9csf794359plo.7
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 00:19:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646813979; cv=pass;
        d=google.com; s=arc-20160816;
        b=tKq6YqtRp0DD185D6y3pxmDVckgaNr1GhOfLRaxUmpjySy0hXhKZFu/atkuR1XCEom
         Z0jTiT2TUdDqCodOiPrXu3m4t/A5GmDgpCYRV568wR05DeXRfKwBNJCiHxFi8IgPj18y
         jwxTsqsqvwlePTLCg2sJPkUhqXJ7uXBGA1QOe3bxm39l19t4VXQDKwyQwNXJmnJGEsBI
         04XxrePxjsTdNy5RFv641GwvYLocSADQu7F3DkuSllqxgb3nI6ckodb+rVH3RPJyyFoy
         bqDoaYY6NYTrTqHgFNNwxbICyABrSvM1JM0jpLwZsDNuPgsKlrAe2NRkelOrsksk1Yd9
         5iwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=CwriIYazwoGg6gT+C5uukKEcJF/FIKXqvAwS8FYe5qY=;
        b=K9pI3DMYcwVt53l8cgtjjZsic4KQ/1+HHG0dTIjjnL+Rv96NrZaRtyVM/Kh3JAIePw
         HgmlcfrTdUqEyLJ7RsqJVTHb3SQxM/YQHm+E3S+Im+eWH0h0+qD0Ram9kBYu5Tvu1GFd
         HFrJhGeMAj5H8K3lii7L/zSboqQpP/OfIysnebu2YEs3YbsYslhGVnjVxXbBSTwNUsIU
         +3gND5xgLMKrymQkCGFoDC7ht928JqJF2N9P97bz2XRiZ8vrvxnZ55oC/ZP38M6L8lcg
         T2rVmdX0RKErQ9JKMHmd45ynxIQd5WCFWmoZx4PHzY1q3oIFlR3F/y5eowAdXwzWrdjS
         LYsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CwriIYazwoGg6gT+C5uukKEcJF/FIKXqvAwS8FYe5qY=;
        b=CE6nzGwkvlRbvezRo05ApvCayD/ngSK24HGM6iJHUQYz7ZV7nUjCqXnhmfdPxMiZHi
         KhUjZt7xsXsPujrrBxroh0k8MKLSZDzrgeRr3eOrxQ41pMrk2WIlkk2MEshcV5lUTYC1
         muKprpaqyH3Or2nJ1nlpMEbVyGAzGTVOgrD6ZrCIRDLgRuFjzOFMb+VsE7fAhAUbwAK1
         /3a4jYDO7T/vGkab9bpEC7pwvgvQHIfrIG2pt2IDDehmMrzKTU1HeITwclPxb0U3Q+T8
         ESZthY0S8MVHc7aCLH03Xo2WAOJPf8ebVADwWbkyNjU3nUdNY0K/Y3ScIWnbKWOm9TVL
         /ZYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CwriIYazwoGg6gT+C5uukKEcJF/FIKXqvAwS8FYe5qY=;
        b=PDxmWQrGarg0ckDgo4IIUNUaj8IuIpf+2jQ+co7ZDnbW6hqc7oQaO07mIWhBa3w2bI
         QNhdlSm+8yb313rMoocp2WkLwjaClyRGqym0Pck0oB+S+abw0dsEP/g8sI9+ecovJQu6
         dqszbmBXFbq/olspn6iF+/Ny7Et3S/EgVgW7QdNg4+f15iKYzqtdehpRCM30bq2pa590
         y9biV9Yo1t7IrWhfD3mfA46WMKS1XGRybHWO4vAvKpndrAVVyZKPIL2pvPW2XaTKdjhq
         pLHvMKHSe6h2UwFCOGZ4ZJ1MwLnsVuPlAD3MqwxyFccJlLuT+VzA4QmvejUPDVIgEawQ
         xX6w==
X-Gm-Message-State: AOAM5305vtzey1RrH6UX5fPzxr6Mj0ZDhU19O13B243oLZUJveY0Hsns
	KOcoxXdaGWiJat8k0vr0uBM=
X-Google-Smtp-Source: ABdhPJze0AbLPMDbFFAf/qKzhzEuZoa/BpFHeKTHcetWlhpepCnCIlN4Y/WygVaMnSFsMeBaAzWsHQ==
X-Received: by 2002:a65:6397:0:b0:375:7af2:9c87 with SMTP id h23-20020a656397000000b003757af29c87mr17679919pgv.498.1646813979381;
        Wed, 09 Mar 2022 00:19:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4f41:b0:1bc:ff52:38de with SMTP id
 pj1-20020a17090b4f4100b001bcff5238dels4154133pjb.1.canary-gmail; Wed, 09 Mar
 2022 00:19:39 -0800 (PST)
X-Received: by 2002:a17:903:32c3:b0:152:c1b:e840 with SMTP id i3-20020a17090332c300b001520c1be840mr5045690plr.40.1646813978896;
        Wed, 09 Mar 2022 00:19:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646813978; cv=none;
        d=google.com; s=arc-20160816;
        b=JYLqUrfdNyfeMa6i+iz2iEVEeoRbGmfwbn4C+jQOUXmEwr9Kjl90bCR2XHs4ipbSTg
         ZUU8kzcJX+90aCMry+owMrEDCsoht9XL2anOY0rFjipLgHbiN9oSLy7vX8Hnlj7KRH2G
         DACMzHxcFidjYoBAbdlWNB2eUfGzyARlRXsWWhIj8X+orB2W2Uwr2GRmf/aibppm6tDp
         H0qRPeGvVORvuUyiURXdN2vvitHQW6Cc33AZR76GJ7qCDiEqithHqoqsuvU4XT+5oj0n
         I8rL+6MYcWWI9F54FIF38MovCfpHOo/B1NupCkkF/I3odERzbxNS1yit7ns0X3UPa4AW
         X4jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=zA4VQeFqjVDUiVy08zViI5deMK4Qad8YMakM2E0oHnU=;
        b=ssDklVDAtwXV+QvlCfjk/tARXr1Lnz/x6hai4sDK5j5V9ool2VWFg9Rsm1x6cS5QYL
         iC1/Whk9sG0s3JFhlnHfihuOJEPvk3aB23oyQ2tYsLQcJDUKHkBLvGjsWuJRES8aT5yy
         D+LxD64/I6qyAUqIOUlY8UVIpwQ/BeaCxB4c7egQQtPgWz7avXxGVkfV1ZdZNSRXRo2s
         kicMIG9CTX0y28pfaivRaK13l82Jnh8azgfaZ7qLSXPgHzTdd1cl+EPqPP4p7KVVvLIi
         UeiPYf1aWu23Herv5mQm/CD2w6CeT84UrA9vcNunC0K72i9SYAwqXKjOxjNeTQEGolGi
         WCsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id hg2-20020a17090b300200b001bedb198e40si259181pjb.2.2022.03.09.00.19.38
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Mar 2022 00:19:38 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi500008.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4KD4k00LnFz1GCDF;
	Wed,  9 Mar 2022 16:14:48 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500008.china.huawei.com (7.221.188.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:36 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:35 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH v2 0/3] kunit: fix a UAF bug and do some optimization
Date: Wed, 9 Mar 2022 08:37:50 +0000
Message-ID: <20220309083753.1561921-1-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as
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

This series is to fix UAF when running kfence test case test_gfpzero,
which is time costly. This UAF bug can be easily triggered by setting
CONFIG_KFENCE_NUM_OBJECTS = 65535. Furthermore, some optimization for
kunit tests has been done.

v1->v2:
  Change log is updated.

Peng Liu (3):
  kunit: fix UAF when run kfence test case test_gfpzero
  kunit: make kunit_test_timeout compatible with comment
  kfence: test: try to avoid test_gfpzero trigger rcu_stall

 lib/kunit/try-catch.c   | 3 ++-
 mm/kfence/kfence_test.c | 3 ++-
 2 files changed, 4 insertions(+), 2 deletions(-)

-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-1-liupeng256%40huawei.com.
