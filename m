Return-Path: <kasan-dev+bncBAABBHGGUGIQMGQEZY2EKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1685B4D2A79
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 09:19:42 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id r63-20020a4a3742000000b00320d9025595sf1338296oor.5
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 00:19:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646813980; cv=pass;
        d=google.com; s=arc-20160816;
        b=S0mOA/tdcM+Z7Tc/jB5vxb7ovBPcNeq63/BfhdTHr0ZwKkPmTaW++YhR82PCd1o1S7
         HBs8LTEw2KwtDdtS2aVnRZZPg5rI/Tucyhhj5txbeT7scY5BFC63ji3um26xCTag+u4H
         s4CjSsF4EQkn1k2vupTxpwqjQxl39JQRSM7YYmFet23duYTWTJ2ioX1LdpZhOW1Mn9KQ
         saPumauCWqbiQT8POeNR9hlI8YK/VwxoMMQSsCujWGqaI8Q/1uzRNyKqndxOhP4arjH3
         7WspGhHcYXXsGW0MI+fHcN2aSB9lJOb7NO500m9Dtp1KNHzMywm0mRgBTa+4AIyN+XX0
         EE3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vOlKGaiuwXYixAuvZVWBfLfJETq1q3rIn3Orh0dnYMA=;
        b=eVLI8LMGzt3AO82dwvgBwyYY+3fEbiKIoHQMegHrzUlO9mGWtED78opS3Ouf/EC/MU
         g/oOJxeFZE4o3DTpQnucoQuOLBn3d8sbGqx5oq/LiTQXckXeHznOMtxHbM92LBPNYqkL
         Ff0fyA0K6J7eWDyCTaN2FqrKJs0mbO5n+zepCZkNVuvl0zbaE6R/1j/67d7T98/6a7+b
         Nl+qNRB7JzhXjqgljCouhozx+dA+IxyQ3yrIk2Y+VWj6dKtiN6ZUtQWg//NuwLPP/pBf
         +nCHziTBHmKS8dH9cAL/uJ/zIRGOrhouLW2NN/7tFXNc5FL5noD4PbfW4cjp4l6H1NNq
         IEww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vOlKGaiuwXYixAuvZVWBfLfJETq1q3rIn3Orh0dnYMA=;
        b=SUtzEHQyiY5scLvIWvPKsW8Ms2eajMw1mme3Ubr9As/udZnVM0Mba/m0btB+9r/W5a
         JYJAAtx7vF51VBw4UtynjQsrJ6GTI50jKkSKedGmvbcoCtZ+uWGGsMC0yhTfaZdlwSrI
         0Z13Kkg+D93pRmjCXBQQKq8h03WyPhci0Ga+zjRkgyPzHaT7knqSkN4ecfFkH+XOhmIL
         8IvhV9/vMu+ZI/u7m0Oghe96mCnvrT/qEBm6iHTQqIqDxENGuYjCDon8tJTUrHSwGXk5
         4gS9WPZ/llLI/eM1juWrHubYFAeORsd1+124+B/YKEVwijV85ljpVqNkGCD14becoP0y
         5h/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vOlKGaiuwXYixAuvZVWBfLfJETq1q3rIn3Orh0dnYMA=;
        b=bBJcZyXYMO6faMi194WOAF0uCWulPps1gGu8MX1vN0DEl15ajLju7AUUxMaM1z47Vd
         fYX6oxem48Sn7Ka0hCJmwVrFn9N7HdZREUtAAoqz/kzaH4qTLThzoxIzenR4nzsgarXS
         DC1ErJXkAVlqOmn9XXM0zXM+pv8A5gaT/dXVn5w99hZ/JB81Z/jP8yPgcL6M+5tPNZhj
         MimvJKTIHeOaRueQb80FgIYWhgI2ZFniUlEWm0n7wKX2PsDAvv7DceSI6N6UirDghXHd
         SbGNnyQclG8W81yLS1hwOAM5D4aZtr49wWmSA+voIohJbHpfHLNxMgjqWUIfcH1/1GG0
         s8Sw==
X-Gm-Message-State: AOAM530U61voc0ZvT1U0fjEsb0wlYU9ep9kYZV0wDe6fWWg2xxDp+vcF
	5WiQNeGrCaAXTrFbXvFFPrI=
X-Google-Smtp-Source: ABdhPJy3BTaLPG1xDkagKZltIvCwMNwZ/VwuUakJtQtBFrlaatPrhVf+we4YsLk9dhfoqNZlruzbnQ==
X-Received: by 2002:a05:6870:e890:b0:da:52ca:41c1 with SMTP id q16-20020a056870e89000b000da52ca41c1mr4713479oan.50.1646813980772;
        Wed, 09 Mar 2022 00:19:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2390:b0:2d4:a1bd:6b2e with SMTP id
 bp16-20020a056808239000b002d4a1bd6b2els589120oib.10.gmail; Wed, 09 Mar 2022
 00:19:40 -0800 (PST)
X-Received: by 2002:a05:6808:124f:b0:2cd:199d:ee01 with SMTP id o15-20020a056808124f00b002cd199dee01mr5224379oiv.101.1646813980435;
        Wed, 09 Mar 2022 00:19:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646813980; cv=none;
        d=google.com; s=arc-20160816;
        b=gYNL1eZFIlShgXVGcMDp8qqtT55ldUjwfPS0gRQww+GpbUx/3yRUtoDeQO6n2ks9mm
         ECxVf1e0yjzRd8Sv+hoTSbp0Jh4qPc6aaIfQqubbx8R4pNypD1ElzLnD9p2asNXtTth3
         uWIrrjkcgOMe9xN6g+qAElW6rdnwhN6OO/paHDDccX+FnlB8/SzcnhVkIy2nBhOhS1iO
         vAhEPtkXtZn+xCYTFWCGGilDWBYL7RDPp7lU8QnHScJqfCHebBJINVWg43b7efxZe+Ox
         8Lvzu6D4/tJuDFN54SE6/wGkNqXw7ueyF1JzjN7R8XAzIo30sc7Yia77anm3jfXByDbC
         o6EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=kNM5CllBw9Dvj99TyGTh14SCoyhs3D6zKX3tEVSkE+M=;
        b=xP33wOB4hfZLzjf6ZQ2mb8Q1BbXFplECkHL9BWSD0cEk6nlCH7LyWwKTh80EfQ4zKb
         IDuSyt9yQxq5uosAWGzjY/FEQkDif6WE75NzjqdwsEA8RtDAWY+kf4ermh4dMYPb8qT+
         gYxnVqFEUzfyyiz9fTBG9lBCfvsXUE8Xmy7J+nnontLvz3Tczs/EyGoHXwa1dJa1vQmP
         yuCxOg0DZpMgcH/Sv7TGOowhpMIG8uIXfOkUiz37SyxH3fKapp1P5h4Pm/pTiMgLtOua
         +1Q9MTXs5nsJaX/VbPCyscf7PnPCUdfW3rqnZnKNxBz4TzWKYNYv2AW3WDHLue99HSyk
         QhVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id s14-20020a0568302a8e00b005b220409750si67613otu.1.2022.03.09.00.19.40
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Mar 2022 00:19:40 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi500009.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KD4nL3RngzBrhW;
	Wed,  9 Mar 2022 16:17:42 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500009.china.huawei.com (7.221.188.199) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:37 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 16:19:36 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH v2 1/3] kunit: fix UAF when run kfence test case test_gfpzero
Date: Wed, 9 Mar 2022 08:37:51 +0000
Message-ID: <20220309083753.1561921-2-liupeng256@huawei.com>
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
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
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

Kunit will create a new thread to run an actual test case, and the
main process will wait for the completion of the actual test thread
until overtime. The variable "struct kunit test" has local property
in function kunit_try_catch_run, and will be used in the test case
thread. Task kunit_try_catch_run will free "struct kunit test" when
kunit runs overtime, but the actual test case is still run and an
UAF bug will be triggered.

The above problem has been both observed in a physical machine and
qemu platform when running kfence kunit tests. The problem can be
triggered when setting CONFIG_KFENCE_NUM_OBJECTS = 65535. Under
this setting, the test case test_gfpzero will cost hours and kunit
will run to overtime. The follows show the panic log.

  BUG: unable to handle page fault for address: ffffffff82d882e9

  Call Trace:
   kunit_log_append+0x58/0xd0
   ...
   test_alloc.constprop.0.cold+0x6b/0x8a [kfence_test]
   test_gfpzero.cold+0x61/0x8ab [kfence_test]
   kunit_try_run_case+0x4c/0x70
   kunit_generic_run_threadfn_adapter+0x11/0x20
   kthread+0x166/0x190
   ret_from_fork+0x22/0x30
  Kernel panic - not syncing: Fatal exception
  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
  Ubuntu-1.8.2-1ubuntu1 04/01/2014

To solve this problem, the test case thread should be stopped when
the kunit frame runs overtime. The stop signal will send in function
kunit_try_catch_run, and test_gfpzero will handle it.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 lib/kunit/try-catch.c   | 1 +
 mm/kfence/kfence_test.c | 2 +-
 2 files changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
index be38a2c5ecc2..6b3d4db94077 100644
--- a/lib/kunit/try-catch.c
+++ b/lib/kunit/try-catch.c
@@ -78,6 +78,7 @@ void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
 	if (time_remaining == 0) {
 		kunit_err(test, "try timed out\n");
 		try_catch->try_result = -ETIMEDOUT;
+		kthread_stop(task_struct);
 	}
 
 	exit_code = try_catch->try_result;
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 50dbb815a2a8..caed6b4eba94 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -623,7 +623,7 @@ static void test_gfpzero(struct kunit *test)
 			break;
 		test_free(buf2);
 
-		if (i == CONFIG_KFENCE_NUM_OBJECTS) {
+		if (kthread_should_stop() || (i == CONFIG_KFENCE_NUM_OBJECTS)) {
 			kunit_warn(test, "giving up ... cannot get same object back\n");
 			return;
 		}
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-2-liupeng256%40huawei.com.
