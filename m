Return-Path: <kasan-dev+bncBAABBDUGUCIQMGQE5NYXKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B1764D260D
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 02:29:51 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id r7-20020a05622a034700b002e06ebbc866sf638406qtw.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 17:29:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646789390; cv=pass;
        d=google.com; s=arc-20160816;
        b=f8tXq8Y8hGdOyTQHJ78UmROUZSeko2J6/jeCe5UVbLAPzMZ/tvWBzZ7ZH75LZWzZxt
         8Eh5go9X/w3MEXhiNAsRa62PPYHGtB3iEjDxPu4W9gTO/wOdldpwkDi4QAsmIW7SR8eA
         /J+DfLRZ2eR5lifHleymP8nfkwpL2vo8gxZILgH97fI4CcCKxTg02b5KDd4YVstKi0FS
         O19+bWT3TcIsVaPKQowHT34eUBI5AEo1KkCt0CVErFaREJKCbjUTfBmnssQJgc1ojYX5
         O6w7hPwz/Wv0sUa2ED++d937GpsXPzwYiU8uaY3tf9pBp54Dqa/T8hblYf9wQsXsPWfV
         Tgjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BvDresYL0Hoxzt7hFb31+afVaoz5hANI2+UyO8SSwSw=;
        b=Ci4f2XdeRt37O/7rXyrjszN4bywPelOcHJ2FOPn/FNAKxDtbc4nDmX1VGMUAztBDv3
         1+aP/QT1KxjKhCFeCZ435CWhC34zckzeIbGry/GG2Vv56/AIXEayoXT3bRZqC/yU7TGi
         xd9qxws1JmvAQcQziJm74I5k/d+GuBL+6HLIgHFnCZK1zfAOktro+cZuqD+LeOFqs2EK
         zpBSK7AkpiklbH/tJdzKKchjlLz6VxMKavGPWUcmRP+GLxLpl2y3f8nPbbNMXbJj+mot
         yWGOiFNo6Z09Q3ziHDYkn/gvtIcEPCS2Ka5cl3YxisA2oJ2lgWMzV3kslfsjug6c2yxR
         Ff9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BvDresYL0Hoxzt7hFb31+afVaoz5hANI2+UyO8SSwSw=;
        b=YYFZs3nKSXadawsQFF+NpRDp0bbYP3ipv7bbrCZngd34ebWjgg9xJ0pPipL4uTAN5H
         MTcENS+atmcB1JfV1SeZqAJwrIf7+JgelwW6kWOrxlG+Kd2TlR7++tOYBvLp0Xfjpyoq
         wIPTb0d+ciB8oH1lvP2+gTnaSo/RnG4FojjBxt9FnJwh2mJAXhAK5vjg++vi6X3JmW4b
         KSX5Y4S1NLthh3I8hzBaJDteUTbn5JtRiR7PFlnI0gttWeegXSAyLizlCrsHtbonl37U
         EuKBdeYp31ifTLPWUDo5jghU7DWdbS03xb+zeSQfMroyPKvKHA9XQYpU5KsEtHGQzYNE
         UwPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BvDresYL0Hoxzt7hFb31+afVaoz5hANI2+UyO8SSwSw=;
        b=w+IzqhrTRinG7aQAj9cGM44brKxNgJJsoPhQWxov6P8qhx8T0uGYsondou20jQNQu8
         sTgT725WBIjk7O47iBi6obByxmd8R6oHfY2jPLWtmb4hst+4jjsSXTyB7/o3hEp+H9Rr
         RlbuXT5hCPjsB9uQjHA35+SDlyzDaJ6Jdd2a/M+w5tdS7WlzoD8CRbyE5edVCGxj5wWf
         HXmQ0NdqaSx+9eY6MbfkY6F6AkNFbGMNNGXdjp+xyeuns6Go33hph5yHd0mm2jcQau/m
         50BFjKIGIw70ISQtSEqX4b6gb1cXij5e2FvBt+XoDx/M+Wh3iJVigde8oSBwyEHTXRMM
         X3XQ==
X-Gm-Message-State: AOAM533Vg23FxgPcfwVcyylmvQDaqExlbNWFnRcHgufilm9yq4H58Mt/
	U6vR5h8M/MjWy4Eaxqimm4k=
X-Google-Smtp-Source: ABdhPJxL06Ftue4Fq799kHToM4gh1ThVDGgMp/clFQzdP1IEmZRWcm8GQ/EM+bTtLBngIU5gIth71g==
X-Received: by 2002:a05:620a:d87:b0:67b:311c:ecbd with SMTP id q7-20020a05620a0d8700b0067b311cecbdmr8019037qkl.146.1646789390370;
        Tue, 08 Mar 2022 17:29:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6657:0:b0:67b:3f9:fea5 with SMTP id a84-20020a376657000000b0067b03f9fea5ls365030qkc.5.gmail;
 Tue, 08 Mar 2022 17:29:50 -0800 (PST)
X-Received: by 2002:a05:620a:25ca:b0:67b:4f61:afa6 with SMTP id y10-20020a05620a25ca00b0067b4f61afa6mr6192500qko.64.1646789389979;
        Tue, 08 Mar 2022 17:29:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646789389; cv=none;
        d=google.com; s=arc-20160816;
        b=dVQVn8v7LM3g/3S9jNDBGebCP7bfR8bUlYGVugxctAUk3yvuew27uyMWLIsTxPvmaq
         qdxXG6LHi31J/35bK2GtX6S9VcEa2LmPEWahAZYU9zu4KzrlFCktGAmvbJghrCLALaFn
         cB22ZJjSguqvYxEEs2RoRSP0QnW7pBDRqPdK0LUECMKBI8b7rOrV/S+RGPYLnc/EGYU0
         +S+gLSpPKwpzRHlvBh66cyDfQS/C8M8D9Qqa8u1KzuQZ8LbfngDVl06+6CoNnxnyGVWy
         CjmZ0mmY8CzTT6ocka+CXhz86yQcQihJmMKcmg55dLMu1M9GqKp9fqefI3zbhKHITfg7
         Z4uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=9ABXrLgfDF9avVc3zQWM79qMnNV8DLj6BG/ohj0xGk8=;
        b=odPXVCPpnvK8bFu+C8mQoBRJ+EIDHQgegK7dqezNXQMNXYLsjPNPfdh+a2X04eMKsc
         sTlr6Xjrjy5CELLTwUunZ1SuYn87YLpfVzrlmNRy+YIKmOhRe1T01megrTJSHOBdT1cr
         LBMRN6W0JzpAV0P59jSvvr829fDgyhKM0gI5+b2U8EL/zYmqcOWnX5uuac34qTknp75i
         I5DIdbGTYrOnzYXfqWcZYxfywxer9bVnpMStOvLdc9VThpq+URkvSvlGwOQwg02bgSGF
         1DQ/kQ3wm8QRWCh6mxR9h1HxO9gmrDbtgGcIqzc8zXh54KH6EUUzgXf/0lYzeRhctDzT
         bEvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id p6-20020a05622a048600b002dcc2269cc0si14738qtx.1.2022.03.08.17.29.49
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 17:29:49 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi100012.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4KCvj52dqBzdZwl;
	Wed,  9 Mar 2022 09:28:25 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100012.china.huawei.com (7.221.188.202) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:47 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:46 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH 2/3] kunit: make kunit_test_timeout compatible with comment
Date: Wed, 9 Mar 2022 01:47:04 +0000
Message-ID: <20220309014705.1265861-3-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220309014705.1265861-1-liupeng256@huawei.com>
References: <20220309014705.1265861-1-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-3-liupeng256%40huawei.com.
