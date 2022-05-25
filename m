Return-Path: <kasan-dev+bncBCRKFI7J2AJRBEFUXCKAMGQEVQDPRZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (unknown [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6190D533C23
	for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 13:59:34 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id g38-20020a9d2da9000000b0060b0e876cafsf3214649otb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 04:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653479953; cv=pass;
        d=google.com; s=arc-20160816;
        b=xYbVWc2sJ5AISSeG5rola0/XzOYrEfUCvaaHm46ciBbFNzadq8NfOgAQdxPHbxX4l5
         T9ii5ikF1AwBCrYUjH+BPKQcRM70mjMu6MTw/PVaWe/67o6BfuYBrMQzcqBPFcoHcRZe
         x8Wuu88HpC292+pBbPh0VcEL9cKacWgo37WUFWxkKD0KiBGQdqDuJi51aAwMLW3rsOu6
         l6wfVKjAw7SBOS8zM4FLHafk8BcyyVbyBavOSA3X5q+m6tjthY0rSNghv+pLbnL78gxf
         BGmKQDc6MjTkcdNjTws4VJW3MGoM1MiSrwuNFzzQdlllFuPtVEt4XM41Yq7yDqnqAmZ1
         f3Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=pNnPVDYIzXANQQgRD3q2Aj9/SIOJAxKz8oXhhSlFxmc=;
        b=xU9LMuxdmA9zfcJOKRT8DmcMRUDX6V+rwdWIlRcVyRnhQoOcjO/FIT4gR4FhHDO7E2
         M1OZgCE8sT24qewFwyegw40K/MJ3ARLtj4/M9MC+1s2MfMUtGegH9XcRwXqws7bwhsGu
         54IfjjvXro9+iuwMQLC9w5vuum+YvxKS+kMpNQxL5j9UIjANmIb1fLnoMxMoPgvGP2k2
         HT6KOrHGM3QjoDk0tHKCcreTDgeE9kjUskv05XKFTCpPKrgx4H0zT+1JYmt5z/RMczV3
         JdmMMzRWLtN2SFc2X0Eku3mx6sK7+AmluuTiBBlMynTmT9TqO73wpE08TomGodsED4N9
         qzAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pNnPVDYIzXANQQgRD3q2Aj9/SIOJAxKz8oXhhSlFxmc=;
        b=oPARJ1AobPZ/eLihmm5NsdllgFZlVjn8meQr71DoTEsnWzto9zBZ7azd8f9iOAtK+L
         xw+RpmgwiyckCaOuhVQVNh2d4npJylc78h5vRRZ6bF0L7TS69P/gp8Ujl9gr/8og5pFf
         Kbbr4IC+Vm5A7djvs9LgcPeyBaU/CDeUCLHA1zDQgboy2TxL9wfK9eZxTHex1vPtooL6
         3ED4jq9reT8PyHS4z3+Bq7Ms5RSSOcGuQsOuSF9ezcL86MvysDvlhrxFgaoypVCPWMJF
         IE1PVVHlpmOmGvWd3KkGcHG3O2Zd2dfhlJsZTqCo+MBtFqFy+iUsARq1PICZt2I4odmS
         dSLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pNnPVDYIzXANQQgRD3q2Aj9/SIOJAxKz8oXhhSlFxmc=;
        b=egrUHyDJD/0rbDAHALsTWldyeMo1f8oPnkDXX0CV76jZcew7pb6SHbsSWFOGg7KvpA
         +J+Fv7mw4iHfTkooSgI60vL/ujFgPTNf5/BIIoulQznbk7RsPR04nHtgHu/5/75e5XQd
         qmVxWWjuEZdlc4mTOzzMdVLH0eMFoU9bJQg6cFS3WpsnGXsqTOEJeR9qQxETAWbvLDvo
         5HhMmKsFMt3ve6+9r7W0ZG0CG/gWCx3VDM0xFU3BokARWM7GqzKoGouh2HMG3s/ZBZJL
         at53CF8oVxTBTZzS3lZQd1Vr7NLOCpffaMswcGp04eQxlU46WjAYSuaJOLEGs3y0iv+Q
         stKg==
X-Gm-Message-State: AOAM5321iuRByaDpnnD+mToR/8L2Xss8I8jaKw6RQTA1OW3pMIFL9jVW
	QyW21YYyQBTA392KeSGe86Q=
X-Google-Smtp-Source: ABdhPJwdxrLYpuvjRB2qToRiWfLH/BCR2sIoNaYtzkhYYA3v+mAy5PtPgOq2wnJFUsCYmU1jvggeJQ==
X-Received: by 2002:a05:6808:1455:b0:32b:8c0a:6ada with SMTP id x21-20020a056808145500b0032b8c0a6adamr3215060oiv.71.1653479952850;
        Wed, 25 May 2022 04:59:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:79b:b0:f1:f328:8e8a with SMTP id
 o27-20020a056871079b00b000f1f3288e8als7522454oap.7.gmail; Wed, 25 May 2022
 04:59:12 -0700 (PDT)
X-Received: by 2002:a05:6870:a1a0:b0:d9:b198:4cfa with SMTP id a32-20020a056870a1a000b000d9b1984cfamr5280747oaf.159.1653479952402;
        Wed, 25 May 2022 04:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653479952; cv=none;
        d=google.com; s=arc-20160816;
        b=iLnrlCTIT/FsjZ6TmR4m1m0ZoB3AzxSQ6hQfE2g2QQv0w0FlcFz0DBTq1g2VW36LuV
         QMVPm2XyU1pH1Wvz4q26uTwVs8EpnccqiHhqWgd0xtqyaNiCQQMonqW8B+esEQQlOtNS
         SfwFJAQByXFWXNclVUa5OFiCaVRYBKJEQhkMom3M79hSqdEGlgC8osh050huEBVCuq/0
         6Yg00rh57NLa8UfGTYQUCUrPj7sajLEKmv3XtFU16hv12nzscmeD9Y1XDHM5x2QZZgL3
         gRYztBTToVRGcIHW7n8MjwpW3aVadechVDVfrPxWHxqn6FC6MS92EyqFoF4SkBJmKAM7
         3HRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=L1SS/YlatBuBMhb+obJ9YJsvOPyL/Ig1CJYKZnvK8MA=;
        b=fmbp1Z49UC/mPFLQtt4IrzLywdtNqEKcQLTWWrxo5OUHCaXAFLijEBrVsigBjZ4oy3
         VntssU6Wyh7aEbX5Qe3oaX2+PYFQMrP+sRJ4eBT2RiqVK6x8Mxojjk/3vMyHBeHt6wQW
         nATwzYlx6tAXdtj42jIR+c5sY2cbmV6kafCDeZcqV6hDIdftcb4/j0vcNB3fHR9qxIPl
         9dPGzJgUVC6Wgpy+dJ91ctURe8iO32nKjGw1R2JuhlUddL3fF08mzYGMWNbhpIUiySKC
         hFwHFgKAna8NmiWrf+ifF0UfgQw469H8ZXGndrtSCHkaLy2tBukzcjZ4Z04oi3HusjAI
         0veA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id fq38-20020a0568710b2600b000e217d47668si1808905oab.5.2022.05.25.04.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 May 2022 04:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm500024.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4L7V105rdZz1JCCt;
	Wed, 25 May 2022 19:57:08 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500024.china.huawei.com (7.185.36.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Wed, 25 May 2022 19:58:39 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Wed, 25 May 2022 19:58:38 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
CC: Andrew Morton <akpm@linux-foundation.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH] mm: kasan: Fix input of vmalloc_to_page()
Date: Wed, 25 May 2022 20:08:04 +0800
Message-ID: <20220525120804.38155-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.35.3
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
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

When print virtual mapping info for vmalloc address, it should pass
the addr not page, fix it.

Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 199d77cce21a..b341a191651d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -347,7 +347,7 @@ static void print_address_description(void *addr, u8 tag)
 			       va->addr, va->addr + va->size, va->caller);
 			pr_err("\n");
 
-			page = vmalloc_to_page(page);
+			page = vmalloc_to_page(addr);
 		}
 	}
 
-- 
2.35.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220525120804.38155-1-wangkefeng.wang%40huawei.com.
