Return-Path: <kasan-dev+bncBCN7B3VUS4CRB6PO7L7QKGQEQD2ZQTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id D309F2F470A
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 10:03:54 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id r10sf762949oom.20
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 01:03:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610528634; cv=pass;
        d=google.com; s=arc-20160816;
        b=IEZQIrtrRGaNBd/EJLJbEqIpIlFIAVbGcPth8cDzLZDORQW02FBVMXSOak/59aV2D/
         QcRuq0UP9xfpgyQvW7dqISuqD9raP4uzoIZepmaHVd1GRCVUImBNmQ9E148wBcpILc95
         c8D/D2mAxTKDwxIUM173M3E5C7xwYI/0BflxJBCtnTEhimXSFFvCK1jh1Xl5nCmtQ0Q3
         vIoJFl2o8lB7pr/qKfipWMCIOksSv60766RQxDIX2WnhUsVj7fKjlRqFwBBHOCowG0AQ
         T+qJ4MK1zXAVDnGkiJIOGYyZ9gl27PWUtTfvmzn38IYP8znYpZ6yOQfVpfPxwybxmrcK
         8Wdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CemhUvQT3CZB0E2QRcxfMU2fCm/4T6QQyrSDiAF7q28=;
        b=hx7QxH4pZKSnJWOTpS8kHiD3c92J8gPZNmE1tjzvJcFx2IyoYwspPrXuC3JXO8hfWM
         vPLR+8FPe8RFATdmwjz8DoTKmPKF0GVcBUugZx0JHcbK3Ct1Mkc57jVtOVRIbeB7tMJ3
         GWdJiwcsNSyy4SJNmBU6Woq5vcGDJD5SHVX4fwCSGjZnN3Cpw+sZl1ouK+xO5hjzodgf
         koDXcCM4igCj92zl6VuNQALEvIUXUqiyQazuxdUXVqglV+QIXj3Kec3xvkyYF9gLhmU6
         d1KjPf5AV+Bm/s5wuD/IkNTwa7HSM/DM2uGcl7rIOug8ROs7U00QClcSUyj+UyHmZkc7
         q/yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CemhUvQT3CZB0E2QRcxfMU2fCm/4T6QQyrSDiAF7q28=;
        b=a5HnjPG4KLlKffg+9NGnrhAbRzntOIql0TPygFq6A4JqGcD0xy4co9kSPCrbR8CJDv
         S29k9XAXoFHWJQgoepUyx/s1vqR7aH8vHCU6HClQ4YldYdnx3g+8QpdcHFb0eEX87jAE
         E63kmYyRBPlU549rbpHSU1zjXmEVmXzugvFfEKLrOJGupRGT8thhSCHsKmXvzLcCU/s5
         JITJXxsE+Oe880FnEPmzkHsH8B1XKfn1XbY/lbH2oJ3YD7ALK6KYPCptY2noaBDxYBty
         UBHdtlR2UtTv6rdGScnbr+RpG2gcHf7vgDZ0k6RDk9J1LrsZ2WjhyihxhEsFSbBqtMNy
         JUeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CemhUvQT3CZB0E2QRcxfMU2fCm/4T6QQyrSDiAF7q28=;
        b=srrs1/1TNzquMQ58tbh/UdXPUWNehnBGnXuql7hA23s4EU6FuxHpVuwQJT5dTMqH6f
         pEesLe5KuGf9oNOp3tzvAKXgO3XZ/bSQoFHQ4844FaVr6edBS7wHiaI7mPB00yNeJlTk
         cAS/B1vqPi0lny31rf2cjBIlVW9OR4MKVJ7CgvRKv/f8gVDds7YMuI/IvKqLcOTKlUy5
         L/5er+t1lc8EHlRa+9Ba+QHC5RzfjOtCTxAzSxPJnj9+p5hLN7EFK519msXZ3nPtlbnc
         pQXGZFDHlHZRADNFdA2wNYId+RzLdJ3YyhP3ZPZr7mrZ6DPPHxNlBZF66150SjzFrwXZ
         NAZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331KnNWRDRfg1QIFCWAMoBeCe+PV3rAG2OFKN2tpgyt170PyGHB
	+t7cJJcn+HqWqCHabIcPrj8=
X-Google-Smtp-Source: ABdhPJxxQxyfAINqNJOq1sPNe2H2kcZKMHxEqVZdMt5HWeIV68nET8WaTXBO0eEic86LbclHeGt2tA==
X-Received: by 2002:a05:6808:3c9:: with SMTP id o9mr584213oie.103.1610528633873;
        Wed, 13 Jan 2021 01:03:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:a97:: with SMTP id q23ls374196oij.1.gmail; Wed, 13
 Jan 2021 01:03:53 -0800 (PST)
X-Received: by 2002:aca:538c:: with SMTP id h134mr647179oib.44.1610528633469;
        Wed, 13 Jan 2021 01:03:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610528633; cv=none;
        d=google.com; s=arc-20160816;
        b=tXd0q69JBL8ANBSdTqL0//Y8TrTUONc0yNi7S0eATIvvhdEE0WiyrieVW9zoMQTWUt
         TET5AgcD1yrMvqeBLw0qjZtLlWQ/TgVDhnHJ6bHVngO9OGuYwyURmxKFXzPunMKYrIqV
         lhkUNQ60ejipuTxjbkKfNGJTEO1F4FlayYGpQNskhWn6L4ZQwSRgOilx9MPKHT5EqePS
         G/nvUhSMH18OKj9SRr1A6sFjcaa8eNXCiQ9ndDlTpSL/KQ2ELPnaQB63JSv7ujBUM234
         TFvvsPoC0dV11c8+c0ffnsPi9m2SzA+eIgNkahL8+3YDa04TNLWbfx3JBNm6FSkmxF1F
         nsrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=qT68LYYy1b+sNR2bSnwQ4QkXCnQqLeW11tWLO/URM54=;
        b=BXsNT4iLe5W53xOt+2Iwfd4/HewaFCNy5CJsOriuSHqVmGn8gfaEKdAYXM8LGvHC7k
         EvDhGjOGnzumaE29Q8bEMUOHbAkDI7d5GmK2BSdelePVvpx7pXAexBHc1bzu3tlmsCFi
         05TI75gaI90yQaq91dBB/clNiYYFP0XwP+JQ1k1yD23Mz0/zecEyfkuCriGOGqh3dtNI
         A+MUYJBzp/ylXJJf+2UM9bhhhnroSTADTN1K285Mt/qHRvAcOgWflVMPhz5c40xiAuWh
         ozblS6zHQ3x1QyTVVuPTTb4mGm0ohHZz14nmHFVth8pcRAEkJZD/NEN8QZ2Pvo3ZRLAc
         KO8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id a33si92125ooj.2.2021.01.13.01.03.52
        for <kasan-dev@googlegroups.com>;
        Wed, 13 Jan 2021 01:03:53 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ab70a5be833e41edb6ddeadd820fe4b1-20210113
X-UUID: ab70a5be833e41edb6ddeadd820fe4b1-20210113
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 91106704; Wed, 13 Jan 2021 17:03:48 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs05n2.mediatek.inc (172.21.101.140) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 13 Jan 2021 17:03:47 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 13 Jan 2021 17:03:47 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>
CC: Lecopzer Chen <lecopzer.chen@mediatek.com>, <dan.j.williams@intel.com>,
	<aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <linux-mediatek@lists.infradead.org>,
	<yj.chiang@mediatek.com>, Lecopzer Chen <lecopzer@gmail.com>, Andrey
 Konovalov <andreyknvl@google.com>
Subject: [RESEND PATCH] kasan: fix incorrect arguments passing in kasan_add_zero_shadow
Date: Wed, 13 Jan 2021 17:03:40 +0800
Message-ID: <20210113090340.23129-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

kasan_remove_zero_shadow() shall use original virtual address, start
and size, instead of shadow address.

Fixes: 0207df4fa1a86 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dan Williams <dan.j.williams@intel.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/init.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index bc0ad208b3a7..67051cfae41c 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -481,7 +481,6 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
 	if (ret)
-		kasan_remove_zero_shadow(shadow_start,
-					size >> KASAN_SHADOW_SCALE_SHIFT);
+		kasan_remove_zero_shadow(start, size);
 	return ret;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113090340.23129-1-lecopzer.chen%40mediatek.com.
