Return-Path: <kasan-dev+bncBAABBK6M2CEAMGQE53AX4BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 340BF3E98D2
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:34:04 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y22-20020a0564023596b02903bd9452ad5csf1654691edc.20
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:34:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628710444; cv=pass;
        d=google.com; s=arc-20160816;
        b=M7INmIYpEJiyhdHpo5YBFLPSCUPEfyJZo/O3hyvfnTdOGmxN7+dTBSr/hPu9anuugi
         yNZY0mVB6UImF4095PRA5uOD7tKojGqDGjJ2wCMzZP5nXuZMzSDmXM6zNpTS3jM/GTCf
         UfN7FmqpchvBHkYNDXIJEocImN+0XOGLAz0XSnEhpyUP0+Rf800HaDgHpMKtrSe/rZxE
         6Per4WxOELIudJJnJTl5i2gUo3GeyMZN8i764gKFhpjybDnS4B7ND0lDJ8+ZYs1vXrCP
         KiIytbjw6GNf/5b/JFjzKpbHrLIWWZ9ycdsmgiBR347/LCoowsj0KuU3nwbwBc/nAecu
         WR1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JNPISvglEQty4eOUYDGHpK9Z+67yrj+HwWnkleIGxy4=;
        b=tLI92eb1/KZbF/9uxTg2Ca7w5Ekdn8DgXSKGsF1KbXn0AGW2tVa36Dv3jViTMWtQS2
         JDhIkIfJ1+c6pHRSZopfEBRphi3VSB+8ppHjv9xGbBmpoqfJp8eFw43gjYBzSFPBl/ML
         Lv1AnVtNoaZtcksB1SJ6ndPpUoycxtXkoPxF0sTCwGY23Hpg2kSL8mymZCwrgHCldBaK
         TES2lohJCppbz4wy7HsWHZQTYRFzPddZcDDsBZpIbey7PmznGE0ZtZxzYckM4teq388y
         piC8LR/XevmQA5A99/p349AOh7KiH62OIBxHF6hc0r4qZ9pyu6NdBtionZNMroBXRID8
         Qurw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gLxXIwem;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNPISvglEQty4eOUYDGHpK9Z+67yrj+HwWnkleIGxy4=;
        b=Xtijnulq1/JS9UrA6UQ9EADNdXQaGw22taCmrZkQFlj5169DDpqU0vu0sQYTEHyXWD
         PPikAABzB4lSTytKzCr9pu6cPH25eAFqleeM8qE3irgEV/mIjHuEJQnNkMHJY9x+LXYa
         GzrPXFilvwyWdi9P4oxX0pCoxZcrSngOHurSR4fmGfX9XufBMB0B31nplQhAAvNngsjE
         dgMlXafuXMmbf1wZ2X+B18iMgsfHOMtzAwVP65dOSzKU2j9pTBJZvuTAd4K5C11+Msp0
         XA4BIN1XjsAmSbd7STOmfivsOAjDYdEKr3YU7qxBDXimqExHv3Tf7QOwgzvUlMjGn4/3
         hlTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNPISvglEQty4eOUYDGHpK9Z+67yrj+HwWnkleIGxy4=;
        b=KTIQQ6It1jc3bXx6+tsOPzts4vQ1GAh35prfRKWooXOSR4TZZSJCpR4NytGgTXE/HP
         0OQzz0mVVumZez1qsF4wpKVJifv1WSeHa5jDF+3b/tNMsKrrpnYho13xX9DVr0NA9iUY
         oN6sr9MKARTbNa/Z0QFFA0zo8IM3tlE8L97tOudxyBrdSc15lhzpcDf/9prHOrE8BDEV
         RCQ+umy9rZakk0vrkr3VsPPlbOp+t4ls/5PDW0eRvnqURJAYneSUTI0xKkL/4bQhFWLL
         mrvHbQc4MaHxQnNF/DgHuPEj7oElk1skH1kDWQzsYkR7reJBmsLrIfj1LByEf6FG9D/g
         cZLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JzRQXXLxlExm/Z/88hIBgGaMrThxki/CdKfegFwUZxKSG8PK1
	MNqhme4phVRZnZUc7xrVznE=
X-Google-Smtp-Source: ABdhPJzA5VA7a8rpTa34f8yAwHLdtBD8iZm5i3vGCFWuiGh0Mh7DEh/WlRJtu7FUiNOesQJtSiMxAw==
X-Received: by 2002:a17:906:c795:: with SMTP id cw21mr89076ejb.357.1628710443976;
        Wed, 11 Aug 2021 12:34:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1644:: with SMTP id n4ls1521229ejd.7.gmail; Wed, 11
 Aug 2021 12:34:03 -0700 (PDT)
X-Received: by 2002:a17:906:9c84:: with SMTP id fj4mr135878ejc.274.1628710443145;
        Wed, 11 Aug 2021 12:34:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628710443; cv=none;
        d=google.com; s=arc-20160816;
        b=tvZQ8OwxV2EBPlewyl+YVlTXyK/d8cZ5HNUYezT9PKdhnKWLj3OB9Aq7QWGjntarLq
         nUgdp5C+6FquI12nOEm3N1sHWes6n1fsxS29XpsCqnk/k2/0Ngdi5aTJ5YzIuNGgquZd
         +PdOoCB00BHn1m1t4++ptXbC89L2cS+zPGhWBW4fRaikdLKeSwCqhTIuJjXrLmZa7Dpx
         SYTBeth/jt8f4YdxQBiRPmTMpCI75aYiTR+7zouGzubvB7uh8o8MM7c8Rk9SQFrjILih
         LAJ5VyvfVkXUuJ2TrnZ0VruNklf8Y+bcR2s5ueSK7XuTeLL8J45ooovWbaH3tm98AyRE
         YQuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ikZnRm2MVtJHm0Ia+fXtL9BHvKn2N23olNLH7huqioo=;
        b=zPCMnDDXpvj26bpblSF9Nk9/fQ6iGKrQ6DcYRPJla6RXDk1qEhd5XsN4/70nPePCgY
         ECNgM6Sw2oBlzqIgGbFJdvUFMwFGKDTRGwsxxJYplhDSvPPnKIqWZnqboNW1mxP/dKnd
         9cpHTCNSsacQZUh10bcSkzaQHCTbflW9bketYXnGZVlcbd4arhzpYYvs4ZVwJygHIsnT
         mPHupjLn+w9I1SWvFplWSat1xjDziUHFCZLtU08khAs7MZ82ahKWz1bOYaHpCNyLl5Mr
         d/RqVX0T0fM+NyApSlMUnc9Oa5siEaYAeqVlxLUwb9VUvVxzaqPLK8Q6HGfYjbepBgr8
         p03A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gLxXIwem;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id w12si16546edj.5.2021.08.11.12.34.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:34:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 8/8] kasan: test: avoid corrupting memory in kasan_rcu_uaf
Date: Wed, 11 Aug 2021 21:34:00 +0200
Message-Id: <da8d30df9206b54be2768b27bb026ec06e4da7a4.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gLxXIwem;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@gmail.com>

kasan_rcu_uaf() writes to freed memory via kasan_rcu_reclaim(), which is
only safe with the GENERIC mode (as it uses quarantine). For other modes,
this test corrupts kernel memory, which might result in a crash.

Turn the write into a read.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan_module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index fa73b9df0be4..7ebf433edef3 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -71,7 +71,7 @@ static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
 						struct kasan_rcu_info, rcu);
 
 	kfree(fp);
-	fp->i = 1;
+	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
 static noinline void __init kasan_rcu_uaf(void)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da8d30df9206b54be2768b27bb026ec06e4da7a4.1628709663.git.andreyknvl%40gmail.com.
