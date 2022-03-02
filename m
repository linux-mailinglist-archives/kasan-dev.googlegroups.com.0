Return-Path: <kasan-dev+bncBAABBIV372IAMGQES65WPKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id BDB274CAA8A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:38:59 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id e9-20020a05651c090900b0024630875e4esf663703ljq.18
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:38:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239139; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDvaLtWutL+bjBHwWFYA8cw2KSLB3q9B8CjCg4IUYqXJVCre7evnuifo0CKIQhDiWK
         UXL2QTmXG+/bsNGPemDCLU0UJvf2JYcEIkASCcKG1yxd6O+4MWvlbbS1y7HciZfbZ9l3
         KuQ8MNqZe+hyzCbAcGryhZxQBwWKJOznrszgqWpAR0RvM/4JOtW4k3UK3pZWX0iTa1B8
         uKsq97sFOQ6aYHN86MGncOdZ4vyGAlWulxjTC8f/PiHELIrsE0yRqaYkEYMEJkcJlkEU
         6eWSAfErflBmAOqutxGEcGO9GOcFSvkanNc/t8jheJiB68E7wmZXkeS3w7RFrCFMgPjR
         14YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6WbOuBbcsGDgzeO+hIlCfCysHOtY/dn3fcazSsHJlwg=;
        b=0kvXzmVwMz4cKHAhmIlmLwkY2QVh24LPA/JDHuqn9RH4VJ2TXdaU44U/nVfjlcVUJ9
         fyzHUQ7LFGVuB3387IBnpnYOmj98JWoGN/Lqr3iNKhhdP6TQdPGZTmNhJHPLgei2ip7F
         WqFWQ6oQY/73+I2meinh34tJ1SLxXY6LbXY744f6wyMS2LM+ktuVbCC0l8ki0tPXZRcc
         mV/CTkSUOYl1f7vs9l6QeCfyDkEcXMgDoKSOxRDUq0yByUmxqEHcwp4qreyrtLdGmlpQ
         I/Zsv25JGFUWtAb92No/kF6RXa8MD/dLuvlc/VXAgp7fUArhVhWl17zXHaRAZGvUYeSS
         fMKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aaBHXo5y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6WbOuBbcsGDgzeO+hIlCfCysHOtY/dn3fcazSsHJlwg=;
        b=a9rpw/ycHsMXIraHY7H4Q0ZuUDwdV2wifH1PDzD8+vZG+/LCOX5TwrOUdtY2Tbajrv
         J83DUlzCJT47PuE9NUSGUgC1A9xNdFVnT4mVZXk+nqABu5Hle334LAwe0JX36YHMf9O1
         qVgrVaUz6KHzZjyjRIza5du6THvLxZ5f+rJBfuIg+JzArsmMzsGHjNMt8jzkEhjoZqXg
         5D///lM3T3odJcq09IXH4TR3XOkyuAcCYRuDtiLxue4yIMPyg1pCY1isPfC14G6VB/oB
         5dCujcCNcPddJEniYBDUYEXr8n8IGKYMY//hRO1L+UO1Jndvn1eSYjH3vT4Po23apkl4
         EXiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6WbOuBbcsGDgzeO+hIlCfCysHOtY/dn3fcazSsHJlwg=;
        b=5NHtgCKgTF/4X3ACuxfXOL0kk2WYsYoktjbHR3PscIZU/v0nvM41sweYLJQbmjezup
         ot60Pr+rPDSBRz2tm5KaTh0fChgTqH99hZ1Gr3XECIXusFVzWejN4t9AYB4WEUknmwbD
         9m9AbshjR19gO7ZukvCUBg09Ot7ViysRF/f0JtMnu/YGuZ4K++O5GF0godXOb9VA2n10
         AyxUWFDnjUPBl0dn2QBP4ofbCQhAkKMYzKyAz1exO3hFdwxHQai9VIKHVt/nGuWCQAIA
         n1rNWyAyVYOUuvWe41aLGmLMbpKE73adqpyjWxnoS/tXTjC67nrLr+laaM+mQ6syhkEg
         D1hA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533q/YmWBJgfHPXprPVvCrevNw2ZU97F5yicnldwSXYieNdNA0bz
	u4ZYeTzkFPDteSwTeGKRxdk=
X-Google-Smtp-Source: ABdhPJyYRsLXjFUoBX0k1YA8pqi26s5KpJHg/FGM6LJsChjv7Eb2YG6TdY491wv7G79cz5AsmVY65g==
X-Received: by 2002:a2e:a78f:0:b0:246:8848:178 with SMTP id c15-20020a2ea78f000000b0024688480178mr11683524ljf.432.1646239139153;
        Wed, 02 Mar 2022 08:38:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2153:b0:443:9651:a9f4 with SMTP id
 s19-20020a056512215300b004439651a9f4ls487912lfr.3.gmail; Wed, 02 Mar 2022
 08:38:58 -0800 (PST)
X-Received: by 2002:a05:6512:3b20:b0:439:25ca:68d0 with SMTP id f32-20020a0565123b2000b0043925ca68d0mr18668903lfv.231.1646239138456;
        Wed, 02 Mar 2022 08:38:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239138; cv=none;
        d=google.com; s=arc-20160816;
        b=urBgGnnxyShYpuMA7VkS11/LEtfazbg1S+eWzeQlhHEtA4w8f7IxwGWhwsiXiOryau
         Fp5G1fnrwNsuL2RbNp1bZ5IhOYTgyurepqXFX+O0/pt6Vosl47iCdi9ShtmtEsxT+wET
         PJdxwL0lqfrPUMPD5F21450mmI6kDf0929C9Z3mVJ+FyBp5tIokQNLko5ANRiDW49q0x
         odyspA4lqyzBDc6PEWRUwJ7WfpP4k/Ys+miMGTmP0q8nh3C1M5Q8MAEJ2zOHf9qOJEM7
         Z1kATkftrQ8j/W9jF/6x0Ct4nOhZOaqXD++Qe9R/Uk6/v1N257qVB36t6KJ4sQV2S0pm
         GvFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GA4CzC5kQCyt9Q46WjPbGlANWaRE9EWTbe6SrvYEjAk=;
        b=gf46ZGhYfXeu3ojvAcENVr6DIgNmzX7LmygWp81Y2kK/K72MFurnyd18qfOqDIooVw
         1SY8nqs0sBEzIBYqKHECMhgNwrCWA9ns+dbAgVoDZi23ZaeTudFJKzVbwzFWik4IcyjZ
         oStOED8Za47+7QvDp4ySRR3DJ6sDeVuzJywaMQONfTjMYv94OGPBtCgZdQRSJeXMORgz
         LtjxZTd6Q6jiAzPJJXLZyjduhBKNqTjIuJp5fko1V1w3PCF8s8ro/3XXqLpiT0wNXIrW
         NaI5THhBRBxUZqPqdVFa7xrXYpx2pKymInTKz0sezi9VyoeY+d0kZYKd7UW2u/05Cazl
         jNJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aaBHXo5y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id w24-20020a2e9598000000b002463b72fb7esi1065765ljh.5.2022.03.02.08.38.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:38:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 13/22] kasan: restructure kasan_report
Date: Wed,  2 Mar 2022 17:36:33 +0100
Message-Id: <ca28042889858b8cc4724d3d4378387f90d7a59d.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aaBHXo5y;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Restructure kasan_report() to make reviewing the subsequent patches
easier.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 15 +++++++++------
 1 file changed, 9 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index a0d4a9d3f933..41c7966451e3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -457,15 +457,18 @@ static void __kasan_report(void *addr, size_t size, bool is_write,
 bool kasan_report(unsigned long addr, size_t size, bool is_write,
 			unsigned long ip)
 {
-	unsigned long flags = user_access_save();
-	bool ret = false;
+	unsigned long ua_flags = user_access_save();
+	bool ret = true;
 
-	if (likely(report_enabled())) {
-		__kasan_report((void *)addr, size, is_write, ip);
-		ret = true;
+	if (unlikely(!report_enabled())) {
+		ret = false;
+		goto out;
 	}
 
-	user_access_restore(flags);
+	__kasan_report((void *)addr, size, is_write, ip);
+
+out:
+	user_access_restore(ua_flags);
 
 	return ret;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ca28042889858b8cc4724d3d4378387f90d7a59d.1646237226.git.andreyknvl%40google.com.
