Return-Path: <kasan-dev+bncBAABBCW4Q6UAMGQEJOPZSBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D0D4179F002
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:14:51 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-401d62c2de7sf43575e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:14:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625291; cv=pass;
        d=google.com; s=arc-20160816;
        b=gVspkcp3j1atprW6EZV59/nh8b+dB0lXY2KHtRYtmLHORN5rr00aRGJAwsRYAHNWYx
         xyzZmrS9fegC+274wPNgacjp5obuKIaDjZzgK/qldcVLe08+cT/MFCQfpoovdexToDUh
         YoD9/JKZXvr1bCeClzT76Vxm9FZkTetN3vxgO9N9vLT5PoRZA36J/3e2voHQu1nUn7Vo
         NTzDsuhNJ7fnEWrwiDdroLFRvFqGgcJJL33RxHkq9gMJFOhZrNwcAiZka+RzUkuNejP1
         KcxZeXlInp9B/1/9hgEwEOBgmHwmTgNPMXY42yO5v+vv1zT9Ikz5xwiSgxB/SdpnEvO2
         msWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=a34iS2kFEQG0Brdwh5ZLP2LP8PFtBU3jjSI92ZjUVT4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=EUTJeAxTbNibPnzpns6sAnwjdDOoBG8ggaJt7O0ZytUbLATxodpX25/XBEYDCbAJTg
         SWQj7BuNdMt3jiPdYlyuxh1wvq2Zkq08aZFBL/CICtmxK6VppmNisJbcdIHGPKAj1LDB
         XntOshy9jIBeiZl6EVmxJdADsw1zVN+BpYqNZs+4Ps9UBm0GwoMwNk5qpzXfH3bfCTvo
         qemk+ZuNA9vzDnoMetvCyegcS/HSdL5Ik5j9THg2+8Qm/CkVqtugh2uHIkzgXuQVJoQY
         w0qD3e2IVBfmlc4wpZQNSlwdnelk7SMs+HyDqUJrTFgcMtnJs+P+QIBdLLAPghoB2IOd
         Km8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NRb1zL10;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625291; x=1695230091; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a34iS2kFEQG0Brdwh5ZLP2LP8PFtBU3jjSI92ZjUVT4=;
        b=Bcthl4N9gdu3ndemLzncm5rkWYzUR4OZV1fgwNJnj38O1BYnPryfUXOcv6vyJR+uNQ
         9GQ9Pxg2m9AfL+pTPkSICm3edTfr2V8Ue4odJztLnJDzLneyCgtnWwtU3CLhu8K3f6c0
         3OpiFSVDOgb1lDJUYrZPd27sqoY1CVSolAFfUPalFSwkSmXV0ZG1/7Z9lnjPQob3OdIk
         orEbLaz1/VfR2490lL4ZrkpMiSt1Pi9YBT9MbVW9Gtv0WxmtkD14+1uEI5XbJYEOOuND
         STrwuUUqvPpsBg/TWhz8yyhrnOnx4vRaSfqgb8b7qISx7x046fA0/1zOsBRLZv9Ir7ud
         7WpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625291; x=1695230091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a34iS2kFEQG0Brdwh5ZLP2LP8PFtBU3jjSI92ZjUVT4=;
        b=FXYaJD2kdH04B2bgsgGgG+gsjgjZ5nihwH+tArXsA2SpjfodQwblrp/JbYZkq8c3wt
         fFnrUIaiaPY9jJL99ZdYrvd1OZJNwSqNrJdb9kQWHdyruDiDU/P/2Dw92O9t3WNFr+XJ
         iU9yneB80EhMCsHxLX6K256VahAZIPpSip/0NkKo9iW19e7ayfO7L331Z2MTKSbXmfoD
         g1bbmWVkylfh1j7x6iRFRnLw8PFvjT6wv8TB3IU3HBSY3GN9/K0A+VEAJBS92wgw4OP9
         AQCjUZrtAVAvvjrGPfSaqyJMx/9B3UAzeFhMFMTF7Eu5dT9BarLxhWYRZWGXLVEjSNdt
         4eyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxv+vJ3LSCl6yofs5Jhm+NdvPO9iCWsHgYOxC22/4Su+ut4NHpk
	WnsqkyY9wl2kZZPJad8Obio=
X-Google-Smtp-Source: AGHT+IHq6yk94eBCMH04zetbrT5nCYW1r5BjJUxYSZ8XDQWyZt7iSJinAIzyNm6E7UiJiecW5AGNeA==
X-Received: by 2002:a05:600c:5404:b0:401:b9fb:5acd with SMTP id he4-20020a05600c540400b00401b9fb5acdmr2653163wmb.3.1694625290496;
        Wed, 13 Sep 2023 10:14:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c0e:b0:3fc:1365:b56d with SMTP id
 j14-20020a05600c1c0e00b003fc1365b56dls1860083wms.2.-pod-prod-09-eu; Wed, 13
 Sep 2023 10:14:49 -0700 (PDT)
X-Received: by 2002:a05:6000:1010:b0:31f:accf:bf0f with SMTP id a16-20020a056000101000b0031faccfbf0fmr2653438wrx.32.1694625289137;
        Wed, 13 Sep 2023 10:14:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625289; cv=none;
        d=google.com; s=arc-20160816;
        b=FSgY5Qly2zYSWJKgt1zkUuDNg2LokNYn7D63TVrNPl+LlJT5f6N65q0uMPiUzQz+LY
         rFDld8A9+FlcMS/k5Vdi0UfoHMJORs+yjYsgj1STnHCuBuDPeIkASn8mxH2QDRpoU8vk
         wsd336S9sKxToLR6D+hYA3+lfOU4sfwTFOTyxMn9882hmPjVusy2FalpZQmpGxRwlssk
         QUyp8Eh10PDvh4Mj/e+gDV5eD6oFJ/KeDAOb/k/CSqL63h7+WDGydyzWpiCRey3Y0+xm
         ig8Uv5jB8hash4IqTqkM/xnmdHyXRR0LOHPRIfb8qfYU2Elyjs3nlT2grvFUzwSfnott
         zyeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dA6zDrMISQ9ixV+61d0CbJSFq6N+6qPUyMdB5Zjx2Sw=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=eic3r+pBnLJ//BB8eAzkeT7a6Um3Eagf/M8wIph5N/O06TH22Q/SSet5kXq0NSD3zS
         o19G1lZfDBtMk1q0pwANsNDM2etWYkaHFmMdY5a46rYO4slM82zUPTIzNJNu/Qnfn7pp
         dHg9JQctkIQpzF4N0dWVZ7b6rznZSPS7Ufw+xfRYGqOQq146+g/CI5rB04V/WaJTGew8
         M/mEm8EMp9NHcJIdDRYoTGz+v+k0mvqVi+33wgvmTVbDMIEr7J+HQarymnTI/bqlQCkY
         oWckhpsPJsLtA1vfOxrfkOTJNbKdBmKeMiyaJ0nZ2x3NaK6ZlYSvx6mxLSu5UzlzGYVm
         oKKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NRb1zL10;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-230.mta0.migadu.com (out-230.mta0.migadu.com. [91.218.175.230])
        by gmr-mx.google.com with ESMTPS id cp43-20020a056000402b00b00317e1e2b28asi914452wrb.4.2023.09.13.10.14.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:14:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230 as permitted sender) client-ip=91.218.175.230;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 01/19] lib/stackdepot: check disabled flag when fetching
Date: Wed, 13 Sep 2023 19:14:26 +0200
Message-Id: <66bf1f0ad22d2c49ef500893340c71355b71d092.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NRb1zL10;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Do not try fetching a stack trace from the stack depot if the
stack_depot_disabled flag is enabled.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..3a945c7206f3 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -477,7 +477,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	 */
 	kmsan_unpoison_memory(entries, sizeof(*entries));
 
-	if (!handle)
+	if (!handle || stack_depot_disabled)
 		return 0;
 
 	if (parts.pool_index > pool_index_cached) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66bf1f0ad22d2c49ef500893340c71355b71d092.1694625260.git.andreyknvl%40google.com.
