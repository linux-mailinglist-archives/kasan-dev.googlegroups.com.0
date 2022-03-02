Return-Path: <kasan-dev+bncBAABBY5272IAMGQEG4MENTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E02834CAA7D
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:37:55 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id f14-20020adfc98e000000b001e8593b40b0sf827558wrh.14
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:37:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239075; cv=pass;
        d=google.com; s=arc-20160816;
        b=bI6viFmBKUEQx1/N/KAXjGM6V3+9A2zBhrIgOIV7KFwp5fXcvuhxJiesddSspA+aLI
         m4HQ0Nl1Jc8THh3M2JrInYiysTGROYKuH0SttE/EB/aQ5juZ1kgKqCrHuoFwZkXiP5uF
         FcKyAe2/JOppMkH755vYgzySuPwi1HcrOXeN6ze4JOZrLxCAfws+gL1WHkMZ69I3vbcg
         gTEzL4in+RasZGfQJyhUKc5pgt1Zy1/HBRnTSN9v34bE5qMbTKzgA2pWwUWbFKpmdbZv
         86ko1vOoAY9KBEKJ6erbLb3vwDZQG8dfoLP1MDd4i1nMd3PxoFn27xaGOCyuYEh0IYvs
         QQVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WiJaBM0jfqGlltNDfqdCCAeDnwRSPEH9YWMouDWsAxc=;
        b=TJsYwASR4Re4iomQbv4Ux/XheWKPlpF61IZCApfjNgr0Sruf79yrlPwkyYW4Vi9CLN
         MiC5wcTJZKbnw4EMHAtxli4OMj9okTSmYrkQ1J7YmnW5WI8yKJ7TaCNAR8GAPSOGhATa
         IRlzIZSsxweCMZNKXS8m73ZGcvCEnNJNXui65YDZITDWN7A3iatEFNJZNSppLfJ02N1L
         Rl5JIRLK/W139TXLxpyzRG8UzO7rDX4p8reFVXtWuS5U9dM4ep6tqOEVIvFzUjjjQbmH
         +nnLb7x59EU7tH8JJjXwdxcb2jKqSs/ZcwzJczHXu3tHI9zcHLG4Fr31DQ/ErbWIC5AH
         VwgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HVbToheI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WiJaBM0jfqGlltNDfqdCCAeDnwRSPEH9YWMouDWsAxc=;
        b=KfCp6SiubyxnaN6EGXm0ztZowHnjwWJjmBY73P4om4WVcKHthBHeNN9vsUOu7Kg6nf
         dexsLBbDGzSqFfbNjNYlMY/uzsWeZLRZtjAvJk74ULUQ8X30ySq04dCUhL1R6Ml1Q647
         kr0oRlFYsGntnc0bcoyvjiRxYV/1MZ/XmQzAJtGoOL7BRW7fa0mlDrxIM6h3DdYWB5K9
         Kk9Fhybq+UmVF6ueVP/kv3V8sNYPwQeGPNe66g99uq+Ee1RxjWUz2oIyb39MzaQPmeRP
         6ipwKq602YYXde5sYovJAbunw+J4tEBQcXFQP/MuoJrKDIW+7bODoTQgFshexP+Cu/wD
         wBuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WiJaBM0jfqGlltNDfqdCCAeDnwRSPEH9YWMouDWsAxc=;
        b=JMTq9/sq75seLfEYXLb0B0Lx+t8DZHqp0A+6WGEHud46vmaHYZE7U/NpUvExwWSwM2
         CBu97cYj7KtzBCcKtPs88c27/D6mnCV3fFgx6jHH5nTNvNOYYA6IUAKlMs8N8fIJNnJC
         cHvWnY5b7nVBWWftpZByYLk9XzZ47ZsAKHkZrop024uDMLzSMBrC+2w2bRlfh2aYS7C+
         X3dX2shz75zy1Vz5RbG+iUUy7J6sV2Pg8ljSaeLd7FB0RKjWP6mYiGn39ZD1BxWQiK1D
         4Foo+0MozdPGEiqnBdjg3rJLJIwrIWyRIvZDQ7F0KfO3gQDbf3BZ+iK0i/32Dt92Lsmg
         uSJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xzOG1Utjlnc5KrqS+/xfuisZiZGDLIq7ztjnfBBG109zJHpuG
	m5KEOUiFUmkLLVsFygCu8SM=
X-Google-Smtp-Source: ABdhPJwCSahw69K0iOTrW3Bbz3XowAA5kXOMoITPGYLE/0si1UwRxVkDkp/ObsufSTpX7Cses7Y6LQ==
X-Received: by 2002:a05:600c:3b87:b0:381:428c:24c1 with SMTP id n7-20020a05600c3b8700b00381428c24c1mr505294wms.1.1646239075505;
        Wed, 02 Mar 2022 08:37:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35d1:b0:37c:dec7:dbc0 with SMTP id
 r17-20020a05600c35d100b0037cdec7dbc0ls2987548wmq.3.gmail; Wed, 02 Mar 2022
 08:37:54 -0800 (PST)
X-Received: by 2002:a05:600c:3ac7:b0:381:32ff:9e90 with SMTP id d7-20020a05600c3ac700b0038132ff9e90mr528904wms.2.1646239074918;
        Wed, 02 Mar 2022 08:37:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239074; cv=none;
        d=google.com; s=arc-20160816;
        b=fzFYubUZoLRZJf1QUrlh80JN1Hq0McbheUFSw4WWi0QEgkDElkSluZMXOiALV3jCE6
         KXd6JYJNFUUF39r0JUeiw5hS/bjGySulzCz5zeHjJVwtIY/eFVIBEcI3k2C8RiA7HoEo
         gK+r5dY8A6S6CNC3OJ41pzNj77IvMebm8m7UV8Gtm7u8arSgu3IN/4Jfgft1PBEGQi5b
         rnVJix+xhkAyWn3vGWv83bcGtuTEOehL3OnMlw9BCTDPUMZvb3MyxlwizxgS4YJg9M9h
         hruFbnbAVUCVxRqdXiEBxVX6KZaOnQKhyReJTb7/apCsVoV0mQJ9BoEIERx0lTXI9zxC
         u+CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4cKKYZ6rFTNdllIAOfnpLukoRzeAYo94WNiwHmUVtvE=;
        b=H7v1ZCm8QcOY9Whga+BrV8W/6DvprFEkk4PE6aIrrSwGCaWX9CycSL2BzWiE1Pkh1g
         1u0zRgsVhEsXznHTEY8CuLFIVm0duuNxWmThaWKMmmOrDydfMN5BDvU3DyDiXe6RnAf0
         LoGK8lO/cAZm3WbKUb09QaWuRAA+HTJ5cRABYh1p8jhsU8FInsCE7JCntj1t/cGbFcxE
         RoA23lgqh1+TwwL2KPjxzF6jphBr2dcmDnG7x7mLuGa4l84moj5t/E9nd6fnAOR9JsZb
         S8Expo5oYleF+49RCxhviEmsiBY2S+ZjOjrjsB6G1O+Lsl7B8XJ9V2r7H7v6yM9uFz14
         oBoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HVbToheI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id v193-20020a1cacca000000b003816971af44si428722wme.1.2022.03.02.08.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:37:54 -0800 (PST)
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
Subject: [PATCH mm 10/22] kasan: move disable_trace_on_warning to start_report
Date: Wed,  2 Mar 2022 17:36:30 +0100
Message-Id: <7c066c5de26234ad2cebdd931adfe437f8a95d58.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HVbToheI;       spf=pass
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

Move the disable_trace_on_warning() call, which enables the
/proc/sys/kernel/traceoff_on_warning interface for KASAN bugs,
to start_report(), so that it functions for all types of KASAN reports.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0b6c8a14f0ea..9286ff6ae1a7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -129,6 +129,8 @@ static DEFINE_SPINLOCK(report_lock);
 
 static void start_report(unsigned long *flags, bool sync)
 {
+	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
+	disable_trace_on_warning();
 	/* Update status of the currently running KASAN test. */
 	update_kunit_status(sync);
 	/* Make sure we don't end up in loop. */
@@ -421,7 +423,6 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	void *untagged_addr;
 	unsigned long flags;
 
-	disable_trace_on_warning();
 	start_report(&flags, true);
 
 	tagged_addr = (void *)addr;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c066c5de26234ad2cebdd931adfe437f8a95d58.1646237226.git.andreyknvl%40google.com.
