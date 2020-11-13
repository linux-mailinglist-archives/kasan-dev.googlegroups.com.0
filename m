Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNELXT6QKGQETJMSR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 132E22B27F9
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:21 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id w17sf4629371wrp.11
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305780; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJnJFx9mY/rmROQRW4DOWcnEybpDEPl1vffuFqlemdPUkMB4IO6UTiTU9WpwdHtBDv
         ccb4JTUoOS3ARSIjnA6wcHzVmTUPwtOG14X7RKfBFCeqikesMJL6u6DI5NFITt0SKMOx
         4rByCP9okuui92o688GRwyKxBEqcbcGdFtNArN/oA4qKsSwt+nO4574Ln4o2VO7CM0/n
         YOzrtW2FbAkBxr6URPvd2eCb6k9lb3TytuakPwnzlq0cJMiLD/Ka0pG6BTtyuuGz48yb
         7f29oFz1u2RqqigIuwLxPzijJ++A0QhAKbPqGTN4NoY+sNyKHr/Dx/tdvIcCoZubqkYt
         2HPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+4VzfYhzQ3nqAva1+/vRm0tKWBTRsKi29XcOu3LShDU=;
        b=NvWvQXjpZrx+nrm235KIQX/kIctGNdPIy+TyCtshxPAmyovNeseRNmUBe0ttpIk6hF
         Sz415QyHI7cgQrfC5erd8bcN5l7eZ9aDDY7+jtfPvZWlDykvfY6lFvgZ9UpK/UHm2BC6
         J/9sVqIjwmfsQ3jXofeP+adsCz9RtbxCpAZPLxaq8dbkoFrmayxY7AemK2oFLhbcQhDK
         2jbD9uq+UZNuvNkTUr91ZtqeyXAMzAE+/IQ7AlAocjx7eY2DmacwXsvTy1jDv9P5C/6L
         1UEBpiCIM1YOS4NZWFvxk7JN8e08Ik4RcnS1vMaLlkgaNqNGDa44A7HzBQm3EFY5cdNX
         gWeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M3qWP0rH;
       spf=pass (google.com: domain of 3swwvxwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3swWvXwoKCX4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+4VzfYhzQ3nqAva1+/vRm0tKWBTRsKi29XcOu3LShDU=;
        b=fUkacqKB8IsKlkKWW7hIMzis/6mJFey8SUJtCHmb97ZOyYo9C34jmzx1/DzNJZmouI
         v2/LfHCWn2oe0/DI0melsjTRdD60WWe4itpv7yk8I2u/ar3+cL8tQecn712Y/VPYGqnx
         fHiCzyt7R+WS1rRREEbPJ8Boo7nzR40gSAUslgxkU1Vq4VQw4RNNx7RFHIIV8oEQS4Hi
         ODlUGbado22W9+uFvYvdT94u58z/PpFbCzvARcSeGXfEGT1fkWkwXALSE/3GRqFWyQ6t
         m1Blc4rG+JN75Ag77F/U2liqysYL3UO5KJEDhRkjIHYBhIB12TWzz4r89ekY5fTlO107
         /YXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+4VzfYhzQ3nqAva1+/vRm0tKWBTRsKi29XcOu3LShDU=;
        b=gXRsd7dD/mAIWCoAbHPEtAsBPX3JU80MMEpHg2aemrCzrRMgcFq2LJ8bu5NStVoZ7w
         inWdECaKnKX8DLtPRhgYb99hm5pMhjKeQM+50S7KgqlwhgNdWe3paoYmKU4A1lpoxoxf
         1QZkftIuJabNtPYromZ1CFdmppbLUmlskRjDo4mteTEG8oHjUgIbnjLr5/3Cu2kqnj/2
         oFt5BO1n/07d0fkPlvjwP4EFEMGUoK4DIt+F4MKf0NakAoVFM8Lp4/oL82u7VDZVIIym
         920xjTymVcEBjEUkEFKyUeEhYCzAS8og3uk7yIKeZ86O2SHQkOfJs/3fydix38+5+1G5
         LpwQ==
X-Gm-Message-State: AOAM532zRNQNzTcSRtndQjsA/GSmfd8Eww/0SJNf7u4ZDLzjqga216FK
	dVbr/Q79SXBJOQqtj7QSl7I=
X-Google-Smtp-Source: ABdhPJxZ82qrquz65ANkln7KZW04BpDiOHvrZn2F+fbiZ3iGMYEEJr61Vdgj6iExlSYgvOgUD41a2g==
X-Received: by 2002:a1c:20d0:: with SMTP id g199mr4840895wmg.68.1605305780868;
        Fri, 13 Nov 2020 14:16:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c689:: with SMTP id j9ls7246871wrg.0.gmail; Fri, 13 Nov
 2020 14:16:20 -0800 (PST)
X-Received: by 2002:a5d:4b8f:: with SMTP id b15mr6423553wrt.38.1605305779984;
        Fri, 13 Nov 2020 14:16:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305779; cv=none;
        d=google.com; s=arc-20160816;
        b=fe7l+ww6N1CMNhzl0TtxuGHMV0xHwzab8U/FpM1l8HgmtrLc9VARu3+SNqIP//qitY
         VJKRNFPFp2CJAFUbOdgvhdKIinF6a1Wb75NF4M01ltJGeVJexeUJaQdlwGIHiYXypVp1
         hO7ambMbQrLU/FrlOmv09ZcHgch7LSlz7x74mVTEKLcu3grxQbFlETDhSphpXWeTT9ul
         OBibXmv67N2ohuM4n7aFYshODaB4rloPOWWJWkAGTelsJUntH/CivjJ80yhn9VoQiwc3
         fiQvck179GDHpAm590+X5mH3Gn9z27/O0Hp7qhEvCVE9rZ+nM1l+HqzsjRpceuYpqDMJ
         z0XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0h4ZiQVa03qeRcJlTu8FgXI56j5Z1qnhf08CuZFwLPY=;
        b=z7niO09IuKyOXvqqeylnM7qva/7UHLSm4Oq6aVEApJNVSltkV6dlRNEH88VNchMYHt
         NiEDt5DKryg4kqDkbHO0OfYyP8ZdUEEPbwsckTl6icwSBkuhkAD17nsJUQDjAErpih0j
         7/YUU4TNiqElFO4xyAQ2Ovp0Xf8U8f9vstHqF50F6S9kTjkdFpZuOLB5YlDisChO3KzX
         J21WOYz5HYq0dZFOz0cnonnTcnBNvkd/QINCNmMXP/YXVtx1vZnyEH7ty7RIWES5PddO
         ROACgoMlhQ7BvWKZiFsNcZ5CtxdflApqfzlGFU/40M7H5V/4ggiglKGAbHK2JNJTKxZY
         1Qgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M3qWP0rH;
       spf=pass (google.com: domain of 3swwvxwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3swWvXwoKCX4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id v10si297772wrr.3.2020.11.13.14.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3swwvxwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id e18so4651856wrs.23
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:9e48:: with SMTP id
 v8mr6446890wre.55.1605305779525; Fri, 13 Nov 2020 14:16:19 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:30 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <23b7935ec33e425f66ab736f6cf2bf74af542ac0.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 02/42] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=M3qWP0rH;       spf=pass
 (google.com: domain of 3swwvxwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3swWvXwoKCX4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 8fb097057fec..58dd3b86ef84 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -146,7 +146,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23b7935ec33e425f66ab736f6cf2bf74af542ac0.1605305705.git.andreyknvl%40google.com.
