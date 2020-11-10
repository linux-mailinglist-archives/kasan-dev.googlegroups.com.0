Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF5AVT6QKGQEOXIIIDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id D82882AE2BA
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:36 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id a126sf156896ybb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046296; cv=pass;
        d=google.com; s=arc-20160816;
        b=tolLeaxB/Q5NjQSNd+6Kp9KqzFL/csWNL9sLT9xOPd6zAj9VeMISPom500OM1IQJd1
         tXo+LP3LI3+5BXHvkmV8/rrtUQEReUT7UTWCMPOGLqBZno4z2SAfwEBB4xC4XaRLidlL
         NrDq9GudN/JDJDolOwoLImU2AIuSVNf9wIKjPeIL2odugJsjkmPxcc7othhHPqVBtVg7
         itOkp2ZVaRoq+K7KFDMl4wRP1ZOEZhtPW6cAcMmeCcPxkyfUxqAIqKhKNiAebOqSQrV9
         +QZ+aG7vM+SgjY5qNw1OtsOgAXbnokzwbdjh9UTG67VFfQD5m3/RSgRgKqmTXH8yMSIo
         hNbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=a2qk8R6tO4a/kIm/gQ4Ig7zosMBkMisUSSXa6yZzOQ0=;
        b=h+wZAostv/KWWdVxvtAZsh91acom+egPRPcZg0CNzrd5osFeDMVNeYDKsq88APEJpk
         LAgREecIDhULzIzjc9S7tjLtPvZB/1zQpM9l7qrIj5/xhU7YzMyb2Xnj1lKFbRY2wYrU
         gv+ohJhial8q1DGzls98jdfV5cgfdpWdhfmMwsA/mw5G/JZgvnfJggpvzidNcfWHTLoy
         ox52H1082KlbYm17qRB+dy13mM1l1O2d0Zo1PhhihxVb5cQ8GdViV7mekZSQGkz8ddli
         cACxiUvk+UHpq/ehD62dZOWp41XZuNq142dJQcwWNYFKV8gpdtQF8ZOSoP0wAHB83bdR
         OZ7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QydEmdA1;
       spf=pass (google.com: domain of 3fhcrxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3FhCrXwoKCeUHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=a2qk8R6tO4a/kIm/gQ4Ig7zosMBkMisUSSXa6yZzOQ0=;
        b=Ikhe5EQfRsvJ/C7HDw2xtOjAP4hORrRu7TcdFGLeeWDKDCOJu6zMzWVao+5cffMCnG
         Lg55DoTqgajB762TUh1IpOuCp0ZmBZmaUMHCE+LnMg+GGjhHPVY367cUhLAiY03IRHXK
         ZKmXA8Yh0zj/6f6YQqSbi5M1q4cbfhFy/QUZHdBykB3JMjm+Xi92ptuD/Y4fNZIBJBRa
         bcuq9LlCT7ccsvKWAKG2EWSUava47ooa/JCVhSpgv9Igx7NDjalwA+WYY7eRknYqjCrK
         Jrp20h5FWQdxYEN3vr2H8wc1qaz5sUpfFx8lxIw2t0iCL+RPFfrDb2vS9WQyN6Q4R07g
         +s4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a2qk8R6tO4a/kIm/gQ4Ig7zosMBkMisUSSXa6yZzOQ0=;
        b=py71/66bO7P1rYe40/WsWa7RK+HZ6VhSj9ApH0n9WooOvMMyzt2h4IfUSjs90Js6C7
         2qiIvlMueocIgF4Gda8wTf4kP9AEA3oV1LB9cEgaSeFfDDZbOj8D8f8O79QunxGtO+t8
         oLLRtJyfZd6IhzqUdtSRRR43CylyGCzXct3EXNBpYXr8fBnGgyWyqVEpG/ctJAozUxK8
         NKbpQqb/pSoXClBwk2q9fcXd3W1zYhQaHDMRNeptltqvvncBPhn9BSji3kZt5lU+dB3v
         KT8gFpBIWpOhd/BuWJY5bWcVLJZ1fazOoqvGqki+NUdOnhiXK3N5g9EYB71zlUd+Lmr9
         JIJw==
X-Gm-Message-State: AOAM533R4Dg3wDtlEP4XqI3uh3jw4NFIlp4ttbe+5+CVgMTqAyq0fDAw
	SdZqEwE49fzH2R/nTiuX1Co=
X-Google-Smtp-Source: ABdhPJzh0PmkDHgxWiusJMUBnDfZbBQbVeGyGv9dAcBs+oM3tS0c1qxqiYjBtiRtay7ecHNl3j06Qg==
X-Received: by 2002:a25:760c:: with SMTP id r12mr32844519ybc.420.1605046295973;
        Tue, 10 Nov 2020 14:11:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:84c4:: with SMTP id x4ls2113075ybm.6.gmail; Tue, 10 Nov
 2020 14:11:35 -0800 (PST)
X-Received: by 2002:a25:80cd:: with SMTP id c13mr33144296ybm.371.1605046295470;
        Tue, 10 Nov 2020 14:11:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046295; cv=none;
        d=google.com; s=arc-20160816;
        b=OdpLDiB+UCE+3/k9hLtQ782b1SEIEXDlyy4hCi+iEG5GxmqyD7MSUdasthyXXyoGGf
         38ABnsdrEfX7b51zW1Zsan6E+h1Y4Uojh4brNZZW9Eri8HOq+4tL9xX4NrZXrSgjKS4p
         49EIIgKyJgRXyKNhmEQ63CyBgsXh11ToQPDrgR7acTlr/sC5AaGYr+OAt+wE1k5EYtPh
         kfKzMikDJvAmuuyaUp6i5n/q5QgUCk38Rw4mlC5xEd/pdXWicH+JtCVcBQ9pH5Dqu7uV
         lbl5OnT2CcTIfNJz9MnGd1uG9Q+DSJYgmTew2j3rI9PFIxArGPaZsPO2iPlsyHp7r0pN
         Rjhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=UUYs3/IPjbrn0Fy6AEi8q/1m6cYKglUE4ldVZ9aX59U=;
        b=sN7N7+PTONd3rnYmTdqpR5NOWESsXK96cGr5pyPpIqiWa9AxtTHkBj7pitYmtecYGC
         MjHy2bxvde5KEPi0Fkf93gSarpozvVdNz6p87De6m41COlAiHYXMQBVZC8bq+HZG7DrX
         3vU/01jgLVmfm+vha+9O4K8yXeiovAA4eAjt/IcWxM0JZtWz/+2ftu7K10tU1ymNXtg2
         CCCUO6RU0nLED139zciAhjtmawQFS5qmv2x3rf2BM1HlwvLmlr4FSJav1xXH9LClih3h
         dg2nF47o287/Dji7ikMw1k0VVW6ZMq95K71L/OC/W9JBiaXyz6flYhfYvSAf6YWesiWs
         G4Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QydEmdA1;
       spf=pass (google.com: domain of 3fhcrxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3FhCrXwoKCeUHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id y4si7995ybr.2.2020.11.10.14.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fhcrxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id b10so5141434qtb.16
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:524b:: with SMTP id
 s11mr16651952qvq.3.1605046294997; Tue, 10 Nov 2020 14:11:34 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:09 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <fc3f94183e4229363d0a891abc791af5b85d20f7.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 12/44] kasan: don't duplicate config dependencies
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QydEmdA1;       spf=pass
 (google.com: domain of 3fhcrxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3FhCrXwoKCeUHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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

Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
those to KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 8f0742a0f23e..ec59a0e26d09 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,8 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +48,7 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc3f94183e4229363d0a891abc791af5b85d20f7.1605046192.git.andreyknvl%40google.com.
