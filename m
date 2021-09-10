Return-Path: <kasan-dev+bncBC5JXFXXVEGRBSOI5KEQMGQEIFFKE4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AE644060B5
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:19 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id t28-20020a63461c000000b00252078b83e4sf100663pga.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233097; cv=pass;
        d=google.com; s=arc-20160816;
        b=G4n5EAgJRLc8ZnxfVuGygC/JTZ4R+iL5l6s7GOuDtnAiboC5LPpONkWFmolw2UnfCr
         Fir6GK69dpHDwfPnxjwOz+uht3PiySH5wGs+W5p4jpI3hYM4UxbN1HtVxfygUsRl4jHz
         o64+8UCxEP0lEHgaEx3ci7MePBRU8S3tauLfOAuzICGXg1gRHdb0ZYF5+5xbNHFq+xTI
         xt7IQPZ9ndTnrn7J1/VOrtAtPtbs+RTc1Li6zpiMWrosfLG+H1kurziuQwkQt0XXeBNh
         fAjBIGouKitugNK2VyK7dZw6/kWzEVGzUN52Xy/sKzi8df365zgmHx+xgBhSTISmtD90
         qU4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ECO3JjThbLqjiFOaRbNgwWcrNpVCP/tnyB47Ie9Lp0c=;
        b=EbKkQDfKwZcNr9JTI4+XDjA6d+VtscWL2shixZfaS0bD0AsfQwCjmoomP0lsqeZYTT
         XhpD8JRCgQScp3qfGLl72d7nHDWEJtyZFqhSihMiWrWrN10sTxQE9yxr4xrwRrW/eCyH
         lLcEuOiCM5Zu05OnShpN7q1EVuRhI7zIeNLHkdoxyPQ5CQm5LgeAANEvg2cXk/hwNVkq
         2ANG7ty7PxfWDU/cme4Uc7ECRTopqmu1OwCXQvhB7CIfQCRAKRjgwYN3SdAH/gV0O4dC
         LzlOu4xIchg5rbkvr2xDorliTYpZ/WYIlHwuE2n9Zfrr+LRiWLwzvCTMhMLNtluw2cjp
         8+zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rSG/0NYO";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ECO3JjThbLqjiFOaRbNgwWcrNpVCP/tnyB47Ie9Lp0c=;
        b=iFyIniQtr82L1qnKIHOihA9gygou2yqA4Urm/34AHYDzX6LgNS5wgOgtnHnuYhR1ik
         /dir6Zo7WXxR0Ciau/xmFsJbVOZ6wSf1rPRsUhxjtTbrWDIhYIONwXI5DZvEyOXeGDFp
         oWr3WysTTiO5lPz9w7EoRSDY94F2z6Mci4Mm2Nv9eP6+I6T8vGmJcU7KdUsAmnoxl8Ca
         WTOPkLNyzETS+FPpO/3uRSoDTFI0OrS7GZyizJcyncOwU7jeVTxooZtwVN2op9oklwpd
         Lxgvu2GT+Pg8k/NCd3VuZxmNyfopYpjoh/iDL25ubLJRn2jUo270Lq6y44tGVk2xq8Ng
         5DuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ECO3JjThbLqjiFOaRbNgwWcrNpVCP/tnyB47Ie9Lp0c=;
        b=3kUGG2xQy+zlGOAIRExkHVXsUy4AMm7+1xMfssQuG7qnQ6awrbKMl2POuWc7ZzR8Ov
         As7CmxFVbTP7iybxfxgsrTG0/oJFwNFSSmQuQTEm/337okEIK6xrEGSZu31FitUVXl9h
         cMKEXXIdSPZn0/ViSMFrsYOyy5Pfxg/no+ahng8by2sEHpBbgbPmQ7ygnBD+hil/AJoT
         l0C9gHexsisipY2wvmnzQCsDpTuiftQklw11z6dvnywG4boa0mhHBlI+MoYXObrqt0ra
         tCzfrFqGTRp9qX3u/goOtO30REGip1x8Lc4ACSeocdp3TR7CHippWh2zqoPRxeTRKHkj
         Ar3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DMU2Xau6nCw5mylh5gpL3c7XMH2r9I7zZKY2miknmiTwhyqPd
	8GZDicutNFlYOckGi5Z2jX8=
X-Google-Smtp-Source: ABdhPJzbOLUw2phmggC9XrI0l2OqtW1sDbOFbsVjAh8WeVzWrLtudCxCIgR0UxYNsheLYiCdyKWmBQ==
X-Received: by 2002:a17:90a:312:: with SMTP id 18mr6449411pje.178.1631233097707;
        Thu, 09 Sep 2021 17:18:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f82:: with SMTP id a124ls668838pfd.2.gmail; Thu, 09 Sep
 2021 17:18:17 -0700 (PDT)
X-Received: by 2002:a63:f154:: with SMTP id o20mr4947174pgk.298.1631233097122;
        Thu, 09 Sep 2021 17:18:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233097; cv=none;
        d=google.com; s=arc-20160816;
        b=vekMB3j8gywZd6HxyfF5C1k092i84maPetzjYn9WCHk29vYKLz5hNixG2lWw6vhQ8y
         85b5RmXGUI1s/yZpFhnNZ7bxFrH4vOzSVSBwBU4xoWaaYzrAZ+ljYPR8Wukk3Rcg/Ocx
         KrRXBVR8CloRP2lqFlDbR0iSf/9RZ2d1UHCrzSuv6SheNXdfuY85C7fNS5zeMXcab3lS
         GEtgHhpy69vM5JVsJuT3hUayCY1/VJKKKq2bcWKpcrLqx3OeHT/nWO2vy5vq1Wtx77a6
         7t79itGk7tYyrMAenn0+U5vcvqgTEq6O/yGEOwBpboi0JGK1+goxMPSUdv/nAzBnGA4w
         KXIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q+RweFKyKp8qtsTxLGSHLb0pdUmr0gK0TikvDyUcYVU=;
        b=M5LsRW73e7IVEc4QyjW9DhzkbVF/gzzQPEHDjX6JalEq6AWZ9oznBirfSGX3t/pbOz
         nImj4NaOHxS89bPPvyxRSM1X2SYrNMwD4h8bceKN4TBA48yEifpd1vloOe2aw+jqR5LE
         TMz5pedpgvEkA1CRt+KJ4bCbhC5UaHqoX8f6kO3CkUOlXfnGvVFMabMis2xVUaa+xGDS
         tfcAO7nBQW1ymXo/QuvEFehap8R3ef1t/PypXHybMeOIAJplrwUC+0fEZLPfdpo7Eese
         XcCDwQEoB2/dcNw7qQCkqaMCnG4k5njys1N5FCP6K6heVqbMT4c/H44wD6Kbi2ngwYeK
         EsMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rSG/0NYO";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c6si331284pjs.3.2021.09.09.17.18.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B9A54610E9;
	Fri, 10 Sep 2021 00:18:15 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.14 98/99] kasan: test: avoid corrupting memory in copy_user_test
Date: Thu,  9 Sep 2021 20:15:57 -0400
Message-Id: <20210910001558.173296-98-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="rSG/0NYO";       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

[ Upstream commit 756e5a47a5ddf0caa3708f922385a92af9d330b5 ]

copy_user_test() does writes past the allocated object.  As the result, it
corrupts kernel memory, which might lead to crashes with the HW_TAGS mode,
as it neither uses quarantine nor redzones.

(Technically, this test can't yet be enabled with the HW_TAGS mode, but
this will be implemented in the future.)

Adjust the test to only write memory within the aligned kmalloc object.

Link: https://lkml.kernel.org/r/19bf3a5112ee65b7db88dc731643b657b816c5e8.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan_module.c | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index f1017f345d6c..fa73b9df0be4 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -15,13 +15,11 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
-
 static noinline void __init copy_user_test(void)
 {
 	char *kmem;
 	char __user *usermem;
-	size_t size = 10;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 	int __maybe_unused unused;
 
 	kmem = kmalloc(size, GFP_KERNEL);
@@ -38,25 +36,25 @@ static noinline void __init copy_user_test(void)
 	}
 
 	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = copy_from_user(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = copy_to_user(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_from_user(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_to_user(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = strncpy_from_user(kmem, usermem, size + 1);
 
 	vm_munmap((unsigned long)usermem, PAGE_SIZE);
 	kfree(kmem);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-98-sashal%40kernel.org.
