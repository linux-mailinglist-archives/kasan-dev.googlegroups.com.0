Return-Path: <kasan-dev+bncBAABB2PQRWIQMGQEZWDOMIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C9754CE556
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Mar 2022 15:49:15 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 71-20020a9d034d000000b005af37922de5sf8292346otv.10
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Mar 2022 06:49:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646491754; cv=pass;
        d=google.com; s=arc-20160816;
        b=AkQV8Ogx7YnC61avvJHVZ96LSQc7OAUnqTSBsEft+i6IiMFykERQha2jcHeFOZJ1WO
         01iqA8Wmb1WzFRzjZ916+NLrLSf7ntF+ffYcpGHcHoMitG1YbzLA8hPZiTRH75Vo53OA
         DGwW/j8K3svxuJiygzoDzPMm5nuNs+/ERuXUIEob4YPf9fEiijb0tJK1JROmiapKEola
         UVOZQbrzpT/C0GBEUzYiAh6h87j1jaYWzAKVoUoXEWNCgTsrYSxlnTwZ2bNS8KNcbMqw
         eWs+SMwBm7aRZJ44xK/Mw+oWRf6Uk7awzt8fAi11g0/lPofIZwuKtZ0Zfjp6Z6/2S6S1
         WNjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T0sAQO+2k37hImZEFMV5sG+rb+UTVjaZz0oOLHjeuk4=;
        b=o2xvZ3liWif2JfGWI2xCExWIie9BN1aQtLSldGjocwwc7pYjISwK6+MAYzTtm1cxCW
         Ivm3j8KN+yeryuAY7kxWwIHKTMygNWa7k2SMoSrZpRP1orT8EECaN6naZmTKUsABYfCm
         2L7xK7Cp+tQFPz3Sa6bhdBKZVA4iLLaznSXzCbKEMsKhsYU3Hy7/bcd1v0hbanSKhuGS
         tIvxS339DLJdPzRNKaRlWH4Xu4z+G2jO8Y7uchzEvlqe76kZzfoIQ7dDnf8eIwE2P+/5
         k+ttxCji4Jpjtk/clcfujiy2jCyeIqJ7/bmbYl2hF927wQR3pUG8ejcvnRwTWb0ERy2K
         5uxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.56 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T0sAQO+2k37hImZEFMV5sG+rb+UTVjaZz0oOLHjeuk4=;
        b=dlUPBRT1v86tWk1DqNJ4GBN/Xyr+XikXssDZoFCAigYOsJL/sbldxc/0v7xk99M+wQ
         Mn06isDVgq0S8x3arIu6N7DiusB6dEju3HV7SkDtq5XeHNWvEks7UniRi5ZB/p47THJh
         bISPGZwJqjE7lXJqsnREz/ys4xYBuq6kAergfOVEbwQ4hxBVWzmcZjKISiEsPJQP+xwl
         9KE93t3H2RP2rW7zpjUoYBoyx/ES/8ATKEBpso/oA+dSU4engs7WeQR36YCiXmqX2jSj
         wOCnQJAV+mVMWLnIwYT4Dq67+ggZh8P2wPPLbOVoiLYk5cD54ZQFuQFK7V0G6Cyudoou
         fFdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T0sAQO+2k37hImZEFMV5sG+rb+UTVjaZz0oOLHjeuk4=;
        b=Sp4+YdmOFH81pxgcBsD4sZ6T6oosgAsWX4Jr9DFpvfJfDu/jtNtvFh6vkIeflzkgkk
         eiUXz2KfAzKTd6d3N0jIggW3bXEjxPCj6Ti01vVtopBJdXzhARCbOA4tEW8god0IhSr/
         lmGcmy7759X0+65oi+klMRgiWCeTCzqHbaKNhYEYpDfchu+/GR+Pg7wZhAyXWuYq3iy2
         jOeKVMO9E+LQrPnoIDM35MVRKLwNLvtzVgx1mmQ0q8jFV4T+cS07Lsvsd4LTVTwLOKts
         admXK49EUkYDFB+81RDGw0qPqikVTXgWQdPZvhrHVq8AWwrgEzyPH2SLSygKG8gK71PH
         YKCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HGEf1dvfJzNlToi4N6fABTbsCeHbM7nddjFDNk2Wgj7oXG34o
	hwDHAw7NovfusB0qICSoOHs=
X-Google-Smtp-Source: ABdhPJy9pA8Ie1+IRDoPQCvUP+Xz7FtiRRDgmkZKkagP5tXFknxMCOtvKF22SjuQyWe8asbQoAjv+Q==
X-Received: by 2002:a05:6808:488:b0:2d4:fb86:6fed with SMTP id z8-20020a056808048800b002d4fb866fedmr12894456oid.133.1646491753909;
        Sat, 05 Mar 2022 06:49:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:787:b0:d2:9f85:b3d5 with SMTP id
 o7-20020a056871078700b000d29f85b3d5ls2722040oap.11.gmail; Sat, 05 Mar 2022
 06:49:13 -0800 (PST)
X-Received: by 2002:a05:6870:e0c8:b0:d9:c109:3bdf with SMTP id a8-20020a056870e0c800b000d9c1093bdfmr1606591oab.148.1646491753608;
        Sat, 05 Mar 2022 06:49:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646491753; cv=none;
        d=google.com; s=arc-20160816;
        b=Mw+r/pihDfIxBikLXAmB65DmnYXwknV0LWY0mGjAbjW6h439x0EgH1wI808Mq/WwPW
         uxvOEZFJFJz9oJziBehrevjWJwCDaKqFnN28TVNa2IAqYqAlDf07eHBff7Nz6OAMK2sQ
         kr8L+2MoUxr0r43sK1YwDCfCGlt0y9pU9my8gU/c4WXmh6xsSWqYqImd3OixvS1Lg6O1
         drx1YtC2iP7FCUlmXZdgdMkCtl7/U/oHxQrxspz74Lecuzi6KzWSfKblgeI/I08+muVb
         JJmc7eOsySPu11X7f/a2Z+71BWUgJ70YnKx1+AUVJ1xoVzE+y1BpIA12/5+ijS6bLJFT
         ZFEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Ukwfw3PX35VdBiCAxfF3K/JBqZ+bYLclxdMNkAiO2VM=;
        b=HFrlshrmJcTzBbG02TNBaWpK3Bw1I1G25vD+GEpwtrZXPNLpF+KUQwWl3IvV1jsrTs
         d8W5QRdBYsYkPntcvXGS9YXDb5NqgIVXZBQuNTktZqkbkllomQYb7eJbSRAINr0ZR8SE
         FkwaZuySpEvNE1iyK9AnU7ilb2RfzKapuCZi6brzFA09K8VV7xpR8tbiNgpg+QTazaxZ
         Vrx+nlxplHolVOKm7ap4HNqtUIbwQABUQH9NUKH5JEPOy5oOFs3V+9seosqfNAkHAXPM
         gO+p4jbZfJI0j/89U7rP5dF84YgVwzBt9PPBphfKUiA8G8irxaXMvynjOEMahN06VEkh
         HgmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.56 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-56.freemail.mail.aliyun.com (out30-56.freemail.mail.aliyun.com. [115.124.30.56])
        by gmr-mx.google.com with ESMTPS id w26-20020a056830079a00b005ad081e3cbdsi1147678ots.4.2022.03.05.06.49.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Mar 2022 06:49:13 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.56 as permitted sender) client-ip=115.124.30.56;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R901e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04400;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6HF7it_1646491748;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6HF7it_1646491748)
          by smtp.aliyun-inc.com(127.0.0.1);
          Sat, 05 Mar 2022 22:49:08 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 1/2] kfence: Allow re-enabling KFENCE after system startup
Date: Sat,  5 Mar 2022 22:48:57 +0800
Message-Id: <20220305144858.17040-2-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
References: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.56 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

If once KFENCE is disabled by:
echo 0 > /sys/module/kfence/parameters/sample_interval
KFENCE could never be re-enabled until next rebooting.

Allow re-enabling it by writing a positive num to sample_interval.

Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
---
 mm/kfence/core.c | 21 ++++++++++++++++++---
 1 file changed, 18 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 13128fa13062..caa4e84c8b79 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -38,14 +38,17 @@
 #define KFENCE_WARN_ON(cond)                                                   \
 	({                                                                     \
 		const bool __cond = WARN_ON(cond);                             \
-		if (unlikely(__cond))                                          \
+		if (unlikely(__cond)) {                                        \
 			WRITE_ONCE(kfence_enabled, false);                     \
+			disabled_by_warn = true;                               \
+		}                                                              \
 		__cond;                                                        \
 	})
 
 /* === Data ================================================================= */
 
 static bool kfence_enabled __read_mostly;
+static bool disabled_by_warn __read_mostly;
 
 unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
 EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
@@ -55,6 +58,7 @@ EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
 #endif
 #define MODULE_PARAM_PREFIX "kfence."
 
+static int kfence_enable_late(void);
 static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
 {
 	unsigned long num;
@@ -65,10 +69,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 
 	if (!num) /* Using 0 to indicate KFENCE is disabled. */
 		WRITE_ONCE(kfence_enabled, false);
-	else if (!READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
-		return -EINVAL; /* Cannot (re-)enable KFENCE on-the-fly. */
 
 	*((unsigned long *)kp->arg) = num;
+
+	if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
+		return disabled_by_warn ? -EINVAL : kfence_enable_late();
 	return 0;
 }
 
@@ -787,6 +792,16 @@ void __init kfence_init(void)
 		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
 }
 
+static int kfence_enable_late(void)
+{
+	if (!__kfence_pool)
+		return -EINVAL;
+
+	WRITE_ONCE(kfence_enabled, true);
+	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+	return 0;
+}
+
 void kfence_shutdown_cache(struct kmem_cache *s)
 {
 	unsigned long flags;
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220305144858.17040-2-dtcccc%40linux.alibaba.com.
