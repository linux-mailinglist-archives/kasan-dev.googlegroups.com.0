Return-Path: <kasan-dev+bncBAABBG7QS2IQMGQE55O2KYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BC224CF2D5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 08:45:33 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-2d726bd83a2sf126104107b3.20
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Mar 2022 23:45:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646639132; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJCrRyWEq8wwVlxQv5Z0X5QYtVN4oWPy6o/LX2ExwS9QR0q5lqsfQSQIW9Fa5Sr5rr
         YeHoKnziZOYDrHbfRvBYXimDtEULjVdfEuQIqf2NOhuaNO30q78SdZIXSEb9jlkUElU/
         37nsJdUr2KI/sEo5xuUobDICko6pMvMPnhaEVS+Mdh8Ou+TYtPTJS6ISa1VwpDgQks6C
         KleTQfT+Al6YmzGWOc65a6Y4UFh1CYuaK29Imlb42EY9qNwlfr2TW3N4zxHD/3bzf1Po
         7JO+AGW9OrVTEp4wogllFZXIinJosvwDCx0C6s+mTtnCe85PkiJF3ZZjFz/z/Lp8+G9v
         7Dag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LyoL+IGoAIYtai5m438XPu2T3VljyridYiFjzxVnWjA=;
        b=MtxJlW0r05b5p6gcfXMOnkTAUUpDDVZBoucEf9fwT6ny1CFMhv1ve13BjVlFY7lATv
         o8V2nJoXvxGarxtVTFhWIjXgdx+zDeDUG+tcYcdwi7eO0utAwURC0+uxjfTsBdXVPfn2
         7ui7G9mnVE3B5A59Qj+rVlFgcsff5cxIPtdMQTyZsbDt51TBOK5HrvgolydDOH3ibgxa
         Quu5ObASpJzXWBw2mu6D8BhJF678RR6Z8xL9gHhPrui9+zngEkJMyPma3ihtnuXFdKJW
         b2lsnHbtwMyB5zI1s1B7Ldu+K1qtdo/+ENAVJsp6iq1te8z9/VCR/V97hApusRut4MG2
         9eqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LyoL+IGoAIYtai5m438XPu2T3VljyridYiFjzxVnWjA=;
        b=RMlUhETJ1rdhJm7U5pk4qISe6/6vNM0T1gZ4lj6c/roO8LOkmAoDPUtSnigTtcTkcK
         md1j3BWyZ+pbm2pjrpThfnzQVI1UsssLW+i25suc7czUEg2rQKreJTTx+XtgEvdZrs4L
         ZTrhU40hIEi92NHwt6iH10E4dY5gj5IjniPlBYheDQAXgPBu/TI5FGyOhBYW50SppUvd
         xsstXIhnXqiqknDF2pUTTlI/8mgQ5ck7d8j49ETEItnAJK2WwnLkUIrNKP+UXe1A4+Zd
         /KV73njE3ACYny0GtYgLM29FUKrlJuzghS3L+yX7AFWtvKpFvN3d9rzp4s7CkUxfAJ4Y
         tzDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LyoL+IGoAIYtai5m438XPu2T3VljyridYiFjzxVnWjA=;
        b=wQ0pkJlDgpxAlrHOqEyYCmvEs/GI87b6Omd2Jy1nj9PAr6juxrYrRzKfIoQOz7RsLi
         ohJhbXUkfrTzXptC1Y1FR6pKK/mqDv9TKzBVxMnDt6zB0YGRREwHADLRZU1NES+3FO5O
         rJ3XXBMxD/aqSxAxQcxcUOGSccXj40N1C6DE6LKIigM4yz0qrD+7UeKdCSpvcQtWGWqF
         a4B/XYAdEQPGv0UThnHYcLCEZYb70zCAnPtPU7kfg93L4c6rveEkXhjq26AVmk0yGGCp
         DERdyXlKHcWf8ECTfQcm8QwHjWZ2t0u1h5Iy3NtLrIKPTdCUuvK5i3YCVchDiUpb3p/m
         Mw1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qTXWNLtie/DH2lRbP1bTZBy0ceFsXkh9/O2OgiLb/zTyCwQsb
	G14ST0P8xZZhpzQJmjBY++U=
X-Google-Smtp-Source: ABdhPJwM0TZfy52UyhkBuW1TbcHDIzh8wt4LFeyotXqHC0lD9QfMOrBME6Z9wvpej4N7V1XNmHgpBA==
X-Received: by 2002:a81:9b56:0:b0:2dc:792:1597 with SMTP id s83-20020a819b56000000b002dc07921597mr7600461ywg.282.1646639132049;
        Sun, 06 Mar 2022 23:45:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1505:b0:629:5586:f64f with SMTP id
 q5-20020a056902150500b006295586f64fls533800ybu.0.gmail; Sun, 06 Mar 2022
 23:45:31 -0800 (PST)
X-Received: by 2002:a25:6652:0:b0:628:7c60:f302 with SMTP id z18-20020a256652000000b006287c60f302mr6908627ybm.581.1646639131610;
        Sun, 06 Mar 2022 23:45:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646639131; cv=none;
        d=google.com; s=arc-20160816;
        b=DncyiTh2bnfi4usRah2rmg1yP5fZvq1E9mu118HfvAtfsYsUFJc69k6EkUCxHekVSs
         mei1te4IHJm/LQOzbH/d5x6FNL2Iz1HW5Tbh2ih6SSZv7kPYQcKTokOhsHP9fAaU+7Qs
         xNzaMALuKrx4I8WcXTLaUhA0Nd7x4r24HVuPdEcDwF+9fIrHUZJRv9Ln0sCdnPo5UQG6
         3tVZxy9Gdtt0zTjo/ZHdsp8hR1nejz/NDOaK5gD+POLQrCuMWT7dTL0LydL7A5ntTJ5g
         9ELCT1mBteHiO0kZZREubLViM4tSEoEI3ODsRxwfNk580JpjR+DEM0uvLHILATDvU7h2
         KiBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Ukwfw3PX35VdBiCAxfF3K/JBqZ+bYLclxdMNkAiO2VM=;
        b=uPBPa4OTs33lPxKdwtipdCgNtpMfM7I2TH7idtCoIq5GVV9XhG1MZcgw13MYTLOURR
         r51IyNzkwe60uzfakNSPGAzuNfnrHy3JNcn/11Aenum8YGctziiurRJ6wyt2fA6yVg/J
         T54XqtlVTLsh2QZQwm/pY8+Cx0850eXYT88jnc+IQyYruBoptiEpWCwEv/W7Dswq+b7H
         Q1HJvgwRCkMv98lcT2kxi4ascbcNCQyjcd7bOJgJl3KZPuFmVgpHvcbjjJni2Ko7LBsz
         iWk+Rbcg+QE5G8yC2Mra/ZSst70H2aEE09NTPGy5eswRvAu3ch4P3z57vprIUsUcmBWw
         1RWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-133.freemail.mail.aliyun.com (out30-133.freemail.mail.aliyun.com. [115.124.30.133])
        by gmr-mx.google.com with ESMTPS id q131-20020a819989000000b002d128e6be04si757598ywg.3.2022.03.06.23.45.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Mar 2022 23:45:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) client-ip=115.124.30.133;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R811e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04395;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6SREei_1646639125;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6SREei_1646639125)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 07 Mar 2022 15:45:26 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v3 1/2] kfence: Allow re-enabling KFENCE after system startup
Date: Mon,  7 Mar 2022 15:45:15 +0800
Message-Id: <20220307074516.6920-2-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20220307074516.6920-1-dtcccc@linux.alibaba.com>
References: <20220307074516.6920-1-dtcccc@linux.alibaba.com>
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220307074516.6920-2-dtcccc%40linux.alibaba.com.
