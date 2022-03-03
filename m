Return-Path: <kasan-dev+bncBAABBR7FQCIQMGQEROPQZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E31B4CB543
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Mar 2022 04:15:21 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id y1-20020a17090a644100b001bc901aba0dsf1786125pjm.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 19:15:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646277319; cv=pass;
        d=google.com; s=arc-20160816;
        b=pyT0CiAyeOtFxTLUq4lsYALbzpZV3CYIMRkGGL06yZVwPzs5g02igIKiFzhm8D0K84
         Zxk/psRC16dv1ZMKcnaCdLhgbZdym1Zx/JzOR0DlI33JQyX680+Z7t8qqgSq/1DibQtS
         LR3ovLeetEnR4Scb8R6gWScEi231EKoNR/TXHVt3zi37ARaliqHVaMnXv8oS9AKX+5Wv
         XjTg52yS1+3gAZ0vy1jQqAWJisNii1udy61bUMOiZ/Qkoux6wVGLAtSoU5D9Mf6iR0u+
         5Ihx0ci6nyVnoJN61bn89CbSMTEJBJDL4IM01qKmW9K9fDGu5LM8CrmIdfcUzkt/CIKC
         ex2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DoK9HtuLi1MmlzHVTajutmRnTrX1n+iTNxrBv3e/1aM=;
        b=EU1Vk4N6squDPBdet810nW/5dWDMY1XxXJOiUzIiYNcHYWDNhXAGltBMpUeh3zszLq
         UT7gsP80Uz7tI031R1FJt5ArQWI+Z9asJfXi3AId8APWnmqD4nOkaaMOw/UhDCF4gSCu
         /nQtLfZrowDopMu50u5HlQoEjowXukWhUMxx/ndLU7/JteVbO/eZUVND9NJKEsa8ydMO
         LWngYlPvHW/6LvTicBC7J6rLCpZ8GLD7RcX3Ko6vUBf1YOOboU4YLnSEUp+Eiqr5xH3D
         fsXEoUjU8GMnqJIyaiPIVOpk/Gg5VbASKMcMEO1S+sHU9uTeGHadkFe+PgYTWGmcQAJd
         Tl9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.130 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DoK9HtuLi1MmlzHVTajutmRnTrX1n+iTNxrBv3e/1aM=;
        b=VmvDD9adnKu6LU96XBne6sT5eR+5ym0fzuHsJzkdsoJPNy+YGzzQAXKTIJp0UFz3zW
         1NeCXlX85VvFrZfgI//1ODtFK1qt+fxQQmzLmA8TUkbKIiHk7Oa4hmjpuUUtqijtRWNs
         zyfAaU0UaF0iVO4lkbchCzb31qwPBj6FAykP3UhoBGr4+2ec/0KUcif7we6CGvqj1cfG
         Wkcblc5OEJ2MPKMBEITz0ScYotMMygiGsBI+2ifrLP0Z9kPz4/AWLGEie8bINNuwfnui
         TdMAcbslxU5tPRyn/uPD2sLu2SOH4Gn5tvB9ngwnktJq7mEa1uOs874nFUa/3djQFS7q
         81+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DoK9HtuLi1MmlzHVTajutmRnTrX1n+iTNxrBv3e/1aM=;
        b=JLgk7RdKq5/wjPEmw+Rm7zWPhF0KfeEXc9dlz4whb5FzJPyKlhbidiYzA5JPcZ8/1T
         HBPHV+R00E3XtHM0VAeuSycZ0wWFlUDjAbTkdH9aloOmttxZYsbSWQ8fp03mD7gCO6D8
         KlCwu9RBGXOr2z947DqxMXsU7GU+lCcflP/naJH3hSxFarctXdU9GPloDIm00uGMzPJX
         8D/qIklGcSVCHeskUIzON+FmvaWHvpjByjERP6YHPg1Y8SwqNqBoc40cQ3k71PWcbvPD
         JHX1+I9mfB4vkl7Ng0h9J7KAFk+h5OxlC35tXUg5B1AsB8ItQaeDC3pcX7QGXpY4eDu+
         dlCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ysRPkWiOEhj/QJjnxb/yKHYJTBrXkP7g4pUQCLhwQWOWQbBqc
	SJwidbU7qZ6lLOUs83iTYZI=
X-Google-Smtp-Source: ABdhPJw72oScRPeG94/EmnAf7g25mfM9pbTMgNM8y8gkAzkhMNnmjDsYW51DRLeesB/Q6KY5DxeJdQ==
X-Received: by 2002:a63:da44:0:b0:362:c3f6:973e with SMTP id l4-20020a63da44000000b00362c3f6973emr29020913pgj.236.1646277319380;
        Wed, 02 Mar 2022 19:15:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:dd14:0:b0:375:8566:f8b7 with SMTP id t20-20020a63dd14000000b003758566f8b7ls486982pgg.1.gmail;
 Wed, 02 Mar 2022 19:15:18 -0800 (PST)
X-Received: by 2002:a63:5908:0:b0:372:a110:2049 with SMTP id n8-20020a635908000000b00372a1102049mr28198968pgb.393.1646277318863;
        Wed, 02 Mar 2022 19:15:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646277318; cv=none;
        d=google.com; s=arc-20160816;
        b=kZ8hudqpdA1t2/fjRidA666ejhdxktq1Y6US5vYlu8DcKtbGMDz9Ab6zx2wAEkBjZT
         71puEKy/rIGYhEqaQMw+A8Lsgj2CfuXOlh2eCFD8WDLSUd6Nh8SUuS6xA2KAj6/zbBKE
         yDTC6KhXoeECpPk9ybfMHM/4DLZzmEdH8RE+Is+LA1O+n7TZlKYOehdmhDhJspPe30gl
         xQZ5y+o8eUSDqxnIObgEtx7NgUvuw4tTpPOHVjTvyRwLDrqiQ7Zg+RRKIu73s9xQHrc7
         0x/6sD8LfQN1RpPB+JrmJ7fNR46EF9PayerAlQbQcYaXeqD2cQA34xdzOMOOJaBU4rqf
         +i0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=/ijYYutsxUojOe1tELAQp7k0K7hU/iWlgmSloY8X9h4=;
        b=FoIq+1rVzJONXvvwPQCWnL5X9k4eqMaIaay+07cAscuAS54FujwHBQRq8egNpbW9IE
         5esG1ea1EDvi6dipX5KUn/bPqgfs/tXKJGKDwwyNPfGSWF8JrE8JvTcshfk0VCsJ32+T
         ZDZRaErTRAWAVjZTgZLz4uKAkPlZq8fFUhIo32QSvmXQKm2AsIpTZ3X9fB7N8QYYtzkV
         Cx6n9XI+FSGceIzTUXZvBJ19OrjwBrL+nd830BGBawEoWPPHSFImlkwsc7ZAvCabrRE4
         sNRPk91xPFOPypzTPvEcy4cAdatkH5mtlREHxCQQ5GSgNGXpSKBsBj0tESRZwi7aT54o
         5iEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.130 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-130.freemail.mail.aliyun.com (out30-130.freemail.mail.aliyun.com. [115.124.30.130])
        by gmr-mx.google.com with ESMTPS id m17-20020a638c11000000b003758d1a4056si33539pgd.2.2022.03.02.19.15.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Mar 2022 19:15:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.130 as permitted sender) client-ip=115.124.30.130;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R101e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04394;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V650kGS_1646277314;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V650kGS_1646277314)
          by smtp.aliyun-inc.com(127.0.0.1);
          Thu, 03 Mar 2022 11:15:15 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [RFC PATCH 1/2] kfence: Allow re-enabling KFENCE after system startup
Date: Thu,  3 Mar 2022 11:15:04 +0800
Message-Id: <20220303031505.28495-2-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.130 as
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
 mm/kfence/core.c | 16 ++++++++++++++--
 1 file changed, 14 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 13128fa13062..19eb123c0bba 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -55,6 +55,7 @@ EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
 #endif
 #define MODULE_PARAM_PREFIX "kfence."
 
+static int kfence_enable_late(void);
 static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
 {
 	unsigned long num;
@@ -65,10 +66,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 
 	if (!num) /* Using 0 to indicate KFENCE is disabled. */
 		WRITE_ONCE(kfence_enabled, false);
-	else if (!READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
-		return -EINVAL; /* Cannot (re-)enable KFENCE on-the-fly. */
 
 	*((unsigned long *)kp->arg) = num;
+
+	if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
+		return kfence_enable_late();
 	return 0;
 }
 
@@ -787,6 +789,16 @@ void __init kfence_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220303031505.28495-2-dtcccc%40linux.alibaba.com.
