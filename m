Return-Path: <kasan-dev+bncBAABBHGVY33QKGQES77DZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-f63.google.com (mail-qv1-f63.google.com [209.85.219.63])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F7C9204A89
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:09:18 +0200 (CEST)
Received: by mail-qv1-f63.google.com with SMTP id j18sf3275105qvk.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 00:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592896157; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZbPOTZSTfiEz/SsCPOpbl4uj1ZCaXVTxtE/R3LW6kHVq0GfcDN3tW/LIyZ6Kba628u
         Zh2Yn2dc+iJwe5tdQk1L1P9vrjvE1CVTsdjnwUvpDKzWhd409p2EAtVfaUO0l1Ss+jUV
         Jz6QfXEXKWQ2T01g7ISU2WvgpVC2DyZcBWj2vt2UYOqylKC+eP8CTPcAELNckSvLQM0q
         /s3THjpoOi8bpW3084/9iqe9pykek6fNeGLKOHpDI3jDh4rmxcXTvGDcFyasKvmiZYys
         pifbBt4rgyxtm4XMUoTfC0X+HRcFKbKdsc8d14LPD6tt8dfXbjA7qdfdHcQI7Pok22lT
         b5HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from;
        bh=OUoJx/Wubmw5DfsMjWDUpb5ZobnhC3gCELW9VHM21J0=;
        b=Ns/kZkqHbXr9r132J204zU8fUOzlDpl/IrVNZ5dYtYsOMHHakClDVpudEisESN9BcY
         bjEnYQvqpQp5Cpe223dShB9y52YxovGYao9wyuXYHn5o2gvggWSWHsCmVT2Nzu0Gn4am
         NdqcfgRpvIzD5bo9O6bMMhV6g3xhOmd1Le8LMIhLnDXTP125kNcDT6zBnfsSjimk4kKj
         5Tv2JOyDExEV+5QbeJoaUq7xEGloFH4KYRjFNiC8pg7YYq1sUMUvGBGd3gA0837izMN5
         TRR4LPqUXaQuHxUuv+cKTKroC+uaqG7q1t8L1RM0jyVKC5VVOORLqwNERL6KDzh74Kns
         aJYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=egMU6jAh;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OUoJx/Wubmw5DfsMjWDUpb5ZobnhC3gCELW9VHM21J0=;
        b=l2PRNeVxcxN5AX+iN+NQySkxO5RfAPi+GRvjobcFwcgE3ZBxHum33crEOkCJhOQgKz
         MLK4BUKy42fX0rVpjiv4c6ynFaBinEzZQ0T628BNfciLvM2KLyF3jWvRPgGflZgA18L0
         ZYMBBLIbfzoNWiSeZOfpWoqgm4xfQI/3IDgKTbUo+/wlmqvgqghBCY3+bKtLj/nmIKqR
         ARFe+Q6daIPyaNXz2a7re4hbT1201ZRksUp04PSSsbLXd7T95gcov/QqNWxBI4MIwyIM
         1C2z4xZUuBwVlmeGi7BozX2Fvy1gwk2z44tGu3KyuYd+0+unFUf4JiJDO2M9hoNMs3Lc
         5/wQ==
X-Gm-Message-State: AOAM533j9E701j8JoemY4LoTLF5C1LRrc2D7sSoea3ADsS2zDF5lBMg+
	BtGiuE3ReDxCFKeqGhzdpdc=
X-Google-Smtp-Source: ABdhPJzvHHwr6v+84lDUQyhukpCc/LfNaieS9H/ZY5NS22/V4xypXdAJ52gZHbJcuTDKOeEnP7+64g==
X-Received: by 2002:aed:3686:: with SMTP id f6mr19979505qtb.328.1592896156952;
        Tue, 23 Jun 2020 00:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d01:: with SMTP id 1ls5235306qkn.0.gmail; Tue, 23 Jun
 2020 00:09:16 -0700 (PDT)
X-Received: by 2002:a37:a315:: with SMTP id m21mr19619161qke.482.1592896156655;
        Tue, 23 Jun 2020 00:09:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592896156; cv=none;
        d=google.com; s=arc-20160816;
        b=rnYv3XjQ5k1L3gWqta3LBkKgJJejh20O21H65MADHuLBOfhlPWyF7eJ3EbEwBRSiUe
         lSn43ZLLAzKqZas8bK3NsJn4rsX7vT9Vrh/xd9pS1sFvclur+skd59TJc2YyUqZ3wJuh
         RZo/RRL4MeMEOk2Y0nju8F2OYsrc4z96Vrp82HbpkbhYJOHP2GRQMOkb8fuBhfNR5Ks8
         jdJEfergdRrArTTOS/7oeO26/CZvDuCjXBamQdGpEkgoJc22kWKRK4yortxlY9rl/2vq
         ysYxU6RjkgKzPvMHIS088hUm3JgSRcCWOOqoMBONdguSmZyvEWtFQtkgaOmInMYut/9m
         eDaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=wmFjuVgOaCaoXk8jeugtryX2MPm2SNs3gRSNuM3cJas=;
        b=LSL/PWpXPyULg3WErVfkcjF7MSXQXSJ6uwVTxGfsWZm1F3J9ScasoL8Ya7Bnh+4n2T
         UKFcRtqRva0zhGiSLm1ANySkBlWbAF17ChixjtRlLLIHiXq0HMVssjkpf9jxGMcqy2VQ
         ubOc9f2nS8UZ7cBuLEhWh76LvRw/6zcd4V6hjJlSyYsisvLiL2KTHK2t5eR0gWO1GHkI
         Q3aBHYf0WZKKHfOLSJQ5KqsPHZaVyBvVsninHTFKuQjsACmIfJclpuO+YiOVV7Do79/I
         IpxqycA1BYDC4ZgbA4KcseE0ZlTLyJmz+V/tzdiVJ7gS4qYIcGzXj+w2WnFhnrNODFXr
         GYTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=egMU6jAh;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x16si965113qtx.5.2020.06.23.00.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 00:09:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (unknown [95.90.213.197])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3B0EB20774;
	Tue, 23 Jun 2020 07:09:15 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.93)
	(envelope-from <mchehab@kernel.org>)
	id 1jnd3R-003qjC-6o; Tue, 23 Jun 2020 09:09:13 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 08/15] kcsan: fix a kernel-doc warning
Date: Tue, 23 Jun 2020 09:09:04 +0200
Message-Id: <20f7995fab2ba85ce723203e9a7c822a55cca2af.1592895969.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <cover.1592895969.git.mchehab+huawei@kernel.org>
References: <cover.1592895969.git.mchehab+huawei@kernel.org>
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=egMU6jAh;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
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

One of the kernel-doc markups there have two "note" sections:

	./include/linux/kcsan-checks.h:346: warning: duplicate section name 'Note'

While this is not the case here, duplicated sections can cause
build issues on Sphinx. So, let's change the notes section
to use, instead, a list for those 2 notes at the same function.

Signed-off-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Acked-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 7b0b9c44f5f3..c5f6c1dcf7e3 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -337,11 +337,13 @@ static inline void __kcsan_disable_current(void) { }
  *		release_for_reuse(obj);
  *	}
  *
- * Note: ASSERT_EXCLUSIVE_ACCESS_SCOPED(), if applicable, performs more thorough
- * checking if a clear scope where no concurrent accesses are expected exists.
+ * Note:
  *
- * Note: For cases where the object is freed, `KASAN <kasan.html>`_ is a better
- * fit to detect use-after-free bugs.
+ * 1. ASSERT_EXCLUSIVE_ACCESS_SCOPED(), if applicable, performs more thorough
+ *    checking if a clear scope where no concurrent accesses are expected exists.
+ *
+ * 2. For cases where the object is freed, `KASAN <kasan.html>`_ is a better
+ *    fit to detect use-after-free bugs.
  *
  * @var: variable to assert on
  */
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20f7995fab2ba85ce723203e9a7c822a55cca2af.1592895969.git.mchehab%2Bhuawei%40kernel.org.
