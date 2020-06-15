Return-Path: <kasan-dev+bncBAABB4FSTT3QKGQELU7KAMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-f186.google.com (mail-pl1-f186.google.com [209.85.214.186])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F31F1F8E0D
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:47:14 +0200 (CEST)
Received: by mail-pl1-f186.google.com with SMTP id f18sf4967084plj.15
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Jun 2020 23:47:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592203632; cv=pass;
        d=google.com; s=arc-20160816;
        b=xReRG9wgES+1XK6SinNdstFKg9WCxZjifYc1jKgtn4SJvEnvryCK8WYHDRKAQi83Ht
         E4yZcCxDz0ysv12P2jr9URWzkM8XG+4VH+BtmeT0I6om/Z89szSJDeDHi8eYA5xiqWPI
         wDktfg/khMVIqMZQ5pNZ//QoUHHUzeKXj6MyfGYjqQvHh1yRXFE4s8Zt9gCeGODZZMMj
         +ioKgwE5cV9Jhg5lw3REuNsbPCDxUaMimc4cIlbZZeWSIzPDHPynMKp3a0RWv+jOTidG
         bk7BYQ0WG5RlPLF2NDY9XjXSSchI8UpKz5TkYKTJSMRXQ7p56MIlMUkgy+70gXAnmCCf
         WyDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from;
        bh=Qw6tbhPqkEX0EFDDUrn0E1DPuKmOwbsPf3KwPsQTZNQ=;
        b=EypfOD0uf/ol6ffflyDq4PrKw8Fmv6a3wjiCuo8KUMwLektciA6t/w0uymoL/Zx98d
         NRFVEPDIPgs8NX+RDBCF52B5ObslPM84WWy7pC5miXj9o11oKHU6x2czS84V9Imr9icL
         EPd2isEXXVjE6j/acIRAwGbhW24m8p+kq7T1fjUTmXkPViNkQSVRZDLCGRawYFJTJg/4
         fXJ/cMcV0/tga28lmSC/+oQwmc6rvVlZ8xACU5xDgsoc4s5g/ta/z9xjSD4ZjMFSykbf
         rKAM9YG3zXyAJuf+Rx65NlEsF0rAnsZRZmYVkI7fvGSRIH5Vuj00V/7LeL+TSEMOr5mY
         JBrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=amBYoBlq;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qw6tbhPqkEX0EFDDUrn0E1DPuKmOwbsPf3KwPsQTZNQ=;
        b=MUjWRNyQ3F4c/CTWbv4KAbjt37YqU3UOqPa63E4c870YXPN+zG5QOJ2h3lqiSQtNMV
         O+2TxL1EUvAw6PW6U/ZfYiv1LL0JqFrV7Zeu0GOe6ow2RAm35KwqkTXZUhxPM/L7+pAU
         84zWAG0OvgdRxxqjZx18qjwXElv4+fKzhUSGgjBLuWiP3eZtcxPpysSkAYxVqqKP+UZB
         XASP+pNYUgJrdgFYOwqhbZykzdMobBVYjW4GurW4Sm38b4XSQQeXa0hDJZfVJE6qvqG4
         cHuAkQ/FDMV6B/R7tr6p2rf7++0pRsLbPZKVJ4DtPA+RAv3T9o/kS5LGNLqyYj7aX9a2
         43Sg==
X-Gm-Message-State: AOAM5327SwWePFkWxd2djvpNiUQpa7kg34j9GPdMRPJBF+hXYc+6Ze/A
	7xUDDXU74tok/XxcBzWjRQQ=
X-Google-Smtp-Source: ABdhPJxy+ZpKHoLsPjkR8seQezaVeS80pxRCBYqwPkcwwNY98+XnWpLOtNYRkM5Hb7rEsXxXvV43Pg==
X-Received: by 2002:aa7:96ef:: with SMTP id i15mr21754622pfq.312.1592203632656;
        Sun, 14 Jun 2020 23:47:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls4940956pjb.2.canary-gmail;
 Sun, 14 Jun 2020 23:47:12 -0700 (PDT)
X-Received: by 2002:a17:90a:2c06:: with SMTP id m6mr11023062pjd.216.1592203632359;
        Sun, 14 Jun 2020 23:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592203632; cv=none;
        d=google.com; s=arc-20160816;
        b=yXmebzlA+HSuks/SEClPx1Qu4iRCm8U5llSaf3Hizr5Zc1LxnzaSo2HAnF9koKva4+
         xK1+ynfK7D5I56ondcT9DOWEag9t1W4THh2BD9hC+pkL2FKhBdUJbnD5/hqwkm0HnRX0
         /hEGLfsTfcXFrzHKZMqE5w6qvpA2iDP3LBn5ixSnHrLI4v+9fdeyfa9tfByHJfCpurKe
         HqVvNSzYaiVbB+bFLJ1eunwfE9qx63kbLUsIsS+vk0XMNYD+cWOzVEAA7QfRDbda6h4L
         g3m+bXv4E+2z0qcv1DnIZQuPFFDiSTMRZHmj93hZBnHe+aMJpBiTmXGDndcBvRu96iKT
         Vq3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+97/KICMcQbf+NWKHSmMZQtHZx0Bz2djUg2HNXJEx4g=;
        b=PJpIZwkOg+XOtsfMHSueN6GZLINWMssUlntP6xbifXaUz/NsGNNmOdIBAjNo2kfKLp
         Aasa2Qn7xnTyr1WHcVmdrY14FZjp6O8/VKmVw1t3pVp4csKuNud/U2joPg4w/blNNt1S
         Ym0Y4EeViLDrG97a5iip4diO2SicRWIa0DLmDOTFmdBKEKlQI4je3zcuioeA3C3CP/VA
         QBZeLYfBjVtuqyMlIKmPXLHzRNEDOvvzruzcAddK8bwvLKwqjmdjvw1Jjhi80+PWz29J
         zHT0eBFu8qNstNQSCnOpdcyTlB8wfrjLAvdC3hPdXhPeFdaxVXmKb0AWH2jd2tf48pMO
         /jnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=amBYoBlq;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x14si833744pjt.2.2020.06.14.23.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Jun 2020 23:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (ip5f5ad5c5.dynamic.kabel-deutschland.de [95.90.213.197])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id AD9F720776;
	Mon, 15 Jun 2020 06:47:11 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.93)
	(envelope-from <mchehab@kernel.org>)
	id 1jkith-009nmX-KT; Mon, 15 Jun 2020 08:47:09 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH 09/29] kcsan: fix a kernel-doc warning
Date: Mon, 15 Jun 2020 08:46:48 +0200
Message-Id: <019097f1fe10e38a04b662f1d002ecc0ce8bef8a.1592203542.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <cover.1592203542.git.mchehab+huawei@kernel.org>
References: <cover.1592203542.git.mchehab+huawei@kernel.org>
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=amBYoBlq;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/019097f1fe10e38a04b662f1d002ecc0ce8bef8a.1592203542.git.mchehab%2Bhuawei%40kernel.org.
