Return-Path: <kasan-dev+bncBDGIV3UHVAGBBT5JWSEQMGQEUZUWORY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 76CC53FBAE9
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 19:26:49 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id m18-20020a170906849200b005c701c9b87csf5942464ejx.8
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 10:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630344399; cv=pass;
        d=google.com; s=arc-20160816;
        b=AELjY3s90cnkMWrVYk8TqGpIVPaeKVmBR7JUQtCiR/TbDK9ndin+j+gaxGJsOmNQ73
         St/rtGKra8lOqrW0m2DcJb7Q5noLV1DSup0MbkYgnRGQdvkeAYTgNUQCmsRZB3KxLPrW
         6S0R6RSjDBpofdbdczcg8fU2NmeoRIenpb7yDqiBxjbom5IXNfmnKS6F/I7qLYWzcjEW
         Iv6BGnWwd96ClebpGJszm2PhhNaE8KMml3q1qvrHV9Z/0OY5udD6gMlwSdPDlPI6T2mc
         al8sb0leWg1vu0IHX2o03qHE3lo07sQTLJohett7AxA4rNIF8gC8+7ZxTCX6aeEq5QVF
         +P0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iGYLrioo+n3cY0OaZ1VtFLSExg7BGdeiOx8Ss/Zyd9g=;
        b=oZ9QYi8mHZEze2kgmqEXbogKRYR+0QTZ5iXk+XR//xVW8SdigoBzkuzZDUiKfdXrrB
         NUEBsulFdFq7ivvXUBAGkWj86a3pkknL7Pssjzox4ySjWG447A+gK3sRd5PZepDndCy9
         Cpq504ZYEQMys+S4/H1UZVmUE4fY5NWwJRrlegIFiwia66GnOn/DGDNtWVeBfINBtk/G
         +PQbuWNIoHw5sX2NZRTxbRZYyRZv8nTfAypFBhsdmmUTBv9Bf1SlWN3dK5xZoECYXS3P
         YMnHgnCIhzEsisq0ziabzZ2Ps2EBNZt+Lp7fD62Y8oxD9mbc1u5lO9lhcYIVbREgodNX
         NAcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fH3wzDSq;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=9j0gqXh0;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iGYLrioo+n3cY0OaZ1VtFLSExg7BGdeiOx8Ss/Zyd9g=;
        b=DnzEqWUhtJmXBGx/X5Qv+F6KruTa5vF5zVe0ZEgELR/qlqpbDz3Bkgq+kQ2UZoiZbN
         KSpPaBCgQbh1f4p3pL8M9kQyF9TXK9buTd3mBg0x4TgAMLLfNlhDpOLHFlgLlQnU8uLU
         krtc6WhKl6HABz8b2pYqsHHrS8NiZomScbchQPCqHxtTL9P5fWhIRiF3fk5qeG0TDGcv
         tDSLXaZvQmyuy1cEm1bwuz9NjGLagvvD+bYM2F1ZPPueZg/B4iDcoBORICFr8IPjBlAq
         mqQXtWEFaljca7Q/avleZxFOn/Q7yO7+wUF8IdjrfyUHsmYTmrKb76cRf+vN2/cydAKk
         oQTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iGYLrioo+n3cY0OaZ1VtFLSExg7BGdeiOx8Ss/Zyd9g=;
        b=ioxabKsbRHKYBMY9rjP2Oq3F/9NqVKlIvh1Vr8Vwvo/AgmsfDTfA4U0ghtP3gm/nXw
         aAnuct8Z/7JTEBDYw3bY1gRfzppQCddvMGMtc73OBg24izVLg9zNDEduGSB7czDBv0BT
         437iwLkqSCh1iPeSkrGJ0ueE/3MldWZD4boafgNBznJfhDBkXJV912GxCV6oMR7O5dJD
         qiFpUPlI908CnxcOdC00U4eAps6QthYCKjTVv2fP7/l0jDvvMNp4bLQCOBIYEq8bgoYU
         06Zlmxb5XVB8MsRfOTzd95Eeb7OBCrkoGA+qI+IaapLnyVVd8qdHMq27irpyZo++g50/
         QraA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533q4dPdFDhdbYP/9VEK2P0YfPsj0ox7QG3wXE6btxXN+d1gg47T
	b5zm3npuHYK4P1CiaIIDdTY=
X-Google-Smtp-Source: ABdhPJyN/tzC0POKm4ybGq7IyMguEQpxwG9Mhse0XKvE3WP8oYlszbMgOPe4B5RZRnnPtvJqRUhNcg==
X-Received: by 2002:a17:906:d0cd:: with SMTP id bq13mr26835815ejb.66.1630344399246;
        Mon, 30 Aug 2021 10:26:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c258:: with SMTP id bl24ls3158680ejb.6.gmail; Mon,
 30 Aug 2021 10:26:38 -0700 (PDT)
X-Received: by 2002:a17:906:6b96:: with SMTP id l22mr16523940ejr.430.1630344398224;
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630344398; cv=none;
        d=google.com; s=arc-20160816;
        b=WCPxr1SuMfVIwloRduHib/MXTKAJwHW5vaOfoTyRbEgCW0e6BlKk/jwm3NF7snmw2R
         pz8AYl8i19nFsTLSvkjlnNIwlvZ+uCSVmmRm9oVVvNcsYkVE7atc5SpvSqiPMCMIi4rD
         w4UmWwVsmaFJDNW0WjxAooamCm4THokgLxqdj3ZBJJW+rYFJhC/nRYQpSctxajxoqCdK
         zmMXsZ/zsdihcTNUwMDgSoD2bJClC0G0GRnM7x9M6G7faVDVj8NAsjVaTXWwKN1vkj6o
         J641Puwd8abpc02ojVBFQ8qo6IkovP7jSNEMEw71WklehthkrKLDLi0vsRW8eJ3g6LxG
         6S8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=i0MzP5fg/W/TLTV2fekKiWllQmlcT6Ku3/vzSWshZuU=;
        b=vJd39bCNZ15F5oxWixQW2IRH3S/aY1aYl7taB9seMtYKJdCyJEtpkoQsw9jL1EJxTf
         6wzQ2uspuKTgnoEujvmp4BuSezadw1HI/nrgjb73zLN23ffbcD35YwcXBAYhe1PCdKSL
         UOt4apMn6mGT8tFwZVsmkb6qLjjKb3frze8l4vSP4wdwKEuNTCA5gY6jcAFj640leN+Q
         z0+RvhLN/z01pwYSpPswtxOfD2MHt169AnMIS8+kNHKc7/nwwHd885rY/NE/bY1nFUN7
         Awrt4Lvj2snVtNkndLZ6Wi380oZFRqqbctHUj5rV6IsfPb+FK1cJame28GTNNtBfCBA4
         HrfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fH3wzDSq;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=9j0gqXh0;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id e20si470050eds.4.2021.08.30.10.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 4/5] kcov: Avoid enable+disable interrupts if !in_task().
Date: Mon, 30 Aug 2021 19:26:26 +0200
Message-Id: <20210830172627.267989-5-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-1-bigeasy@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=fH3wzDSq;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=9j0gqXh0;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

kcov_remote_start() may need to allocate memory in the in_task() case
(otherwise per-CPU memory has been pre-allocated) and therefore requires
enabled interrupts.
The interrupts are enabled before checking if the allocation is required
so if no allocation is required then the interrupts are needlessly
enabled and disabled again.

Enable interrupts only if memory allocation is performed.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/kcov.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 4f910231d99a2..620dc4ffeb685 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -869,19 +869,19 @@ void kcov_remote_start(u64 handle)
 		size = CONFIG_KCOV_IRQ_AREA_SIZE;
 		area = this_cpu_ptr(&kcov_percpu_data)->irq_area;
 	}
-	spin_unlock_irqrestore(&kcov_remote_lock, flags);
+	spin_unlock(&kcov_remote_lock);
 
 	/* Can only happen when in_task(). */
 	if (!area) {
+		local_irqrestore(flags);
 		area = vmalloc(size * sizeof(unsigned long));
 		if (!area) {
 			kcov_put(kcov);
 			return;
 		}
+		local_irq_save(flags);
 	}
 
-	local_irq_save(flags);
-
 	/* Reset coverage size. */
 	*(u64 *)area = 0;
 
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210830172627.267989-5-bigeasy%40linutronix.de.
