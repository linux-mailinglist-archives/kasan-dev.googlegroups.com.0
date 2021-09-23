Return-Path: <kasan-dev+bncBDGIV3UHVAGBBN67WKFAMGQEAFHHWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 63F2041638B
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:47:51 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id i4-20020a5d5224000000b0015b14db14desf5621619wra.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:47:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632415671; cv=pass;
        d=google.com; s=arc-20160816;
        b=0u6pUSwq/jGMTCQpvbKacwzjJ4E10rr83GfKTsWcfizn2x0fMpKY4brxMAh49eVmlW
         jZoZ1EE0ZI+ln7ojW56idyCWAGLC9ZF8zkSguLYXaVofX9gdPaoUgNNnOblNnihjoimv
         mPF5w94V5XMgUCfauZ4B/vv8AZvp9kKxlPky17nDRsqK3TpWfYhptDAsDJeGPvFLyyMd
         BafYYvzlovFU/p9+Ije/gEMbLODrSzISr6v5lj1otjEQKjo7M2NpruJyJOoVMHowfCVr
         1cr23fqT29Vsos+teCZ27jARmpeMM496zDxvriv5gRa44GBxC7rkYsbydDL/aSd0eAMi
         F3bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dIQNaGVDS3kG1R4Dvek26zEDQgFzaRXculh40/eIJBI=;
        b=Oy4psK53EZMIEgeVX7DwX1vsunjBsoUaY0JJyXMIJcinoKcO1g3iJ28mwyhYOqyTPV
         H27FHSK9k734SxE8KEqYTcvUhrnoTXKfja0iTtuUrugkCre/KzYqjWuOqN4gDwOfRMD7
         +wLl5gF96ff7IBjD2iyfMAJVlR8s2RHsvMAwjeGFkPv+jwygDDJGA97891sWfD3rIRoi
         U1w5WdCnbVOY/vcNZnrL0d12Tcjn4gJJmeyoMXcI1DGF8jdDynrV4ScXisRff79vfukb
         hE7DJqtrN/OghtsNVl0qFtXtZViDoonCAb/hYnm5hQnDzasbS0C/o/srDfYq+KjpSZdv
         0qeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Bgn0atER;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dIQNaGVDS3kG1R4Dvek26zEDQgFzaRXculh40/eIJBI=;
        b=eo5KCjx1O5PnlYnP/9EEYJPfbKGEX1QHhEFM1JfZR5xFC/5nMKtqmoZ6TavK8P9d5V
         r2L13Lr0EOpwEOYoyr78otrI9OtxZjHYPgjTDzCpFrl6bXttKZ7dJkrgBDyevgRdsn4F
         BfQIk1Wn1M+P4aF0WbbCQp/OuQ33KdDXIp1w/nyci/17XVbqszOo/6hW0vP9wJuHhWYx
         JVaekFOk5A3oklVxGKQVTWspiaUPhPkj8tdw2WLc/T1dZbugjHTfM1odGzCbfjEzcOhc
         oOXO/XDKc+shDscuUPBo72h/phaE+tZnRhLeykDN1uwnQuwDuPKBdDb5AC0W+5s0ssLr
         fOUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dIQNaGVDS3kG1R4Dvek26zEDQgFzaRXculh40/eIJBI=;
        b=0SjmbcOJ0fQJrxJ3MKJci246FUADaPaEJXxnYF+XNGCIX8FfH5P0dg5a+D5ta6TVhn
         AC8ZuHlxmPjQDGOZTJ4AupzAI8Doh8jxTlNtG3pgd1Tt+qfO5VgXK8NOyT2L7wbEfFlN
         FPKT/NVbzfeKmleyRNVHD22iAKHVvNToZkGFuoXBdLWJtyxIeGyuKZe2y0DfV9gAN8Ii
         g63lfdfAaz1iGQeJ11FPNoxWBO592xDorA4AXGm0OvTKMrtbpG6aWFBTUYQXUuRQDb1v
         hSqAEjBBGkaXjXcWqfQ5U1eRuDTYH0lGLtEZevnI5bkQMuu8LAmshsVfr48Mt5IdJKyB
         2t5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532VxWXSdveXsPKwbxSWATybLM73/ETkwsH896AfeNC6/TtsG2ln
	jBOQaD4IcFo0LXfvxcCXwbE=
X-Google-Smtp-Source: ABdhPJwr8GFNkm2gwgV+fU58ucdV6SEbydHMxLVGHgVYAVKI9QuYl0zgUPq7ZG/Dds9zYPTJOfHQbA==
X-Received: by 2002:a7b:c194:: with SMTP id y20mr17186718wmi.37.1632415671232;
        Thu, 23 Sep 2021 09:47:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c2b2:: with SMTP id c18ls3298527wmk.2.gmail; Thu, 23 Sep
 2021 09:47:50 -0700 (PDT)
X-Received: by 2002:a05:600c:2046:: with SMTP id p6mr17649115wmg.88.1632415670418;
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632415670; cv=none;
        d=google.com; s=arc-20160816;
        b=ssgCWLOHbwL3ZCFQxow+ZUkJHfx1LHu4xgbCuCztGEp00OY6t5cj6SfoTkLjLuTl1H
         ZUqkdA+HMhP4/m73Dyx5r0kdvqd1buMO6qQJHI9MXpDcacBrMbR1IpqBUHfeIQoH6Kfk
         w5ze8NCe49DzEg0iBBGBBKRqrGH1nWNa5X+0cRxpoXHhjIQSOvUZsUR7k1FGH2H5gRZi
         SDudom6qMlEzYsdjF7KLYh63o5Ufey82i6rav+uNUcDozBcePgHF89IS42QcesWfdnxr
         ZA5AnnI5UUl9gUHDH1X1Uthyz4yJVCkgNshKgVJqSSenMjqzzsgjH+hKDRy77mzaYT7w
         fhZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=Vi5RWc6YZLQPlGlsSLEKEH6yFrTkfKkQNlRzcTZMmK0=;
        b=ye/Bo8T4sE+TDuzchLMvC2TsiosZrpXYQSfgNSspFDfq2PXtcQ7ak0ORc1hAsZ0vxU
         wi+rErivVR9CDsA7LHy8in3TOCQ3Niv3atTfPNsj97Doj8D3g0DPZLlaO+GYNJMkgqhG
         fefc+PNthYs19yHQ8ygmVRj2ttRk/uRPAYoymqF1VF3STxYpoETPg7lrv5pTsHpFQY16
         e8fFHZxk9OkMI15IEQ5c+A13Si3Hhp/ewfCbyB3sD4yuCKSrQBIzgzHYCTofxVbCV12B
         zFfDyXPSso2ELog5AsM4OvkZpMdudxXFEhWFPkqyGQLdUJ5XL4tvIWfO+3Po0NHELTSL
         YyZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Bgn0atER;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id i7si381051wrn.2.2021.09.23.09.47.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v2 4/5] kcov: Avoid enable+disable interrupts if !in_task().
Date: Thu, 23 Sep 2021 18:47:40 +0200
Message-Id: <20210923164741.1859522-5-bigeasy@linutronix.de>
In-Reply-To: <20210923164741.1859522-1-bigeasy@linutronix.de>
References: <20210923164741.1859522-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Bgn0atER;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Link: https://lore.kernel.org/r/20210830172627.267989-5-bigeasy@linutronix.de
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923164741.1859522-5-bigeasy%40linutronix.de.
