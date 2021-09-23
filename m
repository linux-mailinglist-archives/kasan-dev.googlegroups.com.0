Return-Path: <kasan-dev+bncBDGIV3UHVAGBBN67WKFAMGQEAFHHWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id E5B0841638D
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:47:51 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id l25-20020a2e99d9000000b001fc59e79289sf120982ljj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:47:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632415671; cv=pass;
        d=google.com; s=arc-20160816;
        b=tj91tc+hSf27loYR87qxv9RDsPaxLzOdCkIc3XXav59A8h6WN3fopCTx+RsxXQiU3i
         QK/vFt8V/3QcuwxQi/MbaFsn/IGQKikBXC99a/xxESS6eVTPjsF8HNh5gPQ90uIZTkgz
         iZrveRho39kJpKpYpjx+p76WZUZcqMuVTKfmrd+gO0dIxWEps47qNfAReypG9E8tjG2a
         H/LK5j3u3nshQO+8/i2i5YbA0TRBIfP9QSfpKOv5xw5OPyZAf4GbIlIbIY9Bw3BwklfK
         BXUFQ2k9SIvTxppGMuR6mV0osf88CToQJusCC9EkodPg36gio85vAUi0HCnO+Xs/pGMj
         tDUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tZrHUTOYSYUbYafSQDpOP6J6nsxt5tqphS6OW0pUJzE=;
        b=oo9Ik29+6KcyJpA5y8T9uuCsk2H4P/5T9tYfPCkMZ8/rB+XmZ3JKM+C3F7rQjQqIET
         OMvwTEyFy5Cy6I2Gx6wdlWs8A+VmIwCURIOhCcNObB/hl/YRDRRhYE/78X+c8jSe/BAe
         8APtgkYJJh62V71w23itr7CDWSwWeERooX/OECBZXy+wJ16FUGSIzIrf0WXKhYxX+1wO
         lEGkW2hkcxIYdzPmo5/N2GK7VtFW5AoEMxoH1E6LiRxlp1eQAWwwtUn9gNDhob3PU6rN
         HRBpIohFm7jP1+qqTPnwuUQweVSLbbCCQbq8D2MN9FQBOuF6kVRSRi/LWb6yRzCEdLzC
         fHBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=iBOYuNNy;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=lb5BHGJk;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tZrHUTOYSYUbYafSQDpOP6J6nsxt5tqphS6OW0pUJzE=;
        b=nND2vdP5rhgzBo031eJd3A7+7meDRULM5B1KYytYhUpjqv+nWMG3aB/132eH15U3Vy
         +jHJ17SLFaEPhoGAjD/j6xjLjTkpdbd8MRhymoW6CMPqYZ38Y2xrJtrYVzsu4kulKieT
         MTp8ZMxASOLz5JJBzp6dCqwc3m3XKZGVSVjEXcwi8Kutte34yItO/xCIUxlTqPSrcIj9
         dMPxFWL9YRhGKB56BrMeWnHKIm47pv5HR/plOSdPG3tm7wOJ1s9HiJq8gYeaARdp5PRn
         1zLig1xo7hgY38MsD+RM3hAy4S9OHpvkkfgru8YaQ23OglLjdJb0ltaDp1ovg+n6cdVw
         8Okg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tZrHUTOYSYUbYafSQDpOP6J6nsxt5tqphS6OW0pUJzE=;
        b=urlJBYNi7/Gvye44WmE2a5deKsFINRnKwE5GQdgWXAL+lMzc60wVeQGmt/cSm9Y4da
         FMWjD/YQC8dpraxB5x4ztPatj+/UluaczbZAltYIvrVjU5+ALYd2UxjuUqs1w/InosAz
         t+AH2cXSY7bVAFOBDGXFe5a2Keoiu8WUCymglfaV20Mva6hhz5OT7mT7XCGgl8T5OxYf
         +xxMzpalZi5dft1UqGMpuIr8da0XOwbi0mQVkU5DSILs292j1l5LqAKm8fx8S16q2qt5
         E0Z3V+wfT+fBQ/6oJGYki/u9/Maopp2dXRIZsneOYXfOYvh04L/QSS0N+C2JKn3WJnYQ
         8uDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kXT3PdIp50svcmEImTecQO0Rf1asGJflPkAex0K3W1Y2xJImy
	DhIB7RgN+QhOWFJERyVst0o=
X-Google-Smtp-Source: ABdhPJy6xB2GERdZ1R7Scfpf0OmPvNvpyAZLDgq6JTGqLyJA2UE4EOrTUiWIaJQXAE4/jPS3dJz7vQ==
X-Received: by 2002:a2e:8782:: with SMTP id n2mr6405213lji.177.1632415671484;
        Thu, 23 Sep 2021 09:47:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3746:: with SMTP id a6ls726545lfs.3.gmail; Thu, 23
 Sep 2021 09:47:50 -0700 (PDT)
X-Received: by 2002:a05:6512:3d19:: with SMTP id d25mr5393974lfv.35.1632415670548;
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632415670; cv=none;
        d=google.com; s=arc-20160816;
        b=GyJYVEWDnxrLIdSTUYnyIuzh7x4H71WJIQt6bWTMSG15evf9XKyYv4tKL57mbXVsMZ
         LTDb1NU/PiYsvhpuGUjbn/vApHdcy1R2cNdBuN5JZpEe05xfnryLSbBycHh1lrmB8hDV
         TS3wuYUnMDTvBQ3Zc/BqG9nO1SocVF2IBRqWnsH/SprNnKqCEC9cFBNaP+Ov0BooghJA
         amLpMM0Cmzyr81X40D5Gb3wxJfh5gckkE0hX4FMYtK/zSxrG0MeOqKOQKkHyskghoR0h
         n9mXww2pzsRT0gR+RDIu70bioBx1OZ7/wWKCDmmeHsMX3M0ceWuAobMaIeBT7JEDkUhq
         e0Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=2MhgQj1OhNDXz0bPvvBfoxg/NZ1WrouJm6NgCj0VKRs=;
        b=UZZcQu/6nL4nv3gzx/B9sU6jiDi2EADMBNrw3lPxnOqrHSM1VaBtbl9RpDr7ir5mIa
         6OiPIfaAXfbwBx5xtMs7JV5WBXVFS8yFaobRihnwTpAZI/+es9IckRVYDScknh/IS2hI
         HYdHtZSMdBGZhyKMCB/Q8SiQ+vDafIBSBn8w1CwxwuzEVpqKwH+SPH02V9WJcFHeO+oj
         t8xUGNt2t1XACrsSv6oRsFXQcIgP7+ddou9v10f56azzTgW+ivJKNQEbKhoMCiygLX6G
         Z5t7vn4sg9j65zq1prgUekiHxXLsIwNIdqT/Y0w/C2iJOpIXgncFxzP/N+S6lMzdM3Xk
         UN4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=iBOYuNNy;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=lb5BHGJk;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id e14si437771lfs.11.2021.09.23.09.47.50
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
Subject: [PATCH v2 3/5] kcov: Allocate per-CPU memory on the relevant node.
Date: Thu, 23 Sep 2021 18:47:39 +0200
Message-Id: <20210923164741.1859522-4-bigeasy@linutronix.de>
In-Reply-To: <20210923164741.1859522-1-bigeasy@linutronix.de>
References: <20210923164741.1859522-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=iBOYuNNy;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=lb5BHGJk;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
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

During boot kcov allocates per-CPU memory which is used later if remote/
softirq processing is enabled.

Allocate the per-CPU memory on the CPU local node to avoid cross node
memory access.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Link: https://lore.kernel.org/r/20210830172627.267989-4-bigeasy@linutronix.de
---
 kernel/kcov.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 80bfe71bbe13e..4f910231d99a2 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -1034,8 +1034,8 @@ static int __init kcov_init(void)
 	int cpu;
 
 	for_each_possible_cpu(cpu) {
-		void *area = vmalloc(CONFIG_KCOV_IRQ_AREA_SIZE *
-				sizeof(unsigned long));
+		void *area = vmalloc_node(CONFIG_KCOV_IRQ_AREA_SIZE *
+				sizeof(unsigned long), cpu_to_node(cpu));
 		if (!area)
 			return -ENOMEM;
 		per_cpu_ptr(&kcov_percpu_data, cpu)->irq_area = area;
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923164741.1859522-4-bigeasy%40linutronix.de.
