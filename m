Return-Path: <kasan-dev+bncBCKLNNXAXYFBBEWWW64QMGQEUIV6WEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B6739C1AE3
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 11:42:28 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2fcd9765852sf11835611fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 02:42:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731062547; cv=pass;
        d=google.com; s=arc-20240605;
        b=H7UMEZKAB2pvCy79VFrzlyfQCGBX8TKWfaJTSb1zaotxXMYk/FHOTeBvRLMii+3mEf
         ZZm9jVcM9CYHEUan19qwRUL18MFN27hB10lizOGrjPHc51Thwi4TebYKiu21sVDp1YV+
         ND8lhw6W0ZAxjsuUrNnytIy4tR7yi8Ljkly3obKaCjkvZXWbl415fXYRfg2pxU+s12Zg
         CWkE3XeTKwX+AQQdVUln6fq1mcS8IkLiBAmEPcazCescDDouK2RSkoDJ7qKAPRPrp+0n
         wQBpYfOrJItrPsq6NEkhIY+HFNSLLwL+zUZj/33DycP6vkL5MINpQCbd4Zh0+d0/elfK
         gE6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KTWamw3GNskXy5qpE8b0XKKEMYfISYL2L01LvL2mESA=;
        fh=SF0535CdsvisEeXzWS0GN7nsSK0ShNkF+Sv2WksCpNw=;
        b=cEiu4UuFWSYXtAu5jaAlWBLC2axn9ru3TcuVEqv5fjlEDDYgrDlJ4LotifZouGeNRA
         Byrk+lhPP6SeXeE/OM32wAYMxbdYAbwsXro9bL1SMSI3+dqxYmhzrXe4FkYVHpov+UiO
         1RCDbVdOcgMu45RUtKiQdUS00xCB9KfKoNoS5gAT/o1Y6pBmT6QHaDUJTXDrqd4VIkAt
         /5BzSONpomznqTaJxg9kbMIYlocrc44+qCTlwNIEP9xJhXB+YwBZu8fbK70z+/BI9HPe
         Xuowf6E3+MkO0jtS6nVriWDJei5a3Vd15TbBRxOB+gbQu40qhWNoGV8QanqF4La66RYJ
         ybHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="aHiJn/o/";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731062547; x=1731667347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KTWamw3GNskXy5qpE8b0XKKEMYfISYL2L01LvL2mESA=;
        b=giOrwB92aVktPpk4vmY7yMUbF54R1l0GPKuAXuk889Qs7S8EOh73RavvCCfw+xG3NS
         vP30JLZbMI7r/bhjRSKx8Da5Gj+LttrgVRw5mUuD3a+JXKYtjHjh+c6Ybmc1QwN9etP5
         gHpvvYUSXeb1591DR1eZ2u1Dq6jB8eQlw5OksstSZT/eiYZUVofkHSNXyo/8jI5LazYZ
         1FKn+b7wyhGvVqw00ZTI2tl/7E5cYV26xL7IugNLIEg+nyWsyw4oYOC/eQiIiUeYED7m
         5w1a3zbljUODDnDmXrgIHeakycm4S09BTW5eMupHEHvFYNTxK3BXQrwbmbiKR693MmxS
         WJMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731062547; x=1731667347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KTWamw3GNskXy5qpE8b0XKKEMYfISYL2L01LvL2mESA=;
        b=VtdYWwz6lH/2WYVYtpv+eNRxiIZEhJsvC8DDFe/27cPiT3cDEL5in35cVp/7bZI2fc
         TRk0GZM/xPWPIInBDEi/bvM5qrcLNY6Qb2fZ5155q6dsCTIh+nbzgXcsvIY3jVGIq+UB
         Ja1h16WW75X4Z+gx0tv4gmde4bNNyOv5Cret2o1VRY2IRCAyhfJVJxhZ9LXLIm3BwJ8O
         mVrEOAIeKN2UtfwDYNARigcTBPyYKGkf/pJK8FDuuN/5orDP7ysVCy/wJlxf/gUHecrZ
         JpxVXfs+Wkk2GMc+8t/HlRr5rDNkDu80XyvAkTEFXLM0TKa0ivWbnfdWAkV7t3PHCalo
         qszw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvbHsMn/CtHF1QUHnxFI9uJorCyZeh3i1LK1Ct48T7vSsC7z7S/7iD2efqCwzjFfGCED7i6w==@lfdr.de
X-Gm-Message-State: AOJu0YxDMh0iaL13vGX2/nJkg89x7a7SaefyrAiIpXIe6OV4iKS22a9I
	fAo1v9GB3MLgi7LMf+Wd89sUSd0uF6ZsHQp3N+yuRJ1E2AMHF0hh
X-Google-Smtp-Source: AGHT+IFB3yA6XHvaDN5JkJYt97YvN7uOobByyNsrU5jL55PrSZ3WXq5uKT3NRPx3bgtWfJfWTVX1oA==
X-Received: by 2002:a05:651c:160c:b0:2fd:e3ed:a360 with SMTP id 38308e7fff4ca-2ff20309b6dmr12870471fa.37.1731062546908;
        Fri, 08 Nov 2024 02:42:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ed9:0:b0:2fb:5304:f15 with SMTP id 38308e7fff4ca-2ff14d4267cls4561011fa.2.-pod-prod-01-eu;
 Fri, 08 Nov 2024 02:42:24 -0800 (PST)
X-Received: by 2002:a05:651c:50b:b0:2fa:d4c1:3b6b with SMTP id 38308e7fff4ca-2ff203098efmr12346381fa.33.1731062544115;
        Fri, 08 Nov 2024 02:42:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731062544; cv=none;
        d=google.com; s=arc-20240605;
        b=X79xpXeIBPvoMtXphT/4iQPCqcKEsmM4WzUKXcRLW2Ztqw6OnfAG2LBZPjzOR23tL0
         Ziat06tURz95QCcV/GEqfFENxlQFfgOHgKfJkNRpTbWSUKaDVZa9OAbUjb+IOwBL4QfU
         BZDGSNW14lKGijKr+6a1k7F5YvhKOM32fYXxOmEg+LXc9PqIyOjaAbBCoSU14M0JSh5Z
         qtk3vPnvjpj5Xd5nU/OV8lubeGIrPCsfwPNyE/2UH+5N8JzCJ8YHe+MWSbYhVeSLWTvf
         ydc7lJIXdTsCoIZbl1T+p75Fyim1Nv0EvuvkrnGI3b12BHUrLAY0DA+1k1h3Ve2IpDVO
         kkbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=CcYB5rXKKViOk7fZRL5jGg/tydDAGzhBkw56NFEZwc4=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=BrMYS+iXHvblL9EKUbpLYC0kxg3lo0NpTitN2DvN0Tw9Y6nNyQEL6sd6TOed5tKJnt
         mJJR3Bcyxgr2UDWwceWl4HVItsGIf4APcvcxw2VFwHNgPgprUW6iWZciu1o6fW6AiClQ
         PKcVXCwXFdjj9DcMPMeHw0EDJ9ztxrCdT0RwUygqYjZLnzpAck1Y+yAY/CMO8hazwOZS
         wJdh/5BbQeN676vJpJE4IdQBpz7fTDT2AE+iZEyIZXo7jtaob81it51RyrxksXT7eDmE
         lxozQYqm4s3w4SKD3Fbh85C8V+TRm6gu/J8BTBd5Kh3sdi0gxlUsvFCea2WirTv6eM43
         bm+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="aHiJn/o/";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ff179d8ef3si778781fa.8.2024.11.08.02.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 02:42:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	akpm@linux-foundation.org,
	cl@linux.com,
	iamjoonsoo.kim@lge.com,
	longman@redhat.com,
	penberg@kernel.org,
	rientjes@google.com,
	sfr@canb.auug.org.au,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v3 1/4] scftorture: Avoid additional div operation.
Date: Fri,  8 Nov 2024 11:39:31 +0100
Message-ID: <20241108104217.3759904-2-bigeasy@linutronix.de>
In-Reply-To: <20241108104217.3759904-1-bigeasy@linutronix.de>
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="aHiJn/o/";       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
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

Replace "scfp->cpu % nr_cpu_ids" with "cpu". This has been computed
earlier.

Tested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 44e83a6462647..455cbff35a1a2 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -463,7 +463,7 @@ static int scftorture_invoker(void *arg)
 
 	// Make sure that the CPU is affinitized appropriately during testing.
 	curcpu = raw_smp_processor_id();
-	WARN_ONCE(curcpu != scfp->cpu % nr_cpu_ids,
+	WARN_ONCE(curcpu != cpu,
 		  "%s: Wanted CPU %d, running on %d, nr_cpu_ids = %d\n",
 		  __func__, scfp->cpu, curcpu, nr_cpu_ids);
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108104217.3759904-2-bigeasy%40linutronix.de.
