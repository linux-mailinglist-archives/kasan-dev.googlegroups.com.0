Return-Path: <kasan-dev+bncBC5JXFXXVEGRBPFKS22QMGQE6T4HOMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B93693E19F
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 02:47:58 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-44feda40d1esf288471cf.1
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Jul 2024 17:47:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722127677; cv=pass;
        d=google.com; s=arc-20160816;
        b=AywuvhvCZZ0JkBz0YGFHZU2tKdCg0pt6ud/l6cRDNFJT/OllAbGk6nXj/yqkcdLKi2
         WDuBtRHsPkeVLfJt5+t8N+Jl5BzKRwaFVBQUfx0Sj5yIS56+Tbpa3Mprjv4QxE88xS9b
         j95sx+E/lXizlCSaUVhNLFlRmJWMM5Y9WmPcd5pph1ODTugf8VT/TMF41AQpkYtu5qPx
         XAPDtLlu9vP2YMaRyV2s/jNM1mVcUkaAQxtF7/IuATnYAdaUy44yjJJ0LPr75A60AOQF
         FV3sOnWhGNGmgDBMTekL+7ZeaIsaf+JG8krKMOTiSyNE0EwmmX01+uHZTNGlxX4seoUz
         E5JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=q0KoJEp5sO/S63TI4KVyXJrj8jqR3cGshuVBdf1KH0Y=;
        fh=/AvU6qMNhjxiI1qcbai2bnulOzGyYKUAzGoncrArdas=;
        b=iPUztNnjvpe473vP4pwnbQpthGB8wkhv/mY2s4Z0kPhVMIebaU7txnxWMypG7PNveX
         qnLxKboQ1kphEvbedYUJoN7pDgSC4J+kome2vP7iw6p6nTMVFjH+jNhoY7xtHzlZcyjC
         n2wmWeRxvvjqF60KPTxZOZxBTRQ20OrHwTpTZGpDEaExSUB+Ub4QT2299owPp5OJd3gh
         RWTehVv7CBun21ljPG3kKz/JhywlN2v7bvKYtZohxmdGrlcxHgtNFPD2uvd0Mrd3Mm9U
         afFjypHjv8yvmbYGStVpxXVQAekcoy7xqD+i6JjxyjsLBV6OBS/nloUZRt5w4Rua1n1h
         Qerw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DQTiZIev;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722127677; x=1722732477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q0KoJEp5sO/S63TI4KVyXJrj8jqR3cGshuVBdf1KH0Y=;
        b=eGCPvKrEkDgZ8mrfZdq3jwT+lySUlzyPf4ReO6SZcGZYo4vbLziDAqXvAA9nS8vbZc
         Ab4/nlI1hixlC0hgpcCVgJt+NxXbDv3HVmCl0vP18FjOao5vruBK7x3d8JByO5AhHwus
         42rNztw07oHZazWJ3n6anVK0HHMmA4Z5OMOvLt3veA7WMK5Drn9125v/N0Y4xrSH7H5G
         Do0HPnMiUZVhYkR/KMokV6vYX+WiTt1vMoRCKVLM+LSs/Xfdv8aZ+u/q8Dp4y6/sdv7S
         cRYD0qvWWKtg5zO+F5ZZbrA8r2TuK70xwZE6OFc0qvEJRDeOmimjNJsSk+eeSNp92Wzp
         ZIuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722127677; x=1722732477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q0KoJEp5sO/S63TI4KVyXJrj8jqR3cGshuVBdf1KH0Y=;
        b=ftuOtR48lTIFFmMHw65bRgXJxWq8Lcuh8l9xqTXS423dRpKta5ENuylPckvLoIrTl7
         3Lx+VK9N/hGcLx+yshLmK7IlN6gpTc/sElrhHet3bDv0tOIu8XaBZdNc6RuL8YZAd7tT
         1xBN2/aQ/A9v81CYc4nxdXexldqOQ37JYSICutPxpR0Xet2oEuTopoCLohE8R5YewIZo
         VFxkh60zzk5Z7S6/8npu682QVgBiL2C1ACOxciRN5FR8QFk3bzrcgAzC8STfk/JxI0y0
         lREYdMnrO78R88GEMdRT6gKM3TFuQu6tegbBX91dut+idN7pBe0RVBett6h/INUOD7Ac
         bFng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEqY7LH4Nwpf/KuDUUO6cSntwo7eG7FUl+H/RpmbxGr4foGlCbIFq32Y58D3h41GQOxtt5FEzYceiQ2XZeSE8Nidiy8DBdfg==
X-Gm-Message-State: AOJu0YyNOZAIPq68dBtSq0eYRvTQJIjq6CNkvr8db61rc3kYVXKV9JDA
	zRiO06vwtRVBiNTgsh5E4koXoGHW+YJMytjOw9rGrSmsDEAyS4Kc
X-Google-Smtp-Source: AGHT+IHQP7bhgSf9CH8BBpwlF4/SA+Vxn6EUWvrC6mdP15ZYJ4ruQl5HJ529/XgJFmtvP3AN4lHPEw==
X-Received: by 2002:ac8:7c41:0:b0:44f:ee20:d189 with SMTP id d75a77b69052e-44ff3a6e992mr6724261cf.8.1722127676495;
        Sat, 27 Jul 2024 17:47:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1a0d:b0:6b7:94b2:b11c with SMTP id
 6a1803df08f44-6bb3c2688d7ls62845946d6.1.-pod-prod-00-us; Sat, 27 Jul 2024
 17:47:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/TGX5Maw2sYgBM6TgNb6N10gSHJYHh4FiX5NdcuNJr2NBik0INRp0Kv3OU4lurgAzVQZ1qpuvhJxkmS+LpNdLPfvSyhUAYj7fsg==
X-Received: by 2002:ad4:5c8b:0:b0:6b5:82e1:f89e with SMTP id 6a1803df08f44-6bb56302af8mr75251746d6.9.1722127675870;
        Sat, 27 Jul 2024 17:47:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722127675; cv=none;
        d=google.com; s=arc-20160816;
        b=Nn5q+9mf13Q2878igjh2CCN0HElMiC0/2TdR42j3G3gOdeyc3qKLjTYIsBdVqfCr53
         c1XiGN28jBShppFIvzHUvVcjEeSuWR4f3aBGNkUId+r3VordRspps1RgZnPVhIEjvsKv
         Dfc4w6QrHr9IakYb/KZzN2PfbyK/j+e2eKtHdajsR1HPc5lFbee6YaAn7iRnQluj7R7V
         XzmmS4Mvmmz66DxoJxf8HDtvvQ52yLAbLcdDc/VFjm5lOki0bnKasaTzIer0qlawnq0X
         yxfj656JNJ7KZfiMXHubLPoGvxc0zKSnth7ZzYYUOk1zT1ArFpnhxEAoOkbfZIXIYJ4Z
         ewkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WRoATlY/hIAiGcrvmHBpJ2oFbRTIburpzFN5XxgLbZQ=;
        fh=NHFfq/j/rWHP94bByHknyzKqAJRJzQrt4qr9AibEjk0=;
        b=bCD4Bx3NJD9sWsNo8X9DxQzvcm6Q1lVISMVdCeML1/ckOiBfUUFfqiuAL3F9WkfZ13
         tyjAyQGMFNlDoIYPNkbRX9ZknTKc8XVRB/AT4X6MfmWZwuBQ5Nwd48hKxN+beAknlmLV
         uaUopspY/i+wgsnKCupEMYMG5IJ+ClM//i9LMO9egfA3Nvw/EbMUziCVbQSdsfg+H18Z
         84v0Aj7boW+/DNaC2izuADny7j1B0S/14rABxd9+Mgr6K6vyaX7BrJSfgXxxcpnjKYkJ
         D/rmBbLeDb0UEpSahyfC7pnu/PhrRdBsSgLo/H4uL1iCLASdze4/nsFtbLnKG0OQAxZZ
         w/Uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DQTiZIev;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bb3fafa1a3si5045666d6.7.2024.07.27.17.47.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Jul 2024 17:47:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5FA4F611D4;
	Sun, 28 Jul 2024 00:47:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6117AC4AF09;
	Sun, 28 Jul 2024 00:47:53 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>,
	dave@stgolabs.net,
	josh@joshtriplett.org,
	frederic@kernel.org,
	neeraj.upadhyay@kernel.org,
	joel@joelfernandes.org,
	boqun.feng@gmail.com,
	urezki@gmail.com,
	rcu@vger.kernel.org
Subject: [PATCH AUTOSEL 6.10 07/16] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Sat, 27 Jul 2024 20:47:24 -0400
Message-ID: <20240728004739.1698541-7-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240728004739.1698541-1-sashal@kernel.org>
References: <20240728004739.1698541-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.10.2
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DQTiZIev;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
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

From: "Paul E. McKenney" <paulmck@kernel.org>

[ Upstream commit 6040072f4774a575fa67b912efe7722874be337b ]

On powerpc systems, spinlock acquisition does not order prior stores
against later loads.  This means that this statement:

	rfcp->rfc_next = NULL;

Can be reordered to follow this statement:

	WRITE_ONCE(*rfcpp, rfcp);

Which is then a data race with rcu_torture_fwd_prog_cr(), specifically,
this statement:

	rfcpn = READ_ONCE(rfcp->rfc_next)

KCSAN located this data race, which represents a real failure on powerpc.

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Acked-by: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: <kasan-dev@googlegroups.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/rcu/rcutorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/rcu/rcutorture.c b/kernel/rcu/rcutorture.c
index 807fbf6123a77..251cead744603 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -2626,7 +2626,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
 	spin_lock_irqsave(&rfp->rcu_fwd_lock, flags);
 	rfcpp = rfp->rcu_fwd_cb_tail;
 	rfp->rcu_fwd_cb_tail = &rfcp->rfc_next;
-	WRITE_ONCE(*rfcpp, rfcp);
+	smp_store_release(rfcpp, rfcp);
 	WRITE_ONCE(rfp->n_launders_cb, rfp->n_launders_cb + 1);
 	i = ((jiffies - rfp->rcu_fwd_startat) / (HZ / FWD_CBS_HIST_DIV));
 	if (i >= ARRAY_SIZE(rfp->n_launders_hist))
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240728004739.1698541-7-sashal%40kernel.org.
