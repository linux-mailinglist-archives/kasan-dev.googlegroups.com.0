Return-Path: <kasan-dev+bncBCKLNNXAXYFBBGWOUK4QMGQEAPRKA5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B91C9BB189
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 11:51:08 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-539ea0fcd4bsf2789992e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 02:51:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730717467; cv=pass;
        d=google.com; s=arc-20240605;
        b=g4Sq3ecuzcE2DyE/7Ss+YjzGy8rAgsvTeTs/DZoY/SRItfG+Pms1d1X+1mFi84hIsR
         uhBRB/l5onBzP/XsMgwKIUD2BQeYOh4dLJcJYjrMLFqsZ19aCKmUS7kJGycd5IzKM1F8
         E++98cq42Zq2xIIdL+qPHxCW2gkdcVQP+PDqkCamZKE42QS/Q3wEujeqXPxp+dvIJgQL
         3GR3S0MVXjSY5Q1m88LetZZ4dIr8hM2rHjHakQVKAIx74bgk6x4VQT9+mqY27fsTYH+q
         BmcrtmKzVTeKMgmyM2uPCt5dp744SEXhyaw3/ma4FTjqrXPYtXGgyKuP1xomCvbf7eyK
         huHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AbLLqtd5zyuQEyrPn/416+rs34qrA0tXMMkpAofgxbA=;
        fh=4TE8WbkCUiywxfnjzzmCCxsvZ4IebcUP+J61rR9gV5E=;
        b=E/HZMyPu5tXk4VB+f9oxCH5Bq+YHMpqKZ4kiSq+5Nza18UeHHe7c/GHyixoO3EvBcc
         sWbCu1mt/voRqoiFad/GpWh6ta0QA1LCkpZeNECAPWHFmA9C8OKwM72kJPGWrPRE5Cz/
         fLMHhJVG9sryePW9ZgM3SXrt7uc6EWEO6zfWC3wUGQTnLbt46daSPQLq0UPTtEOJqbFX
         MdMTxlqDSLpwJ8NwTJ1C0ltWEL8nkbHHyrCKZvCMzy7xyQbhGBNv+JktW9WYgmMuoGEg
         1RR9NG9GhQz884GOmdzPggT4nC0rub+ES7WWGbWJF54go61EHiNGqA6EIvhzUYpg0QFI
         yDBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=bqSJbLly;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730717467; x=1731322267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AbLLqtd5zyuQEyrPn/416+rs34qrA0tXMMkpAofgxbA=;
        b=KTrPLncQ6UBfZaqqhT5XzX3INZmDykZgtcj6bWXiVPqqOQPwOp3N+xoz3Mevhxm3aS
         5LxbErpCy1e8D+QGv4taFtVe7HkvpIQj6iDL9eSOUCO3mO6lmLpydnhNielDUn3CHVxF
         iOk2R8Ne4EkocSPmrrq++riyMaqRmAZVqnclmzVJD5HgpAekVJtWPSzMnf5MGiTwoTyg
         8tGkJIrIt00cecbzF8o0YzM4eUqZFTIXAcvMeEBju7+KfjCDtNVwYCsIJr4ROIzCP9gI
         oJ/5L/m9Kq/Cn6GkyjV9QCz1FL33bo2R5g3TMY2oDNWUcSRFLMfXMgyQMDW1vhTcThP6
         tATQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730717467; x=1731322267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AbLLqtd5zyuQEyrPn/416+rs34qrA0tXMMkpAofgxbA=;
        b=MnR2JM/H94CFeVA07yyS5dN9wgkJdej2vzloNIZhPfmPLDuQnfi7bxXkMtpCGhlZHr
         3IO7dYzKUA+x3WDxqEPLIBX3tLxtX5PNUoq5TsM5cZG1KQN+RSuTE0rt95sCQXiovhAJ
         gs+OkmpkMVcqET6FTtz7m0MMzD5Y2oIKMWOrruYfkHonqPZRt5lcF4qY1jGFwasQKPlE
         tHpROacDN+GaOtpqjPGrSC+5p1OEqA8cuXbAP2KyixvswuAYWK0ow8pYxRksdR40D3vz
         hJisa0LGwlvIZViYOXDCFviiuyeZ9qKTssVkiyzgVHO37ZcoqrqN8PufjuplgDJFA5HD
         4D5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0cXsYRp8c47fuzn06QUiQt2Ja01hKBuKvszpM7D7QoTKALkimfbIrztqn14YXYhJ20WUhyA==@lfdr.de
X-Gm-Message-State: AOJu0YwFWdSOyuX6N0OvxPik7ky7YRhOXfrb11peL6w+xsTYg7xUBvyw
	fT2FFKOWTSBSEL37Frsw4gVvgojddZxQ1hQUHFM6arM6uu+bXv28
X-Google-Smtp-Source: AGHT+IEjt83vvbH+G9vNWaX9wWEpZCVVYsE5EwsX9u6cGEX1hWC7Pc6QjyosPqXDX2AU6AiILiL8+Q==
X-Received: by 2002:a05:6512:15aa:b0:539:de9c:c8a4 with SMTP id 2adb3069b0e04-53c79e3277emr7536715e87.24.1730717466860;
        Mon, 04 Nov 2024 02:51:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f04:b0:53c:75d1:4f2b with SMTP id
 2adb3069b0e04-53c7951daa8ls790568e87.1.-pod-prod-03-eu; Mon, 04 Nov 2024
 02:51:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU/UW/JNFHX6ijZe0iZWHgPMZNd84nVOm8/Fa5zF+pwkwymTc/gB1anOKom0JsW/CemdB69SmCTc9c=@googlegroups.com
X-Received: by 2002:ac2:4e14:0:b0:539:964c:16b4 with SMTP id 2adb3069b0e04-53c79eb3041mr6220929e87.58.1730717464288;
        Mon, 04 Nov 2024 02:51:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730717464; cv=none;
        d=google.com; s=arc-20240605;
        b=iaQY7GmRH8W0QBa8G+zN6l9nWpPk9uzdmOr2hYWW1Ew2G2ud5kPOkRXnH7TkqTEzy6
         4B7bAsW1gh2oq85tNqibeBQIKAeGTaDwtOk9UG6+T/OA6SLXJ+xXB/ly66NTckwhfaZy
         HmMP+F8dtEQvBdLNTtyu3Kt3U1q28mhXPGA8Dl58tiNPsdu9LH8gGV6pxkCJj0Wou8+n
         vR707JQ9CgXwaJCAQp+EshKGboDXxqr80Fp7pWtTKD2YkaY6o6I9rtPJvNv8hVkkCPsW
         TaEvZlU1ApiWO+Anh0AtpIbbjvHdQsH8kHnFciWq/MjCVbJ3SOZ7boI53VYijYTcKnE/
         ET8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=ktKI//sMmnnCjs54hJYaz5s5ts5YF9AmvSNM3G4N7f4=;
        fh=nGK+SoD1ex8by9wamSKwhZcZoH8mNV5YxsuUiQLVlHg=;
        b=gImJ+SL7jjJkix8MngacyVA4egBPQ+cCChPTkSryYWKwpCO7t4nR+hK9xGyTRgPMmv
         uTJohszMPGdSBeezH2mK9Gkte+mTshxQ9FKdrsZmLzQbCgdCh7j4gTtpPGoIMl5/UL9u
         fPCWoAfHJWpNdyN57IemLhSkZxLJFuP0w4WMu3DfFtzJ8s+42Xa2F9acPQkH5cbQq9oj
         iJTkQ3ruqiPTWZAvvj2dWhEMelFSbBuqqDcGiG7jiYf5eGVAn+GICOveWouf5nix3fH8
         0Mpe4yJa+MPqqIsUEhkh2GBva/qbp6V87FMAIlKJmv6RCtMXMGT1zpTWMk0l4+p7rZBh
         /ZSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=bqSJbLly;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bc9623bsi174497e87.2.2024.11.04.02.51.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Nov 2024 02:51:04 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Boqun Feng <boqun.feng@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	sfr@canb.auug.org.au,
	longman@redhat.com,
	cl@linux.com,
	penberg@kernel.org,
	rientjes@google.com,
	iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org,
	Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 1/2] scftorture: Move memory allocation outside of preempt_disable region.
Date: Mon,  4 Nov 2024 11:50:52 +0100
Message-ID: <20241104105053.2182833-1-bigeasy@linutronix.de>
In-Reply-To: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=bqSJbLly;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
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

Memory allocations can not happen within regions with explicit disabled
preemption PREEMPT_RT. The problem is that the locking structures
underneath are sleeping locks.

Move the memory allocation outside of the preempt-disabled section. Keep
the GFP_ATOMIC for the allocation to behave like a "ememergncy
allocation".

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 44e83a6462647..e5546fe256329 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -320,10 +320,6 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 	struct scf_check *scfcp = NULL;
 	struct scf_selector *scfsp = scf_sel_rand(trsp);
 
-	if (use_cpus_read_lock)
-		cpus_read_lock();
-	else
-		preempt_disable();
 	if (scfsp->scfs_prim == SCF_PRIM_SINGLE || scfsp->scfs_wait) {
 		scfcp = kmalloc(sizeof(*scfcp), GFP_ATOMIC);
 		if (!scfcp) {
@@ -337,6 +333,10 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 			scfcp->scfc_rpc = false;
 		}
 	}
+	if (use_cpus_read_lock)
+		cpus_read_lock();
+	else
+		preempt_disable();
 	switch (scfsp->scfs_prim) {
 	case SCF_PRIM_RESCHED:
 		if (IS_BUILTIN(CONFIG_SCF_TORTURE_TEST)) {
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104105053.2182833-1-bigeasy%40linutronix.de.
