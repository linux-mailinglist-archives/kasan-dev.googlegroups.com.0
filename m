Return-Path: <kasan-dev+bncBCKLNNXAXYFBBE6WW64QMGQEIRYASWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 37A6C9C1AE5
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 11:42:30 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2fb50351d18sf14089691fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 02:42:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731062549; cv=pass;
        d=google.com; s=arc-20240605;
        b=SgeooxpZuaeYw7iVoXSrF8M6sfFZzzxnlqjzj9wVdshclapDbxkqpHxvxo2YbFgvP/
         zhXFRQMTSCtogyNexYB0TGhvoaueBMxU1JPiUmuFpD75ay0VTbJU7GVcStxw449Vm2XT
         QFSTpid14EkSSxJG4RXYBp/U+WM/2y3hDEmOnzMM2CB1QiNY2rvmKm5zKKHBUBEiqrgI
         5p0u2fBKh4bsqsh857skvj8l6MQVCUWpZt5aNQjT3vjkg4f6g5WLFim8xCAF4eLT9AHf
         xYst0iGI37cOctwDXdBjhw/mdh/HFwkJr2oQ0BtlLc3Y4UwUXvCnTdaRco1u8o8tWPW8
         uNQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Zi9RG788R9c9yQcEeIrKLEQMUx/DOAHxj/EdyhpKqPk=;
        fh=Mv37udBXMV+RmsX4Zir3h0ASegK8JiVvmGmqOBZezF4=;
        b=ANlfBF6uP7WcSJnndZVN9nN8o0+Yuwv7uGOD5uuKX46ma+2GT7lQ2Cxe9HuGaywEMJ
         +JMOnhZtZpj1uy1+VuncGiXWec2/eZvQ6bS9cQZ3Xs85GKdiOx06u2emfwv2q8C2ms1J
         wOuddY2RvLrc9/7Z83r9z9lOelgANBZGQn8Kqg5HAaiJdzXQOJ/f6/Q0Oczq7WZ+HKkp
         59Q4kRQ7MeWvEBSvFa0J57vf1ZiPxvkXd/2Xl/Ei4HoI44fELoYLeEPSr2u/p5IGvrIJ
         0kvkm5/3mHBIDPoU2YJ9rydAgmk1aJuA+OTokgU+BcVazl+OZ104+jyUHynRkVccVlS5
         xEOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=kM8bbPnu;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731062549; x=1731667349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zi9RG788R9c9yQcEeIrKLEQMUx/DOAHxj/EdyhpKqPk=;
        b=SdD3aDBup8RXVnEXS2aBjCOQuvGSDtW3k453KfRNktJR4ZC5JZdMi5U42AFq+zHCtJ
         +iIGmJ0+FGit52QrvGauKQnBZZ/ZMLYJLHuNme2gAhgB55uQHBb179dqhZzdRFkQSqFf
         DcBDciUA+xBLZuOHqygbGCvBb1oWAQejhYUiqFT+8XyvqQYwnSgh7jDveDLE0eaFuuYd
         sSbZ1F39/geI/X4Lku7LV0wDIo2HYvtrLVtiggoS66Uj2Gu9R+l9hmPOd4rrZW+WGFfA
         83tH12Y7s5UQFgICaQOyDUVraazwi8SIljZNVH+7QjmjKNPvQ95IsBhsznbmW2heuV3f
         KFlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731062549; x=1731667349;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Zi9RG788R9c9yQcEeIrKLEQMUx/DOAHxj/EdyhpKqPk=;
        b=DsTzNsby/hLRd7rjtEZLiHFbg+vvxamzAtfVJ2cMuB3xo8set+MOorFotBVm8N/G4g
         hJRTpQhemQpFqYrJGZapgkyWIYJ8sIG+bOt36dahGeI/M1/ipmgnqoEicYZBqsMcXny6
         yne4dhSKpMLrWrH2d9dBj7yFs9EEqjN+vudPyk878Utwidks3b4/vzvGj/vYdaUXj3lO
         8bQQmqu+Cu6xxajCHquedBMqSVzlkUdkpm6vXi62C3hHEULBREE6BmVrwgF2Mqlw2tG7
         9AUxP9ugyLM9TUYSV58aTEKsM9QtbMaKJhka9Kd36CyweyB1jAzZUKa8RTrALbwdvCaT
         xL5A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUucGRioglVPfRNjGRYwK7vxnv93POEb+ZLuu+1GQbR+nUNEs9VGlqH28ycD+1r6eDodX9vxg==@lfdr.de
X-Gm-Message-State: AOJu0YyIqkP6SsaPpSGwCBXkfRw85lt8jUe5PXOEcMUnJIZ5ZrvNPiBL
	UaFaAL10le2kKSxlTLDWu53lnO6C0VFlxBPhZkY0puY/vqQ/ll68
X-Google-Smtp-Source: AGHT+IE1ciX9eARStbhjzFJ18pUopiyb8npB2zXHzCruEgnVeWVsi1kJCMjYoiaEAfzSDBgFIOIwCA==
X-Received: by 2002:a05:651c:1589:b0:2fa:d723:efba with SMTP id 38308e7fff4ca-2ff20162612mr10915551fa.8.1731062547534;
        Fri, 08 Nov 2024 02:42:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90c7:0:b0:2fb:5214:5c92 with SMTP id 38308e7fff4ca-2ff14d0c676ls5623841fa.1.-pod-prod-06-eu;
 Fri, 08 Nov 2024 02:42:25 -0800 (PST)
X-Received: by 2002:a2e:a58c:0:b0:2fa:c9ad:3d36 with SMTP id 38308e7fff4ca-2ff2016227amr11345111fa.7.1731062544775;
        Fri, 08 Nov 2024 02:42:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731062544; cv=none;
        d=google.com; s=arc-20240605;
        b=lF2oQ4yZf0P3IejS4vAoaTyTnW6SeMqRZKLKf2YFMa6gnFs+/ziSDU8veJnR+nsXkZ
         AGDOcScKpsMA7AKK3kTmj7O6v82Zeu0U6AJxYVfIGTAaFutPdn4gFul+SmRUII3PIGHT
         gCU1rbnQwogxKk+YHBrcWeNzjiGPwAUlQer5kwmRqP3dqzUOFmv6/PV+npBBrfOZvFEk
         LtWL5ns2YR0OqkLGR9p9dFRh23bEBltqPWFD65TQTv0U4PtImgd97W0KUlaUDSXLu8LP
         l+bavSOvnBzLKqSZ9VmZp3Q5CIKul03D9GEuODMObsDKd0EK/ubFuhm4EUN595lpMNIW
         7MBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=rPuXJvFylkEjsJn/hxrBzgh+RNHJWlCC5YCBuHj3y5U=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=R9bA2q7qMkfQAXgHKNvcHxIlxo4pmmVQ/bjLW/jXQTOYyCXMsewii723sctReluRIV
         V/zOiVN63JFkUyhHOIwm9l6L2vyIJdii2jB63ODJ4Ac8kHl6h2FbhyCk4y4UVj3n20tu
         K6+ENk+tS8UTHHv2yso/OV/vrukKJENP9SsncV6SpWmOnO1XSC6ZJ6lnzmNyrCz/Qt0Y
         QS14ZWD6Khe1N4i3L+I+nEW4u/KOr+dbbVsK1ybLzdvKVALe0PeCQ/lCY0mVQosY0Vhe
         DO4YreZUs+tBeLK+TBrczWcXohrJ54NLWJppGPku0QftaJu60GqhgCTm3FQhGZwSUcm6
         NryQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=kM8bbPnu;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ff178dbd32si863101fa.1.2024.11.08.02.42.24
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
Subject: [PATCH v3 3/4] scftorture: Move memory allocation outside of preempt_disable region.
Date: Fri,  8 Nov 2024 11:39:33 +0100
Message-ID: <20241108104217.3759904-4-bigeasy@linutronix.de>
In-Reply-To: <20241108104217.3759904-1-bigeasy@linutronix.de>
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=kM8bbPnu;       dkim=neutral
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

Memory allocations can not happen within regions with explicit disabled
preemption PREEMPT_RT. The problem is that the locking structures
underneath are sleeping locks.

Move the memory allocation outside of the preempt-disabled section. Keep
the GFP_ATOMIC for the allocation to behave like a "ememergncy
allocation".

Tested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 654702f75c54b..e3c60f6dd5477 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108104217.3759904-4-bigeasy%40linutronix.de.
