Return-Path: <kasan-dev+bncBCKLNNXAXYFBBAWEWK4QMGQEWY4TJQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id BF4669C03B3
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 12:18:30 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2fb58c0df21sf4806161fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 03:18:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730978308; cv=pass;
        d=google.com; s=arc-20240605;
        b=EAq4w/XRLsJXPY/MTrig1Eq5fVlMWbTLf3IcN1JdoLXaD0yeUHkD8aHmHQoxTcrJ0j
         lHH8lTBzs3EujFwCmdrdd18N1mnv5IW41PakkY2HZnOCZR8UeoxYE/R+6SB0+so86V6X
         A95KAbnlcMaApIkKp9Jnm7DHSc4X5dKXjb94ZCFLRy8Wt+ayI3Goy/xtun3Di/AbDym5
         fYjh8u/etFL6vcczX7S67uIbhxcanvq9zc5n5CnJcpQ1PI9jVej9FJZsFNu7qk+YJMOv
         Jz4IchFD4jOMjcMkGT170PebWSmcXd8CfgCPcrHJaKiTGHNfpnzHeIATV3o70lWhH+km
         KJLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OJgmuBLcgxVmatsIgyaTigwktAEpl+kOrwt7WkSmO6o=;
        fh=Mg7TOVUK5zlUNuzrUYvnsoQL0SGKLpABBYsxx0Z0fv4=;
        b=LYgG7T8IrOXMsSir8Wg2qD8NhnT70fQlmsjYqzaWu6QPfINP7PTlobTPxASCZMXKeE
         l3/kdsIGYYiu6fccKiJZx79UdQbDjSb4UQpJ5q2JMa98XWjRtkMmlpuNgG6BiAlrBZTH
         dt1X7jh4KO2+ViNnRRgamm/S4ftPRCB0REDkmadYCZeGJ1VQ/ZDjVoiMW7nQQTULGpAH
         8O/Wf5Ta+0UU0yBQ9cckIFlEOPAjGfQ4YBvduuNz4DepCxA2+IRaMNaOHdmYr+wr9+7j
         azmd1oMGSdD9FcCEgCn7oadHKyzWAXCR2OU/63ZxGRPmDtakX7gyhCzMEY3LE9JaBXNL
         v73A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=M9xvkSfR;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=KnxUBCaR;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730978308; x=1731583108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OJgmuBLcgxVmatsIgyaTigwktAEpl+kOrwt7WkSmO6o=;
        b=TC31vt+S+ByvLuT699Upcu37RW0a4lII2eg27a8qWa7o2ZQ6n6zbJoBUTrmxd5ary2
         r/BbGWmiQB3mjWh0f66g2kiaT+SylmVObxTKBuiMCB6pmw9i6wd6Bwx72Ktoie6JEH2H
         z2qpUucdr/u2lVt1C9YSWJR8LkbAIBbKSf0VZ+FsIA6nlKQhJuSGyYILruzhOhBsXtV8
         2bAOD8//HcVbFHp2+qY+GpP6YoAxWqki3mQuniYygA4F+F0BmI7zdVQfR+cGvDXRFThi
         EwvWv4lVuuvAOdtF34lZ/gZnv3LHAFFyW7rGZwBNNOxTutBxQ/3V+aTgQqmhtvTdUpJR
         tglA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730978308; x=1731583108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OJgmuBLcgxVmatsIgyaTigwktAEpl+kOrwt7WkSmO6o=;
        b=HylurOjLUv8tkWr06nOEb6R6TiOJeNduWXjPIwELLlbR4ggWAJosNiD8OcpyFAJr+M
         2oyx119xL1vaqBsrcZoaD2Ua56oJAZN76GWsmPyLYJvSLhZrx21dSpG/7k4LJpHO1KAX
         GkFmT04Y1p4w+J13j2deO5eVOMTFEPq/seetJKVc08wGObMpz8u0lDqoTQz7kyIt4Xxv
         rNSnrWI/pXx2pP0wIGSsC6FxrLP6rNzlGl3OEn+zDTgXJZlZ6KnQRf1csNOzVm6isnzL
         2GXVPM8uPnG1JbPH4/j9428gQg76g3mvCN3KfRzaLJHKXpfCHa3DxwXT03GiM1fwLx/K
         /0rA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwG2Z6V/gJr7TK3Ebkxo+YyOh8e72I/+OQWulvVvm3xoQoTKnnQ8XzpD3yHtnQ3tcIodmVVg==@lfdr.de
X-Gm-Message-State: AOJu0YwojREoY26zA2ZT/b4gG4MXjSZYEwusr8CrIPtrAAxPBQieF0cy
	872MzhgjP+FjPkeW1zScK+1Sl5GHKiX552SopgjT65u1Jqn54+gi
X-Google-Smtp-Source: AGHT+IFJqGhjj98C7I9hXqf+pvKe67ozkwy4/raELOrvV+siozdLA5cAm7I5nQmmT3WItTCn7Jj2nQ==
X-Received: by 2002:a2e:be84:0:b0:2fb:4f2e:5be7 with SMTP id 38308e7fff4ca-2fcbdfe4a77mr219834231fa.24.1730978306947;
        Thu, 07 Nov 2024 03:18:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d90:b0:431:9388:1f54 with SMTP id
 5b1f17b1804b1-432af02cc71ls3410025e9.2.-pod-prod-09-eu; Thu, 07 Nov 2024
 03:18:25 -0800 (PST)
X-Received: by 2002:a05:600c:4f15:b0:430:5654:45d0 with SMTP id 5b1f17b1804b1-4319acb104dmr401057585e9.14.1730978304687;
        Thu, 07 Nov 2024 03:18:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730978304; cv=none;
        d=google.com; s=arc-20240605;
        b=kXm1bhdaHY3OimwwsY47jXdjxWJDUO1h3+rUdNtV52iciJPraGSVHujMxP1ZMqQJjU
         gb/e037iClFGHLfmPuD4ahmOl8hppDAL7+IcYYYpSRxM//YQUBDCu2wtc7IUkcdMz7r1
         HfnBw+AxxHmpjA18RJgfEaVHxEtLq2I0N4zmIka49THgZfBb3QxF4ts+VdY+i2av7YQU
         s1qGNCOhzT6Tc7tJbXoj58IWMwsV6bXmff1s2q1xARqvxvpXK0NsZ6GrhCoBg2WRXgBh
         22RYzD1fj+GUDWWfmIp0ILIV4LaWEZnAcmsUNXc2K2w4km6qLOwXbxX6JrZnjQ/d31Kv
         3FJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=gSS1F9zfYFqWED7mnEuItD0xDLRRE+69aaEbBshj25g=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=lqKQ2sMWznkM2PBgoXRK+9BRjdDZnGDA1OXePDF+TnNCIBet6c5IjFv6l46hZkQ3e0
         ixaSBjyanwudPrcX5dgduZ4+ZniZHK04svBlMQFAUQt+V2vG5P0MV3GqHpRueKO9Tmw2
         XTDqL1m4w8VFkWS0MDIluvv+xYw5UWSGlxca+yq8PLFwFnsboCbZ3GB1VrjVVVYbPJ97
         +7Alj+VgPFDMNVzH71FPGykCjhhnQi5zp53368muEwxz+DhWMk1yY7Pi+N6lcmtnMn/y
         /CyTP0nc07wli6E2Za5M34dOBUlFHJKVSrLcWQr5sS181XHC6qMN8Nd0LB9B6eynXj2f
         Ba7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=M9xvkSfR;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=KnxUBCaR;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381eda2b03csi45048f8f.7.2024.11.07.03.18.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 03:18:24 -0800 (PST)
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
Subject: [PATCH v2 2/3] scftorture: Move memory allocation outside of preempt_disable region.
Date: Thu,  7 Nov 2024 12:13:07 +0100
Message-ID: <20241107111821.3417762-3-bigeasy@linutronix.de>
In-Reply-To: <20241107111821.3417762-1-bigeasy@linutronix.de>
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=M9xvkSfR;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=KnxUBCaR;
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
index 455cbff35a1a2..555b3b10621fe 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107111821.3417762-3-bigeasy%40linutronix.de.
