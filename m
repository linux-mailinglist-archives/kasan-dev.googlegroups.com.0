Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPZSO6QMGQEBDW6Z7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id F0D35A2B04A
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:17:55 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-54409f4aa7esf698079e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:17:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865875; cv=pass;
        d=google.com; s=arc-20240605;
        b=FjvrABUXiI2IQ+vmiolI2AIZSwKI11ahFaDe8qNAvNnkkEGYiqWIhm5NStP9FvBxSW
         v5cyiD/kta4reSJuuKBpCJxUd2dz+hGyWNpgDTJoZYGydRFz0ZqXMgHSxMDJ6SFg+Vrb
         TglK7VjBLdPqjOMWrvAYKn8rhhFz6yprP4c1ggoQj6PL3jRs6oD/bGFkyeRVuBsBYqeI
         LTzua+CkZ8lMWW8/4Q46Td0q5inGHijCURIYRPLHi/hl0rbBlVQhYIR2cyfkA4pU3fff
         4FR10PVGQ+gcBfydR+JaYG+JX53Mx3BtyK0pvA0ZVJSWsYXAePn46QCZcxc23h+yzOX6
         EzTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=wkclHPDY7kQaGKhJd0AWzytQz0Hz/d0JDz/+QvWLX2w=;
        fh=bDE2EX19xx6bjxWJu1tTZQBPV9vzNGayP2uPn3WZqTw=;
        b=aWdMHjyc8crl0bngWUjkKYs9asfP235QHN4rBI5UUctB4a/Mq383gvoD7WeB2iZzhJ
         TBWtCfif+pAsf42RUtyMwdR4FcO7VLcoJpRb8ci9i/TYpWbDd/w5t9Z4vvQ9AvzWt6Dh
         UMjd1brFfmuqCMFaVGGWMSzO2QiVgdnPm37UuHdv/VaBoNoPtfB5OLT4P51vzGxBump8
         TqdznvTS9KxhVrT+0iAgxwyQJ8O9NdnNK9M+hEg9Xan3wjBZr2FnnpDFs9il87SkS3mV
         01w5MS3W98JZWYi5ShIUW5475oI2rBLPHTAHDOk7Q5X+Ia58bU3e90sSBtBAq8SOaBCX
         PQ5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iE2i78gx;
       spf=pass (google.com: domain of 3zvykzwukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zvykZwUKCZ8DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865875; x=1739470675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wkclHPDY7kQaGKhJd0AWzytQz0Hz/d0JDz/+QvWLX2w=;
        b=RdSOlslxjAq+ApC3rsWww8/pliR2exVQkcUcFXbck2zrm+IExY0R2WxDwqtk+F9uL5
         HEJuSlp93R3OA6aBSRTGVT8ll5pJ8CpEXMIeZ0Jg+vFe51Bebi2PHqfrgUsLt3e+uUC0
         g3Rh8SgAHeG/PQhljPha+9lyT+NNts0I5z0FfVZjGtcMpEMA8wRuhJiqO5wTuUPtbGgS
         Qi7wTEUg4MpdVA1E148idd3Z7UIkfA6z4+I237kZ5GFKFILyapGfuRuRUQrSppSbZ7ae
         AJ8dd+Fe9syeLmAL/j3JyHx0wr+3a+bCKv6S2+k5BCju53JqR1g5zSYZQz/ZfhfdaWcS
         B+iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865875; x=1739470675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wkclHPDY7kQaGKhJd0AWzytQz0Hz/d0JDz/+QvWLX2w=;
        b=JH38/mQRi3n9BGvB79UlpYm1v97uG00uwjXrq3+wQSl9g3ofvWGH1dSufUtkOm08RA
         i6eXWDLjCMxqQoAC+zgf1D817flNOuUEzyGhVMh3R1PkIVCP+JVElfMTPXhKo9EvBXtn
         Y+9xBXwfJ4EnrUSXkESpPddtV72mcBf2xlGIdJeyNDL5sctdbNS/g5SiI8tJeSzN8Sgx
         eX3FPmfWatbPYSvZGyzUz2gBK/3NvfrhwAwwEEltwuPvgTLR2vuWS+J+wLbYNkB3jD1N
         TqDQulo0NSNec4VJMEDkNe5f1+Gh2+KIhqLYE9IoIqMqRuYmCq1wbBMpbJWvzUPsVTOL
         ojMA==
X-Forwarded-Encrypted: i=2; AJvYcCVhVjgrGT3KsbtceIg/2nlx1lj8L4hyF1p+UE9iIgS3Ox+yQf6Ngj8IP+Yhq6qBRAe8g2cddg==@lfdr.de
X-Gm-Message-State: AOJu0YwQ52gRAf7aNqUXzOadgXSyTaM7lEgWZT+K62MeuEpAFE4umukk
	1XvCCc/ezMnkIz8vg64cPd1jwYF005ecFjn3Ln9eeVLtC71jNS92
X-Google-Smtp-Source: AGHT+IHRwYA/eGaxbARZX4FRNTfnqWGS+/v2NGrElH9IHj2C2/74XR+h1+VBDfXhOPKJqqrmHX+Ozw==
X-Received: by 2002:a05:6512:3088:b0:544:1201:c0bb with SMTP id 2adb3069b0e04-5441201c5famr845604e87.2.1738865874018;
        Thu, 06 Feb 2025 10:17:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e058:0:b0:540:c34b:91fc with SMTP id 2adb3069b0e04-544142afaa9ls8758e87.1.-pod-prod-06-eu;
 Thu, 06 Feb 2025 10:17:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhCxHrqJR85hXnT1a3v9Q6R4gOP9HLAn40AucVG9vAGff6HhUii+VDc639YVH2rGlD6Gktdz5qEiw=@googlegroups.com
X-Received: by 2002:a05:651c:1548:b0:300:1f12:bbc9 with SMTP id 38308e7fff4ca-307cf38f559mr30267881fa.34.1738865871277;
        Thu, 06 Feb 2025 10:17:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865871; cv=none;
        d=google.com; s=arc-20240605;
        b=loFWwKHQDEdfB+A+d0AbE4D8M5gymVKQDJCsHCPHuRRYeU30mdZ6rj7vBv4hRwAQD7
         48rHexB6p0lvuhf/Q559VZ2eY9G4ZUrPNtGMsPEtyON48LzQn1ZDXK/WY9z7fSfrybnu
         pC8BcyDrGcSTGuvBHYzaMPePPXe/EsEWrz23Oy3bGGNVOJ1n+6sBs92YKZ6vgmrGiD48
         vtXAsshQ/u1U+NLdxdwVfrauscdE0Iv6rnd9JljdypMrIQDXIBTBfehRUnfDZ6Y3h43R
         oH2mvJjZmBRWr50Mjm+vAFXf09cr6eMWEytWbD/TcXYpIzRTJzQAluzW8HUqiooynoex
         GsqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PGmsmIsXIBV39eIxfDyWh+XEHePbJneD0pcTBLdRlSI=;
        fh=oq0yGqdWcyYlYaDqCujZFXDxPZzS/E4o1u7P5KvGhDM=;
        b=Ngvyq8lBeUHNyBQk4zZCGBZegTxcscm/BRTojkyreFPKOTG+2WqVrltuiCYIYnYSMg
         IB314qygdsQH7xTEY/J0R0arRlNDJR2FKjRRFR5ap0lBloe4fTowjx+x2glUn8YMxb3J
         dgEk4KPu04SUf1Xjw0Q8QcWr4Sos3m53bAalyX5zAMgA3pV88CnxoaiMp8XZLIX6DRm8
         2yTYZPL4Bx5k1t9rV6wgL4HiPgpwGa02FjnttShO1ZiNOtBnCS2rDErB9h0W89pqcmb9
         ZBpUK4uWYbe9B0feqvDsHDVHUus5mgfgsl+abZbi3HfURLnJENoGatXM5qo3ZW9U9qmD
         wC1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iE2i78gx;
       spf=pass (google.com: domain of 3zvykzwukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zvykZwUKCZ8DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-307dde4a321si333831fa.0.2025.02.06.10.17.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:17:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zvykzwukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43582d49dacso10355075e9.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:17:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZDeDzHfMcpGJSKtG7TkWWJW+CCYtamURnEP99HiC5msI0CrHxpGCHMDv4hOwRkoqHRa6yR4lManw=@googlegroups.com
X-Received: from wmbhg20.prod.google.com ([2002:a05:600c:5394:b0:436:a247:a0e6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1e15:b0:435:192:63fb
 with SMTP id 5b1f17b1804b1-4392497d02amr4329395e9.3.1738865870730; Thu, 06
 Feb 2025 10:17:50 -0800 (PST)
Date: Thu,  6 Feb 2025 19:09:56 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-3-elver@google.com>
Subject: [PATCH RFC 02/24] compiler-capability-analysis: Rename __cond_lock()
 to __cond_acquire()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iE2i78gx;       spf=pass
 (google.com: domain of 3zvykzwukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zvykZwUKCZ8DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Just like the pairing of attribute __acquires() with a matching
function-like macro __acquire(), the attribute __cond_acquires() should
have a matching function-like macro __cond_acquire().

To be consistent, rename __cond_lock() to __cond_acquire().

Signed-off-by: Marco Elver <elver@google.com>
---
 drivers/net/wireless/intel/iwlwifi/iwl-trans.h     |  2 +-
 drivers/net/wireless/intel/iwlwifi/pcie/internal.h |  2 +-
 include/linux/compiler-capability-analysis.h       |  4 ++--
 include/linux/mm.h                                 |  6 +++---
 include/linux/rwlock.h                             |  4 ++--
 include/linux/rwlock_rt.h                          |  4 ++--
 include/linux/sched/signal.h                       |  2 +-
 include/linux/spinlock.h                           | 12 ++++++------
 include/linux/spinlock_rt.h                        |  6 +++---
 kernel/time/posix-timers.c                         |  2 +-
 tools/include/linux/compiler_types.h               |  4 ++--
 11 files changed, 24 insertions(+), 24 deletions(-)

diff --git a/drivers/net/wireless/intel/iwlwifi/iwl-trans.h b/drivers/net/wireless/intel/iwlwifi/iwl-trans.h
index f6234065dbdd..560a5a899d1f 100644
--- a/drivers/net/wireless/intel/iwlwifi/iwl-trans.h
+++ b/drivers/net/wireless/intel/iwlwifi/iwl-trans.h
@@ -1136,7 +1136,7 @@ void iwl_trans_set_bits_mask(struct iwl_trans *trans, u32 reg,
 bool _iwl_trans_grab_nic_access(struct iwl_trans *trans);
 
 #define iwl_trans_grab_nic_access(trans)		\
-	__cond_lock(nic_access,				\
+	__cond_acquire(nic_access,				\
 		    likely(_iwl_trans_grab_nic_access(trans)))
 
 void __releases(nic_access)
diff --git a/drivers/net/wireless/intel/iwlwifi/pcie/internal.h b/drivers/net/wireless/intel/iwlwifi/pcie/internal.h
index 856b7e9f717d..a1becf833dc5 100644
--- a/drivers/net/wireless/intel/iwlwifi/pcie/internal.h
+++ b/drivers/net/wireless/intel/iwlwifi/pcie/internal.h
@@ -560,7 +560,7 @@ void iwl_trans_pcie_free_pnvm_dram_regions(struct iwl_dram_regions *dram_regions
 
 bool __iwl_trans_pcie_grab_nic_access(struct iwl_trans *trans);
 #define _iwl_trans_pcie_grab_nic_access(trans)			\
-	__cond_lock(nic_access_nobh,				\
+	__cond_acquire(nic_access_nobh,				\
 		    likely(__iwl_trans_pcie_grab_nic_access(trans)))
 
 void iwl_trans_pcie_check_product_reset_status(struct pci_dev *pdev);
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index 7546ddb83f86..dfed4e7e6ab8 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -15,7 +15,7 @@
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
-# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
+# define __cond_acquire(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
 
 #else /* !__CHECKER__ */
 
@@ -25,7 +25,7 @@
 # define __releases(x)
 # define __acquire(x)		(void)0
 # define __release(x)		(void)0
-# define __cond_lock(x, c)	(c)
+# define __cond_acquire(x, c)	(c)
 
 #endif /* __CHECKER__ */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 7b1068ddcbb7..a2365f4d6826 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2738,7 +2738,7 @@ static inline pte_t *get_locked_pte(struct mm_struct *mm, unsigned long addr,
 				    spinlock_t **ptl)
 {
 	pte_t *ptep;
-	__cond_lock(*ptl, ptep = __get_locked_pte(mm, addr, ptl));
+	__cond_acquire(*ptl, ptep = __get_locked_pte(mm, addr, ptl));
 	return ptep;
 }
 
@@ -3029,7 +3029,7 @@ static inline pte_t *__pte_offset_map(pmd_t *pmd, unsigned long addr,
 {
 	pte_t *pte;
 
-	__cond_lock(RCU, pte = ___pte_offset_map(pmd, addr, pmdvalp));
+	__cond_acquire(RCU, pte = ___pte_offset_map(pmd, addr, pmdvalp));
 	return pte;
 }
 static inline pte_t *pte_offset_map(pmd_t *pmd, unsigned long addr)
@@ -3044,7 +3044,7 @@ static inline pte_t *pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
 {
 	pte_t *pte;
 
-	__cond_lock(RCU, __cond_lock(*ptlp,
+	__cond_acquire(RCU, __cond_acquire(*ptlp,
 			pte = __pte_offset_map_lock(mm, pmd, addr, ptlp)));
 	return pte;
 }
diff --git a/include/linux/rwlock.h b/include/linux/rwlock.h
index 5b87c6f4a243..58c346947aa2 100644
--- a/include/linux/rwlock.h
+++ b/include/linux/rwlock.h
@@ -49,8 +49,8 @@ do {								\
  * regardless of whether CONFIG_SMP or CONFIG_PREEMPT are set. The various
  * methods are defined as nops in the case they are not required.
  */
-#define read_trylock(lock)	__cond_lock(lock, _raw_read_trylock(lock))
-#define write_trylock(lock)	__cond_lock(lock, _raw_write_trylock(lock))
+#define read_trylock(lock)	__cond_acquire(lock, _raw_read_trylock(lock))
+#define write_trylock(lock)	__cond_acquire(lock, _raw_write_trylock(lock))
 
 #define write_lock(lock)	_raw_write_lock(lock)
 #define read_lock(lock)		_raw_read_lock(lock)
diff --git a/include/linux/rwlock_rt.h b/include/linux/rwlock_rt.h
index 7d81fc6918ee..5320b4b66405 100644
--- a/include/linux/rwlock_rt.h
+++ b/include/linux/rwlock_rt.h
@@ -55,7 +55,7 @@ static __always_inline void read_lock_irq(rwlock_t *rwlock)
 		flags = 0;				\
 	} while (0)
 
-#define read_trylock(lock)	__cond_lock(lock, rt_read_trylock(lock))
+#define read_trylock(lock)	__cond_acquire(lock, rt_read_trylock(lock))
 
 static __always_inline void read_unlock(rwlock_t *rwlock)
 {
@@ -111,7 +111,7 @@ static __always_inline void write_lock_irq(rwlock_t *rwlock)
 		flags = 0;				\
 	} while (0)
 
-#define write_trylock(lock)	__cond_lock(lock, rt_write_trylock(lock))
+#define write_trylock(lock)	__cond_acquire(lock, rt_write_trylock(lock))
 
 #define write_trylock_irqsave(lock, flags)		\
 ({							\
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index d5d03d919df8..3304cce4b1bf 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -741,7 +741,7 @@ static inline struct sighand_struct *lock_task_sighand(struct task_struct *task,
 	struct sighand_struct *ret;
 
 	ret = __lock_task_sighand(task, flags);
-	(void)__cond_lock(&task->sighand->siglock, ret);
+	(void)__cond_acquire(&task->sighand->siglock, ret);
 	return ret;
 }
 
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 63dd8cf3c3c2..678e6f0679a1 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -212,7 +212,7 @@ static inline void do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock)
  * various methods are defined as nops in the case they are not
  * required.
  */
-#define raw_spin_trylock(lock)	__cond_lock(lock, _raw_spin_trylock(lock))
+#define raw_spin_trylock(lock)	__cond_acquire(lock, _raw_spin_trylock(lock))
 
 #define raw_spin_lock(lock)	_raw_spin_lock(lock)
 
@@ -284,7 +284,7 @@ static inline void do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock)
 #define raw_spin_unlock_bh(lock)	_raw_spin_unlock_bh(lock)
 
 #define raw_spin_trylock_bh(lock) \
-	__cond_lock(lock, _raw_spin_trylock_bh(lock))
+	__cond_acquire(lock, _raw_spin_trylock_bh(lock))
 
 #define raw_spin_trylock_irq(lock) \
 ({ \
@@ -499,21 +499,21 @@ static inline int rwlock_needbreak(rwlock_t *lock)
  */
 extern int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock);
 #define atomic_dec_and_lock(atomic, lock) \
-		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
+		__cond_acquire(lock, _atomic_dec_and_lock(atomic, lock))
 
 extern int _atomic_dec_and_lock_irqsave(atomic_t *atomic, spinlock_t *lock,
 					unsigned long *flags);
 #define atomic_dec_and_lock_irqsave(atomic, lock, flags) \
-		__cond_lock(lock, _atomic_dec_and_lock_irqsave(atomic, lock, &(flags)))
+		__cond_acquire(lock, _atomic_dec_and_lock_irqsave(atomic, lock, &(flags)))
 
 extern int _atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock);
 #define atomic_dec_and_raw_lock(atomic, lock) \
-		__cond_lock(lock, _atomic_dec_and_raw_lock(atomic, lock))
+		__cond_acquire(lock, _atomic_dec_and_raw_lock(atomic, lock))
 
 extern int _atomic_dec_and_raw_lock_irqsave(atomic_t *atomic, raw_spinlock_t *lock,
 					unsigned long *flags);
 #define atomic_dec_and_raw_lock_irqsave(atomic, lock, flags) \
-		__cond_lock(lock, _atomic_dec_and_raw_lock_irqsave(atomic, lock, &(flags)))
+		__cond_acquire(lock, _atomic_dec_and_raw_lock_irqsave(atomic, lock, &(flags)))
 
 int __alloc_bucket_spinlocks(spinlock_t **locks, unsigned int *lock_mask,
 			     size_t max_size, unsigned int cpu_mult,
diff --git a/include/linux/spinlock_rt.h b/include/linux/spinlock_rt.h
index f6499c37157d..eaad4dd2baac 100644
--- a/include/linux/spinlock_rt.h
+++ b/include/linux/spinlock_rt.h
@@ -123,13 +123,13 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock,
 }
 
 #define spin_trylock(lock)				\
-	__cond_lock(lock, rt_spin_trylock(lock))
+	__cond_acquire(lock, rt_spin_trylock(lock))
 
 #define spin_trylock_bh(lock)				\
-	__cond_lock(lock, rt_spin_trylock_bh(lock))
+	__cond_acquire(lock, rt_spin_trylock_bh(lock))
 
 #define spin_trylock_irq(lock)				\
-	__cond_lock(lock, rt_spin_trylock(lock))
+	__cond_acquire(lock, rt_spin_trylock(lock))
 
 #define spin_trylock_irqsave(lock, flags)		\
 ({							\
diff --git a/kernel/time/posix-timers.c b/kernel/time/posix-timers.c
index 1b675aee99a9..dbada41c10ad 100644
--- a/kernel/time/posix-timers.c
+++ b/kernel/time/posix-timers.c
@@ -63,7 +63,7 @@ static struct k_itimer *__lock_timer(timer_t timer_id, unsigned long *flags);
 
 #define lock_timer(tid, flags)						   \
 ({	struct k_itimer *__timr;					   \
-	__cond_lock(&__timr->it_lock, __timr = __lock_timer(tid, flags));  \
+	__cond_acquire(&__timr->it_lock, __timr = __lock_timer(tid, flags));  \
 	__timr;								   \
 })
 
diff --git a/tools/include/linux/compiler_types.h b/tools/include/linux/compiler_types.h
index d09f9dc172a4..b1db30e510d0 100644
--- a/tools/include/linux/compiler_types.h
+++ b/tools/include/linux/compiler_types.h
@@ -20,7 +20,7 @@
 # define __releases(x)	__attribute__((context(x,1,0)))
 # define __acquire(x)	__context__(x,1)
 # define __release(x)	__context__(x,-1)
-# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
+# define __cond_acquire(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
 #else /* __CHECKER__ */
 /* context/locking */
 # define __must_hold(x)
@@ -28,7 +28,7 @@
 # define __releases(x)
 # define __acquire(x)	(void)0
 # define __release(x)	(void)0
-# define __cond_lock(x,c) (c)
+# define __cond_acquire(x,c) (c)
 #endif /* __CHECKER__ */
 
 /* Compiler specific macros. */
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-3-elver%40google.com.
