Return-Path: <kasan-dev+bncBDBK55H2UQKRB36MQGPAMGQEA3JMCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B77D6668010
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id d14-20020a196b0e000000b004b562e4bfedsf7277573lfa.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553520; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2yRtWaPwXneTSn11Dej8EAhFZshyl3jM4nj+/HdaVQ/U/uMJg0R9cIN47YLeHzTiv
         x1cYCDnxHMgRmtjGp23kg+/Vits+mbCOSAIwIquhpobUB9852pU7LNUbqaBKr5bozpKT
         AjnvJud+Jp1KXBlnmPpQlJ2da6ymOaRzhYCZ0Jep8praV3kOVg4EIHgZJsnLeEoSWLWk
         PL0ZMEOLpqyjGQQf/ZVxfpRH1ZzGVT67qWkZn+WYblYRJcFhwfTDvUR7l0jJ/rpPkL8d
         KMbhNDAnc81G4tGosphJX1hI2rmvDYlq5dJDKYaowdaxwIigIaiuHLmfS0fgPd6bK6xS
         +3+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=975SThDOEchBQweZ0VZpC05uoDquWjL3268zKFTu89g=;
        b=FnlWyJKICCnDs0IRFgLc1D5o+Cg7Z1OYbAz9kc4UEuM4nUHRPxDNpGB9yPgm2Lsg7P
         Btp1B/zQNLIJcoKIrFR1t1761PnKUg3dbFcez/LsgJlAoEFStYbJYbYojfZ66BImky2n
         l3GGSlAU9OarC7zpHD/ihzjvlnkmw+zaHOdITRKs9il/aN9IQ3clq0J14r1Ko9lQ8W5E
         nIWFHJ9h9uFYhotWeIY2Xf5vUtK+FqUjfOIBlAYy94xMzOFqxZ/iAV7KCFVANtENcv8g
         6i9NC+jZcw0A5U0JPcv1tI0jvjGfEahavApk4qWkeoFNDnFAfB2L0WyEd5VDd8fpzggV
         do/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=CDjE30SH;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=975SThDOEchBQweZ0VZpC05uoDquWjL3268zKFTu89g=;
        b=qw3zzcYluKQkIRX9shlgr50K1n0p0KlKUaApDnd/UGrXXhyhm5vAXlZBZP/XDSDdT7
         7LMhLgSW/KgAMG7lJP/CUlImuX+ekM/KQ9t0stKtcj+Pr493O3m82Vzaa46FNdLK+b4J
         3k3sJ0k3xRn1aGKzkMEfT2uGV0MUpBgHZEWP8wnv6Q2bn40HhhHeuLexwVs0wcnmbEZY
         vfYqF+FyLpZlzp+irMgSN0NgcX2Yyd6DM5VMEjLHmPLWw+NQ0uHpHp5ucK99To3vqbbK
         vQ637/1m7swoQq/MYn1sskf7UJ9IxAEzoyGySCRsAw4LEeazJhWwfEk4q0XCfu/76rJH
         Cijg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=975SThDOEchBQweZ0VZpC05uoDquWjL3268zKFTu89g=;
        b=GBVXBSRaZ1riU2bpgZauDwpbwATi9TU4MUDf7T+WfHk+VNyJ+UDmUKV6/iWdP+258X
         dCKeb98CP4oQzMXDhFvla4SteoAJK/tsVeq4YLAsGh1ne1dr02M2VZ4GFuUEG/AWaFsF
         iLixHAFndhm1DE75kbvfGY+781MRdjt6PbEoAeEzVA4dgENxjUXMwOAaxFHqBrMsGkuD
         YeJR0xSHPZGCFbvgaHiqknh41EL5WwNFA9iB+iRwCM6WcQFH+Zw1tx+fmcPcUt+V3wZw
         DSZcdDRwLCApdIyo72V/9gGx91M0YHlm62cNAdXLcUvUz0bCJU0IcspaUKxVsGSLgBP4
         jvkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krqyqcCZPiI01Jvur/ql50TUASZSFSDEyL4cnMbw+uoK44JAuJz
	5kRzUBmHFIvhJvVK3fD0ZrE=
X-Google-Smtp-Source: AMrXdXvBNuKmxTEvFpmy4RyKkV6IVFdPf5sC5k+dR79qNtTd7spKiYoZ0tvu6RR3DOi92OpFeBOm9g==
X-Received: by 2002:a05:651c:54e:b0:284:a4c4:1ccb with SMTP id q14-20020a05651c054e00b00284a4c41ccbmr1002395ljp.127.1673553520127;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314f:b0:4cf:ff9f:bbfd with SMTP id
 s15-20020a056512314f00b004cfff9fbbfdls13219lfi.1.-pod-prod-gmail; Thu, 12 Jan
 2023 11:58:38 -0800 (PST)
X-Received: by 2002:a05:6512:1523:b0:4a4:68b7:deb8 with SMTP id bq35-20020a056512152300b004a468b7deb8mr4576005lfb.20.1673553518890;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=mQ+CC1zl9tSo3MX8wUUBuPynIMEERr3hEXJt/DpNqfA0DaBghwlaT1u204vOyHO8fU
         QQjP/6o0L6S0pvhzj5KJdYan6RfIN58ATFc7rm77TugOfH5kbq/6tv2VtQyeBW9nfE6y
         THmULifE5Y9+Ogt14wisTJmavEU8Z/rWDEnijyYvSHi7on/KHyGrPtfEhMV8iILzXUhg
         s3Wp2UAu3Xs6g/llAwLWDh4xGDsW/bCsusy7/Ca7x30VGo5xqGK1/WIeQ1hvH/aA3Sh1
         gBUvB1nMVtHAoU7XbwCy7MrmIEsGKXIIBheju10H/qfYH3do83nByMe+kfEwlCQF67dw
         CKHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=nPi2VaSnukDemWiv4/ra3+urtWJi7QCVP16nY4QbOXo=;
        b=NFAJGYTWy5lTPDq4KWwMewE9qOwx/bgFtHDKJl8eFCjq94NpW3hWxOXquWL9i/Ew25
         8QE8rp/3PQp5iqtOd+UP6RLnLJl473uWmfY0Q53veG0pMzacenXcdkM7jB+vc7AdKYnX
         ieNQnSN2PLI9iQPAf8+ZZOXxpp8LeAMXlicsrS2tWb2BO/f8wn2hR4LcoYkLytDg/6wL
         IDTyg2hoEilQsQqJaNXJcb8qfGvRfN1gsQt/ZPto6lnVYnIC/K8+a6yMvDVclYlOJXhs
         U83psCAJ2Jekz/3bHTyBTVSrzFp5kp0J+8LeCevVhZG4xVo42Nn9EICK/3s4jhzSZLkc
         WVwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=CDjE30SH;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id o10-20020a05651205ca00b004ce3ceb0e80si59549lfo.5.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hG-0045oy-1F;
	Thu, 12 Jan 2023 19:57:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8B0DC303436;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 156E92CCF62AD; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195540.927904612@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:40 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-samsung-soc@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 26/51] time/tick-broadcast: Remove RCU_NONIDLE usage
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=CDjE30SH;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

No callers left that have already disabled RCU.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 kernel/time/tick-broadcast-hrtimer.c |   29 ++++++++++++-----------------
 1 file changed, 12 insertions(+), 17 deletions(-)

--- a/kernel/time/tick-broadcast-hrtimer.c
+++ b/kernel/time/tick-broadcast-hrtimer.c
@@ -56,25 +56,20 @@ static int bc_set_next(ktime_t expires,
 	 * hrtimer callback function is currently running, then
 	 * hrtimer_start() cannot move it and the timer stays on the CPU on
 	 * which it is assigned at the moment.
+	 */
+	hrtimer_start(&bctimer, expires, HRTIMER_MODE_ABS_PINNED_HARD);
+	/*
+	 * The core tick broadcast mode expects bc->bound_on to be set
+	 * correctly to prevent a CPU which has the broadcast hrtimer
+	 * armed from going deep idle.
 	 *
-	 * As this can be called from idle code, the hrtimer_start()
-	 * invocation has to be wrapped with RCU_NONIDLE() as
-	 * hrtimer_start() can call into tracing.
+	 * As tick_broadcast_lock is held, nothing can change the cpu
+	 * base which was just established in hrtimer_start() above. So
+	 * the below access is safe even without holding the hrtimer
+	 * base lock.
 	 */
-	RCU_NONIDLE( {
-		hrtimer_start(&bctimer, expires, HRTIMER_MODE_ABS_PINNED_HARD);
-		/*
-		 * The core tick broadcast mode expects bc->bound_on to be set
-		 * correctly to prevent a CPU which has the broadcast hrtimer
-		 * armed from going deep idle.
-		 *
-		 * As tick_broadcast_lock is held, nothing can change the cpu
-		 * base which was just established in hrtimer_start() above. So
-		 * the below access is safe even without holding the hrtimer
-		 * base lock.
-		 */
-		bc->bound_on = bctimer.base->cpu_base->cpu;
-	} );
+	bc->bound_on = bctimer.base->cpu_base->cpu;
+
 	return 0;
 }
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.927904612%40infradead.org.
