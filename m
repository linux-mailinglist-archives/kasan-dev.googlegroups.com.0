Return-Path: <kasan-dev+bncBDBK55H2UQKRBYMDUGMQMGQEDGHNIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id AA7515BC6DB
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id g8-20020a05600c4ec800b003b4bcbdb63csf4842699wmq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=ceOPcQ6MwIHX2evNype5Rk2YSYAEEItXP1lm20/cV+TDHsTMOSQdABx1C2YXEkLB5L
         HG+8H2jHGVLpTG4iCZckf1/FA32JbYDIJxOBeiCGjq5fJgqlTu7JkFQBTyPWNZC7/lNT
         Ff/ceEj0OO0cze0DHc8pfBTURdEoHLyIrbW9K3OoNhhZbwLPHQ+zZ9+zP4fhDzoJBPwR
         GntGq6a6g4+Lkry6HZB6BpYFP3+j2nCJn3Wvs4A39Feu2WdTrKO85l/PElyoWuFV3IAJ
         9lDCtJSESAiefP+FaIoHMgssk10j8ouGtJCF+HMpklxGpHk1njealujZPxw1zZrJl6cp
         COuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=igHGF/93LunYcJNh//BDyx5LK6F862YeTdmCtKDjIjw=;
        b=HO4AnyMkzqhfnXF5HdxvdXQEOV6cCD+gF2q2OpDsfwnQ7W6nFSvKWa44PrE5lMJ1r/
         9QX9KsQfzvumSpRreKqJKWL+TOcqbp0rIFI2AMCiwiDPPstgLOOaXtx9qKvyVlP6WXb8
         yfhe1Vgkc3yxDTZ18oyMW9pW/OyHZLWQbfYQURGtVPwrtR1d+qsOnnhg/4yHP7mnIP0v
         tn/FEDtIG/fbEUucx5XAYnXeumFo8zdEO38GqfFCzRpw9PDCmU72HKM3biXu87I7x7TK
         AUJoNdWeAerwfPdbWtH3Ufh+qQGCs1VR8tUbHjMju/iAIugfFtPh12bYKPSa8EXcMEdg
         nAhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=gtfdf8L6;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=igHGF/93LunYcJNh//BDyx5LK6F862YeTdmCtKDjIjw=;
        b=HxFr7zjI2y6l43HVnM0ZbzqMLByAXFlWjcXDLF00ojEnzFRS4RyHWVfukEC/mzcMuj
         GjcS6FtmYMBBRfdVjghDLFhNrM0QeB6EM1GBeWxzNU2OI+LBu4KugcgcRtktZPNLjy4x
         2ZTldGI21mmzi596hx76BPmP+sKZUFgNeMfbQH9nnd5maGIYLFAaLeF8TM4XJW7mKZpB
         78Ofdcmzhs27PDwnpypRO1iOnxnLFe3btPmpWdMVJblLEj3wLJQdWprE1cqIXCl7XgQe
         oKkIcreeaeMfx3kCzdDgm0fpVg5KSAADmP4rbqAj4zmuIRhAF6DY0wg2OmTshWNS4EhG
         lPFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=igHGF/93LunYcJNh//BDyx5LK6F862YeTdmCtKDjIjw=;
        b=ZZdpUYRKLkrD6MKePu+L7BMSjEJk9eeuG39XhHw20Ar9DBRRbaJV4Di2C25T2oLmDC
         f5k++4/GlDV2XO3VgpjI/wUDKPsB+WW20sF0RjHDId00FH8wo3LZtVjEh1tdavZdIDIt
         nZKrEb7mPSrTBq95tds/th25KMyK1X12iFUvWFqsntqxYEzwKSNY9pnrltvffj4UqINy
         n2p55zDcWgL9C7XeVAuZvVLPpwBDfiIYf8t7WieDarKITD2dJR+RKcTZDIM7dGycMNdl
         7N/nz/LLk1mWqSHpEoJhwgIKaWcJL8V8lE5mSpvxsr/NAE6x4wPkvA41/C9Z2B83m1mL
         KE2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3VPwf+48IKfMZ6mdQOa4Oatz5gu3NZt5g1uWxe9+wtqpxE9ZuQ
	ej7QbXMimLT5BYUVBsce0jw=
X-Google-Smtp-Source: AA6agR4wqcnIg4NlyQ1NpghACQMH4zmpgNnUECwGrzARJy5QTk6A5BvlsuBFNlhgtQbdUNpU4OS+SQ==
X-Received: by 2002:a05:600c:1f15:b0:3b4:8600:fd7e with SMTP id bd21-20020a05600c1f1500b003b48600fd7emr19062395wmb.40.1663582689461;
        Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20c:0:b0:228:ddd7:f40e with SMTP id j12-20020adfd20c000000b00228ddd7f40els7612032wrh.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-Received: by 2002:a5d:500e:0:b0:22a:44ea:dee2 with SMTP id e14-20020a5d500e000000b0022a44eadee2mr9989959wrt.325.1663582688420;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582688; cv=none;
        d=google.com; s=arc-20160816;
        b=gEYtw7MnaabSyHFx4SSVHL9VlPrIgB9J8p3orx6VNpBb6bj2dC818IwrZoNswvyORA
         L7CAzG28QJAysCc9UG5aonqCoOhue8Fq6sBy5pbVlZji7ctj0IRRkLLdzIJcgpLrNdCQ
         r180buOdZEkvnPOmAuCcICtkgZHW5oJB1+N1ZivCHfkInvy5T14FVy2v6XpfYskuMTlz
         GW7LSH3XFKLTKyXvC3RQlB6V7vL3p6NKMMuZo2JtDgeIPbC1uVp/yKEnNGJGX9ztI31+
         ck5dvbn1uwFeOgPQ+VaUczf9WXQDcP7bg+qvd5WykPlLPLl+8293bEbMTG6/1YX0bTHb
         PaoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=mpoCVwwSlcWMSbFc2ASY4TLxAbRobKK8wUXUoaGZ7qA=;
        b=thZM3TEiLQXBJ1YMk4cJQXJ80u2EfsZfctWRXqGSC/5HG5lXIj/y8EsbB8azPTYfj8
         yVDiJq/z126EQolF3KwDVipMQDARox0UwK1qf/dljMFF69J+PztDpYaJ5xzbgafVLu6h
         t1T5UQpm18WH20I2FrmGvHBxTw65YpfhW42MfOTtjAhJcsshK8C3sUc8cELFrGmhB7Gr
         wBetza66LTwyOYO3qaWwyGA11WgkRESYzqa+L4vPFspRv7o0ImvLWcrtQ9ygXdWj4vYn
         oyZaoyQUu/upufWJYqp1H/uuHpP9OQz0KKX2R33Z7/fHpjuqlYCV92DpNymI5RpVVoW3
         VAUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=gtfdf8L6;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 65-20020a1c1944000000b003a5a534292csi295143wmz.3.2022.09.19.03.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq4-00E2Ay-51; Mon, 19 Sep 2022 10:17:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3D542302F2B;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 55BCB2BAC75A1; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.089180678@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:05 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
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
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
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
 fweisbec@gmail.com,
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
 kasan-dev@googlegroups.com
Subject: [PATCH v2 26/44] time/tick-broadcast: Remove RCU_NONIDLE usage
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=gtfdf8L6;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.089180678%40infradead.org.
