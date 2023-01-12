Return-Path: <kasan-dev+bncBDBK55H2UQKRB36MQGPAMGQEA3JMCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8969E668009
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:39 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id bg25-20020a05600c3c9900b003da1f6a7b2dsf190658wmb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553519; cv=pass;
        d=google.com; s=arc-20160816;
        b=GeKq31c198lhJ5insKkOJ5Sr+kM2GoElNxw3yKwhssJYpdq0y9pNSuoyeFo2j6D59v
         aZ3YBuiqrGkaoMZJQ94aRsQH59VUP8t7IuLGqlkIDkVcZJ6lWtq/LJDFhtiyFDHTrOwQ
         /sFBNQehHdIGuQB4hSvLnKW1klI7IV0SQmTtAwB/wqu8Gjue3Szt98DUxDgJHhidB/j8
         g7mI5PNJrw/Z4F2F1179jFwlcc3Owj7jMHPITESlVVCfQM/b83bUPElo3AxySbte5n9N
         oJz23pnw9PR7zX0N1CPFyffS3zfhMPm7IG3H2LBDjVHa4z16a0dEn+7hZkheTtpR2T3w
         GxHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=7Xl2WPBsX3kf8Op7xJdgsf3G7U4/Ju1XRSaZbpLVDm4=;
        b=GIGnWfjfTl239aWq2DkzGc55HoKv6tVK2cJdt6KKYUqefIEpStrDVMZw5jgA2QhDei
         UocmONlfV/uHd/rgo1f9s7L93Gewe6xrm2LA+ZCD0lDtCrYMTdFKe7l7ZiF7AyUNGo2g
         /HLQ30DqyK/akUdpMw+GrgcPy0p9qMB0MkGA3o1ITkvENZ5wUmboA2nKglW5SgOKUe1T
         HZKT2GKyyzofdpBxfC3GSPlRkb5tCNYiCMOAcQo5724CgGz8wszCo9Y35L/qMv/+rWsv
         K0cJF6HJEGQh82jXwq6AKBIP1MqcE9NmSAD9o2bdVe06BqfYdLqmxOxqZw4EhoAsnV4Q
         YCJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="H/JWwXj+";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Xl2WPBsX3kf8Op7xJdgsf3G7U4/Ju1XRSaZbpLVDm4=;
        b=XHeAw1r9aAjvN08+arq2LO1JY7jPcZfbhigltiYIxko6fjMTB8C19a4NpIyJx++dk0
         gb/aeddRpMMgrUVbCvPuqBTwHgNnIxzk1d8hKkU5FoDaX1GNe2Mhof/EGmtPOGJeppN9
         b5eje6C427QBqqEGfJkFot+ASo9h7Lcw2fVWmlIarbI5cQZou7BEntKnsh+kB5SeTKjO
         6xj/eUDUxHkpFTOfypNVjTM/H8+AGgpNiJOMezRBsp9oUpwW1MjQ9L1ld++mJ/ZaCxkL
         9CVmPaRsaSXnMUhJ4+/VUoE9yDmnpQuGAra4twwqSTwBzgkk1s5CjRtmmQKGOZQPsf/U
         6LbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Xl2WPBsX3kf8Op7xJdgsf3G7U4/Ju1XRSaZbpLVDm4=;
        b=HpAU5LWJrN8RuCZuY0NbktuNH/7R2L3sa1YvwoTA8Y9yUOmlQ6R8bdmuGDSfmTzHfk
         bn+TrgodH3jadMIAhFGiHh/zeZN4UIEdghQ0NzoXUA/HKWsB4qEzI+WKDh/7biv7fhxf
         FPEinr4JFUAZg5zXSMLbs3jF6L0NHiXlM9dPcDoROSB7cupPRmmGUvfI7gnFYY08RvjI
         EfBvOIAIQc/8tVvZaww+bPu1YnewVL53vQ8su0senzfrIXy814jyxopUYlnnBo2bP5yc
         XpBYeoUMGn7lzeOojH/jhvgUulWwwFllAq9NVtlAlRgh82WO+pKYWSyOePHC+D+kDGPZ
         oTWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kouHFPkEF37VvF74xkd8BeNps1V1bXYbHbofl3bB+QQgo2kzLNG
	V2811PjzdDkboEiqAOmVC7Q=
X-Google-Smtp-Source: AMrXdXs1WfPR+Ql6OeC++kr4OyaUM88sl6ORSHhwXTjU5ecIvqxKr9HU1Hp1mIg7rl8wiFCClttdBQ==
X-Received: by 2002:a5d:424b:0:b0:2bd:db2a:ed3 with SMTP id s11-20020a5d424b000000b002bddb2a0ed3mr88742wrr.507.1673553519445;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:2b6:8e51:dcb with SMTP id k20-20020adfd234000000b002b68e510dcbls1471307wrh.3.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:38 -0800 (PST)
X-Received: by 2002:adf:f64f:0:b0:2bd:d403:5407 with SMTP id x15-20020adff64f000000b002bdd4035407mr2056733wrp.22.1673553518473;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=MdddNldNTq2BqX0Pl7FRcfM4WpnAOQ7hlreQbqoYU4QcAhBJNIM4P1JOJWK5QMAg3q
         LyfI3hl9iN3x6nhqJGKqv/WDT/4Axn02ho9Q95WbHzlrjiATkt8IqfD0adPF/ByP7eJ+
         +7utuKWT7Xptb+wLu19k/WsUvPeTE/Vwn50ku6SUCgEHGy9EtKvsKhp+gvPlVnxMyPFU
         d/rRK2gT2yNEu6+pu91IAyeTnjRhjBfZ447S90MxRqtGgHjxwGhQ9dmOXkW8BE5E5AGV
         Y4Q5EkDVdjtGCyg6KpcmQcBTNCiuhkB71ojbFH4566hAaU9x5jcNU7VenPOTj4rMIJf6
         ggpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Xy9+JvHHctWh2TNOLRKTbmGfpkTQoSEdFlJnj8l2Ws0=;
        b=Ko/gmT44wmYrSIZulM7UCL2nWKJusSJiH8HS8emEnOVHNymwJ7zhqnyNjbTRZAGpIc
         MIg9S37WOkmSsM78iMUYv3LaJg9viCcC2RJ80WJLhH3fHY/TgXbN5+1LidK2apbdVaMD
         jYCcr/mKrSDgqtr9HEvvBjp4ssW0hJwDNlECJ6R4km9m8BZiHsxlkQYX/KsKdQN11/Tm
         0NunrDVGXgfg6rybVOaxBK+pTc9dy3l1KMkx8gi3CeiAmhLu/WaimGozx8Pc8LIyzRhu
         aOJ36yLiblUmwGfVqQ2cb26DT2jO2imAg7Ui9UMg9NzJ713sjKv8Bya1XUSkgjHMHZ3c
         iKUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="H/JWwXj+";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id da14-20020a056000408e00b002367b2e748esi819687wrb.5.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hC-0045ny-0Z;
	Thu, 12 Jan 2023 19:57:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DFD51302E3C;
	Thu, 12 Jan 2023 20:57:12 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 996452CCF1F4C; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.576412812@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:18 +0100
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
Subject: [PATCH v3 04/51] cpuidle: Move IRQ state validation
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="H/JWwXj+";
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

Make cpuidle_enter_state() consistent with the s2idle variant and
verify ->enter() always returns with interrupts disabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/cpuidle.c |   10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -236,7 +236,11 @@ int cpuidle_enter_state(struct cpuidle_d
 	stop_critical_timings();
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
 		ct_idle_enter();
+
 	entered_state = target_state->enter(dev, drv, index);
+	if (WARN_ONCE(!irqs_disabled(), "%ps leaked IRQ state", target_state->enter))
+		raw_local_irq_disable();
+
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
 		ct_idle_exit();
 	start_critical_timings();
@@ -248,12 +252,8 @@ int cpuidle_enter_state(struct cpuidle_d
 	/* The cpu is no longer idle or about to enter idle. */
 	sched_idle_set_state(NULL);
 
-	if (broadcast) {
-		if (WARN_ON_ONCE(!irqs_disabled()))
-			local_irq_disable();
-
+	if (broadcast)
 		tick_broadcast_exit();
-	}
 
 	if (!cpuidle_state_is_coupled(drv, index))
 		local_irq_enable();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.576412812%40infradead.org.
