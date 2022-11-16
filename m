Return-Path: <kasan-dev+bncBDBK55H2UQKRBBUE2SNQMGQE542JKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 14FFE62C2A5
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Nov 2022 16:30:15 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id c5-20020a1c3505000000b003c56da8e894sf1350234wma.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Nov 2022 07:30:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668612614; cv=pass;
        d=google.com; s=arc-20160816;
        b=cZ95Tzoqblpf/JBHI9Vnpnc54lmXQNz9q6tduz8C6a93+R96GO/AnjDdG9M0iJCqDV
         HNDsAYewSA13KQlSnAKm/U6leVffWSf+mZySQi6EmhMWBqmTMKYUKc73MHHPfwv6rXlk
         gckSHUIVNq6VSYhwqQl70Ynt4Uszn3ajsIRhGwg6yfoTcToK6C5Hozcmney8Knkv1uLa
         G3EaU9D8s9K0S7IMzuP3FrlbeVrCSEsshKr6pjoq101Ya873ajpXQHLZdXeBemPN0XAt
         bNF4eyOwKjqFtAp1rbrVa9P73fUgO1H0LHWGgkPoHdqAc6ymzli3JNnHcikcHSEMLDj/
         HR6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hgA0CfU3TQyC+mZymVjYu2hF7KNf5hCkCDozLv5xIhM=;
        b=Id3FMq/epWZehWKMwEAD63EyX8g460L/U5xOeMztgSNOiZAWyVblASKxhaqyLEKtCl
         X/oVmmXNYkVOAI1ArCQI8xpNaY6Umm56jR0bCVnVVlBxngbvp/3HWHIISqE55AS6/KxP
         qwRpyIZyG6f5RCAHXJTEcRM7RfTUwMgBxvhH+eyNHU7VrVgJj0eVbnPXmLjM5bqWPK2d
         BmScg+92V71lXISRIkPzU1UQvlzqVA+c0YQYi0uZ6FmxP4vuPQlSB0ReG99nAqVXlIhI
         ecqIViFHcKkykV3Xrwv4MBQEpcKwiziN+gKfeMaiSTMlSRFVUNCYindJaRG1jTneUaZ0
         dGCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gYnS7fY4;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hgA0CfU3TQyC+mZymVjYu2hF7KNf5hCkCDozLv5xIhM=;
        b=Rbtv19JkE+6RoyQqMuMbdydWxEZBXjnrF2BpPwhpQ3MtOt+EdqTFMCDkl8bsQAIV3N
         wjvPsD/+aJf91oD/1yjDLCyHHnH/tLLFQKz2qJ+dRp9oVBZdXM4rYmCRYZZ5tZf9Zr42
         x9Ix4miYaPWcEYOM75KlDaMmTvoJ/NSsDzY9aUToTnmzlfNBFwcS4euwsJtvHI1giVZz
         XmaX5vdXDw6UkWawXKWfNLcUrc2CxUpkOwP3QizkI7gC5BkNaOYNnxTxBoNe1BZhfYWA
         FFhQTlohn6JGj7Ww3W6dRPD4BA0skKE6rflggJL2DWVptLNSzflJMZHMTKj9y9MXs45W
         nhkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hgA0CfU3TQyC+mZymVjYu2hF7KNf5hCkCDozLv5xIhM=;
        b=gpaTREZzt68OcOjevp3gMJq7BlESKU3BP0gHKafVvPsWs30zVsL0+UuYFYwQtorN/k
         wWMTONnUhhjguwrQ28/i0xHVHwDH9O2/JgVh2EvfxcDAbuhLKDyO3LdAWd7c7mOPdQh+
         kgJ6Z/ujqRHr7g+BoTdoI7uNsRP7N4zfNKsOe32zIKv5vFWbjFUf2NM+6bKkJ1TySGmO
         yEP96TOPguQC2eY5ZyQmqZUzKpR+9kaJ8vF1HIxrYdi0Y4gm5TZ+Tblg/+7HPXq/Qsq/
         w4jtPwPDoxNDGzW5jIAWiMGplKS/EZYwCzHrKnNmhcISaeyuYhyTQG2qnhVCGpvuuEmI
         99Zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plzzblAJNU3AcfaqPkfZC9gZL+vA0yKSYce0tloCShY439D457T
	RV6EM9o/6dxqFsJDtdz2+kA=
X-Google-Smtp-Source: AA0mqf5yVNfrWcM3NlsrLB7b1vTcGk71pfbBdUW2waN7nRwyvqnkCrG5BrMjpAY2v3WdJKrTXu3x1A==
X-Received: by 2002:a5d:4522:0:b0:236:5f1c:bedf with SMTP id j2-20020a5d4522000000b002365f1cbedfmr14620870wra.367.1668612614422;
        Wed, 16 Nov 2022 07:30:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d231:0:b0:228:ddd7:f40e with SMTP id k17-20020adfd231000000b00228ddd7f40els27506670wrh.3.-pod-prod-gmail;
 Wed, 16 Nov 2022 07:30:13 -0800 (PST)
X-Received: by 2002:adf:dbcc:0:b0:22e:4481:4a4 with SMTP id e12-20020adfdbcc000000b0022e448104a4mr14827031wrj.450.1668612613150;
        Wed, 16 Nov 2022 07:30:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668612613; cv=none;
        d=google.com; s=arc-20160816;
        b=QJvqDJPs5ep7E2IzyZic6VeJMvjqhVnvE88+V5oZWepJ8hpL+dy60xkyXKpqFcIttH
         kTl/SCUMdOgoutSmSnRWTu3N6aAxDAs8Glj+Elkw6WmsvTWdIEUhvq7Wwb6sNwYbrJu9
         CZUVJcBzJrIBGN4yEJ5eUeZZEtxoaHSNWrmuGx3BDuLkvPwzHGIGMbM6uX49+TuUXPLy
         UIwMQSQ6lL0rtZSXMv5k7D5VEbna4z0UD/DrtMjM6Uw9kH7Je62YyCpb+QCcrwZ7B+Gx
         folKiRR3/Pjvemp2Ugg3mCtqJi4X9daBtkymHygYkTkdWOzt3e1uGAf9BxM80PLlcZ0v
         hLBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4XDB6ZbR3Awa7mOslon9xFqMWj0psrdiARhozQeRyJA=;
        b=r9J54vBp92/LwRsIIYamrzcmHE1FI88FcQM0awltHMEFPUMS4k1051oWYSUrADwPOm
         sw9JfhT7luS8WaLM4/UGfixgKmLA6WDcm5PpFxX7tF1i8gkPAjuo7g/Aj48rQSnxrMIi
         NuaGetYGv1Igy0DhdtuyHYLuptJh++9ukrf3VVD0PnbaEIJI9ZqqmD7gAe9iKujNYdXF
         laG6hmS4gkqhor6BfyODE8xD5cmbzso7uZsvXyps46XBZEIc46VBj3ZuZFqMyz8zwsUi
         VWtysG/tN16GdZSW304LPNQyT1IW3WNfIgXd3CGUPSxf06XWwZCKy5karJvSOFBsaCho
         /bHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gYnS7fY4;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ba16-20020a0560001c1000b00236e8baff63si543595wrb.0.2022.11.16.07.30.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Nov 2022 07:30:13 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ovKLk-00HX9L-Px; Wed, 16 Nov 2022 15:29:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C6F08300129;
	Wed, 16 Nov 2022 16:29:05 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A500120832696; Wed, 16 Nov 2022 16:29:05 +0100 (CET)
Date: Wed, 16 Nov 2022 16:29:05 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Ulf Hansson <ulf.hansson@linaro.org>
Cc: juri.lelli@redhat.com, rafael@kernel.org, catalin.marinas@arm.com,
	linus.walleij@linaro.org, bsegall@google.com, guoren@kernel.org,
	pavel@ucw.cz, agordeev@linux.ibm.com, linux-arch@vger.kernel.org,
	vincent.guittot@linaro.org, mpe@ellerman.id.au,
	chenhuacai@kernel.org, christophe.leroy@csgroup.eu,
	linux-acpi@vger.kernel.org, agross@kernel.org, geert@linux-m68k.org,
	linux-imx@nxp.com, vgupta@kernel.org, mattst88@gmail.com,
	mturquette@baylibre.com, sammy@sammy.net, pmladek@suse.com,
	linux-pm@vger.kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	linux-um@lists.infradead.org, npiggin@gmail.com, tglx@linutronix.de,
	linux-omap@vger.kernel.org, dietmar.eggemann@arm.com,
	andreyknvl@gmail.com, gregkh@linuxfoundation.org,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	senozhatsky@chromium.org, svens@linux.ibm.com, jolsa@kernel.org,
	tj@kernel.org, Andrew Morton <akpm@linux-foundation.org>,
	mark.rutland@arm.com, linux-ia64@vger.kernel.org,
	dave.hansen@linux.intel.com,
	virtualization@lists.linux-foundation.org,
	James.Bottomley@hansenpartnership.com, jcmvbkbc@gmail.com,
	thierry.reding@gmail.com, kernel@xen0n.name, cl@linux.com,
	linux-s390@vger.kernel.org, vschneid@redhat.com,
	john.ogness@linutronix.de, ysato@users.sourceforge.jp,
	linux-sh@vger.kernel.org, festevam@gmail.com, deller@gmx.de,
	daniel.lezcano@linaro.org, jonathanh@nvidia.com, dennis@kernel.org,
	lenb@kernel.org, linux-xtensa@linux-xtensa.org,
	kernel@pengutronix.de, gor@linux.ibm.com,
	linux-arm-msm@vger.kernel.org, linux-alpha@vger.kernel.org,
	linux-m68k@lists.linux-m68k.org, loongarch@lists.linux.dev,
	shorne@gmail.com, chris@zankel.net, sboyd@kernel.org,
	dinguyen@kernel.org, bristot@redhat.com,
	alexander.shishkin@linux.intel.com, fweisbec@gmail.com,
	lpieralisi@kernel.org, atishp@atishpatra.org,
	linux@rasmusvillemoes.dk, kasan-dev@googlegroups.com,
	will@kernel.org, boris.ostrovsky@oracle.com, khilman@kernel.org,
	linux-csky@vger.kernel.org, pv-drivers@vmware.com,
	linux-snps-arc@lists.infradead.org, mgorman@suse.de,
	jacob.jun.pan@linux.intel.com, Arnd Bergmann <arnd@arndb.de>,
	ulli.kroll@googlemail.com, linux-clk@vger.kernel.org,
	rostedt@goodmis.org, ink@jurassic.park.msu.ru, bcain@quicinc.com,
	tsbogend@alpha.franken.de, linux-parisc@vger.kernel.org,
	ryabinin.a.a@gmail.com, sudeep.holla@arm.com, shawnguo@kernel.org,
	davem@davemloft.net, dalias@libc.org, tony@atomide.com,
	amakhalov@vmware.com, konrad.dybcio@somainline.org,
	bjorn.andersson@linaro.org, glider@google.com, hpa@zytor.com,
	sparclinux@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-riscv@lists.infradead.org, vincenzo.frascino@arm.com,
	anton.ivanov@cambridgegreys.com, jonas@southpole.se,
	yury.norov@gmail.com, richard@nod.at, x86@kernel.org,
	linux@armlinux.org.uk, mingo@redhat.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, richard.henderson@linaro.org,
	stefan.kristiansson@saunalahti.fi, openrisc@lists.librecores.org,
	acme@kernel.org, paul.walmsley@sifive.com,
	linux-tegra@vger.kernel.org, namhyung@kernel.org,
	andriy.shevchenko@linux.intel.com, jpoimboe@kernel.org,
	dvyukov@google.com, jgross@suse.com, monstr@monstr.eu,
	linux-mips@vger.kernel.org, palmer@dabbelt.com, anup@brainfault.org,
	bp@alien8.de, johannes@sipsolutions.net,
	linuxppc-dev@lists.ozlabs.org
Subject: Re: [PATCH v2 12/44] cpuidle,dt: Push RCU-idle into driver
Message-ID: <Y3UBwYNY15ETUKy9@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101521.139727471@infradead.org>
 <CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=gYnS7fY4;
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


Sorry; things keep getting in the way of finishing this :/

As such, I need a bit of time to get on-track again..

On Tue, Oct 04, 2022 at 01:03:57PM +0200, Ulf Hansson wrote:

> > --- a/drivers/acpi/processor_idle.c
> > +++ b/drivers/acpi/processor_idle.c
> > @@ -1200,6 +1200,8 @@ static int acpi_processor_setup_lpi_stat
> >                 state->target_residency = lpi->min_residency;
> >                 if (lpi->arch_flags)
> >                         state->flags |= CPUIDLE_FLAG_TIMER_STOP;
> > +               if (lpi->entry_method == ACPI_CSTATE_FFH)
> > +                       state->flags |= CPUIDLE_FLAG_RCU_IDLE;
> 
> I assume the state index here will never be 0?
> 
> If not, it may lead to that acpi_processor_ffh_lpi_enter() may trigger
> CPU_PM_CPU_IDLE_ENTER_PARAM() to call ct_cpuidle_enter|exit() for an
> idle-state that doesn't have the CPUIDLE_FLAG_RCU_IDLE bit set.

I'm not quite sure I see how. AFAICT this condition above implies
acpi_processor_ffh_lpi_enter() gets called, no?

Which in turn is an unconditional __CPU_PM_CPU_IDLE_ENTER() user, so
even if idx==0, it ends up in ct_idle_{enter,exit}().

> 
> >                 state->enter = acpi_idle_lpi_enter;
> >                 drv->safe_state_index = i;
> >         }
> > --- a/drivers/cpuidle/cpuidle-arm.c
> > +++ b/drivers/cpuidle/cpuidle-arm.c
> > @@ -53,6 +53,7 @@ static struct cpuidle_driver arm_idle_dr
> >          * handler for idle state index 0.
> >          */
> >         .states[0] = {
> > +               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
> 
> Comparing arm64 and arm32 idle-states/idle-drivers, the $subject
> series ends up setting the CPUIDLE_FLAG_RCU_IDLE for the ARM WFI idle
> state (state zero), but only for the arm64 and psci cases (mostly
> arm64). For arm32 we would need to update the ARM_CPUIDLE_WFI_STATE
> too, as that is what most arm32 idle-drivers are using. My point is,
> the code becomes a bit inconsistent.

True.

> Perhaps it's easier to avoid setting the CPUIDLE_FLAG_RCU_IDLE bit for
> all of the ARM WFI idle states, for both arm64 and arm32?

As per the below?

> 
> >                 .enter                  = arm_enter_idle_state,
> >                 .exit_latency           = 1,
> >                 .target_residency       = 1,

> > --- a/include/linux/cpuidle.h
> > +++ b/include/linux/cpuidle.h
> > @@ -282,14 +282,18 @@ extern s64 cpuidle_governor_latency_req(
> >         int __ret = 0;                                                  \
> >                                                                         \
> >         if (!idx) {                                                     \
> > +               ct_idle_enter();                                        \
> 
> According to my comment above, we should then drop these calls to
> ct_idle_enter and ct_idle_exit() here. Right?

Yes, if we ensure idx==0 never has RCU_IDLE set then these must be
removed.

> >                 cpu_do_idle();                                          \
> > +               ct_idle_exit();                                         \
> >                 return idx;                                             \
> >         }                                                               \
> >                                                                         \
> >         if (!is_retention)                                              \
> >                 __ret =  cpu_pm_enter();                                \
> >         if (!__ret) {                                                   \
> > +               ct_idle_enter();                                        \
> >                 __ret = low_level_idle_enter(state);                    \
> > +               ct_idle_exit();                                         \
> >                 if (!is_retention)                                      \
> >                         cpu_pm_exit();                                  \
> >         }                                                               \
> >

So the basic premise is that everything that needs RCU inside the idle
callback must set CPUIDLE_FLAG_RCU_IDLE and by doing that promise to
call ct_idle_{enter,exit}() themselves.

Setting RCU_IDLE is required when there is RCU usage, however even if
there is no RCU usage, setting RCU_IDLE is fine, as long as
ct_idle_{enter,exit}() then get called.


So does the below (delta) look better to you?

--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -1218,7 +1218,7 @@ static int acpi_processor_setup_lpi_stat
 		state->target_residency = lpi->min_residency;
 		if (lpi->arch_flags)
 			state->flags |= CPUIDLE_FLAG_TIMER_STOP;
-		if (lpi->entry_method == ACPI_CSTATE_FFH)
+		if (i != 0 && lpi->entry_method == ACPI_CSTATE_FFH)
 			state->flags |= CPUIDLE_FLAG_RCU_IDLE;
 		state->enter = acpi_idle_lpi_enter;
 		drv->safe_state_index = i;
--- a/drivers/cpuidle/cpuidle-arm.c
+++ b/drivers/cpuidle/cpuidle-arm.c
@@ -53,7 +53,7 @@ static struct cpuidle_driver arm_idle_dr
 	 * handler for idle state index 0.
 	 */
 	.states[0] = {
-		.flags			= CPUIDLE_FLAG_RCU_IDLE,
+		.flags			= 0,
 		.enter                  = arm_enter_idle_state,
 		.exit_latency           = 1,
 		.target_residency       = 1,
--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -357,7 +357,7 @@ static int psci_idle_init_cpu(struct dev
 	 * PSCI idle states relies on architectural WFI to be represented as
 	 * state index 0.
 	 */
-	drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
+	drv->states[0].flags = 0;
 	drv->states[0].enter = psci_enter_idle_state;
 	drv->states[0].exit_latency = 1;
 	drv->states[0].target_residency = 1;
--- a/drivers/cpuidle/cpuidle-qcom-spm.c
+++ b/drivers/cpuidle/cpuidle-qcom-spm.c
@@ -72,7 +72,7 @@ static struct cpuidle_driver qcom_spm_id
 	.owner = THIS_MODULE,
 	.states[0] = {
 		.enter			= spm_enter_idle_state,
-		.flags			= CPUIDLE_FLAG_RCU_IDLE,
+		.flags			= 0,
 		.exit_latency		= 1,
 		.target_residency	= 1,
 		.power_usage		= UINT_MAX,
--- a/drivers/cpuidle/cpuidle-riscv-sbi.c
+++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
@@ -337,7 +337,7 @@ static int sbi_cpuidle_init_cpu(struct d
 	drv->cpumask = (struct cpumask *)cpumask_of(cpu);
 
 	/* RISC-V architectural WFI to be represented as state index 0. */
-	drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
+	drv->states[0].flags = 0;
 	drv->states[0].enter = sbi_cpuidle_enter_state;
 	drv->states[0].exit_latency = 1;
 	drv->states[0].target_residency = 1;
--- a/include/linux/cpuidle.h
+++ b/include/linux/cpuidle.h
@@ -282,9 +282,7 @@ extern s64 cpuidle_governor_latency_req(
 	int __ret = 0;							\
 									\
 	if (!idx) {							\
-		ct_idle_enter();					\
 		cpu_do_idle();						\
-		ct_idle_exit();						\
 		return idx;						\
 	}								\
 									\

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3UBwYNY15ETUKy9%40hirez.programming.kicks-ass.net.
