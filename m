Return-Path: <kasan-dev+bncBDBK55H2UQKRBGHQTGPAMGQEMFNRTLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id B687C66DAF9
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 11:27:37 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id r23-20020a1f2b17000000b003b89463c349sf9084545vkr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 02:27:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673951256; cv=pass;
        d=google.com; s=arc-20160816;
        b=I8i9MyZj0skKPGxD7vOU7qJKDbVZLEp/8FdRAzaXuSyX35AgpPQS+ZCdDaXgHPUq9b
         1fgmPSgb1YpcZPuV9cq68TiPJfffR4YVcyYL+bcOXigelXo1kdwLuCSWdyoQlBAcGV54
         jILE6qk4c4SxIyJGATXu/8SNR14dPM1uB3CsvlQasopnUEY6YuGS5h1eceKjoch8OoNf
         tZajAo6q2asM8TQlj0cew7kOThLRRDDV2SprbRjDkMZy6caoVZwHNru+DD8Vnu0kNQ9P
         XmSmUmsGkB3RXK8x1JCXbm45XiXXutnAV8GfJ9jz5MBhRO7nchuOwHPxDEFcWUfKG6gv
         M5lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=akWT68toSUZEdMMylGZAsV5UOpeX0nUdC+vbRWBMO/4=;
        b=VPr6iBVvfc4IMqCMZ2tcyPePGz3UZWop2byV4iq9QBIZHJU6I/lur1QGwC2gby8/bp
         6ba3Iz58xhV2eRdjIm0nw38F4YTosIQebtnha4jgu0QU+92+APwhpgpDSu4ycNtJmqn0
         3eMwmYnfOTSRGRlbaILEj3XJPxVOPIOJ+glTEYhcWXNXl4tSLCEkV9rmh9yn9Hu3adcI
         ejnF58M5+Hs35TsHbWFMzDDBGgXGf29uFCLDzHLrOg8QzfZGG9To4gEhcxorOG79/smI
         4Z+UEqBSnhmXVlvHT8DgUOcTe+A8iQv5uY+K+KG2B3FP8g2nBZxPeKl784sIq0283QwK
         oblA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eZ7RF5Th;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=akWT68toSUZEdMMylGZAsV5UOpeX0nUdC+vbRWBMO/4=;
        b=N8f8gaCoLp6FCwsjZkE9EcBbdUUq6q9yI8sAITgyip3TKQT0f33WJ1OEXAN57iAQL/
         yhBHnKLv9bnubQE1e0IbxnqWxqOkau4TcQPQKhXbyMTOPWTAiKOyhy+bEaQObDdEPquR
         +z7w85HfqpFQci6GHWwExunJO1v31p/lNG2Kqh+yl6ZTVxvLk0vIcN6UwSIs1x5Nzm5C
         2pcN4fJzcP2XP5WF9svKTvobceNw4mPPY+gxUldgmpJQQ9DRqc3dUp9oNeiwIGYjO8HA
         w1Cu8HTAX52ZMw5hZEpmEVLgGLGN7AC0zq5EH+cjvSkc4mR2U/Tn93BqH3vPihUAxxfi
         AkHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=akWT68toSUZEdMMylGZAsV5UOpeX0nUdC+vbRWBMO/4=;
        b=esZiTSUuP+oGJYtTLaGvJA+zrf2kipbmnIr9Dzs4FY6S3WQujgOg8h3qPq1KyLOsyG
         i453Kj8qqFQGkocbL9Pn+i3UW/PYJYKWdzOL5wc2z1/NxXlbNU91Aw2tgfPsuSOWq5Bf
         l2KRDLnQfFeqkHIWHVAR71HFbdevUXVqON8DwizvqDkpfmM/jjaKHvgkkndK1Fh97uw4
         384LzzdxfFF9UQeimGqjE2Z1djF8DnkXr5FNetr2yUJYhWQk9dzCpedH7WPUl8944XND
         PNYRZJATEEe0Gd95eNHNJGje6GQyhoOjJpTS95Y8cbuHUCVuPl9uqKKIZAZugBZATWye
         IOpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqb+gHCOdB3dw93Nar09g4LNqlL3mFj0te9z7NRkdtgQoavZMoW
	DvJwqke9qJm9HALld+Y6OtM=
X-Google-Smtp-Source: AMrXdXtOL8EonNzfgfIqK+XJr/tmkM6Mtw3UNq1s220eQX8aT86mUm/6X5vF2/YdO5e6Xj3aMOHCmA==
X-Received: by 2002:a05:6102:36c:b0:3d1:b51e:ba78 with SMTP id f12-20020a056102036c00b003d1b51eba78mr355426vsa.36.1673951256266;
        Tue, 17 Jan 2023 02:27:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:b4ce:0:b0:3d2:6934:6234 with SMTP id d197-20020a1fb4ce000000b003d269346234ls2351488vkf.1.-pod-prod-gmail;
 Tue, 17 Jan 2023 02:27:35 -0800 (PST)
X-Received: by 2002:ac5:c55e:0:b0:3d9:8842:1844 with SMTP id d30-20020ac5c55e000000b003d988421844mr797732vkl.13.1673951255393;
        Tue, 17 Jan 2023 02:27:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673951255; cv=none;
        d=google.com; s=arc-20160816;
        b=I+NuLGC601JOaRKCoB1ya4hUaFIjK7UJFVSIGoCTa13Ct+mX5UYKV78/VTqrZ8xmoa
         4Z9d0DhkzyqOH4hwTl3wOXtZadqq9cldHSEAgpq3HpCalZS5LHxDT/ZuKAj7oMHU11dc
         FkQvsMDQ4C6HD/0j+alnUfeUNCj28qTJOK6aHg5CVi0btG4PJKr8Zz81cisfOSQEDyDD
         +TmA7kHPkMoH3NjB+GPvrxocO4lXHvIpS2e1qXLi0tMwkjIj3NKz9ZqWwj86xPE2Dluq
         0zpmXEbK3/Ts+RxSCc1nGDRNMM4kMNjGe7XdKcDNMVR2/zRD1nQTLP8QM/ZiIRm9NzLb
         rSTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oxrJBZkAaCeFAHBiyHLFWLeqn2s4gXmFVHT68O/MsFk=;
        b=oLOBSGtDmJB7hP7Db+0HTZtewUaLmonxIFfkYTRHcSHuNIXygOa1EF6E1M7lgg0OcT
         zMW2bteBQG7YQAa5TDz4p3+Cn5rohXcOaMIssPtVKM0Xja5FlMA8t8tSAJBp8PpSL1s6
         iRDOP+6DgyvfhHtAXGIw4+sYUWwWn0zfjiP2HqwKSNhutDrIzCK41TJaLL3eAZYMjXu8
         4yue2FBKgh0VJtjpmQAGdKvAPNE134QJP21Vsm9ZGMfFpCdWtO3A16/IyA6FvyHPqk7J
         HEwbYg6WbySgRMhXICF2e3S+8bHpSklmi2T9pCKLiaIYPpLF4t+yA78sqcgKoRwNUorS
         ring==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eZ7RF5Th;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay9-20020a056130030900b005e2cbd30052si4300160uab.1.2023.01.17.02.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 02:27:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pHjAe-005tmP-38;
	Tue, 17 Jan 2023 10:26:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3731A300E86;
	Tue, 17 Jan 2023 11:26:29 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C3475201C94B3; Tue, 17 Jan 2023 11:26:29 +0100 (CET)
Date: Tue, 17 Jan 2023 11:26:29 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	nsekhar@ti.com, brgl@bgdev.pl, ulli.kroll@googlemail.com,
	linus.walleij@linaro.org, shawnguo@kernel.org,
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de,
	festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com,
	khilman@kernel.org, krzysztof.kozlowski@linaro.org,
	alim.akhtar@samsung.com, catalin.marinas@arm.com, will@kernel.org,
	guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org,
	kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net,
	monstr@monstr.eu, tsbogend@alpha.franken.de, dinguyen@kernel.org,
	jonas@southpole.se, stefan.kristiansson@saunalahti.fi,
	shorne@gmail.com, James.Bottomley@hansenpartnership.com,
	deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com,
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
	gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, alexander.shishkin@linux.intel.com,
	jolsa@kernel.org, namhyung@kernel.org, jgross@suse.com,
	srivatsa@csail.mit.edu, amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, andersson@kernel.org,
	konrad.dybcio@linaro.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	mhiramat@kernel.org, frederic@kernel.org, paulmck@kernel.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-samsung-soc@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org,
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org,
	linux-mips@vger.kernel.org, openrisc@lists.librecores.org,
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
	linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 00/51] cpuidle,rcu: Clean up the mess
Message-ID: <Y8Z31UbzG3LJgAXE@hirez.programming.kicks-ass.net>
References: <20230112194314.845371875@infradead.org>
 <Y8WCWAuQSHN651dA@FVFF77S0Q05N.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y8WCWAuQSHN651dA@FVFF77S0Q05N.cambridge.arm.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=eZ7RF5Th;
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

On Mon, Jan 16, 2023 at 04:59:04PM +0000, Mark Rutland wrote:

> I'm sorry to have to bear some bad news on that front. :(

Moo, something had to give..


> IIUC what's happenign here is the PSCI cpuidle driver has entered idle and RCU
> is no longer watching when arm64's cpu_suspend() manipulates DAIF. Our
> local_daif_*() helpers poke lockdep and tracing, hence the call to
> trace_hardirqs_off() and the RCU usage.

Right, strictly speaking not needed at this point, IRQs should have been
traced off a long time ago.

> I think we need RCU to be watching all the way down to cpu_suspend(), and it's
> cpu_suspend() that should actually enter/exit idle context. That and we need to
> make cpu_suspend() and the low-level PSCI invocation noinstr.
> 
> I'm not sure whether 32-bit will have a similar issue or not.

I'm not seeing 32bit or Risc-V have similar issues here, but who knows,
maybe I missed somsething.

In any case, the below ought to cure the ARM64 case and remove that last
known RCU_NONIDLE() user as a bonus.

---
diff --git a/arch/arm64/kernel/cpuidle.c b/arch/arm64/kernel/cpuidle.c
index 41974a1a229a..42e19fff40ee 100644
--- a/arch/arm64/kernel/cpuidle.c
+++ b/arch/arm64/kernel/cpuidle.c
@@ -67,10 +67,10 @@ __cpuidle int acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
 	u32 state = lpi->address;
 
 	if (ARM64_LPI_IS_RETENTION_STATE(lpi->arch_flags))
-		return CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM(psci_cpu_suspend_enter,
+		return CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM_RCU(psci_cpu_suspend_enter,
 						lpi->index, state);
 	else
-		return CPU_PM_CPU_IDLE_ENTER_PARAM(psci_cpu_suspend_enter,
+		return CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(psci_cpu_suspend_enter,
 					     lpi->index, state);
 }
 #endif
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index e7163f31f716..0fbdf5fe64d8 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -4,6 +4,7 @@
 #include <linux/slab.h>
 #include <linux/uaccess.h>
 #include <linux/pgtable.h>
+#include <linux/cpuidle.h>
 #include <asm/alternative.h>
 #include <asm/cacheflush.h>
 #include <asm/cpufeature.h>
@@ -104,6 +105,10 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 	 * From this point debug exceptions are disabled to prevent
 	 * updates to mdscr register (saved and restored along with
 	 * general purpose registers) from kernel debuggers.
+	 *
+	 * Strictly speaking the trace_hardirqs_off() here is superfluous,
+	 * hardirqs should be firmly off by now. This really ought to use
+	 * something like raw_local_daif_save().
 	 */
 	flags = local_daif_save();
 
@@ -120,6 +125,8 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 	 */
 	arm_cpuidle_save_irq_context(&context);
 
+	ct_cpuidle_enter();
+
 	if (__cpu_suspend_enter(&state)) {
 		/* Call the suspend finisher */
 		ret = fn(arg);
@@ -133,8 +140,11 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 		 */
 		if (!ret)
 			ret = -EOPNOTSUPP;
+
+		ct_cpuidle_exit();
 	} else {
-		RCU_NONIDLE(__cpu_suspend_exit());
+		ct_cpuidle_exit();
+		__cpu_suspend_exit();
 	}
 
 	arm_cpuidle_restore_irq_context(&context);
diff --git a/drivers/cpuidle/cpuidle-psci.c b/drivers/cpuidle/cpuidle-psci.c
index 4fc4e0381944..312a34ef28dc 100644
--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -69,16 +69,12 @@ static __cpuidle int __psci_enter_domain_idle_state(struct cpuidle_device *dev,
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
 
-	ct_cpuidle_enter();
-
 	state = psci_get_domain_state();
 	if (!state)
 		state = states[idx];
 
 	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
 
-	ct_cpuidle_exit();
-
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
 	else
@@ -192,7 +188,7 @@ static __cpuidle int psci_enter_idle_state(struct cpuidle_device *dev,
 {
 	u32 *state = __this_cpu_read(psci_cpuidle_data.psci_states);
 
-	return CPU_PM_CPU_IDLE_ENTER_PARAM(psci_cpu_suspend_enter, idx, state[idx]);
+	return CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(psci_cpu_suspend_enter, idx, state[idx]);
 }
 
 static const struct of_device_id psci_idle_state_match[] = {
diff --git a/drivers/firmware/psci/psci.c b/drivers/firmware/psci/psci.c
index e7bcfca4159f..f3a044fa4652 100644
--- a/drivers/firmware/psci/psci.c
+++ b/drivers/firmware/psci/psci.c
@@ -462,11 +462,22 @@ int psci_cpu_suspend_enter(u32 state)
 	if (!psci_power_state_loses_context(state)) {
 		struct arm_cpuidle_irq_context context;
 
+		ct_cpuidle_enter();
 		arm_cpuidle_save_irq_context(&context);
 		ret = psci_ops.cpu_suspend(state, 0);
 		arm_cpuidle_restore_irq_context(&context);
+		ct_cpuidle_exit();
 	} else {
+		/*
+		 * ARM64 cpu_suspend() wants to do ct_cpuidle_*() itself.
+		 */
+		if (!IS_ENABLED(CONFIG_ARM64))
+			ct_cpuidle_enter();
+
 		ret = cpu_suspend(state, psci_suspend_finisher);
+
+		if (!IS_ENABLED(CONFIG_ARM64))
+			ct_cpuidle_exit();
 	}
 
 	return ret;
diff --git a/include/linux/cpuidle.h b/include/linux/cpuidle.h
index 630c879143c7..3183aeb7f5b4 100644
--- a/include/linux/cpuidle.h
+++ b/include/linux/cpuidle.h
@@ -307,7 +307,7 @@ extern s64 cpuidle_governor_latency_req(unsigned int cpu);
 #define __CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter,			\
 				idx,					\
 				state,					\
-				is_retention)				\
+				is_retention, is_rcu)			\
 ({									\
 	int __ret = 0;							\
 									\
@@ -319,9 +319,11 @@ extern s64 cpuidle_governor_latency_req(unsigned int cpu);
 	if (!is_retention)						\
 		__ret =  cpu_pm_enter();				\
 	if (!__ret) {							\
-		ct_cpuidle_enter();					\
+		if (!is_rcu)						\
+			ct_cpuidle_enter();				\
 		__ret = low_level_idle_enter(state);			\
-		ct_cpuidle_exit();					\
+		if (!is_rcu)						\
+			ct_cpuidle_exit();				\
 		if (!is_retention)					\
 			cpu_pm_exit();					\
 	}								\
@@ -330,15 +332,21 @@ extern s64 cpuidle_governor_latency_req(unsigned int cpu);
 })
 
 #define CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx)	\
-	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 0)
+	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 0, 0)
 
 #define CPU_PM_CPU_IDLE_ENTER_RETENTION(low_level_idle_enter, idx)	\
-	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 1)
+	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 1, 0)
 
 #define CPU_PM_CPU_IDLE_ENTER_PARAM(low_level_idle_enter, idx, state)	\
-	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0)
+	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0, 0)
+
+#define CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(low_level_idle_enter, idx, state)	\
+	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0, 1)
 
 #define CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM(low_level_idle_enter, idx, state)	\
-	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1)
+	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1, 0)
+
+#define CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM_RCU(low_level_idle_enter, idx, state)	\
+	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1, 1)
 
 #endif /* _LINUX_CPUIDLE_H */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y8Z31UbzG3LJgAXE%40hirez.programming.kicks-ass.net.
