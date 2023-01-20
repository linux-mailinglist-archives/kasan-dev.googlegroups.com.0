Return-Path: <kasan-dev+bncBDBK55H2UQKRBQ6LVGPAMGQEBXEG26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 35F436751E3
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 10:58:29 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id v12-20020a9d4e8c000000b0068653f5e950sf2216933otk.13
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 01:58:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674208707; cv=pass;
        d=google.com; s=arc-20160816;
        b=NMXIsWz7qWkV6/uI28haamwxoFd5gO8mRf5lTsHxhxjpI+wOw1P+Pj8wdJkxz/ptDj
         wBhBI7JjVShCoG0I1nhY5cUDVL0VqLHG/Yy3iZTeNlYTnZ9Pl4WdaVb2JgWjndmYy/oh
         UqhoGkK6OK8b0fvJu1R6IPeYMvBIV4tNWgja/LuSiZudRJXzuXGTPovhxZMsTvbObfMt
         2HVl5ScxagW4bH3vHMRbbvMfTgQR8HQiHY9jIPTfyPUTx/9PXQnNgJ2kRR5sToV7HCIv
         jRAdIWaxICWNTp5Wi4jpIWfYvdadjGOXwY2OK25tarGK8aU7+nFEQy5Ln5Mz0J0FTjmh
         2D2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:to:from:date:sender
         :dkim-signature;
        bh=zsqVMVpIzNTr7IoQ3O/Dm44fKdtIOuUfQLAv3kt0J3k=;
        b=0HQiqSrwTOviqFLGGO716LA/IS2PQEO6p0YCzYk6Qq+pzYyOL0xlEQ6mZhS77i9sxW
         cu5pLo3qvx0VNUkNZA4eandJldOJKoJ3rjHF0Jbzmpb/QAXRwTWKGNo2/L8VOIcQFDwY
         bYzgrU7VcgoXsEZA8V38fZf59mpogUU1++bmiR7zTA/6/LZ1ILXj+JlGC3yvvCiBlOsy
         nJNEpYUXKecyASJ7MsYv6uozefuL2s1QqZpIx4VW10Dmcq0lFm/hWShglLnqsSkh4Bxa
         yCwo2hM4L2Ls2wPzntLjOxqGqBEKZSQiZqYsLvb4q/mwGysLTln6r7rN/HXj4DdBEtsk
         eAIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UZLTzgFB;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zsqVMVpIzNTr7IoQ3O/Dm44fKdtIOuUfQLAv3kt0J3k=;
        b=t33WFDy0ZcwjfEO2J7yJj3rDJSqK+il5ujeVLE0gFVAw6InZA8sDS1q7/Sr3F20qft
         sJ3ITJAN0GRTsHJ0xTRubeQmPPrdIgdykh4q4tKoCOqWMKCtdD9MCuXWbcNT29TUKHsS
         Y6aGHa70m0kt1ZDNzlPjE+zGGuQ8SspWD5Mj9RFcQmyG9U78EUwnCsIzi3UNyxZa+qx0
         NhZMfYQ1eIC5vEigIynxXJfe9tZtGMEqR1Ax8FuDMzITlXNvrRCn0s+pmrCs9AGkmpG1
         vvgt/DunGJUKAPPXZY0TtA1RAJQhgiiJVvuQg+WxsN3BiLOPUVo+rhOfy2OnXI4UoCKY
         rXoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zsqVMVpIzNTr7IoQ3O/Dm44fKdtIOuUfQLAv3kt0J3k=;
        b=Mkq9Qa4VObIUaiRB62Fge9ScqzSU/rJM3AlWFxu6YmDoPWuvuAz5eTtapXOmd+UgYe
         NRGnBDs9DJAF/FMhyrRGxQHjYvxyASCJ9nFMdjtVN9kdZvyDgu/9bE6/UcFZ26aULw9/
         WYuWxUKJc4gsvLyEeS/e9op3WX6ClhtNnqyAUIdiIu8xi0l0u68ZUqYIseF9uRppOaqt
         52OELWNyCwxlM9hnfJQwj6xs+c12BqD3gnjtbCvZWBGOBKiui/UShS/Gic/GXCg/OUtI
         O/YEOpmu9tBbGWgPL8RjRC1TVHef9ufF3tEMGvjtfSDCapr+3qcxb3caOp7tbB2XM2DA
         +8aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpp5C+NGv30BgR1V/0jqNQIeHI/IXH902vz8qLP7FSvwLpLbdbi
	+7RZC+hgunPC4TKj7mpTgUs=
X-Google-Smtp-Source: AMrXdXtR1oqnZAK8vGwTajD30MLjIOb8gf7eZD/+57wD3SuPZpl7sIgmhmvWAy9fCNbBHXCOft/AuA==
X-Received: by 2002:a05:6870:bacc:b0:15f:8b1:503e with SMTP id js12-20020a056870bacc00b0015f08b1503emr1025012oab.81.1674208707730;
        Fri, 20 Jan 2023 01:58:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:601:0:b0:36e:b79c:1343 with SMTP id 1-20020aca0601000000b0036eb79c1343ls146637oig.7.-pod-prod-gmail;
 Fri, 20 Jan 2023 01:58:27 -0800 (PST)
X-Received: by 2002:a05:6808:301f:b0:360:fe3d:8b32 with SMTP id ay31-20020a056808301f00b00360fe3d8b32mr7777373oib.49.1674208707247;
        Fri, 20 Jan 2023 01:58:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674208707; cv=none;
        d=google.com; s=arc-20160816;
        b=CzhU8QHHMYb1vz+/WtqJhAk/55ykG7HpF3OaUOOKQDdAOsl9FxSvJvj3eq+eA4hvPh
         dQKZ3LqTQ4PonoOQIJ+XRh97i92Ztk1tMwjOeKi5DzfFjSYjzX4Swju6A8/CWmGE0wS1
         h/M/ajNTZL7nAk91cmKkl3rPnAFrkQAV1Vh/ZjLR0GjKEpkh3ViQh9i/abHygPVc9ZjD
         STkyLMGWCwBL1n9LCHR+TIWqf4CrWWYZMWnrfQeSYKwE3OZSAc1SuzYDoks6ayuHKnZo
         keNTdvO4xxinJ0uU+cvPbEdnDzPbFCn5rBQpsEGJWs/C4CinH9NIok/+dO2NwLDb2Tuc
         ZX2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:to:from:date:dkim-signature;
        bh=5PCjUACeYMR6O3y/YgzV4vR8g0qeDy6mmRm0X3w+etU=;
        b=rhl+tpJO2wHHWkQdAhp01Qsd2hVWrDhOFWQBHg1K2LkXGXODWc69ax5ePAkBSeXlfv
         +/wNzXUUgZ7OfxJxo6aWfLus30EV4zEsWMmJUwnRxikQSuzIo8WpPMsAIz95iRM8D8kE
         5WTOfPH8bbV3tn76vDMb+7lNGk+aXzv/rjlwNhpyRZ2P0R63D6y55mjN7NIzVqdk8chX
         x+N2pCyNj5jLfbseZ8bDXt/pBAh/cLd1/LwWQbmFJ2xJ8y+kPj++0sJGqOccDY45SE0V
         TWmnL+Dct5zixRf7WdVtajkc6kA0QxlWAv7w5Dh8H6J5HDV+7c0vlFWtTazvbm+CjoIM
         aE/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UZLTzgFB;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id q64-20020acad943000000b003649544b773si56232oig.4.2023.01.20.01.58.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 01:58:26 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pIo84-000bhh-0o;
	Fri, 20 Jan 2023 09:56:12 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8E6D0300657;
	Fri, 20 Jan 2023 10:56:35 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 739372133D202; Fri, 20 Jan 2023 10:56:35 +0100 (CET)
Date: Fri, 20 Jan 2023 10:56:35 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
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
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
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
	linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
	Ulf Hansson <ulf.hansson@linaro.org>
Subject: Re: [PATCH v3 16/51] cpuidle: Annotate poll_idle()
Message-ID: <Y8plU/f2WsmGG66H@hirez.programming.kicks-ass.net>
References: <20230112194314.845371875@infradead.org>
 <20230112195540.312601331@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230112195540.312601331@infradead.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=UZLTzgFB;
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

On Thu, Jan 12, 2023 at 08:43:30PM +0100, Peter Zijlstra wrote:
> The __cpuidle functions will become a noinstr class, as such they need
> explicit annotations.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
> Acked-by: Frederic Weisbecker <frederic@kernel.org>
> Tested-by: Tony Lindgren <tony@atomide.com>
> Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
> ---
>  drivers/cpuidle/poll_state.c |    6 +++++-
>  1 file changed, 5 insertions(+), 1 deletion(-)
> 
> --- a/drivers/cpuidle/poll_state.c
> +++ b/drivers/cpuidle/poll_state.c
> @@ -13,7 +13,10 @@
>  static int __cpuidle poll_idle(struct cpuidle_device *dev,
>  			       struct cpuidle_driver *drv, int index)
>  {
> -	u64 time_start = local_clock();
> +	u64 time_start;
> +
> +	instrumentation_begin();
> +	time_start = local_clock();
>  
>  	dev->poll_time_limit = false;
>  
> @@ -39,6 +42,7 @@ static int __cpuidle poll_idle(struct cp
>  	raw_local_irq_disable();
>  
>  	current_clr_polling();
> +	instrumentation_end();
>  
>  	return index;
>  }

Pff, this patch is garbage. However wrote it didn't have his brain
engaged :/

Something like the below fixes it, but I still need to build me funny
configs like ia64 and paravirt to see if I didn't wreck me something...

diff --git a/arch/x86/kernel/tsc.c b/arch/x86/kernel/tsc.c
index a78e73da4a74..70c07e11caa6 100644
--- a/arch/x86/kernel/tsc.c
+++ b/arch/x86/kernel/tsc.c
@@ -215,7 +215,7 @@ static void __init cyc2ns_init_secondary_cpus(void)
 /*
  * Scheduler clock - returns current time in nanosec units.
  */
-u64 native_sched_clock(void)
+noinstr u64 native_sched_clock(void)
 {
 	if (static_branch_likely(&__use_tsc)) {
 		u64 tsc_now = rdtsc();
diff --git a/drivers/cpuidle/cpuidle.c b/drivers/cpuidle/cpuidle.c
index 500d1720421e..0b00f21cefe3 100644
--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -426,7 +426,7 @@ void cpuidle_reflect(struct cpuidle_device *dev, int index)
  * @dev:   the cpuidle device
  *
  */
-u64 cpuidle_poll_time(struct cpuidle_driver *drv,
+__cpuidle u64 cpuidle_poll_time(struct cpuidle_driver *drv,
 		      struct cpuidle_device *dev)
 {
 	int i;
diff --git a/drivers/cpuidle/poll_state.c b/drivers/cpuidle/poll_state.c
index d25ec52846e6..bdcfeaecd228 100644
--- a/drivers/cpuidle/poll_state.c
+++ b/drivers/cpuidle/poll_state.c
@@ -15,7 +15,6 @@ static int __cpuidle poll_idle(struct cpuidle_device *dev,
 {
 	u64 time_start;
 
-	instrumentation_begin();
 	time_start = local_clock();
 
 	dev->poll_time_limit = false;
@@ -42,7 +41,6 @@ static int __cpuidle poll_idle(struct cpuidle_device *dev,
 	raw_local_irq_disable();
 
 	current_clr_polling();
-	instrumentation_end();
 
 	return index;
 }
diff --git a/include/linux/sched/clock.h b/include/linux/sched/clock.h
index 867d588314e0..7960f0769884 100644
--- a/include/linux/sched/clock.h
+++ b/include/linux/sched/clock.h
@@ -45,7 +45,7 @@ static inline u64 cpu_clock(int cpu)
 	return sched_clock();
 }
 
-static inline u64 local_clock(void)
+static __always_inline u64 local_clock(void)
 {
 	return sched_clock();
 }
@@ -79,7 +79,7 @@ static inline u64 cpu_clock(int cpu)
 	return sched_clock_cpu(cpu);
 }
 
-static inline u64 local_clock(void)
+static __always_inline u64 local_clock(void)
 {
 	return sched_clock_cpu(raw_smp_processor_id());
 }
diff --git a/kernel/sched/clock.c b/kernel/sched/clock.c
index e374c0c923da..6b3b0559e53c 100644
--- a/kernel/sched/clock.c
+++ b/kernel/sched/clock.c
@@ -260,7 +260,7 @@ notrace static inline u64 wrap_max(u64 x, u64 y)
  *  - filter out backward motion
  *  - use the GTOD tick value to create a window to filter crazy TSC values
  */
-notrace static u64 sched_clock_local(struct sched_clock_data *scd)
+noinstr static u64 sched_clock_local(struct sched_clock_data *scd)
 {
 	u64 now, clock, old_clock, min_clock, max_clock, gtod;
 	s64 delta;
@@ -287,7 +287,7 @@ notrace static u64 sched_clock_local(struct sched_clock_data *scd)
 	clock = wrap_max(clock, min_clock);
 	clock = wrap_min(clock, max_clock);
 
-	if (!try_cmpxchg64(&scd->clock, &old_clock, clock))
+	if (!arch_try_cmpxchg64(&scd->clock, &old_clock, clock))
 		goto again;
 
 	return clock;
@@ -360,7 +360,7 @@ notrace static u64 sched_clock_remote(struct sched_clock_data *scd)
  *
  * See cpu_clock().
  */
-notrace u64 sched_clock_cpu(int cpu)
+noinstr u64 sched_clock_cpu(int cpu)
 {
 	struct sched_clock_data *scd;
 	u64 clock;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y8plU/f2WsmGG66H%40hirez.programming.kicks-ass.net.
