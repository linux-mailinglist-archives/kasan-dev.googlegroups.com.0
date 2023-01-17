Return-Path: <kasan-dev+bncBDZ3RP6QQMIBBCW6TKPAMGQEBLAKAVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E7ED66E053
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 15:22:03 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id y26-20020a0565123f1a00b004b4b8aabd0csf11702582lfa.16
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 06:22:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673965322; cv=pass;
        d=google.com; s=arc-20160816;
        b=QY73MpaPM+71y0PAcax3brcr9iqxWhVBq8GW10kBXY47rwczLh+2jHpE7ZbernALnn
         rvmhIMut1JbUV+ZIlkJ2EiDvu89Eaf+1VM7Yjs3s6ofAu4z4u1/GR0wrSleBJo2lGd3q
         jHcLpOj4qQ+o2axO1gsTcCV39cISmAWHvHXkWgMZoAVqlaOMo18LRQx4Z70AF5pT7+JH
         +wXnoEL3/Zp6LxfgUUGZaCQWjVYJDvDIU2iYE/n1Pk/ArXOYOPgFUjO/JBEEzCDzdWMJ
         lU/Gdau37hCRq6yw2Wp5ipTH9tQK9jEzdFKxF8nQoISGZB8L5SdWNPM99xIKcmWNruiO
         n87w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AMweAGBAo5FMtSD/IxSU/0p8ga90F5U6uSdb84lbov0=;
        b=ObLmTRPRVnN5OTxRQzaIJhO89QRedbFwdYJ6K7oCMgoVVM8J3ybak+0X4PfcLY0SR9
         d1naFlSfWZDOlhE+4OUR5PfXXuNSZdRNIBh1EjIJjJ5jp+OktJTMtm8FDKuzoRHIE9Gx
         YE5olzHhgUAxsVYWjh665ffl7PyTewTM0+3EzRQsxT/0wDaujCPX4UXFdt1g7S5xqFzm
         Ofa4/xCckULOgjv391xdTFvbAZT9+c3hqkbyFGNGnj0f2BTOerNYX+96tNcUzrprOg49
         8jNPl/WIChntC4VORQKaWevvBQ+OQLCvHHEr4pih4/hQ8UmZXONL2dPWlLhfIN2rjMYa
         P6rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sudeep.holla@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=sudeep.holla@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AMweAGBAo5FMtSD/IxSU/0p8ga90F5U6uSdb84lbov0=;
        b=IZ0kIRcSHYhxeluC4zdvwbGsP4qjG30D+xYn/exopue1w0jmvzq3nhScItCMAAlRyH
         a867YvCm9mZN8flXMMNU7JD8WUnGxxpAx8oW7lv4jhMs7apYIO8GzOGdytCIjsYilZXm
         JmCZZ5K7QIZ/uWO/9nUKHtGkEpbgKEs6NZyHfYU4HfdmsV1ln1moxD+44GjpNsoeqDeN
         uDZqlaEzjOES7RjRGg1KPw+8VEgX50OpV4gWffZ8ur92AH/8G8CEEpAHSc2Q63F7OOBf
         ZELAbCKadESL/TLEMV/UJoIvedb/zA2uHYvvjG04DJbdK3wCSvD/E4OojLR7Y/x6iqfq
         xx2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AMweAGBAo5FMtSD/IxSU/0p8ga90F5U6uSdb84lbov0=;
        b=LkdXnvxKQjKcmJqghm7xLI0EXMtueP+0Rr+aKN1y4Cc5HF3TN6zIyyizlIn6SmWQvR
         KGvSF1OsKUX0eJ1ysJ5W9pqpbiFnVY/Xkb1EuTUR+JelXVvhW7c0JKSRHx5E4Q4JS4wy
         qO4qdPAPPXc6+C6S9pxIuZu1dRfkMtIbrF5CQmnek5dDsRLzUZ3dOtu8WrKOqVJX+7HR
         8VD96tDX0PRaYbjlU1Q7DE5BmMOdmMgy+zMmfi8E2R/jT5wJbA0uWv1spg21wYR7gN3f
         mPSYF3ouk7D+xSmyVFFDOgIYbtoDcm+Adsre12TU09Npectuam4zsx+XJdu/rhcdwqK+
         4JLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koS97Xr9F5ouZoJW3zQCH3f3QOrrdlV4Kze5Vryw5IPYFldAeaG
	pItDsB7bLEmlMpWzR0vXg6M=
X-Google-Smtp-Source: AMrXdXuXyIRFbufEvY8djMMb9F3uCMoXZ63vz7++YtNa9fUBIrRXC61geL72M0rk7AIxpeagju1XTQ==
X-Received: by 2002:ac2:51dc:0:b0:4b5:b87a:3271 with SMTP id u28-20020ac251dc000000b004b5b87a3271mr157450lfm.18.1673965322586;
        Tue, 17 Jan 2023 06:22:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9cc4:0:b0:27f:bedd:57d with SMTP id g4-20020a2e9cc4000000b0027fbedd057dls2198200ljj.10.-pod-prod-gmail;
 Tue, 17 Jan 2023 06:22:01 -0800 (PST)
X-Received: by 2002:a05:651c:1593:b0:28b:803d:6edf with SMTP id h19-20020a05651c159300b0028b803d6edfmr1300471ljq.47.1673965321074;
        Tue, 17 Jan 2023 06:22:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673965321; cv=none;
        d=google.com; s=arc-20160816;
        b=b04YHyi2BQsEN8thi0g/exIrchd9+B2Lm/htNPy98G4RJCajFoBxNBANecgYaKPx3T
         ZWfdsffDYM+VtJIyLBzs2UsWkdjwB1YlimYLMDVw0YkFxGkDYYVb/pkUV6k/kvlFTAG9
         wmjIa3HuShLcx5ZPi//MnDnwlFxysnJB55i5cGTjYcFg6I6sjOqSPdOF7JzFUcaYuT6P
         U0BJyHj/YiyZDwKghTUXFiSOUTNrq82+Zgacp0yWjCIHrh/WffW0hSDrI2YN4kCM+OmK
         huOVujJwpJL8TSTJ++c3cdbbvv6dJDKBU8BHAOHgidQwAOiky87P8I6LUH5qYPJL8E2H
         FCgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=7+kFAh0wnPL2tfKa1ef1/Kgl91+ayvD2C78qXGWHpos=;
        b=rZli4gwV+TKP8VwGxGuFW+qABXNJ53ezs3qVtkgzNVCDRA/hwcTcOuup6eIyOFSjOS
         IytwA/K4BIEaisL0SzFh3JkPXCngsBeKa6WdXDimR7TkKXKPPuStvDcu2o1fdb1vdSKX
         VbVkDXBH7Q8e3zWJb7I9j/+SVZanCEn803ixoAadDaskIo6Fh5fFlvzIbcBQhR7rIoYv
         V7CiU+q44tpzMeaoEfd7T4oYRsx4dZZ456JxYLd+exF5Xl/ZvI5mScUnyCmuSTMnd265
         HrgwmTzPN/R2mRtLoR6hdiSc5i/O3sZlJHtMCzgEObrxLnYDPltohfaAmZ1GnKGLy6wV
         ba0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sudeep.holla@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=sudeep.holla@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bf26-20020a2eaa1a000000b0028586d0af2fsi1103709ljb.7.2023.01.17.06.22.00
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Jan 2023 06:22:00 -0800 (PST)
Received-SPF: pass (google.com: domain of sudeep.holla@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6A88CAD7;
	Tue, 17 Jan 2023 06:22:41 -0800 (PST)
Received: from bogus (e103737-lin.cambridge.arm.com [10.1.197.49])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1B3A83F67D;
	Tue, 17 Jan 2023 06:21:43 -0800 (PST)
Date: Tue, 17 Jan 2023 14:21:40 +0000
From: Sudeep Holla <sudeep.holla@arm.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>, richard.henderson@linaro.org,
	ink@jurassic.park.msu.ru, mattst88@gmail.com, vgupta@kernel.org,
	linux@armlinux.org.uk, nsekhar@ti.com, brgl@bgdev.pl,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org,
	krzysztof.kozlowski@linaro.org, alim.akhtar@samsung.com,
	catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org,
	bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name,
	geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu,
	tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se,
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
	James.Bottomley@hansenpartnership.com, deller@gmx.de,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
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
	agross@kernel.org, andersson@kernel.org, konrad.dybcio@linaro.org,
	anup@brainfault.org, thierry.reding@gmail.com, jonathanh@nvidia.com,
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
	Sudeep Holla <sudeep.holla@arm.com>
Subject: Re: [PATCH v3 00/51] cpuidle,rcu: Clean up the mess
Message-ID: <20230117142140.g423hxisv7djudof@bogus>
References: <20230112194314.845371875@infradead.org>
 <Y8WCWAuQSHN651dA@FVFF77S0Q05N.cambridge.arm.com>
 <Y8Z31UbzG3LJgAXE@hirez.programming.kicks-ass.net>
 <Y8afpbHtDOqAHq9M@FVFF77S0Q05N.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y8afpbHtDOqAHq9M@FVFF77S0Q05N.cambridge.arm.com>
X-Original-Sender: sudeep.holla@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sudeep.holla@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=sudeep.holla@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jan 17, 2023 at 01:16:21PM +0000, Mark Rutland wrote:
> On Tue, Jan 17, 2023 at 11:26:29AM +0100, Peter Zijlstra wrote:
> > On Mon, Jan 16, 2023 at 04:59:04PM +0000, Mark Rutland wrote:
> > 
> > > I'm sorry to have to bear some bad news on that front. :(
> > 
> > Moo, something had to give..
> > 
> > 
> > > IIUC what's happenign here is the PSCI cpuidle driver has entered idle and RCU
> > > is no longer watching when arm64's cpu_suspend() manipulates DAIF. Our
> > > local_daif_*() helpers poke lockdep and tracing, hence the call to
> > > trace_hardirqs_off() and the RCU usage.
> > 
> > Right, strictly speaking not needed at this point, IRQs should have been
> > traced off a long time ago.
> 
> True, but there are some other calls around here that *might* end up invoking
> RCU stuff (e.g. the MTE code).
> 
> That all needs a noinstr cleanup too, which I'll sort out as a follow-up.
> 
> > > I think we need RCU to be watching all the way down to cpu_suspend(), and it's
> > > cpu_suspend() that should actually enter/exit idle context. That and we need to
> > > make cpu_suspend() and the low-level PSCI invocation noinstr.
> > > 
> > > I'm not sure whether 32-bit will have a similar issue or not.
> > 
> > I'm not seeing 32bit or Risc-V have similar issues here, but who knows,
> > maybe I missed somsething.
> 
> I reckon if they do, the core changes here give us the infrastructure to fix
> them if/when we get reports.
> 
> > In any case, the below ought to cure the ARM64 case and remove that last
> > known RCU_NONIDLE() user as a bonus.
> 
> The below works for me testing on a Juno R1 board with PSCI, using defconfig +
> CONFIG_PROVE_LOCKING=y + CONFIG_DEBUG_LOCKDEP=y + CONFIG_DEBUG_ATOMIC_SLEEP=y.
> I'm not sure how to test the LPI / FFH part, but it looks good to me.
> 
> FWIW:
> 
> Reviewed-by: Mark Rutland <mark.rutland@arm.com>
> Tested-by: Mark Rutland <mark.rutland@arm.com>
> 
> Sudeep, would you be able to give the LPI/FFH side a spin with the kconfig
> options above?
> 

Not sure if I have messed up something in my mail setup, but I did reply
earlier. I did test both DT/cpuidle-psci driver and  ACPI/LPI+FFH driver
with the fix Peter sent. I was seeing same splat as you in both DT and
ACPI boot which the patch fixed it. I used the same config as described by
you above.

-- 
Regards,
Sudeep

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230117142140.g423hxisv7djudof%40bogus.
