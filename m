Return-Path: <kasan-dev+bncBDBK55H2UQKRBQUJUKMQMGQEZMEL7MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF6215BCFEE
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 17:03:30 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id h21-20020a2e9ed5000000b0025d516572f4sf7152817ljk.12
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 08:03:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663599810; cv=pass;
        d=google.com; s=arc-20160816;
        b=W+TXKdDSwF1HPpemW8mLuphH1HO9QtCO0to/arIV2gykryPWbKNAJfxb/sEajlZvZL
         BLCEmFC74x0JUlGIUUCyqzDGa4ba2hvPgtMOBfhb+60wxCjApDR99HK0Hsa+zrzwAoKN
         xFRqL0P8iRF5/CL9wUtOj8Wa2bQgqwOEmeiWjZ+t/K4le8OfKO+jv68S3XuHBVexMQ6s
         4XZ3Nhy0rVdEB0A9mgpsgMjEsd3RWE0Yl1PdvsU4vNhicYU21YKHbxDwD01HvB+rJ+rS
         CPpWdQ2Sm97SGXLLtXps8pv7yMLENuzGbIg6H0bLbhBq8Y7aL09PbBgslsFupDDEiQrK
         9Dmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7JFLJBhCfPLQj8OCe7bcsQT7cXEu3QrVFwT7lHu6BYc=;
        b=q2RBPe4AwlgiG7EEiOJ2czWJKSWjN4z+d7FPoP9J76Ut/UmFeCcv0ktlABcZ3sf9yw
         lAmDqkIzm/1FEB0eK6Lpu4UpDO0DLRQ5/eXfVVU7BcPUNGwnL2yvEr4nTXng/DC2DRFt
         80jCtGsewLKt9QVbZxUEKUhreMBY5y5vMUf8fUbmEy/LYz6dC5dn4jUJsHnxrElafY5Z
         SVpRokW2ejZ50GjkG+tC0DWuenLDzy+sJ1xTbZcg4DeJkANGJLTpw2u7u5Dt+/S/XlOj
         JW+leRda6bsYkZsb+I7EQyuxkveisyf9+yCHvBg4NT1Nzyff6dicnUWBqeEtq/NKgPPK
         rR+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=U5nJ9bmb;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=7JFLJBhCfPLQj8OCe7bcsQT7cXEu3QrVFwT7lHu6BYc=;
        b=r6Xfa6gPYsQXzfEVDIWZmW2Mq4UxfCxko75LIp6sk63ZsuuKBDAmqiAbV6aHrVeCIA
         RhjZBn3ho8ezP/3pz4xjrCo1P5PXsUdqxYZbJFQv+w4HcjdyOplgjNBvs5Hw2QjrdIA4
         qxzEzdRGNhXSo7ag9u9XEEw9b85o0BS8vGcIzM+aoyhReVf9OjH83tkXd6/2LhgD1ot0
         sfVB9kZXcB+c03WyzIa1AkzD7NFnTmbhrx8LGptsGzf/wccSZggyTRgS/LfFRhu48S+J
         sQBdW9GCesRV0pqJyqezO9JH0jrjHbteuRmd5IO9puw6qQkWGrQGN5CCA2luiIFy65Vl
         UABw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=7JFLJBhCfPLQj8OCe7bcsQT7cXEu3QrVFwT7lHu6BYc=;
        b=dNaQMVI5AjHgrun/CttWgVQ5yggJoIDMO56v7SoTgocua/ge5s2WwWMrZrB/NWJIF4
         hdslvgn342Xyq9xMB8K/dJ7XrSmK0BcvGDqOSbRpxVwMZpGH4nWinu+PiKeUsItavvht
         PyJapYlefZgNzIx8Tu0rcnJg8IQWb/oNnMwHJd1K+atAW2CJOZJIGAMl1mzMyCTuP98h
         5Xa19TPhJytX1+ff1qvUpoY1X919gsIZ6PmTH2zCYfKVepcK/B1j8Tlx2b+mzj7QphXG
         E6u7TGa+mFjSKW70IqK/sJlUBMkYe972azv7txry7/FxVZ5OqAWIw+b2Kxry/kzLB+5m
         lojQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1K+kKXbpq9P52qnHrEcej3/63I6uC+j8rUMNj0dI17A4ReNxtJ
	FgCfwAw2In3cXRRF3xsyXnw=
X-Google-Smtp-Source: AMsMyM6wod97rDn+8vxVc0TI0vaU0h434p6NsTcigpJ7lWMR2f6VYbj2nSgQjVLJRt9g5PLpBtsEcQ==
X-Received: by 2002:a2e:54a:0:b0:26a:c623:2a3 with SMTP id 71-20020a2e054a000000b0026ac62302a3mr5538960ljf.135.1663599810329;
        Mon, 19 Sep 2022 08:03:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b60b:0:b0:26b:db66:8dd4 with SMTP id r11-20020a2eb60b000000b0026bdb668dd4ls707312ljn.8.-pod-prod-gmail;
 Mon, 19 Sep 2022 08:03:28 -0700 (PDT)
X-Received: by 2002:a05:651c:1a0a:b0:26c:d1e:7b3 with SMTP id by10-20020a05651c1a0a00b0026c0d1e07b3mr5754961ljb.160.1663599808802;
        Mon, 19 Sep 2022 08:03:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663599808; cv=none;
        d=google.com; s=arc-20160816;
        b=RqsU8rgOoD52FAHd/9+IhaL8i+HAjtYb3f3KUSjxkd64Zkj4sM3NBJrrd9lF1Z3o9D
         ibAdpMHk09N/YXF3dYcHjqDeV9wrBNMCQNYZdH1NShU4Vuaon2W/Q06qC4kdYMoMgloG
         AAdjECagrNgRJmkeWXkNDyY7EfeNEdAj+VY5ZSZ9UCHB+j43VoxL9NvVNpVMi7+a+VIg
         2kEpudPwriUzXhndOI+II/nNZ1hHwrniNEcW4HkCS5nEkoTn7bf2gw2KVGqX9oNkahrh
         HkkmAsBuRezoJRLFTvtXqb8ovAfwEnr6GUn1UBn2omn6wG1Yfi5bE+TwOlexAxznViCe
         40lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8W4ANpZZg81bkZotlJvZ4fg4qiAvSnY5PZyc1BTsWP4=;
        b=PqoeOJurBdQkEBXoqIk/ZJfkElx2ZY0eK6hc69D2aJgyuQwhyqFnsSyr2X7nN2Sk2Y
         mFmFJ2P0r1QVPq/5kpWo1B2+e0e1sQW+YqpUfxg6EzI/eRpjbOHXsd+4vcP0hTHAzMXm
         zJ7BiMMayycosJZm0dcw60848t0XnfxE35kD+H201955FynR+WbCWs62nG0HWaMmDPPd
         FtuYIcpq5Lyk3pZxt/K5I1W1yticoBqzSpIYwPxCNDs+H0iXMfsAvbAcW7gf/djArzto
         f0q501PhPr6XVX3bHIQAQa/6HVd+YA4biEoM8WvZ1sGpknjyNwV5m5FU2WH1bd+k8S62
         b+kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=U5nJ9bmb;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id z20-20020a05651c11d400b0026c3d772786si279033ljo.3.2022.09.19.08.03.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 08:03:28 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaIIb-00E6gm-0R; Mon, 19 Sep 2022 15:03:05 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 833DC3001F3;
	Mon, 19 Sep 2022 17:03:04 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5DBEE2BAC7A31; Mon, 19 Sep 2022 17:03:04 +0200 (CEST)
Date: Mon, 19 Sep 2022 17:03:04 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Frederic Weisbecker <frederic@kernel.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com,
	will@kernel.org, guoren@kernel.org, bcain@quicinc.com,
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org,
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de,
	dinguyen@kernel.org, jonas@southpole.se,
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
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
	konrad.dybcio@somainline.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 08/44] cpuidle,imx6: Push RCU-idle into driver
Message-ID: <YyiEqDSJVOZrQYg8@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
 <20220919144941.GA62211@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919144941.GA62211@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=U5nJ9bmb;
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

On Mon, Sep 19, 2022 at 04:49:41PM +0200, Frederic Weisbecker wrote:
> On Mon, Sep 19, 2022 at 11:59:47AM +0200, Peter Zijlstra wrote:
> > Doing RCU-idle outside the driver, only to then temporarily enable it
> > again, at least twice, before going idle is daft.
> > 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > ---
> >  arch/arm/mach-imx/cpuidle-imx6sx.c |    5 ++++-
> >  1 file changed, 4 insertions(+), 1 deletion(-)
> > 
> > --- a/arch/arm/mach-imx/cpuidle-imx6sx.c
> > +++ b/arch/arm/mach-imx/cpuidle-imx6sx.c
> > @@ -47,7 +47,9 @@ static int imx6sx_enter_wait(struct cpui
> >  		cpu_pm_enter();
> >  		cpu_cluster_pm_enter();
> >  
> > +		ct_idle_enter();
> >  		cpu_suspend(0, imx6sx_idle_finish);
> > +		ct_idle_exit();
> >  
> >  		cpu_cluster_pm_exit();
> >  		cpu_pm_exit();
> > @@ -87,7 +89,8 @@ static struct cpuidle_driver imx6sx_cpui
> >  			 */
> >  			.exit_latency = 300,
> >  			.target_residency = 500,
> > -			.flags = CPUIDLE_FLAG_TIMER_STOP,
> > +			.flags = CPUIDLE_FLAG_TIMER_STOP |
> > +				 CPUIDLE_FLAG_RCU_IDLE,
> >  			.enter = imx6sx_enter_wait,
> 
> There is a second one below that also uses imx6sx_enter_wait.

Oh, above you mean; but only @index==2 gets us into the whole PM crud.
@index==1 is fine afaict.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyiEqDSJVOZrQYg8%40hirez.programming.kicks-ass.net.
