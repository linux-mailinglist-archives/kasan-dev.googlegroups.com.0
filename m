Return-Path: <kasan-dev+bncBDBK55H2UQKRBVEIUKMQMGQE57L57TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D3F765BCFC6
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 17:01:41 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id o21-20020a056512053500b0049c6aae1c40sf6580941lfc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 08:01:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663599701; cv=pass;
        d=google.com; s=arc-20160816;
        b=hQwUhiTUEby5iPnILg2pN9HflYziMTbIFP4jtGi7OQaDZUuJETMz5hPJg0vaMBVPZv
         y3qzQZ4lHd9T1/owjK3P/Xvwvrze/P9KFHP4AoGhTOs8/ctgb2jsqDFxoMUSW35ggAwr
         blj0nteg4GW3XCE+abUsarNW47abYjYt/KkZK3JTxl1OfV9UyZnV8T77NipFgJH78ZXM
         pR2D4mUzXx1YLA6+i/yyWRecKrodK03kcwkyvx9596dta27n8X/a0CTMkMCK8ipPCx3h
         kG6+M3dWiaxz82gM3+23L3IRTq/IaPWwaDvZDaKFf4nYtz2KCSn52U09i2ptvrdRqcYs
         BjKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wwyyboNnDMYgE5DQGEBigsqdVBosuXz7zVPqGJrSa5M=;
        b=ePkabB1uJO88bNoaF4bj0406DTp6Si/Ys8OzCikg5dT9GM+L3b14Em2oTSRDnS/aU+
         HmkIiJVSifQwb85uiLzhq10a18YcS/oN2UDTs8prakNNGPqOVAAhBVse4qIfmcY0RXtV
         JYm0EiDYR1ZUM1On46ljJNnJEMZOosTJgdVpVPOTkrocb8+PzZRJqe+NIELdiBieAE7H
         Nx9mgTT4BHYyK+Qu3qilM0RRzFbbSl0wBqwHlJ2tRvPzEycHF0mITEYuckTDw+wuByQ7
         zYXc/aj66N0N29afxsA0VWl3te269E9MPtciCh3wYRwJBey9La7cboiOhkU7D/c8soGE
         eXDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="g/io43Ri";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=wwyyboNnDMYgE5DQGEBigsqdVBosuXz7zVPqGJrSa5M=;
        b=cBUmjikt7TfbhvCVcjo8pbP4j+gQY5n4wlqO9IcxDzs7aWJSkSq4ugZD8XqpPc67Hg
         ZRghl69R55LHtAEQRGSIlTQCGOAK1yJ/CzBMwoNljtlGFaBK3uiAEjjxiK4R+wcNtZRs
         6e/wGz2SG/gXvxw3/pZKv+V5ZjqMDj/I30KdEIb8MO6gA82GnSReHIPMTtVb1TQAdUBI
         2KI+eBqwcP3lY0SVHOR598Od5TCVh6z8O/nsftjHOvBvNlzVdSILZRxT17pJ6m6poJGu
         bTKNnn16daHXegiOFJAu4T1hlDja/XkEB5bIOvM+bufb1o/rwlM3b8FxLb/Ff6cmi0iP
         VAzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=wwyyboNnDMYgE5DQGEBigsqdVBosuXz7zVPqGJrSa5M=;
        b=w51yBPtePgzgbv9BU66EAyFQVGKpePaG6CzWLumP2hf4g1ffIrJ8jjZp40nGldYZsx
         n9MH8x53x4Lvn5wSy0J2o4T5IWrSrZd17cHXENtu29YR/6XSUclRAqL779BnA/uqATkB
         TqF9DWucVeGbxSt2kSQdfaGOYinBWsboOxaQjqCbgz8zKSVb3YWp/SI4kPtbHPPBhAxJ
         VdUFD+okQgoXmNOLZMqyjlhrFzwcjxScv2f4mUq8EfY9PmhVArRE81rgqZ1k2n5ng6Ss
         WIJiHte7X0vJ/Rl3x+bzoy+UTJW/VaYzgT9w0fen/y3PMlCHI35wWBoWdKIDN3w3Ahpj
         JaCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1/2qz1nwIOxDc49sfJo4wnSz8abcfcbKTf9QybOVArGJNGbeF5
	TZ+Cq2R9mMahFZIs59odlDA=
X-Google-Smtp-Source: AMsMyM4b03LE26bUXiK96K8xTf9Q93mIovwNMsVtkplSuwB2qDt2E4TrcYvnr/CLilLaHwXTQIVjMw==
X-Received: by 2002:a2e:bd09:0:b0:264:6516:93f9 with SMTP id n9-20020a2ebd09000000b00264651693f9mr5403926ljq.127.1663599701246;
        Mon, 19 Sep 2022 08:01:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f7a:0:b0:49a:b814:856d with SMTP id c26-20020ac25f7a000000b0049ab814856dls323747lfc.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 08:01:39 -0700 (PDT)
X-Received: by 2002:a19:dc1a:0:b0:494:903a:1fa8 with SMTP id t26-20020a19dc1a000000b00494903a1fa8mr6476907lfg.55.1663599699800;
        Mon, 19 Sep 2022 08:01:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663599699; cv=none;
        d=google.com; s=arc-20160816;
        b=WVDI886dHPUspihO08htp9LmEDljt28QBK4rL5d6Emdns9fdpQL/NLxCUTyCNOI/5G
         Q0ZYh6qecb0x2vdPb4lZ4y1CQranjE7pIOtjTpDlTwRE20+4cVP3P24D3rVO7DsjWngL
         xMapfJA8J0OhPQ96n3NwliJMeOzMXywQzr0SsrZuQHA5L6SKp34geVfc2KWT7Ym0i4WS
         11JVPtqNHyZZmwqJQIl9hAXODwP8P+r9QjjN+0y12xpAsb9RqZeP6zT2rLaQA+skKaGz
         7+6QcoFJLteD+r/roOpgMFlmC+AkZGgA25Ybjy2JmkIyehEMM77LYpjUzSbccD3GzRre
         34zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GQT9ZKmQZViLafATQeaZBpdND2gP4uRG0ahM2YMYtd8=;
        b=R4mWanDMEBXCXMP1jCLiQSJ7Uov2/+2wai8IzQeECe9nZp/UKYOZRbIf6dVfOIZ4/I
         0dNqHS7Bxph6q5n2kL+qCC1fs8ECKdap8hnmJa2NS0cq1+giZ2Qm83f5rX+0bDppGebk
         wjzWv7YYWCitmvMnJZZecCiTl67BvxQiGieXJ3/uXu+MrC4Ad0TRbW9IPQ8hymQffBgy
         V5Yz6h1Btwjpaz2fbOlMnndF2VWq8x2kJfgQpOzwRUYgVPCd0SUI4zr/U+Dqc7TqwUVZ
         7S5ZqkN0y6vGTRYegAtj55MGuG+K2fS0lOZd0Q2ysgpMrrGY4X2ztF8x+1m2XYFqk7Ou
         OCGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="g/io43Ri";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id p4-20020ac24ec4000000b00497f1948428si836375lfr.8.2022.09.19.08.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 08:01:39 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaIGj-00E6aa-7F; Mon, 19 Sep 2022 15:01:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C28A13005DD;
	Mon, 19 Sep 2022 17:01:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A79C82BA49026; Mon, 19 Sep 2022 17:01:08 +0200 (CEST)
Date: Mon, 19 Sep 2022 17:01:08 +0200
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
Message-ID: <YyiENIiiw0lx4z3l@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
 <20220919144941.GA62211@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919144941.GA62211@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="g/io43Ri";
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

Duh, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyiENIiiw0lx4z3l%40hirez.programming.kicks-ass.net.
