Return-Path: <kasan-dev+bncBCBMVA7CUUHRBFEQUKMQMGQEORHCCGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 565DE5BD066
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 17:17:41 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id v11-20020a056402348b00b004516e0b7eedsf17687887edc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 08:17:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663600661; cv=pass;
        d=google.com; s=arc-20160816;
        b=d0YCosN8/X6pvXemDiVCYyASv/dmJ/6OeFpH+97HQWJ0DS6orfAc+E2ZGE/JRJIb2y
         ivuJuvimjoCNEHnsJO/2uiA7PCKs/0gPYTK3H5j5pw4p7moWBIm+JDVMf3zcWH2h7nHW
         4hCktNTau9MLiEB3q0WJ1woKqyxVWB/9nLFzo/pBpQm8SjJPsdIVGI/BDHM6VMBAH51Y
         PN0odY+3JD0sTm0Kl9oyOw6jcYVz14495+Hl/2140Sq8bJM6sADeTVJWEPmWQAgGXXbM
         grEk4DFx4zTdK2+V+oqJGlgn3QA98Xw33Ey/J9YzS+bljutqgme6vXO0VyG3FTqKaiMg
         nOng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=A2mP3CyrEv0YxNh0Wc4+6SnWQ8kT49X5yDRvUt40Jh8=;
        b=FOzGmOf+Eb9QwXlZpWmakYoNqqmUH/zFkdKEh4fPIJDPK1dDDSGDh1ZYln/71qnwCo
         e3GMdIzXx79BxPpTMZT3T9UG3nO1TBFetkXJMCQLo1BE6S8xM0v8z0i5rzqJLWOOotaQ
         cf3cjUN0GIdwqtYeDpvPY3Xkz8uFQGbGqxeqRHoT8RiwnYH7mabndL51kwFqUjknNTV8
         pkf5DFvdLSpHJm+PFiCTP4Kwp4O27BqsKi8BlvgwNp+p3LDJxWnhUluJTUnbkewKvBxW
         7e3ZZocd+VXMZA8PfPBkbIUifasxKb9p/6dAvT2KDm42wEqT9hxFs0EY1paQXw8pAMOM
         ykiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fxVxz+v2;
       spf=pass (google.com: domain of frederic@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=A2mP3CyrEv0YxNh0Wc4+6SnWQ8kT49X5yDRvUt40Jh8=;
        b=q70nx2WWV66ejj5eTPiS4/Z+fedw+HDI6oEzHts7vhreBxfkxMbFxPxsEk+2xKFPlz
         jp+7Hky+t/DiG97bZ6lzlY15HNwoZaK5l2rh5ZDA3CAMeY769f9zCKhvYhaftarqel9G
         d2HLVm7H4SFW4owI75y1+cBx/FcARsgSzz/uN+Q3cChFoXO35ANzxN/9owdw7+k6ggv4
         fb+Euy0H7ibpr2nplw3tXYPNH9/lanlNrSkWHcMhzZXkTNE67uwiJjT7CdVbKME2ylzB
         atVpm/gjYo+1UgxREpQEMl9K8fnwKN6CkGWmpi20TrCoubUnj+YcQ2m/QcQvC4tph49y
         rXvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=A2mP3CyrEv0YxNh0Wc4+6SnWQ8kT49X5yDRvUt40Jh8=;
        b=3PlbwGA2VGJpf6QKZi3oj176jl6R4ZYwiIabKsZTCnKKz7cUEHy6pVav+4PkGKOsjl
         vdqQ6fd44YC0P9I5OTWgvPQZ2Jyluaaw3n4U9zfKQ+xwcAAZ2iXvYTBrcdasda/12Y9q
         +qXeo5PHuCdQFlkHCkWALPvDfd+EUDc+49zd2h5hMM8H4p/lBA5MHS8CnbRh5O8p81CW
         jO2QSYORZ1e/4o1NsSIGGkQRB1EWhNuvAm8OaSQedTLz61FlvtW9pOe1//pQIqvJKJds
         SAEeFPu1xqRa8THQdRwaRCCUiziHGgqYgkifor2vdx4sMoN2dAY1qhAevslvze+gDZTr
         IWjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1ns1Qs262oYZOge3ddFgQEgSzBCOAzMSYDuIaR5s3UshQVCyC1
	B4vF0rymdEQqtALX1sf4Dys=
X-Google-Smtp-Source: AMsMyM5FPB1pNPpfkbAWm5aigx1s0RzRTUKL2/S81QfSKsbO6oZm6qrXr/TjducTxp1lUbGNVCqmQg==
X-Received: by 2002:a17:907:eaa:b0:772:b571:bd7c with SMTP id ho42-20020a1709070eaa00b00772b571bd7cmr12980185ejc.563.1663600660774;
        Mon, 19 Sep 2022 08:17:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3b0a:b0:77d:b590:5e60 with SMTP id
 g10-20020a1709063b0a00b0077db5905e60ls2394490ejf.8.-pod-prod-gmail; Mon, 19
 Sep 2022 08:17:39 -0700 (PDT)
X-Received: by 2002:a17:907:2d0d:b0:77c:d528:70b8 with SMTP id gs13-20020a1709072d0d00b0077cd52870b8mr12896663ejc.681.1663600659768;
        Mon, 19 Sep 2022 08:17:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663600659; cv=none;
        d=google.com; s=arc-20160816;
        b=OH3AUXNzDqUjNrUu6cu1aquVk8/FR4DW/HyaGJ5pYVbfhvkTu72N0xR1aX4GSvw5qc
         RNEmTLnEOXep0uCQwPFn5TtHQ1zKQ2XJXv3MEd7A27MC4TMMx2o2k9Pp/pq7+cSRdv/x
         tzDTTLj5XkPLpUnY8gYZ1s1NLKxQKDPL+r8lGst1Ck13zCRDV1JN0yVu4qPLCuQqMvqf
         CtmEqQoNB+U4TX0behuvh/xrBOmUJuOPSpWa0Cik4haEoQBoWtIAxJVLZVWcR1QK9ORz
         Kh7fijvRb2nsW1rOr1nHLPn5J+iI6lebUq6VpXriyOISj5i5OgjxKl1h3xEhuQssroPs
         MEaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GAWZKjgcowaWIL5IFK97hXiNgqbjuBY1+jY9f7JPqdg=;
        b=HNvcEOeiPKHfrAuNQy1DTem00cDKLqu9qnBQQnkj3cfZ6DQ8sW92ba5iOI04C6Ez9r
         7D0lPcsT17jcGLxdJ4wJXdwT3zuV80qwCUEGYpE6P2yAkvHvTK1n/ovu7XuacfJCdDkf
         lRnhE2wEeZjw9aTz+REs2eCoy1axwwsNflWb0DsjSGU+6bs8TDLSiCMEMwiftv4/lCO9
         QIRl/ac5r8jVwfXaPhFRBuN7UQuFpG9ub+bX8F9c2wDk8Pjumy8oIh5TGYd2flYWx8fP
         h62ajzlOQsjc4mL9zJnf2Y8eepvweRXjGYsPM9S+cbvIcLSB/Q4OucxUlcQ+dWxglChX
         HHfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fxVxz+v2;
       spf=pass (google.com: domain of frederic@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id jx24-20020a170907761800b00780aaa56c40si231361ejc.2.2022.09.19.08.17.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 08:17:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4907AB81D9A;
	Mon, 19 Sep 2022 15:17:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D47AEC433D6;
	Mon, 19 Sep 2022 15:17:36 +0000 (UTC)
Date: Mon, 19 Sep 2022 17:17:34 +0200
From: Frederic Weisbecker <frederic@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20220919151734.GB62211@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
 <20220919144941.GA62211@lothringen>
 <YyiEqDSJVOZrQYg8@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YyiEqDSJVOZrQYg8@hirez.programming.kicks-ass.net>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fxVxz+v2;       spf=pass
 (google.com: domain of frederic@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 19, 2022 at 05:03:04PM +0200, Peter Zijlstra wrote:
> On Mon, Sep 19, 2022 at 04:49:41PM +0200, Frederic Weisbecker wrote:
> > On Mon, Sep 19, 2022 at 11:59:47AM +0200, Peter Zijlstra wrote:
> > > Doing RCU-idle outside the driver, only to then temporarily enable it
> > > again, at least twice, before going idle is daft.
> > > 
> > > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > > ---
> > >  arch/arm/mach-imx/cpuidle-imx6sx.c |    5 ++++-
> > >  1 file changed, 4 insertions(+), 1 deletion(-)
> > > 
> > > --- a/arch/arm/mach-imx/cpuidle-imx6sx.c
> > > +++ b/arch/arm/mach-imx/cpuidle-imx6sx.c
> > > @@ -47,7 +47,9 @@ static int imx6sx_enter_wait(struct cpui
> > >  		cpu_pm_enter();
> > >  		cpu_cluster_pm_enter();
> > >  
> > > +		ct_idle_enter();
> > >  		cpu_suspend(0, imx6sx_idle_finish);
> > > +		ct_idle_exit();
> > >  
> > >  		cpu_cluster_pm_exit();
> > >  		cpu_pm_exit();
> > > @@ -87,7 +89,8 @@ static struct cpuidle_driver imx6sx_cpui
> > >  			 */
> > >  			.exit_latency = 300,
> > >  			.target_residency = 500,
> > > -			.flags = CPUIDLE_FLAG_TIMER_STOP,
> > > +			.flags = CPUIDLE_FLAG_TIMER_STOP |
> > > +				 CPUIDLE_FLAG_RCU_IDLE,
> > >  			.enter = imx6sx_enter_wait,
> > 
> > There is a second one below that also uses imx6sx_enter_wait.
> 
> Oh, above you mean; but only @index==2 gets us into the whole PM crud.
> @index==1 is fine afaict.

Ah ok, got it, hence why you didn't touch cpu_do_idle()...
May need to comment that somewhere...

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919151734.GB62211%40lothringen.
