Return-Path: <kasan-dev+bncBCBMVA7CUUHRB2HVUGMQMGQED2UAD4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 238625BCE66
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:21:30 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id br14-20020a056a00440e00b00548434985cdsf8889874pfb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:21:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663597288; cv=pass;
        d=google.com; s=arc-20160816;
        b=easLN/sqQVfcHgnDWaS7nfvrwi3np9RNLqVnAQBUifzjmYfbwgV/14osWI5I1KYbXT
         3BZseIIzjH8sydBZ0SIYJeIHrrr7BUo0l8vJS0C3f8He7pu0eK3Dyd4g8lqh9c7oKSwA
         TSG9yx8tz9dZUJl+4ZCWCnYuX+DijOJC/eC0fUt4p3qxiwp0UBZm1Kvo2ooB/ZYb6PJf
         8y93NV+lLwzTFbwS4DVg0vY2TIZViuF3oTYIAwFW/Vwi8W2pc37Pln2H0XNh1tXwwoAz
         2Liw7zWjhKbH4ebUyc/Ai7hHY0A5KZbDcxbSGO/NMhY+GE2PvCMrdFiIoLooiTqmt0re
         P4aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qYooU2H24yfLUIEvaZwRcjEq7qgXmoGamI3OPX5PJao=;
        b=PedG3RMgHB5YF2LB+z8WvPg3tKIGJdBhumahkQe9N1NYZXK2SzltqiqdvDdZWHAp+3
         56sfy6oTn3A9ZXnaBfRg1UPvjqfh7lgL0D7NaRnlRgunLcc0wUaal8AsxZrkoYFDTduA
         9CQJ616eKc4SMoDF9rWq1IlVOA48o+mR/NDoZwkUrYrS8a0MqNG/HUIYt5IRkUjnDfzv
         noHpqLWLapw5aWjs6Wq/cysCkcWYJ3BcF1NQqUxNjkiVPol/Ht6eZIVzcmmulhHIunxS
         F5GWFJl6PmCWM7tI7wdBV+FNJRH8ddCff04bqi8hXJqCbkUgN1KBT+gSGRs5VQl/WnCU
         DJrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rRXMvBKE;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=qYooU2H24yfLUIEvaZwRcjEq7qgXmoGamI3OPX5PJao=;
        b=PyfDfPWjDGtc6Bx9/IutS6rfmLVfUXAiyyiW+PUJHpsSJLoal8GCZKy0CaRD0ds09J
         Vo2XJCku2fh22UFNQRSq4j+SgF69whtgDlafvF/qofK/01zMOpONUWJACJpiaPKeCMak
         sGygMP720sdkM+1te5rjr/yp0jHg+CbgXoFDZ4yvp7Gxf8N1B+7MTtggMC9x2jiWs6uK
         uLr0SQ+tJrBamRTvUtdP9tBPQ2dC/BmCHkK+M5HmPPR9RQ25abspC9Q8UXd/MhCftSJX
         BUAdO+se2NBIe4EhmMGq9+kQxQe5dyAf5onAkwudI3X3O/B/KBVjRCG17TVeWrI46EDJ
         CCpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=qYooU2H24yfLUIEvaZwRcjEq7qgXmoGamI3OPX5PJao=;
        b=hCLlKAbm5n44yqvbqgh+QcA1mytVQMzjZP3o0HkMHCgpk4Xc8kViHF+UPq13S1VAGG
         YfW+h7PabiiUq0aQIjd+oPeU77lq1RNf+pk2AA7/+RH5TPda0qnnUQYKTrmh/GInYSvf
         Kl+tlbEmK5VFkFe7NWjkQ8U47brp3dcKEtv6vBjF52AW7ea1nQCAy5uGLe7Y9JTTYMqx
         bzvbUHJ72YHjDEXN5GPkHKKkY52DoKnboWrAORBeEsNwxFc/QUcOruzFbcuiSGLE8Rlm
         ZNWXFBWjxX8BRzUJTd/NSRX4ckuRD1/SjO/Dupg7gr2U8np55QX+gcJtsZ/xqp/1OWaJ
         8Lsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1UogWuFrqJiwJZw/FbJnB9tPKEf1069J/pKEX3AQSV6bcMwzfb
	GRg56APOshU61xEethbp/Hs=
X-Google-Smtp-Source: AMsMyM7bJh1SohFYKeV3xwYsol1cFWpC9JGUTm4XM56CVXNwUJrUFJSOns0mid4WKps/Y6B6svoGUQ==
X-Received: by 2002:a17:902:e353:b0:178:77ca:a577 with SMTP id p19-20020a170902e35300b0017877caa577mr12917700plc.93.1663597288732;
        Mon, 19 Sep 2022 07:21:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8e87:b0:178:a977:d723 with SMTP id
 bg7-20020a1709028e8700b00178a977d723ls528826plb.4.-pod-prod-gmail; Mon, 19
 Sep 2022 07:21:28 -0700 (PDT)
X-Received: by 2002:a17:902:9a07:b0:178:8024:1393 with SMTP id v7-20020a1709029a0700b0017880241393mr303plp.128.1663597287927;
        Mon, 19 Sep 2022 07:21:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663597287; cv=none;
        d=google.com; s=arc-20160816;
        b=swY6AGIIh84WWeHR4maS3ugRNSNiMJ3lS8B/iRKsRpJFU9n1NcOah4jh6DKFcctnzh
         eVvccGAKntiDgMwYUFR+dY4snPTFqmaI+wuuK4FZsYcU9YgYprVGtn+BPwxYESpRZRE+
         saAku6b9V1NTiJHoVLVlHNBP9d9x1jdL7k3S0qLLgsa5QmtaxeuZKrh+UpzwBy73tfud
         cD6rCzZhiucyfKqA7ImVmvonkFSVTUsr2/BV+PpK2JI03M/3JioTZUO7loK356Y7HEHr
         16scBwT14fvYDiS6wEJm9ffcxm7AniOak/LWgioV+I2kW9MDAiDaOsbLWlRS3WCcmdMv
         cpMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=E8gtTcTgf/9SjcnFxkRrkfBGUBa6nV+lMvnUjN63//8=;
        b=iOYiDBEj7gGm+2bl/jxKQBoUkiL1stYOo3qv1+EvlUJVQH/E3Eu0unIxpU3dJ5FmVq
         M0ayvuphYuvZD8L5/EY3FFGNSa/9W3FnAw8uclxYuxYQugMM1WDd3bYIWcuMbp3TO1/J
         SiC83GvS96x3sqockJJ0vvtLMCIHHtl3dWBD9GLbsR6c87vCk54QhFg/AsFPiUVwjkJT
         qzQlrTOf8HlKcuNSbqvB54+tzc+eQdlcAuz3zdaLWx1fSnXJeX5Z23eOIdmqCo3hPZXU
         p9vnWYlvmD/umxNDm0GMQIsC4eSW48QlswjwV4rbp6xHC0VRjoVqznRB8bKl4fk/Wrh8
         d7QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rRXMvBKE;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n14-20020a170902d2ce00b00176a0cc5ef5si880891plc.12.2022.09.19.07.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:21:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3B18F61D2D;
	Mon, 19 Sep 2022 14:21:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 92C90C433D6;
	Mon, 19 Sep 2022 14:21:25 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:21:23 +0200
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
	James.Bottomley@HansenPartnership.com, deller@gmx.de,
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
Message-ID: <20220919142123.GE58444@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.869531945@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rRXMvBKE;       spf=pass
 (google.com: domain of frederic@kernel.org designates 139.178.84.217 as
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

On Mon, Sep 19, 2022 at 11:59:47AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.

Hmm, what ends up calling RCU_IDLE() here? Also what about
cpu_do_idle()?

Thanks.

> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
>  arch/arm/mach-imx/cpuidle-imx6sx.c |    5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
> 
> --- a/arch/arm/mach-imx/cpuidle-imx6sx.c
> +++ b/arch/arm/mach-imx/cpuidle-imx6sx.c
> @@ -47,7 +47,9 @@ static int imx6sx_enter_wait(struct cpui
>  		cpu_pm_enter();
>  		cpu_cluster_pm_enter();
>  
> +		ct_idle_enter();
>  		cpu_suspend(0, imx6sx_idle_finish);
> +		ct_idle_exit();
>  
>  		cpu_cluster_pm_exit();
>  		cpu_pm_exit();
> @@ -87,7 +89,8 @@ static struct cpuidle_driver imx6sx_cpui
>  			 */
>  			.exit_latency = 300,
>  			.target_residency = 500,
> -			.flags = CPUIDLE_FLAG_TIMER_STOP,
> +			.flags = CPUIDLE_FLAG_TIMER_STOP |
> +				 CPUIDLE_FLAG_RCU_IDLE,
>  			.enter = imx6sx_enter_wait,
>  			.name = "LOW-POWER-IDLE",
>  			.desc = "ARM power off",
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919142123.GE58444%40lothringen.
