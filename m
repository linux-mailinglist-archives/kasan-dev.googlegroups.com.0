Return-Path: <kasan-dev+bncBCBMVA7CUUHRBCUDUKMQMGQE2TSNQIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C1B715BCF85
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:49:47 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id q3-20020a056e0220e300b002f5e648e02esf1218704ilv.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663598986; cv=pass;
        d=google.com; s=arc-20160816;
        b=wekyHe5+W2AjjhsLDj/hdzw4oyvx5d70QHGOZ5IhddkI1qdxuzZ7bJ9A09LztwWwgN
         Nfn/18XAL8GgRUzh3rM2HAWGJ4XfIBqpM6u+lTVs9KTGshlZreZhvyxIsxXGXHeo4ixA
         lJmtssIquU31w1BQzUKNa1AGNaDiGIWqjhWVqtPL69ztIrtM3jRtq+3U/OpGqbcsc536
         /ohHErP71DlEWYvwETFU9lK1YpqU6Z+208lh7xfK4q0tE9YUAqSqTwiz+V1UNSjMN2SN
         DOsHX/sDiThhtkINmE17EMQ0cRoxhNIxOib+GKT9P9KHIwHbVpZW5NeSDkWIrWSyuQwO
         gC/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bc/yp2mPsWhoriC1d5IBUy1NgIA8t6K64gJ7dXifIIw=;
        b=lj7BjsYYfclofSG81X8myaj/w5Ti/ilLVeTv8Iky9zGP6UtM3z0lGA+f+Mf9+pN8gF
         MYQJPWtyHdvgd6d+TufHLW+fLVNGokNt0UkF0lBvlb01dMGClmUOHTxfQxKQnUec8m0L
         a1hlqjHsSPwotlh4c49HZ/xS3MJZs0k9+FmJwB8yGX47UNN5LhO/RcVd1GHJ4KfbMVia
         Dc6kr/4sduTV44qpGQsmn4gHPlD+8LoX48fZxStE1LOjlTV+vKQPcgxxWrf2gG/JGoDK
         sD9hFWYk0OgyTi14jjIAlmOyjAaD3aTEFnNTEmKHuv3OJaLpeA+dU5Vm/Yl9MmXGgeAC
         tdFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gguXnCN7;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=bc/yp2mPsWhoriC1d5IBUy1NgIA8t6K64gJ7dXifIIw=;
        b=jgfL+Z1LtP4TpOAJ/HMOLcDhM5jeIDwBq+xdtLdUenfLvcJXEIyv9TF12XAWx+H7jR
         uTSPHaS7ObJhwJ6GhhFp8lOGANQf+8xoWQsdazph5zykj13xDspjlohC9nRv6GZ5XTRr
         MjIJ4z0XEu32TllLtckRaxZuzFutSt6RfkT0FlHNgrNV7JpIk8LT1icLQp0qhaSkV6eP
         u1O+t6+SJSXLVb0DcYSd2dwQUAn68fyrggM57IJ/DnwTcUyflckn5oeTFkKv6+pnOwZj
         z+R1qn3SnYuOd4WvYddZDG//gPuQ5lBYO0nIkW5lYydJ537RuEdonE7XeLz7AKq1+sTw
         /Q/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=bc/yp2mPsWhoriC1d5IBUy1NgIA8t6K64gJ7dXifIIw=;
        b=ukMRfRLo66H5hbYVRyU4thCRnwzC5i+B39mc+D4Dyf1/3dKSwXjGBcCOHu3Qae76Lj
         sX1tNgt2gn/Ucnte/PCykU0s+Kn0v+4/xrxeV+GPLJMAtAPG6CW+xqh9C3MEdFNuJKh1
         UX+p//uOsrGhv9Po6e+uKZI2dwyAWrOzCE+o0lewrq/68QVflFS4DXtQsqcI7/zCZpAt
         U/5n4kJFfC5MEZrDaistnL4FVujOahs48fymZGtuSnL3l3Ie16e2SCm5BZowce7LNbTe
         50iBwTspjX7HJvMTQK2C+pHMMrx87Z8asdFTXqSM8R4SQmyKxwCEQYJPHaOaZLw/kWpx
         RoLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0jM1g9Sotz7874wlDk8Q3C5QDHH4VBcOQ+cha+CPLonfkhC0oL
	xipkQX1dDJvHfZcaKW7Tsyc=
X-Google-Smtp-Source: AMsMyM5qiecIuSYu6Wg3pYww25+iKIcY3JMJiTAC9EaFste+2eq980I1T/Sjqozvr505Xfu5KYRi4w==
X-Received: by 2002:a05:6638:24cc:b0:35a:5ee3:8f68 with SMTP id y12-20020a05663824cc00b0035a5ee38f68mr8658772jat.255.1663598986644;
        Mon, 19 Sep 2022 07:49:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:eed:b0:2f6:1ab4:f214 with SMTP id
 j13-20020a056e020eed00b002f61ab4f214ls82121ilk.0.-pod-prod-gmail; Mon, 19 Sep
 2022 07:49:46 -0700 (PDT)
X-Received: by 2002:a92:ca49:0:b0:2f5:30:bfc1 with SMTP id q9-20020a92ca49000000b002f50030bfc1mr6102634ilo.224.1663598986174;
        Mon, 19 Sep 2022 07:49:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663598986; cv=none;
        d=google.com; s=arc-20160816;
        b=Y9qYzwBLSmlnZ0xwfh8kraDBrsa6W5G5JlkYYrnmvVRAc/Egi0h54/NSGiHCULROsX
         65Wa4lyMMf2OHtMRx5FHKohtdryzynW0nm9ZDJMa+B1xAve4elnhnS2lpTakG+E15Q+b
         d1qameuebn7fNu6qfu4l2Esx6RC+yWIySfdaOSBgtZjX+yyoLjiAcqqieTx0wGVt4zcM
         30rj6MIKY/QJpJn3KLDchXXgToLCqWRUwWBm6DGy1+fTbYIuBV30cgYGRnt2ePCQ1nsx
         YEl3KWY/Cf1i/sMJOihuHvO+iPPHCfl5txYnN364vjIoXsAzbZ2Jsij6E62180DrbqcU
         MUIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EvUqRdfSLx+z8y2tvj4uYC43w587n/AAoGzg6s03S18=;
        b=UfpKpmnDvkIImJe98tBu9MiBSdw77x7J3J5NaFpRl54j4DHZxbDBJmtWL21qaMoHGq
         L1MNlOA+Ci5xRlUUfr2U0E20tsf9B+zrPd85YrhVwwEUQ0AgagaFf91Me0Qi5lm20hBT
         1ldUrp+BUdNlKuJ1BhDPULNtZXYWyk/An4Hvq9rQ6ID/gNiLxv+QBD87Xicz3bFCkjI7
         GzgNkAzGaX2MlM9sxGPZ134TlxacHi6WzIQ2TqEhsAMH3LA1apiuILfD2K+tqekzpl9W
         IFA1z1u1v838kmznCZEn0sOo9u/y7lSkK8hcVFbs11IyCDM3fWLmaTyi1yujDRRJLzv0
         A2hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gguXnCN7;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bk10-20020a056602400a00b00684c9b5bc7asi1516665iob.1.2022.09.19.07.49.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:49:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D8C1E61843;
	Mon, 19 Sep 2022 14:49:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3F2B3C433C1;
	Mon, 19 Sep 2022 14:49:44 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:49:41 +0200
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
Message-ID: <20220919144941.GA62211@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.869531945@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gguXnCN7;       spf=pass
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

There is a second one below that also uses imx6sx_enter_wait.

Thanks.

>  			.name = "LOW-POWER-IDLE",
>  			.desc = "ARM power off",
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919144941.GA62211%40lothringen.
