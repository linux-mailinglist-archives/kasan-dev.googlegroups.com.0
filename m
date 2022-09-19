Return-Path: <kasan-dev+bncBDBK55H2UQKRBVEIUKMQMGQE57L57TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A2C135BCFC5
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 17:01:40 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id f25-20020a7bc8d9000000b003b4768dcd9csf2656641wml.9
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 08:01:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663599700; cv=pass;
        d=google.com; s=arc-20160816;
        b=cBvH8DB3bMu943L2XN8dXsK/d5mY/z0y9jZqxx3TbeMNwCKMQKInKRdXRjuRgyvYb2
         zdwHDB6X4BTKO98DzIOotwtFGqh/MqBszCVQqt9Ab89kUhcs4MxhLcsMH+wQAP9UhfLF
         ovshPyFOJGY0pwOWqL0GtGdqBXvPFdjhd3+61TJ2hgWH2SUm0yMFyBsZcdN0z4GPvt3u
         kJPCwcrWxCcdFA+Wt2wFKxxhkIWc4fwUeh5APtbvSVFusFox87qR9k4w3t7OslMRA8wY
         Jergluc4m9KiI4YmYuLPOEJNvmL76S4BJKfhF1MnPAwJPOQWVfxOZnXPRNyW+sJc1p3H
         /4Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3eAqTmCHIW1SD7m467alU+ktH+ItpZESvm//sR8HLUU=;
        b=nmbnjp2l6xxCrciPEvWBVGOz8j45QqLMaQP0o0IaCFauSJTqIxU5f9+XXLGcZ3pGHx
         q24ww34vjFK66CahDMTTIqX3ENLYzQJ8B4A0Ny6YBhVeVG8N5/bsYRalhxlUC2PU8dOU
         lnHIro+SuTmrHaIviTzQSxPc335FTGZ1UyIzpFopyqSoV50MmdB8Mrpx/twgldaCCQl+
         ioG7xjCfVJ6Hv8YfpG9DpEjHKnXe+36+gv9jVWLBc4ugcoavPo4FTGEH+pHrNzELabiV
         lVSpTx1WiMRWrCFQdDeQjj+El6tAjOngQdB4mlkKa2Yp0L2FvTyCbLSECMrOTpYjHCCR
         XUYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="Z7/2OIWT";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=3eAqTmCHIW1SD7m467alU+ktH+ItpZESvm//sR8HLUU=;
        b=AV7ofRM5bxeYHhgyq+bWjqmlz1Q0RKsnhZ8dP1Hv/TavIxMIAAVGpuWthUHiM1jNc4
         xdYNvk+KMRQUFoWH5cTIXsIvJUT7/MHgyRt8Z7dnSV04osFPz4s2DDykb7dSF+uKwFSK
         WcHf6WCOvRiINSd8DfFoiT7rLnp+5xfqnyUPfUPvJYvvWNjz06bVZ2mROFfTKvtVNA4v
         c0xiLL6Hl4wMHamETjeXUadp+NV/HPjKOFUTLjm1/ewupNxh/jZDxmh6gYeYLojMYdnp
         A2yl9NvY8PqEeJ+UQyUiioVeccGQh5JTdimJkmWL/918+/T1rZsQ/+atanFHI0LVUj2I
         kAVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=3eAqTmCHIW1SD7m467alU+ktH+ItpZESvm//sR8HLUU=;
        b=MIyUr+BBErNWRSVEcO5SlWV5WU7jjX+7Iiuk9Htamb55O+02GbaIPJ8T4gYOUSr2uC
         Vjb2inccazeXDpQRvc8YS6vSDytqn/46Jcr5v7Q5n0R+IhVLU7kj5HRxNcr/Zpoobej/
         xkxzAYHBOO+Om/iHmxU7I7jAicmatD6LGs1ilsuzMZx2LYm/APKLdTh3FEJvGt5wSdEw
         HAa+SUPhcHVduOY4a0yge1/UgnoRDJUzuZRBrzEurtqcstdihqPoLFTUN4o0GYzH4CE3
         +mAmQFzxT44RExZ4Q7a7i6NzDbZLir3HRZ1p6SE/oogztMjz6dN4P09Vsdv19vq0nxkg
         g6fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf37wadq0MVWa0La3RgwfnHeJQtQvcohuqEXwJXa+2C9Cz36kMxs
	Fb4XHYM1lhNjnx+5R+1nKTE=
X-Google-Smtp-Source: AMsMyM6ec+RdxgAeCXV8N7gyznnLqaaAJKvW0jbehlGBpHWtNAltvblP62umctz3LSkuwig8BBAffw==
X-Received: by 2002:a1c:ed0b:0:b0:3a6:30c:12f with SMTP id l11-20020a1ced0b000000b003a6030c012fmr12567544wmh.133.1663599700283;
        Mon, 19 Sep 2022 08:01:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3489:b0:3a3:13cc:215 with SMTP id
 a9-20020a05600c348900b003a313cc0215ls2900294wmq.3.-pod-canary-gmail; Mon, 19
 Sep 2022 08:01:39 -0700 (PDT)
X-Received: by 2002:a7b:cb91:0:b0:3b4:75b9:5a4b with SMTP id m17-20020a7bcb91000000b003b475b95a4bmr12185118wmi.33.1663599698977;
        Mon, 19 Sep 2022 08:01:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663599698; cv=none;
        d=google.com; s=arc-20160816;
        b=AEgiV6Y0ttBGn5hnjzqgaUErNBqEOTx7tFRb8of57RBTr22nwOGYlhE/oAmDvuC9R3
         R6uPeVvyjtS0e2O6lQw6k4cQzX446zTMmsl06L8/impjlZnSHvL+8+VlU//drO0E6zVV
         ohE0WJVxjzwYdZRFnOelvfJS/3xiF9tDoo0naZZ6MN/Q05z634D/S8NxHx9OHWrGrIVL
         YAEQRN4dwZ3EPZAQ2MVCQVTCNNbEgGqgnAuVxXcQJK3AxyQFw1UTKSBgx3Xyt3Lnau/7
         1YDRZs+S5VVpqQGXV76XLjlFs7YoAUTu/uY/U/2fzale/RfpAg5cxQF+u25XKOKt2WQm
         TmfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DH0Mbf0oZaE0931sFQPw1e06bFjL/ZiWgntyEnYtHbE=;
        b=LQE6SIMnCrn0LWa3mWUChqU9bTPsQ8iBHyuLcB2YNw5wQbbrSLAnUBIdGJwzMBP4uP
         FlQ4PsWHHklj8es35ufcYqVKuMaBMKRWH8djOVK3qSdt+vsuI9FuaLoJUKzIqCW8eHik
         GJfavLP0ij0esqjbDI0W+PkHjX5FqO2vpAw/EK1LnZBd0eL0TcFFqJycTG212HciKJDR
         YXjAn/K2oxGsmSdLoIA2lTOEdAdjYijfu/L9d/0Loh2ztaSQv7c7WtN56+Bhq/24xELJ
         fnOVCtWh6uSH4B1W2kUSkRUegTf09iROl5Rd/YWY7CmIV4uxrtjlA7DQciCeJm8xyK/4
         g3Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="Z7/2OIWT";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si507816wma.1.2022.09.19.08.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 08:01:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaIGV-00E6Zt-3k; Mon, 19 Sep 2022 15:00:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DDE9C3001F3;
	Mon, 19 Sep 2022 17:00:52 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C27C020139CA8; Mon, 19 Sep 2022 17:00:52 +0200 (CEST)
Date: Mon, 19 Sep 2022 17:00:52 +0200
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
Message-ID: <YyiEJOJL5/Bq+9hK@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
 <20220919142123.GE58444@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919142123.GE58444@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="Z7/2OIWT";
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

On Mon, Sep 19, 2022 at 04:21:23PM +0200, Frederic Weisbecker wrote:
> On Mon, Sep 19, 2022 at 11:59:47AM +0200, Peter Zijlstra wrote:
> > Doing RCU-idle outside the driver, only to then temporarily enable it
> > again, at least twice, before going idle is daft.
> 
> Hmm, what ends up calling RCU_IDLE() here? Also what about
> cpu_do_idle()?

Both cpu_pm_enter() and cpu_cluster_pm_enter() use ct_irq_enter_irqson()
which is another way to spell RCU_NONIDLE().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyiEJOJL5/Bq%2B9hK%40hirez.programming.kicks-ass.net.
