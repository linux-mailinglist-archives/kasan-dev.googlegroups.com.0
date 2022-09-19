Return-Path: <kasan-dev+bncBCBMVA7CUUHRBLHRUGMQMGQE34VT3BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B78035BCE23
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:11:58 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id d18-20020a056e020c1200b002eaea8e6081sf19307639ile.6
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663596716; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/p8bntdv1U24cqrATTQWgTeTzJHn28UwItr2ZBPNUXcE9XIc1VI0KC6Ol2G/G0MVF
         0axn9IO/5ZpFfd8uoocXsjuznUjUxvsEb/GX17p6qGHoP3mygopRzv6sVsngR7gzNPjm
         OgeA2rXYcxAUNtubSU7E//JOKxBdWCUVXpC3njOQ1JS//1vgPnPgpL1DtuY1MPUI0oDY
         +npeGRb2hJS8AFWn3IQuQvXkBeiwdmFwYA7StQ2BVW7AiOry6YeoipT3TXSrZ4Do3+dz
         jLK1okYBjBTI2YhxKDiXsc2X+NnLNDS0zZZQ2QXhpVpLjn8/AnIYu3rbjRU+px7SLOsf
         xLag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=38Fppx/Vmc+BZj599Z607zNf6zrnGWKanMWeMZ01VRE=;
        b=v7089AE2UiueYWfCoxmVkQHztgDleKEFuOJV/rBuaB0YHQ3a2Y8LP9APiQzjdBUByF
         p4W58bzOLrBMUY64X0yOVuW/REaFJ1ht/4n+QQLgovaMGghcdyuHu9JnDV2C9ezxAFIq
         9JvOl/615fmNY2sDz72wGPNyO8rluVX8v94l7OE2mIN1OaPs8Xoy4zl55vh1C9QzUqLa
         r5MuzMRxxqw0IOxFTHqCTvYksqejuOhCB7gQbnDxypdY5Kkv59KhYYkwrjy4igtNJLoz
         frRkWsgL7gh7xnJ6GmQ8YKoX0G/Svt6bX88gEXSNCTAhjlp6oRUR6+zUf0RCOOZdgr4F
         dfIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IzEUztO2;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=38Fppx/Vmc+BZj599Z607zNf6zrnGWKanMWeMZ01VRE=;
        b=DEG9EbhkVCmIG+b3GH/JkTp+8NyzHxU8oDeGQPTrYpqZhsoUnGHCxf7gJGfFrUZ6Vi
         iO7zJLv2Aiqv/D4RkGGmRyRWeEJH8eAk9oaG7zd7cSNALHuXtbQDwIH+NzrenLuvJ+ea
         hwNjDNtz2or4z9P3ZthJ2WWGss08Eitys2d4H48JkvrkXqU3km+sUd2AzLvxtl2ydkkR
         0SHyZpqTXjLHwR2KVlxxtB9oMcdkgPg9qYElfXVfSULt4AQaF0SWsSN/bGo/CW83/hdf
         vaf3gP/mXgrDcMtcjX9m5F7rAxIsRACFhPAlqNBlIrJ/Z9TNYTiDLEl5fLTi+4Zwovp2
         T5ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=38Fppx/Vmc+BZj599Z607zNf6zrnGWKanMWeMZ01VRE=;
        b=xAANXMrxe8iZaDIZiN7/jKsx/2BwD2fGAOU5yeENO4YKroB6o85yjh2yRHFsPteiLF
         H3A15eq/nPoK6D2rxervVGuIAdJdaaB3WpvE5dv8D4Po7abomhdzoHI/fCNFcBKuteQW
         RUblrcbYa3uXOxLMFxuGPQJFhl5Hv6TK27RjRSIVFlHBmin0XR9SLCHSWGqKMvDKEa8K
         LO2xByWYbLuPARltgwfeh0A2QI30isOKyJy55I92bxolpZ9VgLuvRsBSLKmy1GL/nu3w
         ZpdVpfS+D5XJLIesV+tGEun+DnCqr20sSbVY8uxQl4RczgNKn+Mu8QGNoVe/Hg+wMd8H
         2Ffg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1fKEgeOsiNKm7u/53q5kUJP1STIB6ywQG3xggRrtvEZTYEIvl3
	YMC2X73S5q/imFc1bNBKfBs=
X-Google-Smtp-Source: AMsMyM5Z6URJPwg+bsJHyyhDKHz7Tk/vs5oyo8UI2EdfK3jQoOVwv+NZqbDXdl3hEG4IsuXk1VL2cQ==
X-Received: by 2002:a02:cc18:0:b0:35a:13a7:5ddd with SMTP id n24-20020a02cc18000000b0035a13a75dddmr8366264jap.29.1663596716344;
        Mon, 19 Sep 2022 07:11:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c7c4:0:b0:2f1:52e3:faf6 with SMTP id g4-20020a92c7c4000000b002f152e3faf6ls961046ilk.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 07:11:55 -0700 (PDT)
X-Received: by 2002:a92:c64e:0:b0:2f5:9ba:8055 with SMTP id 14-20020a92c64e000000b002f509ba8055mr6003973ill.290.1663596715835;
        Mon, 19 Sep 2022 07:11:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663596715; cv=none;
        d=google.com; s=arc-20160816;
        b=VIsXLzoQqT9m3bfphPh5l7/UMTQipRjXwrrmqGqGDWfQsFUT/t5GnPe2zFdJGJnwdB
         e1+2lNXg1z7XIFnRgFZtgreTrf/fPstxDkPnb9YR4IminrrqG0nm9B3iASyWKZbDpKvu
         ypOHBvcDCLhht99Ap9Jg6fEbo6VxWWtx56vgo07n+RPYgpu59jbcxSckOdm+qFxLyuF0
         Vt7uCKGBVqIbTBBjb6qVm++5Dw03I2IXPdQ5AvaBVyZXJzFwcfRglcWfw9BBAQ4Uih0r
         arbHbtT5t21wdGfTpgnDop9c9qn5faJdks5OwRDrwXWlV89hTOxXZzDFz8f1cFX8egtY
         Hg1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=D0IrEkgJL6GrGGojWzce61S/ELvmT1BR4Z1HmSWYwrY=;
        b=hM8xGj/065mJHi6XlbgN88HAQKPGFDx3a/hxKcuvVSPAd9T4POF0OStfuJGipJ/wnq
         AA/D7CX6zGnSh5DtXNBgYBY1QuQWc1k8EfdYVoFRm4kpcp9DYqkbXrHzS2xUOOBtYqI5
         xsbUsW85EyBGuxo/UK2Ywk/UyMt2xTxfX8ly2qvEF6YWbHV+sH/6jnoNn3pdSmgNrtN2
         Z/tST4wAb0EwIGCCXL0xK4Soz1d85JhvRq5URvvIU0vZ6zoFp30zdKYAFCX2mQ0B8Ltp
         tNehLyRKCjfxkCt+dT/VK1w7bPg1GHfq+1Gy2EEpYgd0YHb7ev427IHrQ9Yg2LpVdB7g
         GGJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IzEUztO2;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d22-20020a6b6e16000000b00688ede7086dsi1405595ioh.3.2022.09.19.07.11.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:11:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DA96561D15;
	Mon, 19 Sep 2022 14:11:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D756C43470;
	Mon, 19 Sep 2022 14:11:53 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:11:51 +0200
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
Subject: Re: [PATCH v2 07/44] cpuidle,psci: Push RCU-idle into driver
Message-ID: <20220919141151.GD58444@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.802976773@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.802976773@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IzEUztO2;       spf=pass
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

On Mon, Sep 19, 2022 at 11:59:46AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919141151.GD58444%40lothringen.
