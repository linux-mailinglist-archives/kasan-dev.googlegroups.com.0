Return-Path: <kasan-dev+bncBDZ3RP6QQMIBBF5OTKPAMGQE2AGT62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B3EE66DDC6
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 13:39:52 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id hs18-20020a1709073e9200b007c0f9ac75f9sf21409084ejc.9
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 04:39:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673959192; cv=pass;
        d=google.com; s=arc-20160816;
        b=leBXz4P/EpS7DbCYwk4uGdsYPHl1rJcqw391PeZj15y6jbpzVX6apjd09Ofb5VgRMM
         C1f6E3ZGEK1AFSQ4iOaeJrWG5sq91xozVIM8wLjk64ByuirnY/KE0Fwgw9lpGjzJd99q
         asuh2wBU2En3vvv9fqVScOkwfoREQK1ewu4mXBFZovuApmaS94ywVdLHFATUG+U6Xf1p
         qxk692AIRKAJfQwyW+OVMqxhBR8Iurf+n7WDiP+FiIeJz6L89QFOIBJWus+0xcBIfVfb
         EyoTVNlomHbEjDNPlLqjWZ+zYAMZjHVW9CGIcBp/1EwekEXngM1r8BTHSkm6+t5A71yZ
         jKUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5p527aWKZsX+p/bbr6wqrZ+3+LHAg+F1MdVVbMoYFB4=;
        b=CN7Kuu/vAP0+hFBpdNJtoumHdltNU95aUwvgAV9mVJOl7g5UO064PDHT16CIudDxxZ
         PZiOXqvG2OkwHYRkt+BzUnUc2WEhkvglETRQtOc87U5GwFY+3P2pJovnrcz09emtoXRH
         BdrqAPCerWOo5PSSrjhdTufDng4r2RW5clu4DUYKfAhYeeurDC5jhTQuaTGA3G7X2MGn
         zmRaEwZd3QrOgqzx6QZPyeopQf0m1gCy8alLJOvn6BxkRqvZlThArCcs9cLbBUTVm0yO
         71aff4Psip2zoputKe2ZzVH5goo2hwhttjtPX30gu7yQV0Wt9O8nERsHVlPxAD01IxBr
         1Fhw==
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
        bh=5p527aWKZsX+p/bbr6wqrZ+3+LHAg+F1MdVVbMoYFB4=;
        b=lNZ8DX5pXAsQvfC+HY0uxb3ov3UNtwl3UyjnSmaG1aV0LKZIS2bG+uvBPMI3SnQE8q
         +5S04V44wj/diysSMrTnWlxdv6847zSEGxrqImpS4r9X2FXncGsIdAJJzESU9xi9ZOx4
         SAI3iumt4iAHfV1LkrZsjX330yu21dxbnpzzxW/sp6l8DnnMafPSMs5Lh7lPbLgKOIkE
         Mb5qG1xmbyKoqemnGvsrhO4yy5MYA3DpdSakBlYZgWzQgl0UhAbOnvP84Ie+GLN1QMaT
         UTjAC3sgGwZmC6SyrKWK7L5bTAxzZLTsy4uKFXxd8SpYcoNyfNvH3SwsvaDbj3sH9b9S
         TIrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5p527aWKZsX+p/bbr6wqrZ+3+LHAg+F1MdVVbMoYFB4=;
        b=KDA2jY3TejcC/5DHzXWH48ZUzD5MjAuXk5P9r0bOyA+cr/OmSrfvFpIm2+AGGBcAV5
         4P2B969dzHIM15Bii2nh+rhdl2ed53M2/JxP1BnhGxK7W5302AR0Z/FwYIq7GyKDOSiV
         zMh6qTATQGbKjCv5jQX4sHlfMhO+dU/TBtH/q1vi44doWTRlRgmbvn2mU3UBRleOFuVo
         ZZ4q7p1fsSFiIuCKjwSgkDOj+U0W4+5vQ3z0Q1fr7gn2BNVZ93l9g4djvKacp5zfief9
         bQ00wyVllwjYZ0nbppeoHD8dLpsmVM0tQ2DW0Wh6hQl2vV47UVK5rqjc2rZMQ5RLR0G0
         J1dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpgFPU413UaftfjHLydjla7oiTcMsmuUKhxe07iP0D4OT/X/TOQ
	LSfV22uqMnk8MsYVA8QdWw4=
X-Google-Smtp-Source: AMrXdXuMTI/pLkZsZ66EQIV0mtkgmPCeMoaH6dmaekGnJaBmb70qfLJuIb/8K1VG53ZjwkguUZliKw==
X-Received: by 2002:a17:906:b106:b0:86d:d78d:61a5 with SMTP id u6-20020a170906b10600b0086dd78d61a5mr203763ejy.253.1673959191901;
        Tue, 17 Jan 2023 04:39:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:af8e:b0:7a7:f2a:d325 with SMTP id
 mj14-20020a170906af8e00b007a70f2ad325ls9014436ejb.10.-pod-prod-gmail; Tue, 17
 Jan 2023 04:39:50 -0800 (PST)
X-Received: by 2002:a17:907:c928:b0:870:6554:92ac with SMTP id ui40-20020a170907c92800b00870655492acmr2625776ejc.18.1673959190576;
        Tue, 17 Jan 2023 04:39:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673959190; cv=none;
        d=google.com; s=arc-20160816;
        b=t5PTuagwYc5nkRr94AwNudhc8LkawSBxv/LDTJIpk8vqhnA9uuRznfqP4jLiCAKJNz
         P29pGzbej/bRlqSnSMxScwm/wGvxKxKfaiUS6XipavFTCdtbkXuVYAZyG5e7EJKNysqn
         2Vw4GRLs3C0dZWuEMK5k6DciC0k2YIVbC+NWmrMrkzrZvdataCdkSe/purkQyTxUpQ4a
         oguXTxZW2l+jcM0nAysZ8gn6wK3k5wiRRdzUusxVbqZxqRnyd8+uLY6wibzf5y6i+XHV
         rDd1TVpWhuBlAZI96zAd13giNlHIH8Pw2CO0TyiRZqsqxjvlyFgHHtJrXrr59V5Wuid7
         2RTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=8PQET2inuxXodzNz/Jp9ZxK1RazBm9bUL0sxBd2ab5U=;
        b=B0r19SI2gtRqFC8Ngf0BZ6gZ967lMc740lrxZcTrajF6zI4eoWXoyCA0dVwfQ3Ejm8
         LM+g/OcRHk8/ev3yp52SCm9UEtOPOdh9adS0XF6FvuMuvQkKC4yCjZJGrcdPuRjmHCR+
         kVXScw3q1ne8r17tuG1TmoiFfq9ZBxdVUororb3zSgXkpOokkKBW5on3QYut1sc+dmfK
         Fq4vz+tTOxrqvWC3SQaQQunZDpcUmzvMXir4XVQyhqN2oLrHE5LffZZ+aMPADGW4/mtU
         ifbDSInQtRZVMV6lGSVP+lXmB0rAXCHwAIo1Cl25FxvRKooKSlEH5XdKnDovcTLb6o76
         jxMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sudeep.holla@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=sudeep.holla@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q5-20020aa7d445000000b0045a1a4ee8d3si1250055edr.0.2023.01.17.04.39.50
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Jan 2023 04:39:50 -0800 (PST)
Received-SPF: pass (google.com: domain of sudeep.holla@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CF6C0C14;
	Tue, 17 Jan 2023 04:40:31 -0800 (PST)
Received: from bogus (e103737-lin.cambridge.arm.com [10.1.197.49])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7F6B53F67D;
	Tue, 17 Jan 2023 04:39:33 -0800 (PST)
Date: Tue, 17 Jan 2023 12:39:31 +0000
From: Sudeep Holla <sudeep.holla@arm.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Mark Rutland <mark.rutland@arm.com>, richard.henderson@linaro.org,
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
Message-ID: <20230117123931.3ocl3ckkf72kusbz@bogus>
References: <20230112194314.845371875@infradead.org>
 <Y8WCWAuQSHN651dA@FVFF77S0Q05N.cambridge.arm.com>
 <Y8Z31UbzG3LJgAXE@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y8Z31UbzG3LJgAXE@hirez.programming.kicks-ass.net>
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

On Tue, Jan 17, 2023 at 11:26:29AM +0100, Peter Zijlstra wrote:
> On Mon, Jan 16, 2023 at 04:59:04PM +0000, Mark Rutland wrote:
> 
> > I'm sorry to have to bear some bad news on that front. :(
> 
> Moo, something had to give..
> 
> 
> > IIUC what's happenign here is the PSCI cpuidle driver has entered idle and RCU
> > is no longer watching when arm64's cpu_suspend() manipulates DAIF. Our
> > local_daif_*() helpers poke lockdep and tracing, hence the call to
> > trace_hardirqs_off() and the RCU usage.
> 
> Right, strictly speaking not needed at this point, IRQs should have been
> traced off a long time ago.
> 
> > I think we need RCU to be watching all the way down to cpu_suspend(), and it's
> > cpu_suspend() that should actually enter/exit idle context. That and we need to
> > make cpu_suspend() and the low-level PSCI invocation noinstr.
> > 
> > I'm not sure whether 32-bit will have a similar issue or not.
> 
> I'm not seeing 32bit or Risc-V have similar issues here, but who knows,
> maybe I missed somsething.
> 
> In any case, the below ought to cure the ARM64 case and remove that last
> known RCU_NONIDLE() user as a bonus.
>

Thanks for the fix. I tested the series and did observe the same splat
with both DT and ACPI boot(they enter idle in different code paths). Thanks
to Mark for reminding me about ACPI. With this fix, I see the splat is
gone in both DT(cpuidle-psci.c) and ACPI(acpi_processor_idle.c).

You can add:

Tested-by: Sudeep Holla <sudeep.holla@arm.com>

--
Regards,
Sudeep

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230117123931.3ocl3ckkf72kusbz%40bogus.
