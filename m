Return-Path: <kasan-dev+bncBDBK55H2UQKRBQMDUGMQMGQEH2IOVSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 628585BC677
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:38 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id f18-20020a19dc52000000b0049f6087124fsf2474723lfj.15
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582658; cv=pass;
        d=google.com; s=arc-20160816;
        b=jjv1UVmPVfz9U/feE++n/NzhBjWCssHzpS4237Yf1sORUG/DxcS3bIZEonKEE5uf1A
         /4ZFK/IV8cWTsGHaCHsUjFMGlW1/9/YcLSj6p0FpKQwNP0sQa61znrmsbOifaP/PhsHl
         V49DmAYURMgzm9Uf2ia72HpGZbQ7eZbV+gvjphrbz1XJOGCYNRphSkx9yggRe9hxL8zm
         NATSPfwkaOp0UaPw1cE2xCDACDMQLkPIPf55YMW9dIapSbU2A5mrGdj+PKSNMAUHLkaT
         Xw8RbLsvws2aNdz6UwfNw7BEe8eVm01Jd6GnpAtao7LfWK968d3ADEPZW1eDy1LQZiQf
         u2Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=2jqqoA4E6mXjfWn7dE90Ag14bBrMtWroah1WR/goyYw=;
        b=jzzwDVbK3uDe5QPe/STl1t5ltrGZn5aVuXeaTtEE/sMeoJ25ls9DXjQFthnRbnlQss
         183PKibTjU58TD6lhZaPeiW4QyppyhlxRyaGuEhBIVn7QMsQhiWrVL5s9RJbQoBmX++R
         DVnTDKG114UkQf8+Rz1QC0LAsGzw6DwSvkCMG3ttbUzfg1VAq7oqfFP0uNGS+2gmxRpU
         DdkFeXkcx0up4oNc6hB4SQ6oWuih/apkX1pSOjeAVu5ONanJEgVf0j8OINWkv9k+Zv3I
         XxVY2UUWcMPeHagCuwad1KqkofdwaiRwjZz0M2Uf6aNTh6U8yK0q4uPYq6arhyPdmJ80
         Uwkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=X99rZ6W1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=2jqqoA4E6mXjfWn7dE90Ag14bBrMtWroah1WR/goyYw=;
        b=X5HoNmNjACrC+m9uGiE5KqEHrkEoUIJXoCexB7s9rcOPSZP9cmc8xhkK3CbJ7zVZmk
         CrJGg/jH5RTeEiuiMZNHxqyrJzPdwTjvsviDgjrYglpI9pyhKrkzm58jUUkyQwpmv0f7
         yM+bOe+zFLPyZSLLx4InbSAM3rcYDUlVEgUTFbBfxViOPJyIxwFhxcEA1Ekjpnu4CMfR
         /sgmVf6dZnOO5rSj2ifO8mPtILFSjNPTQ8t1ZWDGjLxneSaut0rD/BlCVAeXilVqoUpL
         ZynL0w6KmZV9p7BVJ+DCoJ89YxWolZv5kPUIWBTJhdCVJKKftnoqlUcLcbtaOCMZdjgx
         CR5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=2jqqoA4E6mXjfWn7dE90Ag14bBrMtWroah1WR/goyYw=;
        b=oDj1phXDBivUYGA2Jvr4uVCUXxN/ylSmhvZ6bl/5lDO34D9iQe3OzIWGdOvcXfQ3xo
         prTyyXv/FiPKqWZ4BCGaqQbN/z3If7Ipcb29AGMJeHeO+qql7uA232LUFZ77OabHef1V
         qTWxbSOGcEZexEBLn/5GpglUGs/kVH5+lkkqmI5+O6v0TK3vRBE4m8aVnckYfy6welKQ
         hkDjDxtjgAMZAwLvbTPBW0ZpuJa6feezLxaCughWOrmhUj1rYt/KQ3m+t5KHN+ABTLAt
         73uJ3+fgE2i56UdufqJU7aL9PPE5NwsyMnSSt7ogSudd+4Yf7fL/caj+yNWVqjiWcmpK
         WgJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2qIOMm9Z+hW1JRyUpZNsXiBH73e66HSA5lxKpnpc7pWrKoRWFM
	UouzxBfYPHUXXuJR9FTnXHY=
X-Google-Smtp-Source: AMsMyM7Ln88QTHr43qunIFv5haWtft7mdUYP4xUY5dYFKlmFN16eWHn5LhKcJkVnmu+Z57inKGddnA==
X-Received: by 2002:a05:6512:3d17:b0:497:9e34:94f2 with SMTP id d23-20020a0565123d1700b004979e3494f2mr5659792lfv.285.1663582658077;
        Mon, 19 Sep 2022 03:17:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0:b0:49b:8c05:71a5 with SMTP id
 v16-20020a05651203b000b0049b8c0571a5ls555893lfp.0.-pod-prod-gmail; Mon, 19
 Sep 2022 03:17:36 -0700 (PDT)
X-Received: by 2002:a05:6512:3b06:b0:498:fa72:c24d with SMTP id f6-20020a0565123b0600b00498fa72c24dmr6155415lfv.538.1663582656715;
        Mon, 19 Sep 2022 03:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582656; cv=none;
        d=google.com; s=arc-20160816;
        b=JjmrnO4wk8eBV6IE64P+sKoXeYvDK4c57VauL6dttzrG589QbWOZK7jvaU/7bCIYfI
         Ei5QdUCjhdI3uaf2urzpvanP9sEN600QR8KccfRk2PtaDwoWLWh4qZnLAYrFcrDx7kum
         5M2HhBC0PrAdUpWy3MwdCfXHOB66PD/maCkQNGcPVWnONIe5w1XUg8YjI29vERfBuvzr
         Qbxj4hgThKbYvaqoLvOCtEaPgczFflJifP4493XW+8q1m9FFGuoLb5p3KMaR8o/sL0PV
         lRTvpcIwNZn74n07pJdV+yvUsQGfahlY6JEt0Yn7mYeTimhd7fixFWo5dSHp9KA+aWXi
         ZW3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Jv9RVwj6ep0TNO3s8uQfW2HtHTmBFm30lOC4tMkhMhE=;
        b=kfy/6xp85k55NAH30HrLT6UYtSW1in+yFAfjlFFBvpDGv/cawpirgWd1+LH+ItOpso
         ciyX71tXv8P3ekmPqwUDArXhsi73mrFwUKwZI8at+QNoUOZZp2x4lNnsucTvZ8bpeGZB
         nCQbo0IJpEtbz+nVSrjEuQ7ButTNzXdzWz4rkZZxHS3O2k9q7LUadPNL+Lh4oCJv1S0t
         yiKxMUvBs8MrKK9MlICiBDKAm7hlIs1WcHUK4KDBmwzjElkga35xJusPh1wgXlni+gq0
         EqeOpooM85bvAjSadb6MBtfc5saOAXvn/kJI7F5V+EynprZ6EQ3euwGjt6FhOOq4csol
         mcYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=X99rZ6W1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id g6-20020a056512118600b0048b12871da5si864036lfr.4.2022.09.19.03.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:36 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq8-004bAU-MX; Mon, 19 Sep 2022 10:17:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6D100302F56;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 7C6A32BAC75B2; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.640861846@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:13 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 fweisbec@gmail.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: [PATCH v2 34/44] cpuidle,omap3: Use WFI for omap3_pm_idle()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=X99rZ6W1;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

arch_cpu_idle() is a very simple idle interface and exposes only a
single idle state and is expected to not require RCU and not do any
tracing/instrumentation.

As such, omap_sram_idle() is not a valid implementation. Replace it
with the simple (shallow) omap3_do_wfi() call. Leaving the more
complicated idle states for the cpuidle driver.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Tony Lindgren <tony@atomide.com>
---
 arch/arm/mach-omap2/pm34xx.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/arm/mach-omap2/pm34xx.c
+++ b/arch/arm/mach-omap2/pm34xx.c
@@ -294,7 +294,7 @@ static void omap3_pm_idle(void)
 	if (omap_irq_pending())
 		return;
 
-	omap_sram_idle();
+	omap3_do_wfi();
 }
 
 #ifdef CONFIG_SUSPEND


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.640861846%40infradead.org.
