Return-Path: <kasan-dev+bncBDBK55H2UQKRBMUDUGMQMGQEQDKTV3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E4B5B5BC65B
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:22 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf9627347lfa.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582642; cv=pass;
        d=google.com; s=arc-20160816;
        b=KuMWqPU0vFBRgM7hUO8W4SZBw0+ot18qu3VZRiIIVmIJMsKgJ/yjg3KkYOGmgcyIW4
         EKoG2T6qfrcAXtvq4V0HT7M6aEWC6t7qL+9jZ1TFSbaqifz9pqbGswJAL+HRzF/nYDAl
         7P1SXssURW3NXo3FzbsL1kAa0BUE19Wwm9q5pM1QWBpIAU6VyURsVPctoE04QpNAsSCH
         oy8KZMaoZ0XIDjPEA5KIpsbEB7+7PoKVfmDvrHmE0bip1tV5eYK9fuySqF2KoBR6ZqNE
         WtW3WPRfMfBms3TS1NXl9jVUXB6wdEuslxiNIldcTWA7cOwXrCd9z/8IcUxv/GMU3KO3
         Xosg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=P6kS2vuYgXMx71BCCJRJ0jBAeaoaAjDtKk8/1LFl/sI=;
        b=czktBkyUMc3PoU06LYXZbg7LzoRrigv0251gX3ebtoC4DjYJXPUoy29HmzENmFYTSB
         e/tT1YlDNmpf7R84W45t2/gBXVybK3DErSjYGdATIrldP/iFljWPx6h8JEYzDckHHEUK
         SlzuG3uHmV5njo6df/o4F7gBv84L2Ky5Lp7JIFDFH+2nDISOWt+fl7I2TbNlKMcGRupg
         bkDoNIxQfpT/z5kQpvrk8SX05pHzYpH8ZUoLo7L6Mjm53jCsXU9mP/Yc44vXbmPz9bFo
         Q9DUtQVWkIAZIbaQnUdM9UeNkfG3FXalUTW1ZwNPWlTOdBGX6Oal86U5WPaBYfOJJg2v
         S+hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kHVZnfdi;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=P6kS2vuYgXMx71BCCJRJ0jBAeaoaAjDtKk8/1LFl/sI=;
        b=VElaXNE+8iQid+dMycMXaInhFtdGwCzgR2pYB/D75K0I6BtgC+nZTxJWW/ulC9Eto2
         AtgVKBAGAN2qVeJfiK1HHjB9pP+l10srLcG3PU+wvUgfNv+I183KpxEEeKdUE/bbhKnP
         Wc0nRR4nJGDmmaOc08yx+lO7dxb4/tNXxPJK0LLb4xOC20DjZZV9ola5JumlqmkqSwVn
         w6/NBOjpvLzU8YBzRxuaWHTqjVuGL/VHCdtdTya6aiiLRRv7gCyb/4472GeVYss4i1lW
         0CDHkI57kkI9Cx6NG0/qD6+Sg21MtVpX6ligrZ7963WVRYGaHUdr8aZMUFP1KG8uLJei
         85og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=P6kS2vuYgXMx71BCCJRJ0jBAeaoaAjDtKk8/1LFl/sI=;
        b=gJ5v7V28qPicxPSW4iMX042y1w8trmTUl+FzRjGTHEs3wzrdorm3mKRYUmYR8gm/eF
         yamDSb3TCZC5iAryC3KzwGxxijsqRT6Op1impBfTNDS9vysJVnlkOygKlVEQVyupR06G
         9YNKojm1XzdWkjrnleh5YUgH+6ebnWmdJfEl1RaRbndwTD1pmxcVrFyJdgGby+VJzoxf
         Gl8KhCbHBnZyS9JcvVcM/DhRL4EylfAApf6Z4ah9GR+CKQcBEO5NIF23h0V3j3gCuABl
         /XSO945z95Yg4TInOJH06ikJY8619NgKqASrTGuFBwYRqXXYMdP2xz/DVMeMnWTvBSRI
         5Z1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0LUhRGAvfTMDgUukkeXmuodS7mPfwpaP7rQoveltY8XcJ7fCDL
	vCTdIjJeI2SubrvN3PIycD8=
X-Google-Smtp-Source: AMsMyM6plaEgYn11VFpWuZcJtDq+ZtJowp/A3kbuFvmpJYWzDNup7GaGW0n+am6tWXhF4Ov9xdIB1A==
X-Received: by 2002:a2e:a601:0:b0:26c:4149:251a with SMTP id v1-20020a2ea601000000b0026c4149251amr3286423ljp.348.1663582642314;
        Mon, 19 Sep 2022 03:17:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e7b:0:b0:48b:2227:7787 with SMTP id a27-20020ac25e7b000000b0048b22277787ls555366lfr.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:21 -0700 (PDT)
X-Received: by 2002:ac2:5cb9:0:b0:498:eb6f:740d with SMTP id e25-20020ac25cb9000000b00498eb6f740dmr5583553lfq.106.1663582640933;
        Mon, 19 Sep 2022 03:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582640; cv=none;
        d=google.com; s=arc-20160816;
        b=OJ8CwXSxJkq3cbd+2nUn+/+HYhI4mbfuteCCls0wEHm967b1/qfK86WVHh6kDxYMQn
         pRzMq3Q3d2GLJoWo0Tl3rWgQE+U060CPfDD31BHsLh1AXpmrrluo8MGxmfOjCB2FVpq3
         zGrHxUFYkQ+Yf/LX0pxXi8Jvx89R6l6R15sV5S91M16CMlcpmElNWFD0eVoRzdKVtGL1
         GiUoANEigjx0bUB1hdh4ztBcrBmE5FZPTPpTjOlAD5YtMvypu7NHBIEC3n8G1UVryK0x
         viKy0A3Yv75LYOsq8maCEyclk4iayolGbtZdworkJ+gCXtMLoyGDf24VF7umhUHKrybN
         4KfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=0408VWH2WFH9JXFcPPgwTxDvr1YxbJ2d7rq21E3aJ8U=;
        b=mYjsK1kxppL1kJgu3TfuUvxpkYEr7hziPkZQaXdbiQ548BXIyZdnjrvg+JgnHxapQi
         Wmoy/kTCOhQdqV9lCeOfv+O730jt05YEy65mTvUUzts+E7/dM1+cr76A2THbiTUqkCVh
         FYK9bmfRPR9g+3fgUZMljo6OlgzjBTRyLEi2lDw5fbABHinxtaG2EWCrjPz6LPLji0CJ
         xGvoSLdVbahueFl6IRhR3845ogIDqo1i4emC8IBf5oubHAVyrkauR3Pdxp6WfMv1NuaW
         6JPceJchrjxGmSTjQTYv9f0cwPQRI9gT8SceJmHfn3UVj+g4Cjixv2R+KPXIMKLpH7qb
         verQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kHVZnfdi;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 14-20020ac25f4e000000b00492ce810d43si771124lfz.10.2022.09.19.03.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ai3-KG; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C913E302E1F;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id EBD782BA4903E; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.936337959@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:48 +0200
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
Subject: [PATCH v2 09/44] cpuidle,omap3: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=kHVZnfdi;
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

Doing RCU-idle outside the driver, only to then teporarily enable it
again before going idle is daft.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Tony Lindgren <tony@atomide.com>
Tested-by: Tony Lindgren <tony@atomide.com>
---
 arch/arm/mach-omap2/cpuidle34xx.c |   16 ++++++++++++++++
 1 file changed, 16 insertions(+)

--- a/arch/arm/mach-omap2/cpuidle34xx.c
+++ b/arch/arm/mach-omap2/cpuidle34xx.c
@@ -133,7 +133,9 @@ static int omap3_enter_idle(struct cpuid
 	}
 
 	/* Execute ARM wfi */
+	ct_idle_enter();
 	omap_sram_idle();
+	ct_idle_exit();
 
 	/*
 	 * Call idle CPU PM enter notifier chain to restore
@@ -265,6 +267,7 @@ static struct cpuidle_driver omap3_idle_
 	.owner            = THIS_MODULE,
 	.states = {
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 2 + 2,
 			.target_residency = 5,
@@ -272,6 +275,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 10 + 10,
 			.target_residency = 30,
@@ -279,6 +283,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 50 + 50,
 			.target_residency = 300,
@@ -286,6 +291,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU RET + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 1500 + 1800,
 			.target_residency = 4000,
@@ -293,6 +299,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU OFF + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 2500 + 7500,
 			.target_residency = 12000,
@@ -300,6 +307,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU RET + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 3000 + 8500,
 			.target_residency = 15000,
@@ -307,6 +315,7 @@ static struct cpuidle_driver omap3_idle_
 			.desc		  = "MPU OFF + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 10000 + 30000,
 			.target_residency = 30000,
@@ -328,6 +337,7 @@ static struct cpuidle_driver omap3430_id
 	.owner            = THIS_MODULE,
 	.states = {
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 110 + 162,
 			.target_residency = 5,
@@ -335,6 +345,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 106 + 180,
 			.target_residency = 309,
@@ -342,6 +353,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU ON + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 107 + 410,
 			.target_residency = 46057,
@@ -349,6 +361,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU RET + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 121 + 3374,
 			.target_residency = 46057,
@@ -356,6 +369,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU OFF + CORE ON",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 855 + 1146,
 			.target_residency = 46057,
@@ -363,6 +377,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU RET + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 7580 + 4134,
 			.target_residency = 484329,
@@ -370,6 +385,7 @@ static struct cpuidle_driver omap3430_id
 			.desc		  = "MPU OFF + CORE RET",
 		},
 		{
+			.flags		  = CPUIDLE_FLAG_RCU_IDLE,
 			.enter		  = omap3_enter_idle_bm,
 			.exit_latency	  = 7505 + 15274,
 			.target_residency = 484329,


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.936337959%40infradead.org.
