Return-Path: <kasan-dev+bncBDBK55H2UQKRB3WMQGPAMGQE6PN6WFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 396A0668007
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:39 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id t2-20020adfa2c2000000b002bbdae91832sf3324941wra.21
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553519; cv=pass;
        d=google.com; s=arc-20160816;
        b=HHhxvFCI2aKV9YGfF2gWd3O/cfOulR4okUhzIyBF/od3CL8Uh9v5em5Kkz5GV6trhM
         3Vm/wtMaBSLJqoMSVqUfYgBcSiYJYB7yC7h/zwEjRe3+L0etGZ+lbsCetaYWDyb/kJlV
         tuSDG9bLt1rUqmoJaWqnXD37idcpfUbgpVuzqqEYrVpRo5rL/Hb3DM48KlCnZlqyukCU
         CpmN8RrOStfJZI2kkRr2UNoILgHPYronMVVdbaioFq/yiyiC4mYCBpcdCgG5pSzZwO0Y
         PK8XJPMWzs0pUKkf9QcNPFLFtnyPhEXN6IwZSmvqEjbz5E8SLo8IQIXLcZM+P5qW6U2Q
         7ZIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=mPNBaYt/XrAnZiJVPL3mFpyhiZGgDDWjDIG3k75zqzc=;
        b=OBCiGFv7J/HEF4aTuRGDCw0asm1ALhAAN/DwcLsmXh1bJrDDKmzJev1d4yGXdsnnne
         HtT5Pn86BRDtzSEBnQ0AllfkBcbNTdIgmFvWS/WbC2u47mPMnDZcFUMO4XFNKi+E+7lh
         Sr1iXO9OcAg/GzjRmsRHMDSbe6klMyuoMmTf2y6vux7wqeqsgEs6N/1E/AUc35b7PCOW
         yCP7RjVUXm1O/tALkzHP5nZEjWRkCJNE64Et86LS3b3aBcicQA5xM1E2h17gGfRmi2tz
         kRFqtctZYR8OCZmZHPuSp9HOQpfivYVtW9rei5ycW6ZezhV8lyuI35hX7EDi5ltQwdfF
         BMPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Bz7q8sFy;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mPNBaYt/XrAnZiJVPL3mFpyhiZGgDDWjDIG3k75zqzc=;
        b=DC1UBWFLW8inAfx4uvqlhW0Fo6pZkXE5m9sMOvJpO5FmUmYGRAf3fQObAAZbIlrvpo
         vHf+NmjoRjetRo6j2WILoAG2IxNEUL468F1yldBKt3Q1v20DYbx95Gw8jAw98DmrHirA
         6kMiVZKjFnKhvZvNK+bv+8J5CW2FkMuqdnxj3MIBhmgk6Wswg9XrPclHC++vIVZcyln2
         dKC8Uw3qMeY43q7gI5IxTiH1T1d/XmQxhXkSADJ+8IBpGET9+yr7O0kmkLOZDtnNJbHB
         Z4FjOZs4UMK1CUDoUWy+dTDd+Lbny5y4S0PpaGxb5soHkJHe0/1cMEmXu0qjEubaTqrW
         pF8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mPNBaYt/XrAnZiJVPL3mFpyhiZGgDDWjDIG3k75zqzc=;
        b=TVIr2GQXpB5MemBPBGhnoe5TSicEi/kFfZ+2ZFGnRF921l5sWUwJa49/e/Fkjx8ar2
         E+rM/MPzJd8aS1QNIEPs0f4wKtyZzy9tJhO9VoLEx/ZRmG7Qiy4F84rq3E1mxGloHXbG
         XJh3B+UTUcflvRZKKArP7fQjEiv3XkDNDQftmQtmvo7OMSg4YHdITR/fDZIEBXJAJTU5
         HDgOf62mpjZWpgLxuRbnrbtS2Xz+94qz/I9lLcxGXF7SDOZxc7bRBPBKQbvW1Vm84iJl
         cffdZje3Hh4Yvs5JDm4Xcvla5wEhQMqBgdyU0yQcHa905C8Cz4aY1bIyPmXpJA14HJr4
         uO1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq0jiVOwGSpLzWDlfhdX6yS5eVzwmGJKIYpTwu75vn8jAsXx11R
	/yKlV+0kqFHbAm1dzlvnL74=
X-Google-Smtp-Source: AMrXdXss9rC4xNI0PaRngcDes4PxSWEMv6O3ahot0w9qAwrA56WBtYqoT7sxRrmg890v+MBq2t0D3w==
X-Received: by 2002:adf:eb09:0:b0:242:739d:7f85 with SMTP id s9-20020adfeb09000000b00242739d7f85mr2173888wrn.407.1673553518880;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b0c:b0:3cf:72dc:df8 with SMTP id
 m12-20020a05600c3b0c00b003cf72dc0df8ls2948754wms.0.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:37 -0800 (PST)
X-Received: by 2002:a05:600c:1c8e:b0:3d2:4234:e8fe with SMTP id k14-20020a05600c1c8e00b003d24234e8femr56555474wms.19.1673553517748;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553517; cv=none;
        d=google.com; s=arc-20160816;
        b=hQQ/lEV2WbWcPi7kBP0hGKQmyHQ90Fk02xBZV1x72oTjLBUFjD1FmtPaDLPTu1cj0d
         VtX54xb8x8GslV2+lRK0TC9eDz4c1SZSHp8SnLTtxNnosU6AI2Y+3IDlzc1jO8dWfc9B
         uOUo/S5rfuu2eK/QzjLeopLIVPQDVZztFAPS+bTX0k0/Q+gubJjM7mQk8QGP2yFWF9nb
         /hXanwQSI5YP3HwHQmAq2jEvb7LD1Hdvu0AJIhY/148UgbP2/SSIraWG2D3jI0SAMVat
         7oElgbAE3lQcISngXwGpX2c61N+Ot3ZMuqEX54OvYIelSFuq+XDrOZ0HgYMmfH7q+fHg
         huKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=JTqeKYECYSubBnJX/J9QEXdDkgA0NkIECFSZWgBtZ5c=;
        b=z5/tugnjIh1sb31l6zaoxDCCKC5VSk3VFrZoUvzNVC+IVNWWi9DNvHXskt/E9RMwzL
         HFj8WDk8+sK/T0xOKtMFYmasIzVMgUzXSC/b9sLVGS1FLqZPUCSIX5DsYn1wdxm+aEXK
         /YLwqeJT2TlODbOg5I5Tq54dl2A0rpLYZgpYMIR51VSkjJcGBlkgHUjV2ER0evkESshQ
         mY8GjAK3Du2oyOm1BY3XESuQKpTS7ObCYl+bQGjXlQaadT2cnpKQYbKPR402KEO1Jg8h
         bpn16csTQQptpCSishDSrXgvxDVALVSd42CgCOIEG+w2rdyK3Kq8Vy35KKgKx1KUQ7xQ
         Rcng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Bz7q8sFy;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id s1-20020a5d4ec1000000b0024222ed1370si827141wrv.3.2023.01.12.11.58.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hO-0045qZ-0S;
	Thu, 12 Jan 2023 19:57:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 144A230012F;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 5B5522CD066C2; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.967699392@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:57 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
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
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
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
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
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
 linux-samsung-soc@vger.kernel.org,
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
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 43/51] intel_idle: Add force_irq_on module param
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Bz7q8sFy;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

For testing purposes.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/idle/intel_idle.c |    7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

--- a/drivers/idle/intel_idle.c
+++ b/drivers/idle/intel_idle.c
@@ -1787,6 +1787,9 @@ static bool __init intel_idle_verify_cst
 	return true;
 }
 
+static bool force_irq_on __read_mostly;
+module_param(force_irq_on, bool, 0444);
+
 static void __init intel_idle_init_cstates_icpu(struct cpuidle_driver *drv)
 {
 	int cstate;
@@ -1838,8 +1841,10 @@ static void __init intel_idle_init_cstat
 		/* Structure copy. */
 		drv->states[drv->state_count] = cpuidle_state_table[cstate];
 
-		if (cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IRQ_ENABLE)
+		if ((cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IRQ_ENABLE) || force_irq_on) {
+			printk("intel_idle: forced intel_idle_irq for state %d\n", cstate);
 			drv->states[drv->state_count].enter = intel_idle_irq;
+		}
 
 		if (cpu_feature_enabled(X86_FEATURE_KERNEL_IBRS) &&
 		    cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IBRS) {


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.967699392%40infradead.org.
