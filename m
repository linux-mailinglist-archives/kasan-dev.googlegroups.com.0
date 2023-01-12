Return-Path: <kasan-dev+bncBDBK55H2UQKRB4WMQGPAMGQEUGKNKOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 145D6668019
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:43 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id l18-20020adfa392000000b002bbd5c680a3sf3336453wrb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553522; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQt7qw50Xc7ZNmq1Z8ZYwqbPIPtjglAFgFJnNE7Jll0e5fUO782v4SKGy9XoFj5Uja
         5KdQwhkM0YiKxZrintj4BkV9dZ0Jzb3GiJGw8FGLohXlhoF3qJzTfF8KFQvNKbfDzEZ3
         16dsVcXSmuwWfOrnT/pEO1w5+J971ys9FRx83vL8QOsra0d2AbniHl+iKVWdDcHO7XLe
         frASDvtojOIZP0xUHzD4CKHBQybQoAZ9KhzhHG6Tm4VgViUtkLtPhkUDgMgTV8Cwn2M2
         161EDH526oAfHar2NGV0uQkUIX/yp9mmNt5/mT4p1NI3EsgX0h2WgwI02NDtahQpHIao
         GNvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=S6Lzc0D1jz6PmmSv4htupm0tRAer3rETP4apU2gmW4g=;
        b=BXfD2Ms/WhPfZBxEv3zULrc1gcmhisd4km8sCJdX4+3Vux5jETshI4uY9unCJ9ZJxY
         QforAZjCWsFOT91XFB9N9zUIO8lGbP6fRgXlAe7Dx9FoyzfGWHaS0V9Oe4LbNkLqXEG+
         iNch8Lh5FrfIUrCFkUFvw+mFEusVtNWlpeb6IF5krhFaLJazbo3rAtOAlFzk/BwaOINc
         39cBJyrn5SIKeb8M1pNwd23ZLd1Jz1rzkjkU72nZMSnEPnjbn8cw3mR3WDBKNQQx5soO
         LqsYeFC6a6sgPYzZh9T2LiMixqIaQM4r7Fx++uJuOjYU8Slzlxztf0OX9lzi1ZBgE1s2
         MPvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EXFl9MaM;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S6Lzc0D1jz6PmmSv4htupm0tRAer3rETP4apU2gmW4g=;
        b=twZgP994I6TPkltCrMDe9EJwkL9s+m98Y7SV/2/o2i8igJ4/616GJyAvER+5ZCXtbH
         pC8KkjaTC70MImyYWnxWy3mDHtkmvSig+alB1Uyp0Nyevf15/vZ+wMEO7XwfOQCRi6aZ
         PPSopncjOJTx7oJ883AEpslrTZQGSCbg6W7G6gtYRSnTA6xJVQrdKSDzTKvoSJUvUzVc
         TmPXpDx/IDrdxHt3Do64xmYZmy8Gn2TFAdYJhhehCkPBK6brnabkGW3U39Z+tRRt0Es2
         GUOq0FYSZiiuzVtSVwo1xt3RCNqMG8cBEzwVxRUIRJeo65TqXpwZ/iEOu7g3BACSUZZC
         G9iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S6Lzc0D1jz6PmmSv4htupm0tRAer3rETP4apU2gmW4g=;
        b=qzvsy4LJVxbg1cfd8d4mTv4aoJLwqnzwNskSzXk2+yu/GIiSYv0X/Anc0nloWP1OI3
         U6WXtxI7RArhsJKL7fYJ3U4kcPUBC/SD3fMopB0y8xjVTZ1F7X+HTRDKqQHv6X5s8UNH
         jr2Zjyra8i4Sl+sjcmXstMgdXcY4hYDMFsH0bw+miBw4jReLb+Y4Z3EqCOCxAstWPQno
         WWq4MFD7U9a2W0xyHLa6vnvI7484XT94MGdMMAcnPzeHhLoKJ2O05hLNyBtq12PVEd0z
         LNOnPpC3eDxUqlJ6lJ6vd5fVODMLvWfVCiSS80isDp996Onc5FK9CrsKnRGN848ql+Na
         Vmyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpnCMvj3tWlZWHpjYd/YQP2+cCXaCuM5/yQVBvmrDmOzpt9Gvl1
	jBnipfLp9ynztGdC560BBIE=
X-Google-Smtp-Source: AMrXdXshPd8+jVxyLvwMtIJmvGvfgnq6JR4LQ4cBatjqsVfqkTXasgU6z2lVnP1lYY3Kh6J5rV8dYQ==
X-Received: by 2002:adf:f7c7:0:b0:2bb:edb4:a50c with SMTP id a7-20020adff7c7000000b002bbedb4a50cmr901208wrq.652.1673553522761;
        Thu, 12 Jan 2023 11:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4943:0:b0:298:bd4a:4dd9 with SMTP id r3-20020a5d4943000000b00298bd4a4dd9ls1473978wrs.1.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:41 -0800 (PST)
X-Received: by 2002:a5d:5704:0:b0:2bd:dca8:a4b with SMTP id a4-20020a5d5704000000b002bddca80a4bmr410119wrv.63.1673553521531;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553521; cv=none;
        d=google.com; s=arc-20160816;
        b=fJw7i/nP4PNBM3Wt/f2EsfL9xtItIQTHt29yksa5mVtdn9eaoS+6FrEeABGb2iN05I
         j2vj6RtiVwHCQk84+oS1ty0ntEdcohX0/wOQpWRsbVAA3FdpsSePKWuJuWXNAQ2QQi2J
         Ld+S4OTNmwzU2X2FTuiWSC7SEV8iTVTuI5dFRLWQ7KYf0L/1aA96iETitDw7jXIa96JF
         g/ElOmp2VjD4yY6PLixW82hl+n1+z26yNv2/H1ctXoZq2AOtjSLOD3M2LfSjLxbc2Ht6
         ktlHylvJPq+j0bYEsIqmfegvj5d/E/zuWHdVYINGP29SMcDmPx1NdFXKo2erlYHnGYWd
         gmfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=4aFpXbTN+2q/sQWoIhQXRuBIzQdX59WKAp/kjFjx5nI=;
        b=Y+Yv9h3jAbm9LRE3xY/9t27MCk5qfQ/DYoFqeK3Ar1tXZQNJdZ5BsdvtUnRaoZ268T
         thLB3ChfQhD2W8ywrnrKFjYdTbjRLWVXPe7LsnYZY/i4z0AxmRHzYX5Mxk33Mcs+sxie
         uDIC8fHykSTmz4pltTIvjvy3SL0HCWypoWaYN2mK5Vfm9LCbVDojDlmf8+exXcok2x+Z
         c5KYvfvvCOxPZwgKQiv6gpIA5uxHVDiX0BPWfk5tlQlnEESCodNmYXLtaRrKMrYNw8QA
         kU/XlXWSbgIjagIcv9ZaJOPDBFt5Hi7owWzfByV5rSNDYwr9RtdMHjTZi00jxrCmXsNM
         kg4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EXFl9MaM;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id m7-20020a5d56c7000000b0023677081f0esi826746wrw.7.2023.01.12.11.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hL-0045pk-2M;
	Thu, 12 Jan 2023 19:57:28 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EFD64303464;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 4EBB62CD066D0; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.782536366@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:54 +0100
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
 Ulf Hansson <ulf.hansson@linaro.org>,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v3 40/51] cpuidle,powerdomain: Remove trace_.*_rcuidle()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EXFl9MaM;
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

OMAP was the one and only user.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-omap2/powerdomain.c |   10 +++++-----
 drivers/base/power/runtime.c      |   24 ++++++++++++------------
 2 files changed, 17 insertions(+), 17 deletions(-)

--- a/arch/arm/mach-omap2/powerdomain.c
+++ b/arch/arm/mach-omap2/powerdomain.c
@@ -187,9 +187,9 @@ static int _pwrdm_state_switch(struct po
 			trace_state = (PWRDM_TRACE_STATES_FLAG |
 				       ((next & OMAP_POWERSTATE_MASK) << 8) |
 				       ((prev & OMAP_POWERSTATE_MASK) << 0));
-			trace_power_domain_target_rcuidle(pwrdm->name,
-							  trace_state,
-							  raw_smp_processor_id());
+			trace_power_domain_target(pwrdm->name,
+						  trace_state,
+						  raw_smp_processor_id());
 		}
 		break;
 	default:
@@ -541,8 +541,8 @@ int pwrdm_set_next_pwrst(struct powerdom
 
 	if (arch_pwrdm && arch_pwrdm->pwrdm_set_next_pwrst) {
 		/* Trace the pwrdm desired target state */
-		trace_power_domain_target_rcuidle(pwrdm->name, pwrst,
-						  raw_smp_processor_id());
+		trace_power_domain_target(pwrdm->name, pwrst,
+					  raw_smp_processor_id());
 		/* Program the pwrdm desired target state */
 		ret = arch_pwrdm->pwrdm_set_next_pwrst(pwrdm, pwrst);
 	}
--- a/drivers/base/power/runtime.c
+++ b/drivers/base/power/runtime.c
@@ -442,7 +442,7 @@ static int rpm_idle(struct device *dev,
 	int (*callback)(struct device *);
 	int retval;
 
-	trace_rpm_idle_rcuidle(dev, rpmflags);
+	trace_rpm_idle(dev, rpmflags);
 	retval = rpm_check_suspend_allowed(dev);
 	if (retval < 0)
 		;	/* Conditions are wrong. */
@@ -481,7 +481,7 @@ static int rpm_idle(struct device *dev,
 			dev->power.request_pending = true;
 			queue_work(pm_wq, &dev->power.work);
 		}
-		trace_rpm_return_int_rcuidle(dev, _THIS_IP_, 0);
+		trace_rpm_return_int(dev, _THIS_IP_, 0);
 		return 0;
 	}
 
@@ -493,7 +493,7 @@ static int rpm_idle(struct device *dev,
 	wake_up_all(&dev->power.wait_queue);
 
  out:
-	trace_rpm_return_int_rcuidle(dev, _THIS_IP_, retval);
+	trace_rpm_return_int(dev, _THIS_IP_, retval);
 	return retval ? retval : rpm_suspend(dev, rpmflags | RPM_AUTO);
 }
 
@@ -557,7 +557,7 @@ static int rpm_suspend(struct device *de
 	struct device *parent = NULL;
 	int retval;
 
-	trace_rpm_suspend_rcuidle(dev, rpmflags);
+	trace_rpm_suspend(dev, rpmflags);
 
  repeat:
 	retval = rpm_check_suspend_allowed(dev);
@@ -708,7 +708,7 @@ static int rpm_suspend(struct device *de
 	}
 
  out:
-	trace_rpm_return_int_rcuidle(dev, _THIS_IP_, retval);
+	trace_rpm_return_int(dev, _THIS_IP_, retval);
 
 	return retval;
 
@@ -760,7 +760,7 @@ static int rpm_resume(struct device *dev
 	struct device *parent = NULL;
 	int retval = 0;
 
-	trace_rpm_resume_rcuidle(dev, rpmflags);
+	trace_rpm_resume(dev, rpmflags);
 
  repeat:
 	if (dev->power.runtime_error) {
@@ -925,7 +925,7 @@ static int rpm_resume(struct device *dev
 		spin_lock_irq(&dev->power.lock);
 	}
 
-	trace_rpm_return_int_rcuidle(dev, _THIS_IP_, retval);
+	trace_rpm_return_int(dev, _THIS_IP_, retval);
 
 	return retval;
 }
@@ -1081,7 +1081,7 @@ int __pm_runtime_idle(struct device *dev
 		if (retval < 0) {
 			return retval;
 		} else if (retval > 0) {
-			trace_rpm_usage_rcuidle(dev, rpmflags);
+			trace_rpm_usage(dev, rpmflags);
 			return 0;
 		}
 	}
@@ -1119,7 +1119,7 @@ int __pm_runtime_suspend(struct device *
 		if (retval < 0) {
 			return retval;
 		} else if (retval > 0) {
-			trace_rpm_usage_rcuidle(dev, rpmflags);
+			trace_rpm_usage(dev, rpmflags);
 			return 0;
 		}
 	}
@@ -1202,7 +1202,7 @@ int pm_runtime_get_if_active(struct devi
 	} else {
 		retval = atomic_inc_not_zero(&dev->power.usage_count);
 	}
-	trace_rpm_usage_rcuidle(dev, 0);
+	trace_rpm_usage(dev, 0);
 	spin_unlock_irqrestore(&dev->power.lock, flags);
 
 	return retval;
@@ -1566,7 +1566,7 @@ void pm_runtime_allow(struct device *dev
 	if (ret == 0)
 		rpm_idle(dev, RPM_AUTO | RPM_ASYNC);
 	else if (ret > 0)
-		trace_rpm_usage_rcuidle(dev, RPM_AUTO | RPM_ASYNC);
+		trace_rpm_usage(dev, RPM_AUTO | RPM_ASYNC);
 
  out:
 	spin_unlock_irq(&dev->power.lock);
@@ -1635,7 +1635,7 @@ static void update_autosuspend(struct de
 			atomic_inc(&dev->power.usage_count);
 			rpm_resume(dev, 0);
 		} else {
-			trace_rpm_usage_rcuidle(dev, 0);
+			trace_rpm_usage(dev, 0);
 		}
 	}
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.782536366%40infradead.org.
