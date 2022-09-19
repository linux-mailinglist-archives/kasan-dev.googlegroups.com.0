Return-Path: <kasan-dev+bncBDBK55H2UQKRBRMDUGMQMGQEMGY3OOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D5B485BC679
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:41 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id m2-20020adfc582000000b0021e28acded7sf6449364wrg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582661; cv=pass;
        d=google.com; s=arc-20160816;
        b=AMQ3yjfT8TgDEhM3vkOFZAOIpcf3lNHQZ27P+LFgRbcye1/OJ1S1JBYhzAQCL9ZgkY
         WsYJLHX0sluAPV8eFKQjG+Tfq0We2GuedM7FQEU063yKF4blgcVSRXGEVR8o+afle8/V
         vHnf5p6RULMrnfgDDRAkRQpYe8xC9fymopyFEAKwZP0JkuwdCEx4TdDjlDqjnNvpWBqr
         24/B2clwhl3m4ghdb1F5kqQqdNG8f/txRz06/uAQbV5Pj0u9Ub2/sHiRwCgRPb/oiixX
         mE6sI1I7irKgsky6MSIv3JfBhOA8XCvyLjPxep4Ltdn/UA1QVJl5s8MHsvInE0s5zO3d
         u0ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=y8gwaIxpU4mucC5K7vVMdAwSEQrP3zrvMNy7Ics9HGQ=;
        b=DyuEq/VWHbHE/qSmNSg3mo0j6ti7IHg2IIEW8DYWXAErfvKngEkCNpqIU58qMHh5ox
         zqAjcst3+NbgpISgyXSQ2hdREPkJzSCQEYxdhPYrVPXHGJRsGjRwcsDjskRmo+IMvsIp
         Q/qv0DYKo2f7UpnJPyqM6g8aknWkkWGg9x3ZCN47RBAUQw5jZvN892LoC5n6ZWiIdawW
         FCLJNtWPCnvmPYFjwjRTVxAUftQBvz4fGTRcfCoQqArKsz8ar4luhoGyadt92UCcnC/m
         InmGGntuEFaQrh23sW9Q19VXVEixwoZlbdJ3m9MqsMPvq/K+UqbYddITrZVMnMTNZGZn
         YpCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=CFepZEnf;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=y8gwaIxpU4mucC5K7vVMdAwSEQrP3zrvMNy7Ics9HGQ=;
        b=YZXIj1rOo827YULJz+2+YyR6zqUYsf2meekyN962y1R+qS8hbztvcbthnJNGD9ajXw
         crmZLDBzyvvpTOkL7Sy68QHAMNnz0SkzkBEcRPEG41jFnjWJRKZGirEuI/RNMXmLcgu4
         aLgvoagteeAD+fSlWXVLRb5SxZ8X1kcy+pyUgqXTWNLz5S7u/Ojy64htySogGYH2Kf2j
         I4To2kT+7Q+p3qcTagSIZnbIkjeEv51SMzaLsuwg7vq4p0EgS/EmRFBqUFKYMKk2rCsW
         VaeeuXu3mkweQ23oXoG0Nm8KEPxlKJQibfNeO5pDM1GU5L+EqNcUtC+FSAnoNS4uJ3Wh
         AU3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=y8gwaIxpU4mucC5K7vVMdAwSEQrP3zrvMNy7Ics9HGQ=;
        b=Wxg2U62NxM/VTQNoPknomVcVtCvjfp7ePT2n8PPbAAm/0oqT/K9O44gIOjPjCVVDtb
         +o6zn9SC9EsOo6i/W5A1J9+HuY47qcOfAcVUQCZemYViS2+9+obZBY/g2EcfloC15V4K
         ST5Fu6J/kr+4nNnMwGyGtTp+Ig0ihHfiTCA1wzZDIgrWFFcfNEM/kCFBkfAXBzPs4LJH
         t670cfLWHprOqkdOmOKAmdxfxNxOVdW7MYNtAyF5+/RnJgTIrBCWVLfWLYfdpdK2I4Dz
         qSGnfuVLtJimvBhSA5J5H3LhS76/BccJy2EX/5ZQggB/0FgQ5E6uVSbWsTRNqfgSd2Yj
         2B9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Lb9tMKJgeIKAnvDwGxP+ibhhWSkLEvhWaM/RWrR73E4TroVYE
	9g2uayxKbOQrPf3mA76LPA8=
X-Google-Smtp-Source: AMsMyM6gm/OIEZ9zi1uMzPXrGUIhTExR8PHa+HhtdL7UeF5vkeHlfA9+lhvEIkMLySfOxYyYB/oQFg==
X-Received: by 2002:adf:d1ec:0:b0:228:d9ea:cbd2 with SMTP id g12-20020adfd1ec000000b00228d9eacbd2mr10207970wrd.609.1663582661446;
        Mon, 19 Sep 2022 03:17:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2881882wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:40 -0700 (PDT)
X-Received: by 2002:adf:d08d:0:b0:22a:4560:9c29 with SMTP id y13-20020adfd08d000000b0022a45609c29mr10092968wrh.579.1663582660361;
        Mon, 19 Sep 2022 03:17:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582660; cv=none;
        d=google.com; s=arc-20160816;
        b=juJa94APKWuUm2SVk6/zooT05BdWNfqNoK6OtfMhLJP8jNB7wV1aj1rRt9/6WDQstY
         B1vfV5pkF2aDROrY6Xo2JodEQC8jhL7aKNjHo7d5rHK/OZu8n7+B8sqHBQiTaRIINEJh
         pGn9EpWA5nGZ5juczN0Lvag7SpZ3QP4f+Hnrr4k9Yzv3aPOiggDY9SeHmqJDkkLXVAtu
         /CJbWVpK738y+pxDvk8PQi29LGZgO0NJ/4UPnK1iqheo5Gja+/CVexCeiTknTrywasJ8
         LFSQUySxE0pKIahEhwi+cqzKIUibcWNUvdfbOREQBU01wj0X+llcnL2/XPvOeF2x2UPH
         tBSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=HzY3jBvKRSGcnvMJEPYny4/0n/oTUbqDiv/WYyIgET0=;
        b=xk6Qs/hqjWQWG3P3o5TBTiMf3bbtmf+d8TNwUhKXYAjqZxHZzgUQTZX74TJypu8/dz
         W3u6oYesQE0pRIRf1cepKizAIiQotD9an+hT08IUJ1lXamo+LCcblvfVxWH/S7tDFymb
         t+5QhaG6xcvRvK/4RaweuumoDWrgTqjhgaYLnis2pzRIL/yLcqOqmFPjA2hK79uMzn2r
         Kc0CCBTDYTi8Y+PH1C0P1s7XGDxQP1yz6szntz7H2SpR+XoWxvqc3e7UP6Jj1hR2d1f6
         H+kLv2yF4xbntyuLypoHJ629idF7Nmfzegvlj7Xv1h9przukCi87MzIcNmzLLmG/xqDN
         eNMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=CFepZEnf;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ci10-20020a5d5d8a000000b0022acdf547b9si291136wrb.5.2022.09.19.03.17.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:40 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq9-004bCQ-Pb; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7B0F4302F69;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 9253A2BAC75C1; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.908560022@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:17 +0200
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
Subject: [PATCH v2 38/44] cpuidle,powerdomain: Remove trace_.*_rcuidle()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=CFepZEnf;
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

OMAP was the one and only user.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.908560022%40infradead.org.
