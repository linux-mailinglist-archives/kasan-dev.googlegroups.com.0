Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id F1F655BC6D3
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:08 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id c188-20020a1c35c5000000b003b2dee5fb58sf14987266wma.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582688; cv=pass;
        d=google.com; s=arc-20160816;
        b=J2Yza6HbSmEKf7iET+RD/niSkBGuFH9guxnY/yj4CSxg1MCSnHjK8R0s9JUXg3KRzV
         DbsO+auIQq4L46VsN6wmAftX3o/e/cJH5HEVXfPpzAaz92pBeZRXDPVaeecYc8mI0bDB
         N/51qpuB0Wqeym5lzUL2K9PXBNhzQWeT7CcGBhnZUmyUiTgI0Xxeuv6QeqCSGGWu+eqD
         bFkyX3ftn47NdJDRiODXwC1lZjTcjDL1ftryFHj1Ak6WpSnxpxTs7/EkwAVxAa7iyOxj
         WJpL4DuFmSjK+fwKeelz+pqrNQtDtQPThbx3TYVOZnl7DM3uGqWNEr3E1BZVA18+cyw9
         WUpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=x094eW0e6UPL6RNKs4pL8Ws3OJNWFxVt5cxwWGfdzNc=;
        b=bm5GqcvKwoCfAtGW6gYvEOfT4iu4D03uAzvzccW5zMWof4qiVHLQtaG7r50Mo6+mLQ
         d/K1vQhvBNmxF/K9WxS9mRsyPssTkCLaKGegccXhva1MqP3tx1XeLuieWnjLL4MUc+Fa
         AHT3ZqtNtvrB8qjnGJ6KHdzkR3veTVypKkwCkP070fBzTMSCC/8p0MgzwqQnYqSQxxSu
         afkAk1gQ0b0XwTZHZLFJzCf2NFE7h7V1UPGJkLV+H2ayZDUylZXZZaFBzhdaBoZr5JSP
         d6CrKN5XCdXZDlLBuWalC6tu2NqVrWOzoROb98U7Y/PMBCPtbLWQ61muWVs+g3uJOglV
         1DAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=WLGHjeKc;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=x094eW0e6UPL6RNKs4pL8Ws3OJNWFxVt5cxwWGfdzNc=;
        b=A9mc+BUNCz0KmGaUxQ+a20TSUhZedwuKNtu9dGONpLHkaPn7qtrRs8f1QOjtI0JF0u
         74+k+oDnIdtI29kfC1lbF5YxluJKA5GSUqaE6OoPlc6/NEnr0wLT8BHGdXljEzF4YgMZ
         VyqBeabTVWWhgSEyhXXp3CB2Bkpg5X/+ORHkBWQv/mRG7Y0E1q/JFsh1jZaB8laprzjG
         QXjSOr3B2febURMnJjCzvvdu+wEe5MMJAbqaUAeOFVNsDRE+BHM8rzrGaddLsCSI+kFk
         IfIMRLg9vheksQDxpCUxQ8sXO1QT2L4iHDeS4FSecN1+fxxNEkJI8nZf7EOHRrDNT0N1
         aISQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=x094eW0e6UPL6RNKs4pL8Ws3OJNWFxVt5cxwWGfdzNc=;
        b=AfDf5Pg7TUpmV8DEY2dMEy9X5Pz1MvO0arvW5DXuR4IHrTxBOhgj78SkR9TY2nTz0v
         8OHxxpN9EcnKSl9qaA44VRsOKdA7GZo/tLKlqFtOC2a/913y7flUwGRMGKuac7W4jLXb
         1Djov+/mxekdUB3sBetHZlbO1MUNz9M6i6e7+fPAOYemFhaY10MUb2bLh7uz2YRnR2SM
         XnPk++QzVI6aHMTSYUuJHOxve2B81qBSwCJgWbCr9CrRuoUSlKhhw7XpimltaQTfVWqf
         WmodY16+FpPO5P7zH8C7JdC73p4N4LxRVImgvz7KGgwwXzgDSu2hZq3fbQVJX4am1qa6
         IGQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3PxrWpAxkXxcsCik06C8KD6+o/vzqhZcnjsbqTuoNshobea4FS
	QcCGfvoVRoyqpkUaEEHutA4=
X-Google-Smtp-Source: AMsMyM5mM8ZBJmi6EqOniBecSRy0opA91GW2aFT8WR5UhrFnreEJGVrPZDzGLr2q4+6L68n86BSGqA==
X-Received: by 2002:a5d:5a01:0:b0:229:3d5f:322f with SMTP id bq1-20020a5d5a01000000b002293d5f322fmr10196532wrb.707.1663582688471;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:255:b0:228:a25b:134a with SMTP id
 m21-20020a056000025500b00228a25b134als7688974wrz.0.-pod-prod-gmail; Mon, 19
 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:adf:d1ce:0:b0:22a:36d6:da05 with SMTP id b14-20020adfd1ce000000b0022a36d6da05mr10723295wrd.719.1663582687394;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=EU0brow/vPhI54YBP5pnJPqYqHnsx/7dLc10qhEV4cmE8swxL/03BeN8s0gyOhJZ0c
         iWJ1PhIpX7Bb8lmxmwWgVae/z7OAGca7ACYY5R3xyaiFKE4BTbjz//oT9rbII86DisSK
         a9OM6c/KXa0pAk/P8cq4yzosvOr2kn27zI4ND9RJrsOoAfErNPmq776kC05fkJXaVoGU
         H16gh1hxJG7zfRo2r5z0ZGntKPcOkywOM+V5SSRw/qpVjqaYJGwmG82XEY4xL6HNfr4i
         GeBkrM1w/POoO3JIK+/9LzQ3he0SLkwzKuVdcr95v4fMDcbbK1GBXpbh/LVU6nXEeRC/
         qHXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=QoMAr3LApQWawpgafmfgLtjlo5s7sxEjoowggy+JX/o=;
        b=ahNi6jTywPln6H1rGJDSMcuHwIMkZ3LFXJcHx6Ur+XiNM4GgDgzh4dR/NfGnIoQE0c
         Bv91Tmq8uoERENDB7B30hgh/h5DNS7RBSaNE+VtLGRlCZWgMrn8HaXaexiXgF6VVPfdZ
         zktWvqCJJEsfoB07Yqc7ReQNYq6N7+fCvOIEeiFSFlyiexFXf/Wd837X3KUaEmJFRtG/
         0YLe0y5ijAMhRqzOsGBMZf+qkOJkrsmKxWhFcg2k2Kq5qj941dkrBSXRQjP4V4uhmj3r
         97M9/DWIrP8zNMAEdoqJ7MDrYKpUVExdVGx/Xpu2zMegolOzAcx6KieP3vuUu1aJA2oI
         nTvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=WLGHjeKc;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bv26-20020a0560001f1a00b0022afc97eb06si83867wrb.1.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq8-00E2C0-IT; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A5CCB302F90;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id AFEB12BABC0C7; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101523.312333837@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:23 +0200
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
Subject: [PATCH v2 44/44] arm64,riscv,perf: Remove RCU_NONIDLE() usage
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=WLGHjeKc;
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

The PM notifiers should no longer be ran with RCU disabled (per the
previous patches), as such this hack is no longer required either.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/perf/arm_pmu.c       |   11 +----------
 drivers/perf/riscv_pmu_sbi.c |    8 +-------
 2 files changed, 2 insertions(+), 17 deletions(-)

--- a/drivers/perf/arm_pmu.c
+++ b/drivers/perf/arm_pmu.c
@@ -762,17 +762,8 @@ static void cpu_pm_pmu_setup(struct arm_
 		case CPU_PM_ENTER_FAILED:
 			 /*
 			  * Restore and enable the counter.
-			  * armpmu_start() indirectly calls
-			  *
-			  * perf_event_update_userpage()
-			  *
-			  * that requires RCU read locking to be functional,
-			  * wrap the call within RCU_NONIDLE to make the
-			  * RCU subsystem aware this cpu is not idle from
-			  * an RCU perspective for the armpmu_start() call
-			  * duration.
 			  */
-			RCU_NONIDLE(armpmu_start(event, PERF_EF_RELOAD));
+			armpmu_start(event, PERF_EF_RELOAD);
 			break;
 		default:
 			break;
--- a/drivers/perf/riscv_pmu_sbi.c
+++ b/drivers/perf/riscv_pmu_sbi.c
@@ -747,14 +747,8 @@ static int riscv_pm_pmu_notify(struct no
 		case CPU_PM_ENTER_FAILED:
 			/*
 			 * Restore and enable the counter.
-			 *
-			 * Requires RCU read locking to be functional,
-			 * wrap the call within RCU_NONIDLE to make the
-			 * RCU subsystem aware this cpu is not idle from
-			 * an RCU perspective for the riscv_pmu_start() call
-			 * duration.
 			 */
-			RCU_NONIDLE(riscv_pmu_start(event, PERF_EF_RELOAD));
+			riscv_pmu_start(event, PERF_EF_RELOAD);
 			break;
 		default:
 			break;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101523.312333837%40infradead.org.
