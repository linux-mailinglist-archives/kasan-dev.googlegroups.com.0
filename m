Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id AED72667FF1
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id r20-20020a2e8e34000000b002838fc9f1fesf4228136ljk.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=VaA0T132ZlzEpJrGlh8oB9s58kzmIxJDnecXhIWXJFaGlg/0WjLjoRZPo0NLPImhZ8
         Vc8GPeXmC3kjJijHtkGOFm7r+yYm6PajDaOCUaw27eoZPA94DJbpk2Ht3mpDNf5/l2qh
         Jvx9KFZaSbzvNT2HsPjhFOGr7SYn770EpABuAGgJiCf2uHp+priM7jPCoDr18ekiH5L/
         J+ZnVWNCXpcJjmkCmrw14G8usQsibW6wUMxaQYun4qJPPiIM6IqvVtNKo8sRvCTFQAYF
         MfMMhhMjAtgZRE0n6c+uAfcDSlQTm8dNELteBdu9mBlo78D3Bjf/D4K8XtvKiG60VTAB
         r9iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=gSVar04hcjeD9wxFYLD3dwD5X4E0SrOpIW+OjbIEC1A=;
        b=Xx4VPeOVC/Zs9TXcyhom3fUGQjIfOTGr4Kn7SFEbrMwk+o8MfiVCSQacztgkkbknGF
         JW6qH2dr4XOjiudkfoWvZYjw4nkh27A+zx6DGf2j/wLbKMjb4SUeLbD4h0O+Y+tCMda3
         niDKfyMOcgyr4/Db+5K6UMV3CKCwGuXKJf/PGIc7teZyc+woLjeLK+fiGohz7F6XYGId
         0CcedbjPp5NwPJNipWvwo6CyuB5ujDgwH7RYc3EdKbsFgDH1aruFGnAGwT5zeEYr8Y07
         2BXRa1FMhmSxn6zYyJwfCLW+Ctw6jDRW0mYr4jxp7k3JxX8VFszsNk16NVQKAxxoSiNM
         ynDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=XXUxTtqv;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gSVar04hcjeD9wxFYLD3dwD5X4E0SrOpIW+OjbIEC1A=;
        b=hCILs0Rpr4wgvUgORKjJ1e+N1sTDpozh816T1HUSmiL5itOWOKGz/pbXF4btw0KQrw
         srFgpMNGRE9xwdB9GCJNYIQ7S8AdZdixe+TE6OhVE0kYU4Qydr0dVZJOE+diGCN2e5iw
         gO0+cTmuxEpWSXVUiRE6UAyPzywvxqS38z/5w4KQJaFlgRwbwfNlASIF529fhoVzzhcm
         0W2CDbik8VuAaoeUoczwHIYcEcprOOrlu/F/0iLvag+EkvI1zxSnnpyAqH9qNGHZeONr
         ADLvUKtw6PcwSfc3ExhB9KcCfbOwNGPErAyOn98/HhKIuOVtRivWR/SmmSSPcklUQ0G+
         m6jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gSVar04hcjeD9wxFYLD3dwD5X4E0SrOpIW+OjbIEC1A=;
        b=DMCf8uyjNepFT4RZ6KE/1IaJmylECcgRgurpz0RFH7RosPRISKwrfU9oxTpPaQ+6fr
         7HLbMPnnoBMB22Zdzi9h5ah5fg+rtGWRY80s3xIOkqAZF+q6ZO1NIECVKl6rKg9h7dEX
         VqyYdRQ+ZATwGTnqqmtdlZyvFmnQB2m0dXzznAqrBnROAycm/RJNwohDDaapkmXzsY91
         bpjme8Bnrkw/6bK8ykZmn625gG6X+NAeu386oRuAB+WBikL6cf9e0Zra0AHI/I/8WJPM
         w0Xj7doAeRc2OzhPd16FsoUB+s0B2BgkkKnDJkDFdB9BT8Ktp+3wbgDvo+WDXFeZrQ8e
         1szw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koqBizMFbd3JOhAq2i1ZYy5WJVqGw9DF4bsw1WKu8ailwmvF06Y
	UcvJdIm0neots1LuwsvNbq8=
X-Google-Smtp-Source: AMrXdXsXAB2DXtiDmqn74/NP9za66ujkNftRnSvvkrG56jbJ+Pk202PrYPli7gnHaV1lfol/PcCYKQ==
X-Received: by 2002:ac2:4c91:0:b0:4cb:3183:2f08 with SMTP id d17-20020ac24c91000000b004cb31832f08mr2343181lfl.129.1673553514912;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls1755062lfr.2.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:a05:6512:3d93:b0:4b5:a207:8d70 with SMTP id k19-20020a0565123d9300b004b5a2078d70mr25444073lfv.5.1673553513474;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=McaT6dN5y5NfbQpQ5vFZsR//XmKEJJMWPw5R7bgTxniPKkOPlOVns8Qvbf3QRwBels
         CwjgOlMM8EFnrd98LQJbAbg7/mRe8NuW2+BdHRxk82kT1JPzC6u663dx/xP76tJ+NJv8
         5C53MqswSUEqTsriXZNTxk+8EYXXHrQoMFB0NJBZUOW3dG1N6vTmU3u9OvP8fr4xYevu
         0Kr6JLjCXvxL5p3pBknRXsudCnMk8/k9lAfdIlLpYEAElgFD21qMCMGXT0izFDmNkq0g
         2PPkNxCeQX1DuwZyyry5PuG/x2awSSt7+5zHBHmKhxdq4t2fDrEaTnvu12P+HJ5JfW3W
         +BRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=g+drg6uUsP6YHX5z1pA/AishyJbSIL0Ic60jCQj0FKI=;
        b=GF57a9/fU35+ekoth4tU4s6qPWKUZTVpZzdVAmClBNNRtwZ69HuIkSzI26uqrR/lvB
         toK0gYQ4skql8f0/dH2hckdUWzdzKFGOZRa0AnlxU3OPUur1iDAj5ZbKdc8CJfzPRq34
         73T6tICNtyPqzSlc2lFbJToXBCyqzQqGnytIRz7z5FrFdTC9+XrEf2WQFWF0j1XGyZ5W
         84606GdUsJD2TZQscL5yQz7DSQWKtmyBnh0SrYJbmYfj6uMeL7AnBJuR+VnCWOcy75Ad
         fajPZm7JhXQYKhICxMcTWwcXs5SNLC83utZRmsD0WtqrEg42eGMuEMsKdn5kMhf4LSYq
         LsNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=XXUxTtqv;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s5-20020a056512314500b004b59c9b7fbdsi795310lfi.7.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hu-005P82-Un; Thu, 12 Jan 2023 19:57:51 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 51DE8303485;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 810012CD066F0; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.458034262@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:44:05 +0100
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
 kasan-dev@googlegroups.com
Subject: [PATCH v3 51/51] context_tracking: Fix noinstr vs KASAN
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=XXUxTtqv;
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

vmlinux.o: warning: objtool: __ct_user_enter+0x72: call to __kasan_check_write() leaves .noinstr.text section
vmlinux.o: warning: objtool: __ct_user_exit+0x47: call to __kasan_check_write() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 kernel/context_tracking.c |   12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

--- a/kernel/context_tracking.c
+++ b/kernel/context_tracking.c
@@ -510,7 +510,7 @@ void noinstr __ct_user_enter(enum ctx_st
 			 * In this we case we don't care about any concurrency/ordering.
 			 */
 			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE))
-				atomic_set(&ct->state, state);
+				arch_atomic_set(&ct->state, state);
 		} else {
 			/*
 			 * Even if context tracking is disabled on this CPU, because it's outside
@@ -527,7 +527,7 @@ void noinstr __ct_user_enter(enum ctx_st
 			 */
 			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE)) {
 				/* Tracking for vtime only, no concurrent RCU EQS accounting */
-				atomic_set(&ct->state, state);
+				arch_atomic_set(&ct->state, state);
 			} else {
 				/*
 				 * Tracking for vtime and RCU EQS. Make sure we don't race
@@ -535,7 +535,7 @@ void noinstr __ct_user_enter(enum ctx_st
 				 * RCU only requires RCU_DYNTICKS_IDX increments to be fully
 				 * ordered.
 				 */
-				atomic_add(state, &ct->state);
+				arch_atomic_add(state, &ct->state);
 			}
 		}
 	}
@@ -630,12 +630,12 @@ void noinstr __ct_user_exit(enum ctx_sta
 			 * In this we case we don't care about any concurrency/ordering.
 			 */
 			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE))
-				atomic_set(&ct->state, CONTEXT_KERNEL);
+				arch_atomic_set(&ct->state, CONTEXT_KERNEL);
 
 		} else {
 			if (!IS_ENABLED(CONFIG_CONTEXT_TRACKING_IDLE)) {
 				/* Tracking for vtime only, no concurrent RCU EQS accounting */
-				atomic_set(&ct->state, CONTEXT_KERNEL);
+				arch_atomic_set(&ct->state, CONTEXT_KERNEL);
 			} else {
 				/*
 				 * Tracking for vtime and RCU EQS. Make sure we don't race
@@ -643,7 +643,7 @@ void noinstr __ct_user_exit(enum ctx_sta
 				 * RCU only requires RCU_DYNTICKS_IDX increments to be fully
 				 * ordered.
 				 */
-				atomic_sub(state, &ct->state);
+				arch_atomic_sub(state, &ct->state);
 			}
 		}
 	}


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.458034262%40infradead.org.
