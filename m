Return-Path: <kasan-dev+bncBDBK55H2UQKRB2OMQGPAMGQEUXYOI2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F58C667FE5
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:34 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id i7-20020a05600c354700b003d62131fe46sf12971609wmq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553514; cv=pass;
        d=google.com; s=arc-20160816;
        b=UXHST43f+/V1+DM6lx0NfOsU/0YHT1Cxk++wLNlcUP5soj6/VekSuwggMeAzZRf0uT
         qtqmS3bZ+RqgZLzFuYM6ZWlaUqltV0lvAvy/nuDysKBS17VmOsS5lfjfhBAWXGusVWyC
         6JxRHbUOwa4p6yTFTqB2X/EZWWf5ey5jUIK0TV4RXm2BOntetPQCkKyPsqBbGrU3lu+X
         0DDxYSdL3hWC/hvC4x0taIDMCNTmiqxk1kR3HUGgcl1gh8KvB5YHAIGGARHbYFQpSAh/
         XN9esplrvTrYRPclduC1JYZanZOqMycHa2rXDXvrJDW17e1bnikgqVMtSZb9LZZUhBCt
         o19Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=LWnWyLgilBvf+iLx/PoMZY5BU5J/S1Jbl5V6ys/oSVI=;
        b=QHdMo1mwUdcD3a84f0PtZ3KDYYIdWTS/G1qlpT5501ILS0SPkzgt+F9+0VsdHCLcQP
         QF1hFJ9EpA6nXqey7/d3yonlCk+9R82jjUUYUsD20ehNUJac6T3TT+48vFvHBOhhaHoa
         ey7+R4cA4EmSi2WeCnwDZ4HGAMyrJsHrCtQ3XFbkTH3L5FVVFG4kGKDE6kYgmVoS10vu
         ZY9yhl7IqZfiorQQojJXnGuTMPY4yJ2cYYB9BnATtyqGWlIPUh9DkDgw0tEViPlOgXvd
         bhwLRlL5k+h967jxZhFfJM7X2HcGxbZc3qcCmogxAtHmGUsjlI6t6XqLQsQSEd6av5Aq
         erqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=XY7SfD4J;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LWnWyLgilBvf+iLx/PoMZY5BU5J/S1Jbl5V6ys/oSVI=;
        b=GZGnCZKyyTTxYV9Scb2yHjHuJpn76X36LRNQjvBqwnPYhlt4Uko26ByulbXug4C5K+
         V/zwytqUiDG3Die2ORwZDjjduYxcIWHu5CBEFCr5m1XtniS48pMUzdNhhbvNGHTktRyL
         5bs4RW+AKSNzeeKS8fPl4UiWY4KaXGMruwDH0xGJEw4WJYbIPTUvAwY3WZL7EoiYrm6+
         t2GhnpgwoTZ5zMYi6IC4P9LcD3g8sTlLP+crN96dL0lWqZLYAgfjw6oV1yl4+U0jS/4H
         3Qg3TnzUYmmM/Cee8KUhpA3AM0rFl2B1pxfZcj8MO4Oa4A4Sa01BD79kqnQmBwwVfjSA
         nFJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LWnWyLgilBvf+iLx/PoMZY5BU5J/S1Jbl5V6ys/oSVI=;
        b=cXlM2pUv4GTviywvwkFKK407H2t+p3hWepu+OAeG6CvLd//5dnD1abh2YKO9iQMeyg
         FHIuPpYdPLwNExYDoZ40SzS1xNecEB0WoJdQp+TGt9N62RnYAEUZf8joM7IeyM6xblHE
         nqzBqqg5ox36SruzPHmXa24N9kkwofyQQwpGApCLjP3h98N/mYKmt8XRtdC+qx0hD1Sg
         sd/KGP+9RxDDb1nlwvfB+WNZvfHQmSdFGBVFgyQl09xddfXVTenRCDX4dlp5XZ2VVn3N
         P4EGRWJ5Y4EuIe3mIs4fLEFVZceh2hh4OceT7i/7tmm3OHurHbfptb+dfNPjbaMq959X
         wVwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpS4x9gXS3tOW+GRhKyc9THYQc26HyTsT6hXgQnokCx0ZqSMqRX
	GDN5H620Ay8ieDV23nXfqBo=
X-Google-Smtp-Source: AMrXdXsAqLihQMnSw8TedBAYgSVUClwJiRfsthORY+y2ar1xTHSWLVd84EQcPb/8/pRVvZih1psMXg==
X-Received: by 2002:a05:600c:4688:b0:3da:1c49:d630 with SMTP id p8-20020a05600c468800b003da1c49d630mr174328wmo.190.1673553513743;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4ce:0:b0:3cf:afd2:ab84 with SMTP id g14-20020a7bc4ce000000b003cfafd2ab84ls1268796wmk.2.-pod-control-gmail;
 Thu, 12 Jan 2023 11:58:32 -0800 (PST)
X-Received: by 2002:a05:600c:4f41:b0:3d9:f806:2f89 with SMTP id m1-20020a05600c4f4100b003d9f8062f89mr8895456wmq.41.1673553512672;
        Thu, 12 Jan 2023 11:58:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553512; cv=none;
        d=google.com; s=arc-20160816;
        b=owoQSV6ljWVIbt9my1u0tKQ9RNbHe4+hA2d4Wp7QX3hlKeGchb1N6Kc32V5ZT+5Uy+
         evItukk6802juhSskjSIj5TLWeSyjNtmjjDjwEh7MNIXieRM1GlT1rY9cqEqHvJUJRMV
         YHaOjESWzvVOm8zx5eu4z9YbIQ7GgURXlNEYtMQMZmtySrvFFefGXF/n9u/s3wq4JOvt
         XuON7nHMvZyDP/ynsU1PKUX+xTgOGQR9r2+po0ErzSswC276FNSrTrwTLvxwJMQAYF4C
         ZNaRJjoN4TuunGfm5TjBF+150mBpZLkIlL8kNIwecEPtvFL4z/ZLzDIe0iQ5yEPNZd2Y
         d+RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=zetob5Egrh+4xSqY+h3U8eHRaaU6Xv/VYHG/8LvUn9U=;
        b=jgb2BW+b++tan4QRMGXQ9TyCKP7sNK9ng4kDKlViJc/DyPYoGugITcP7P0F7M+GnC5
         M/QM+qRS0QT2SNFfg6d9K9jgT1bf63hqjAXhTDXhCeabBtwJKl6fsaMkdXFjhZOb6RWR
         joPY4GAlG7mf2j65GoLIf8p4EeD7xe81Wa7SdvXxiD7AIQ7o/hkbXuPX0ud71k1rZxnz
         LuhmL9Tqdmu3F7S91GVLb7npWZqTYGowUCUqmZpVykXDRxQjeL/nJTFuGORPhQvmQsQQ
         ZLpiqN3sDqudYhHzC/gLh3FkYBKamr9XSWMNNNkZU/q+4SknOHYLp9qWlq96fT25Fyin
         dGDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=XY7SfD4J;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ay38-20020a05600c1e2600b003c9a5e8adc5si1075722wmb.1.2023.01.12.11.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:32 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hW-005OcF-NU; Thu, 12 Jan 2023 19:57:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9405F302D4A;
	Thu, 12 Jan 2023 20:57:11 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 956222CCF1F48; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.515253662@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:17 +0100
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
Subject: [PATCH v3 03/51] cpuidle/poll: Ensure IRQ state is invariant
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=XY7SfD4J;
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

cpuidle_state::enter() methods should be IRQ invariant.

Additionally make sure to use raw_local_irq_*() methods since this
cpuidle callback will be called with RCU already disabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/poll_state.c |    4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

--- a/drivers/cpuidle/poll_state.c
+++ b/drivers/cpuidle/poll_state.c
@@ -17,7 +17,7 @@ static int __cpuidle poll_idle(struct cp
 
 	dev->poll_time_limit = false;
 
-	local_irq_enable();
+	raw_local_irq_enable();
 	if (!current_set_polling_and_test()) {
 		unsigned int loop_count = 0;
 		u64 limit;
@@ -36,6 +36,8 @@ static int __cpuidle poll_idle(struct cp
 			}
 		}
 	}
+	raw_local_irq_disable();
+
 	current_clr_polling();
 
 	return index;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.515253662%40infradead.org.
