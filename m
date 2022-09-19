Return-Path: <kasan-dev+bncBDBK55H2UQKRBMUDUGMQMGQEQDKTV3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19A5F5BC65C
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:23 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id f18-20020a19dc52000000b0049f6087124fsf2474460lfj.15
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582642; cv=pass;
        d=google.com; s=arc-20160816;
        b=VoSt9QyaiH0PQgvvOuWnb7+omgRUNBXm5tVV77rVmwkUDzZmGslBPeJRWAxehlV14R
         L6Zi+ItUIa8HiybHYmRmEFi1EgKCcuEnXNM/Ir+KBnYErUgfWWtNAA/BMSGJ38/E42tk
         ohJK7nh89Rbr4Q/D1eAzfyhm/4QdASD+w5qlb7hgO7KiMVx5ahwsnclO47iNJCMKzaxH
         yoNeu6tbEpE32mqRFAQwB59GJOzAXcFs2UPM8a2X4se/aTrBXYo/DSyDVY/uljn1HD4u
         5uSCoVk9594GVS6cvHzAVqhnDD0Voo8FJKwWlVKXVh7CQc9WLpijKc1LNh5RJidS1hae
         ZuTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=XhqjTytx3ieIEyTpWMkt3XN+Rc3VBz4Sj7JInBmLfFE=;
        b=hpiU2c+XzSqf04O4StBwriK+wUoppEBvd4EAkALMViR9L/9d93DVc+LPAqjk/HxNcu
         TU9EeoO5e4P/6duwQt3oAWrtdHFO7nBw1/KBNxGysICA5kWxOS0okKAj95XMQCY/SuvY
         AVRx3c2xot2kK+iBXPNd4LtWIa1d1ZjTwG060HxiXszQAKyDVt4DsH+gZun5c6w5ZCmM
         O1zm29L4HBB4duWlQo4Du4po4i0kSl6tItWvLQYqtLnAEnZ+UiKK48D6M4T3HQMMhjyp
         Dtjj9Iq5uVzk87FTLkTCbcVmu3cNqgFuE9K+CA016Eaat50y7wsrYConhbR3I5pjqXp/
         Sbcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=SFQYA3jA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=XhqjTytx3ieIEyTpWMkt3XN+Rc3VBz4Sj7JInBmLfFE=;
        b=b4cTZZsfvwU5pKQewLqir19GrNAnNh0UPUrPFOuIwh3M6blKU/G0If574DT/0Bg9kf
         5q4Imtijkx0m53ueV0JkPZ86G/Vtq+wIK/E+62VF4Willhr2P/kgtR1SrBvuFEIV+UME
         7mOy7X028JkwBXHP5tfdodQ+HU1Yn1hgzN8zkENhFwUX8YBvWreAc2+m7RkL8D2ZnciL
         UdE2qgsA1J9vMwJ9SKAvyIUzboozMAZVp2Mh+vV5FmG9cIfdfYzv0wrySmxlor7SiqAp
         oUzvt6NfVh90+Zbpc2E6+XwZ5Vt2W9Qbj/TBFHynM6wexwaDdF1YYEHLY1fApsWpBmvF
         Fv7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XhqjTytx3ieIEyTpWMkt3XN+Rc3VBz4Sj7JInBmLfFE=;
        b=dQO/U69YPepvaiXcRvky9eRdYO3mlpzy65mKDmOTrYkupmlRI5zS23cNmVZ1oEX5TJ
         5ur52EXWo2alFVxiPVB5+7ZqwRfsGieSGrTDSUtqUG8kZcukCDu+ARrkY9ffWCsUK0pe
         t8/nI5Ce30lcwmFWjamXov7LcK4vIulVRYWwbJKoTnP2KzlzD+JB1kqJQA0qPO0E3mWR
         YUV1syD+TdC5utToguA6l/Vilh49+OVGX2/DcjUdS7/GUv3nQZ48zaLzv8uSBxhBWyaW
         UzddN6CGJOIwH5Y86foTjpEMVhJ1RaO+pce18gCyecJAios0aNanfu7QFgiCIPKBsuUP
         E9fg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0e+lZ0s7b+INf+noDpC8+wA9BlowgP90yKiA103upNdSyGrYpR
	rbb2ZlPUfapi4gqsZYOMuIM=
X-Google-Smtp-Source: AMsMyM6DyT9Z0j/tDhUOBj476E7RkuICu6BjUT0z4AM4S8stXNBWojBheD/2tjvk4p/6XdE2mgB2aQ==
X-Received: by 2002:ac2:5cd7:0:b0:49f:ae59:3b87 with SMTP id f23-20020ac25cd7000000b0049fae593b87mr1452730lfq.291.1663582642296;
        Mon, 19 Sep 2022 03:17:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b051:0:b0:26a:d290:d306 with SMTP id d17-20020a2eb051000000b0026ad290d306ls580269ljl.9.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:21 -0700 (PDT)
X-Received: by 2002:a2e:780b:0:b0:26c:1458:ddc3 with SMTP id t11-20020a2e780b000000b0026c1458ddc3mr5290887ljc.375.1663582640934;
        Mon, 19 Sep 2022 03:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582640; cv=none;
        d=google.com; s=arc-20160816;
        b=YnLWltvzhRQH2Ra8qz7GxW66sidDkEfPhA6t7cpHg1ws+DNlGTA/rL377aFWoQRAuv
         N51x+iyGU/rzRkyQByAImqVo0OpJmRCNcGCskaZ+ye6J/TO+y0fKneJB6afAYbLK43eh
         4OTroKfdVv+o1rBGlq2s2skk/LT/oaUN90JDp9T+v7tWcKVBxG9sP4WhOQ0PAdSp6Lx+
         38K96gTRQwmpwZsj1Z07uGqKSDpnSiPTmNHnOUo50fvIgf7sun3jx+/lZdYzz0An1dn1
         dLTObTdYcD5CEumacaWU7r+z5viNon5mogciD7pJSbbSUM0+ASi74h3oNk1JqOUBBa5J
         nThg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=74awPgmRWnz6TtiKDYLgK7Deo1BdG7DroGRjfVtm8U0=;
        b=ArjpjERYI7FIE89dnt5wxQMe47zftImAJkquayJ3LXrbmqk2066s9vsnKvNBqcR+t7
         tDarFXl3dCUXgDy0gCibggkiPlXdyrNRP9qYc5Tmxcu/2V3mXz29e1NO/7nkdxoEq1wI
         WETAfLA9kWP9um6sEOLTyW1+n55qd5qP8ECmQMZxSq2kAXsyENasSuMBOnNGHGAHQpzL
         mkyY630ikKaSD3+WxS76IT0HZ8Jo1jR8p4VWeGsAENyuGBzTnblP08GDjr3+s9UctaIG
         ZCuVzDouMdWHKTTp/rIOddXv5xWZMx1/ZeYxYHLxdLNy/8olNxSnZcm6kQ0tZvVITLgE
         /2gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=SFQYA3jA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id g6-20020a056512118600b0048b12871da5si864015lfr.4.2022.09.19.03.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ai4-Jv; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8EB1B301BE1;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id CE9192BA49038; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.534233547@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:42 +0200
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
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v2 03/44] cpuidle/poll: Ensure IRQ state is invariant
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=SFQYA3jA;
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

cpuidle_state::enter() methods should be IRQ invariant

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.534233547%40infradead.org.
