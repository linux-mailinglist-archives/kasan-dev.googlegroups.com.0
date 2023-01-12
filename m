Return-Path: <kasan-dev+bncBDBK55H2UQKRB26MQGPAMGQEXK2OTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B451667FF4
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:36 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id t18-20020a2e7812000000b00289e0c04d86sf865972ljc.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=q5H32Evpa19fi/HPfSaTUkVgcz//fAhuOmMVNMwPaqu98U11KcNzR9zuE+WoQ5iJoa
         9R3v8dVkkh35k7PP/zoKYkITW73SEJULn02YgYN3/6pL+sC2mEx5M8/2XfQN9jHWZVgE
         iDskVQfFo7HEemb71JUqCFOQpJlIdZaNqj6qvTTtJUKXNVFT8Q2d2N3CbnxmYjVdYOIE
         U6227e7iWR3jlC2gDCzvQy2UeglVdsWoAOPyWPTgqRLzN2lrJqhV0HLs9xnHG3TSx7gv
         i7hKquYlcHLt7EP4mPYCRNQiLGOzV6tPDTl+CKqYlt8hw9MhdawcqbBYdMFlfVy3ZnUs
         4zgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=7KiI5I5rd0R9J3NpBber7tT7UjkP/an36r6FTLIipWA=;
        b=ZAkjeQYjKAuo0FUdIhgFbES1ZXvZYk0d4CVNUSF9i8FxF4i/6kPQwWGqnyd5TGFiy+
         BF0R90JfaiUs8/2GfIBIu3CdDh8fe7e6zIKjGQPLR4aU+3o4MwsPRrCmHamT0I0DBlm7
         KQYm1Eq4Dw3TpGT71nlE69skDvufDNWnoWzUqbTwZZrbNKUcZ0FNxQMW2G79NypDwhaS
         tnO9/5sGT3GxkSv3RqIjDkjVG0rYd9RIyPXWQtGmGfjEz4Mr8I/JRXydIXNKRqoyQKhO
         lx96xXmteZv9kc31m7VoVCnXvsSc0OzXYZnh5BEtrRXbGIwbRiN3Ie9xeYyBACuUALGF
         xw1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=sAS+cVfJ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7KiI5I5rd0R9J3NpBber7tT7UjkP/an36r6FTLIipWA=;
        b=Ak/lWoePL28zQUNSJyN4nqMH2P8PKHa9XWPZhzcSO+mhZHib5eTpQaZoBdJNfhUSo0
         JasZS0trsYhzZHVKG8YfLfVNrDUjo0Th5fgAeG3DjQb6h+ISFu+X1yyJphfSm6y8swCw
         tdWOzH2fc8O87AL1Cz6DqRVlKm6LgHEtZqCqLgkkwbYn82qkIt3fTOWZ4+yNMYcgmMjW
         XBWiA1Mi+CmNOJMf9BXkg5dmOpvizQm2vfxjR0gCcKWiT0X5MJ+ZE35n4+MYuKzNtSm+
         utHNYOe+3P7Gfv+ZSwt9v7cqTdS6namo4KEcQx01YE04H5E4ZlgWbKuQgmP5IQZwqe9b
         kNaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7KiI5I5rd0R9J3NpBber7tT7UjkP/an36r6FTLIipWA=;
        b=xQFhMdbAfyxfT93vTMQDFmYSfIdELREuyr5tZUNYtzdBbkPzMi0ych8fQwfGWaXqRS
         A7/497ayV2X+9Fu4q8ewMZuJa5ljGeGlIXm0JRx4d4MqQXGT/87o5RgVlQqE2oz6jX9o
         jKIQD+unw6MLTkDXNLg4jNxX/NbrRjVIsAh1pAgLhEVDINJfoP5McizxeHCOb5U1jPgh
         G6SEP/O6hTqBCflaqHSaOlARcAQI0/NV+VhWZBlFjpW9MZBIYdD6RpHW6tCDYdPxxHiB
         mfY58yHQB9B/xSywZ/4Qfmqz49ICBqDXiE3QFVqLXgQuq3ae0PXnv7q7DFiWfOp6rzIX
         rGEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqxppR7xw7dhfHeD6BXDQGC5dxYn6KBgYDu1vhTY8ehx8FyPlqe
	RuUXzIiN2t67fAbBOzk8xE0=
X-Google-Smtp-Source: AMrXdXtGXNR2/JxELEmsSfQw2TTKmjjHY/snCuQgXa/cjjztTaRLzqFsDXqlfOmvXcLT6cux3kqRQA==
X-Received: by 2002:a2e:8750:0:b0:28b:63dc:4c7 with SMTP id q16-20020a2e8750000000b0028b63dc04c7mr25950ljj.423.1673553515522;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1937442lfr.3.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:34 -0800 (PST)
X-Received: by 2002:a05:6512:2a98:b0:4b5:23c4:ab1a with SMTP id dt24-20020a0565122a9800b004b523c4ab1amr21921793lfb.42.1673553514177;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553514; cv=none;
        d=google.com; s=arc-20160816;
        b=GTFwcepmyu6qhVbaUQ7dthu98HOLP4gWEvsZ7cLFe+1EH+RBfoEnbvU7x+DXpYQEia
         pow5DS9ARPXoDglMTtpBLlnkjGxi3ffxHPxdhr+85HiBcW6r5ElFu2o0OSJcsfNTdomQ
         ktnrMg+CZ84wxsx4AyvUh/dX44rOv4rEIND7pKrYpZmlLmvSYwFNNkcOKFUwSChCWgNX
         tVXo1fkUwNhiMrSjpNLXUsjkHrcasFR724p6S2jSUihhjMJEcDvH7ETA5kjTQWDvSOk0
         r+cQv4nrfwb1gjF1h0iJ6+L14rEdFOJNdLSjAv1jK6u00+FbUqvQrrpyIX3jUULuGivX
         wcFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=grsvYP38q4MnN8oBsFSgy8h24Veck5RfPmpq2ugRYPM=;
        b=U3GYkWvnoxGBlQu+u1uPs9P1m3HyBUB8Sm4xY+S5RoxfYnh9PFEerdmxblzSuPFeyq
         +IuEE0EOSUQqihY+Qx0jdYoXfixwI4SDIUniQf/8jV1ww/6g/+mdFim3dqCr+vcyQc4J
         d44YSn2YbHzQTHXr4qyhDq45sQbj/TKXxZ2SGQ5ghFsW6hbd2hkJBKHHWX7yq8tPsIm4
         AVWclna102r6mfxdX7ICVTC3H14djAWHJNr1i2MTumn9Po8I6BBWDYobDUb2DFc7/Gyn
         2dBSGykWMU01AHbZHKKCA6OR6YhYXGJrznBfdp5/wG+9jEYV/CbiWrYUI/pQkUlQPqhd
         TCiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=sAS+cVfJ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id j11-20020a056512344b00b004b49cc7bf6asi863039lfr.9.2023.01.12.11.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3ht-005P5s-4V; Thu, 12 Jan 2023 19:57:49 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2F65230347A;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 6E8FA2CD066EC; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.212914195@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:44:01 +0100
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
Subject: [PATCH v3 47/51] cpuidle: Ensure ct_cpuidle_enter() is always called from noinstr/__cpuidle
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=sAS+cVfJ;
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

Tracing (kprobes included) and other compiler instrumentation relies
on a normal kernel runtime. Therefore all functions that disable RCU
should be noinstr, as should all functions that are called while RCU
is disabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/cpuidle/cpuidle.c |   37 ++++++++++++++++++++++++++++---------
 1 file changed, 28 insertions(+), 9 deletions(-)

--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -137,11 +137,13 @@ int cpuidle_find_deepest_state(struct cp
 }
 
 #ifdef CONFIG_SUSPEND
-static void enter_s2idle_proper(struct cpuidle_driver *drv,
-				struct cpuidle_device *dev, int index)
+static noinstr void enter_s2idle_proper(struct cpuidle_driver *drv,
+					 struct cpuidle_device *dev, int index)
 {
-	ktime_t time_start, time_end;
 	struct cpuidle_state *target_state = &drv->states[index];
+	ktime_t time_start, time_end;
+
+	instrumentation_begin();
 
 	time_start = ns_to_ktime(local_clock());
 
@@ -152,13 +154,18 @@ static void enter_s2idle_proper(struct c
 	 * suspended is generally unsafe.
 	 */
 	stop_critical_timings();
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
 		ct_cpuidle_enter();
+		/* Annotate away the indirect call */
+		instrumentation_begin();
+	}
 	target_state->enter_s2idle(dev, drv, index);
 	if (WARN_ON_ONCE(!irqs_disabled()))
 		raw_local_irq_disable();
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
+		instrumentation_end();
 		ct_cpuidle_exit();
+	}
 	tick_unfreeze();
 	start_critical_timings();
 
@@ -166,6 +173,7 @@ static void enter_s2idle_proper(struct c
 
 	dev->states_usage[index].s2idle_time += ktime_us_delta(time_end, time_start);
 	dev->states_usage[index].s2idle_usage++;
+	instrumentation_end();
 }
 
 /**
@@ -200,8 +208,9 @@ int cpuidle_enter_s2idle(struct cpuidle_
  * @drv: cpuidle driver for this cpu
  * @index: index into the states table in @drv of the state to enter
  */
-int cpuidle_enter_state(struct cpuidle_device *dev, struct cpuidle_driver *drv,
-			int index)
+noinstr int cpuidle_enter_state(struct cpuidle_device *dev,
+				 struct cpuidle_driver *drv,
+				 int index)
 {
 	int entered_state;
 
@@ -209,6 +218,8 @@ int cpuidle_enter_state(struct cpuidle_d
 	bool broadcast = !!(target_state->flags & CPUIDLE_FLAG_TIMER_STOP);
 	ktime_t time_start, time_end;
 
+	instrumentation_begin();
+
 	/*
 	 * Tell the time framework to switch to a broadcast timer because our
 	 * local timer will be shut down.  If a local timer is used from another
@@ -235,15 +246,21 @@ int cpuidle_enter_state(struct cpuidle_d
 	time_start = ns_to_ktime(local_clock());
 
 	stop_critical_timings();
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
 		ct_cpuidle_enter();
+		/* Annotate away the indirect call */
+		instrumentation_begin();
+	}
 
 	entered_state = target_state->enter(dev, drv, index);
+
 	if (WARN_ONCE(!irqs_disabled(), "%ps leaked IRQ state", target_state->enter))
 		raw_local_irq_disable();
 
-	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
+	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE)) {
+		instrumentation_end();
 		ct_cpuidle_exit();
+	}
 	start_critical_timings();
 
 	sched_clock_idle_wakeup_event();
@@ -306,6 +323,8 @@ int cpuidle_enter_state(struct cpuidle_d
 		dev->states_usage[index].rejected++;
 	}
 
+	instrumentation_end();
+
 	return entered_state;
 }
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.212914195%40infradead.org.
