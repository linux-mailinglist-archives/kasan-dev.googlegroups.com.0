Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E295E5BC6D0
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:08 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id g15-20020adfbc8f000000b0022a4510a491sf6177298wrh.12
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582688; cv=pass;
        d=google.com; s=arc-20160816;
        b=sIJL/pzH1pxD4iqZF7WaWW+kCSP3vNTfzQ/+gP4bpZQd1nwaDokPelqmJCwZP4kyb6
         k2ylKNnuEdNV4gacfhDkwB3t8EBve3JP71eblq3SwgyHgandA9H0yWwdu+q+PVHNxmaj
         iduFbkAe2KRaQHKJkg8PcZuTaD3jNBM9PRq86muNPbmMPtsuzqPI+jvegY2TuzXk8kIu
         TkYFpIyxLdIAx20zdJtSjJ1BAFNiBim6i1I5f5/ANxqkteUq633WBvenbwmLkhYgShjq
         ahqOat1jKyDtFe+hItCktZWlyWuAg/1MRvtuEuTyN76p/qNCvyMxaIvTdkkiX0rIgXTH
         Hsxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=owJiQf9R3kEj9+vaFPRgJZ2/DNnGWkVlOnj0etQWaF0=;
        b=GSSeUwGafDISWpSUGHHZGuX8vzjW8IgqFoi2+eS5OVR2r73tq14OJLK35D52WCI8Vx
         AepnftGGWJ32yec8siGiwPfphvEq6GhIPXLOajLwVlr8KYhrwRZ2js8G4P4pGVMicUz7
         xcoT1mff/8TDiZwt0s37EPbG/RV2BzDt9ij9Tlkbzja9AH9ZfZF3NXiKnSa85xKfoOKx
         fnYcl47u7G6Gae7RKt/4YWHsQ+br1U2OWZYybOO8ouhTJBtxVzZyBcVDURhk0zvbSK3+
         GPSwsjTLuJHdRqbJ95/OCZDUXED/Wufo8KNX/0rhtSiiv2/MTQxDLTdxEsXPw/JDElyc
         1r9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=VcyWGd4y;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=owJiQf9R3kEj9+vaFPRgJZ2/DNnGWkVlOnj0etQWaF0=;
        b=Ji1+KVIqm5r41Ug00uBx73WrM/oTQ5r1/9xllm2OFHFV8xZRbQ512XlgAJ87JqjkBi
         UyIEoEqwzQaIGSJtnbwuH7nsGzf3mZmNhOc4Gcb+tA/MZEerLg0gxZuojnr9PEqpWAjx
         Vc4KpjZpZ2W7y82EONMB4TYbPMHbc1fiA6gShQh3juiEGq7qFV8LuOfcDIIb+Ud/MUVW
         LQQyaMusYNuaxVij6sXE+FFwtnX90ZPP6MRCvHD652SoZrB4CHs9Pr8TWDPuWWmQFGXa
         Z670OmScfpQZuE+qp7jq6l88IOkTGNizIVQNuUfb9Z85zrBBwiuJhMD1UGxydRTiRFXQ
         g63A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=owJiQf9R3kEj9+vaFPRgJZ2/DNnGWkVlOnj0etQWaF0=;
        b=ukLJGgv/0CwT7N+pWspdMaluoRIb7qURsGlrQf5V2tdFH3vceYEjjlBJ56N+Sp9eaE
         nJOgqqsk1E+sMzlp+0qTV5ewRY/sb5KK1gl19Ho4CeGs+Rdfu1eS6RyssZK0xLlHOBXT
         BsuE+jvmpMv2jIchvGymGe2NUAcLwSIfX65Swcy1113IFGyf62IilawDAM+gS1no3q6u
         ZOK1pWlf2bBwArHvxR856mGhjgEqA17uRbN0uagudH4VEJUxt5ReYABFP/4KeB5qM+Qm
         jbiLlZ7yr3rKuBu6PJrafFczyfFPWf3DQjpX0Q44e4bmXuNSdk1m3Somfv+d2s7qytBf
         hfLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0/P/m+DLKI/jlAqCiT2TbzQyEudEWoxTXF54pyqnIDUqHVxbnC
	frNMd807xSCM33K7uuTAwy0=
X-Google-Smtp-Source: AMsMyM4WBEm7iOOmclXk5CEwZVy62nYOJxFLmaNRd7h9VK8+6XH0XL/nfPO1UH9sERmDut1sTtFrYg==
X-Received: by 2002:a05:6000:1363:b0:228:d605:f9dc with SMTP id q3-20020a056000136300b00228d605f9dcmr9581834wrz.109.1663582688477;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f615:0:b0:3a6:6268:8eae with SMTP id w21-20020a1cf615000000b003a662688eaels1744343wmc.0.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a1c:f009:0:b0:3b4:9398:49c9 with SMTP id a9-20020a1cf009000000b003b4939849c9mr18786849wmb.174.1663582687422;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=GVDjhDJYNvEKvZgEKqcb0+qjMzo53URzDJn9qGzNnLeVuV4DJdyAQ6VNW5aZv54lt5
         hMbJxc0muO5IWeY13N8qBW0x4geb0K4WJzZNl33Q25ZAmbOziD9+e4s23dvPqYr+AOw5
         1WOKMm+/cLrw85xbkKCfIYXF262tCQPx689nDV8eKvDrT93kMSqcgu6JAy1PJ9kEVG0X
         4nxxoyFPQjbiEjdviwk1h/bUfJYFfg0maIuDCuy/A5tFv5/zdLx3e3fh3ZP+FbVU2Fo7
         GvnokIaK8qH8MSjngqXUxgSgRhrWIBe6CQsuw0RLv4imo23No2JRrTkD4sKKtWL2Sg1Z
         wywQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=oZwbrkDz2YxQ2tCMIP+SsyU178fWwXoNNNkzTKP67NE=;
        b=fGdeUaiEM667mGFQhym4rVym5KxcHq+sxAtiilf75eyziZ7VzJLvnc8LLxWrn4zd1H
         jxCjrRZKR+Q2mmRrV7TF9sjb6OH9VQBJXS4N7eBmiMKo1p1UMDQt2jRB7CcrRylTxY3d
         ZKoTTr/WP5Ip+aThvS8bc+DlcYHB1jTyB6X2GEL6ljC+t2Q8pY7H869TflGmptAGH6UG
         eX55Wuim1OfThbt9iNCb+xA2HQBE9GWdwc6tbeb5r+vfNJVJrnnRiOHaP6eYb11CtcoW
         I1rpUGX9Q1tVxbz20ablRkGcQ1Nvl+VGUFhniZqVYeura6RuW5JexTRvbEY6VIHgBzy2
         FPrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=VcyWGd4y;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id l21-20020a1ced15000000b003a5582cf0f0si236239wmh.0.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpE-00E28w-4h; Mon, 19 Sep 2022 10:17:19 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9F17F302D4F;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id D7B952BA4903A; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.669962810@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:44 +0200
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
Subject: [PATCH v2 05/44] cpuidle,riscv: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=VcyWGd4y;
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

Doing RCU-idle outside the driver, only to then temporarily enable it
again, at least twice, before going idle is daft.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/cpuidle/cpuidle-riscv-sbi.c |    9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

--- a/drivers/cpuidle/cpuidle-riscv-sbi.c
+++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
@@ -116,12 +116,12 @@ static int __sbi_enter_domain_idle_state
 		return -1;
 
 	/* Do runtime PM to manage a hierarchical CPU toplogy. */
-	ct_irq_enter_irqson();
 	if (s2idle)
 		dev_pm_genpd_suspend(pd_dev);
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
-	ct_irq_exit_irqson();
+
+	ct_idle_enter();
 
 	if (sbi_is_domain_state_available())
 		state = sbi_get_domain_state();
@@ -130,12 +130,12 @@ static int __sbi_enter_domain_idle_state
 
 	ret = sbi_suspend(state) ? -1 : idx;
 
-	ct_irq_enter_irqson();
+	ct_idle_exit();
+
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
 	else
 		pm_runtime_get_sync(pd_dev);
-	ct_irq_exit_irqson();
 
 	cpu_pm_exit();
 
@@ -246,6 +246,7 @@ static int sbi_dt_cpu_init_topology(stru
 	 * of a shared state for the domain, assumes the domain states are all
 	 * deeper states.
 	 */
+	drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
 	drv->states[state_count - 1].enter = sbi_enter_domain_idle_state;
 	drv->states[state_count - 1].enter_s2idle =
 					sbi_enter_s2idle_domain_idle_state;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.669962810%40infradead.org.
