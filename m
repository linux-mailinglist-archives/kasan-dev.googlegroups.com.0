Return-Path: <kasan-dev+bncBDBK55H2UQKRB2OMQGPAMGQEUXYOI2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A9F83667FE7
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:34 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id ga21-20020a1709070c1500b007c171be7cd7sf13624823ejc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553514; cv=pass;
        d=google.com; s=arc-20160816;
        b=G5VQaxKoGNuiwxTDZB/bLPvVe7l/M8EI0wiZmda2UpjKBzUQYH/b6S3zfp/Kt5vyMr
         XQljt3Ov+/05Vt5pemdAeTfMe9KS0F5c+GOhspWtiFTKASmGsUBsGncmWL6hIMt7S0Ym
         lWSTIEiSo2ynl5Wjo4dTWZbzNclm/FA0w3SiIS5azk6fOzSRYT5L5rHbRjqNtJaWlhhb
         jE+6kJM+eIzhrAoFcp1gSBCFxDPFk9kWOG0kpHofPU7IBvw+6Arikc5HsUpSCPjsOaa9
         waeTxmaSEKYhho+8hcmkqzL1442CDA48i1Zrqx47HoqZp5CIC7rOz3+3AyZp0xW7WL5g
         0/Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=i+PWln3rlexszkca5i0vTcZY2RTyRjwG1bmonxTDo5s=;
        b=C/mPaS3JZxLWtnzFhJ2cB9yjLPRn4ELylSiLr15gnV86LeT7chVQhu3igpfQQASuS6
         6JZUEZFEzcfLZAdyJUmONqkP2w6XiXNIfgchpGZL3s4WYSqrT2TskwNcOZBwFt+zdfP0
         7achOO93G7agAwiB0eixwclR/X8D65wmKK+b5R4/tb3Y+3pjw6IjNCGx+Tp2WIrL94UA
         w9SPmVh2j20fvjPc0u1t+17AuwKDSJi9MHj5rp1/nA53LoSERJL01IpBCoLM6aHWVzCe
         aEcQtFPiFk/qgoD+Nb0xstol0fk00miNWmUW6TdbB++ia7XorPSAIeKeK9PFg17Jbtw+
         zFYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ATY8kiKn;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i+PWln3rlexszkca5i0vTcZY2RTyRjwG1bmonxTDo5s=;
        b=SCJSmsb7ohihzYtSEIjisySObwygxAPc+hHfocOkSAFThaJOyNrEn8Yod3l9GhgmFk
         aJ5cG+01parKD8k5ixVpe2oOkKEtl+6E7MNWbisaoQmC3kgT1SSuxjy3wHEbOXsdH0jN
         KkXT5OJQM+zWd97KpqUt8LGpIZZy8R/NT2nvaOGAuSkbtA/jiFJGBoAxgFR4fCCbnDB/
         /yySYcitV6Ldj7VcXUVVePdJ8EDJE9Dl56dhOfmoyhiYIe09RxSQ3NFPKOhOv1XMrKpC
         6pXB7YGoTv7LWYiGTJlwzgKxJuMdqNi/a8HmLmpOBzBIKoQNE81QcC/uMreYpGU3cPEV
         TmLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i+PWln3rlexszkca5i0vTcZY2RTyRjwG1bmonxTDo5s=;
        b=YnmQQRke+KObcG8OQBWr78cSn0bMIxPKTJF+A/AF8TgI/fGBEBmERa/jZK86fK16EO
         qe7SZYM4P5Pg/U6LVGNsIS4GehcKSa/aOMdcvLxO9sP67neHvXfyYA4agOcm3vF/Oduv
         KVXGSRdHFjCr5+WpMrlU8zQE1w/A3vSaKzNA64Y8ukBEEJtyoTsTcnG8sOoGhn79l0bC
         6/DbI+nKUFnct+qFPuoyCFl4pkR6/eQkIuYm1EDAjHhEqCyCX0afN3phlm9srlQU4MDO
         9LA2w6E7Nh8BLpV/qdcPesCsqzvS1arFK9aRk81TOtGW2zBfK3p5FKuri5LPiix+ziTU
         QGgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koKvY9g/HeZNgnyqhAAYnlwKNZXJ0Go1mhNhTvRmFf/fE7So6yS
	cucXD1g0KSa7L7jV3QjqSlE=
X-Google-Smtp-Source: AMrXdXt1SF+c9X0IsYnPWnBPhqZ6P87JaMCRTN1TcdGN1jThNOOqLsClL+F2DINslkAOJT2buHxNDQ==
X-Received: by 2002:a17:906:284d:b0:7c1:6c46:dd56 with SMTP id s13-20020a170906284d00b007c16c46dd56mr9881005ejc.182.1673553514104;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:94ce:b0:7ae:83f4:3bed with SMTP id
 d14-20020a17090694ce00b007ae83f43bedls2040398ejy.2.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:32 -0800 (PST)
X-Received: by 2002:a17:906:4e82:b0:855:dd40:e96a with SMTP id v2-20020a1709064e8200b00855dd40e96amr10674260eju.64.1673553512707;
        Thu, 12 Jan 2023 11:58:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553512; cv=none;
        d=google.com; s=arc-20160816;
        b=Hd1srCn9irJqMTfB7McbSc8Hlh1OxetceBgch/Hr0+RF73khB+GtxOPR8z9cXSG/mA
         vO5iDsu2hyf7hmDVzjZjHl/LmhT2y83vHpmmYJANtd5Y8ZRMFJhSQPUzL8ge9KhnKAqy
         frQSSJD/IiyhpjxPeYKyosrlgt+RFjb8AvRlLnZRrL2Z2HIbA8ndj28AJ+bMP6oUEGZF
         VR8FSun8vU1Za5BUTZnNiDlezG+yBOwwEK/LbLNezCQJWDiu2Ndbvk5se0Evovn438F4
         B0lHG9wD5zfA67dZ9B3Zz+vSiVSbae4VXVOVPJyJPpuEuAJ7qumZPReSalaRD3wzJf5X
         8uwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=KLAmYUkc5o4iaLgWEzyq0DD4W34Vw8wzkDDZ9nw8rNA=;
        b=y8QKElpAVKAwfl03JJCjDCpo+gbxqyBaeyLwhhvaex6euolq2qqhV1TAVon4XkYvQY
         b/c5lFRe6E26xilYGFyOMrWK19D3W4LM/xSNHJ9INQ1DUELDhl3H4PAn0PsPtZGsYFTn
         7SxFQTeTdnTqbAG+LW34EOog9A0jfhJF+U3yBRU/clK7CENApU8N6A4LZP7O/XiLMyYN
         acbV5oRPcdHHmp5OzmNUOxqvQH69lsYaKmdvqm0z3T/4KxgsvhANwyxBCRRiWphnVaux
         /WF4zizT6B5FgwCNuz4UnhFLsz3mSl2Ub/8PMujGs/inK3FwSetPXI7+ouDRQL2h1Bmv
         7eTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ATY8kiKn;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id hx9-20020a170906846900b007ba8b8a416fsi882030ejc.2.2023.01.12.11.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:32 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3he-005OgH-Gr; Thu, 12 Jan 2023 19:57:34 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D0FD2303458;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 3DD3A2CCFB77A; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.538053457@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:50 +0100
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
Subject: [PATCH v3 36/51] cpuidle,omap3: Use WFI for omap3_pm_idle()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ATY8kiKn;
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

arch_cpu_idle() is a very simple idle interface and exposes only a
single idle state and is expected to not require RCU and not do any
tracing/instrumentation.

As such, omap_sram_idle() is not a valid implementation. Replace it
with the simple (shallow) omap3_do_wfi() call. Leaving the more
complicated idle states for the cpuidle driver.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Tony Lindgren <tony@atomide.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-omap2/pm34xx.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/arm/mach-omap2/pm34xx.c
+++ b/arch/arm/mach-omap2/pm34xx.c
@@ -294,7 +294,7 @@ static void omap3_pm_idle(void)
 	if (omap_irq_pending())
 		return;
 
-	omap_sram_idle();
+	omap3_do_wfi();
 }
 
 #ifdef CONFIG_SUSPEND


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.538053457%40infradead.org.
