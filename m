Return-Path: <kasan-dev+bncBDBK55H2UQKRBLUDUGMQMGQEUE3RGAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 560DD5BC64C
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:19 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z13-20020a05640240cd00b0045276a79364sf12379371edb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582639; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nz64ZWp4L6T+ya8CmRUF07vBLxQSotRD2X8M/YVmEWaAKyIGZFTKvSoVumi3fUgi7k
         92Sqa3PwzKHIpUGTn7citUmi7bWb7Rl9U4Bg/wQt+80/82hB2BHMvxFg8zhxoPBqGoX+
         W/+beLqaQsCpKUSnpHVPtGz43YPDVh+rJFTfR8FD2ToOYm3i9XFoJnkeuJ1/Tj54Rq4I
         Zt9wPiO6RsM933zou6QOarCz9s2gPIkdXapre7jvcFEui2uvPAnp5mCd24PDGttfj7G0
         EqSiisN6ic+uhKyKgfPc0rcS/Z6/l2KeOm1GSmJaHM+2YZ25PNMX+YLjNJL2uosRCI4y
         vWow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=zqzuQv9fl4jYm+VYN8tMN9sBNNXUV8Rua/pSHRAvgUs=;
        b=ACeDWkx2odn9t7CSmogikef5okgDStoAFGo/ZUFoABMDPNZqe2eHzXpI1tVhQd1WNJ
         XBfOVC13VejGAOU0e+RtCmsY6n2Mlwmnv7H/kovur/fWASWlZ44oxmP5caYaqkqjRoW1
         jEBf8VMEfTPeS/PRoSWvVrviKmMAv0iyEm6kSRWxEMFNDVBQz6TFvnujI4QqNu6o6G8W
         3bXlH93td5BJMeeQD/LTYXpBOI9hviHbJwPOjn1JmQC0wb5fDv+Cz3pC1K29aIQpsb/Q
         tnqI3V2Yg/sTmJODZ8bnNgsvcyoyZIR+y1tHpDGIa9VzbYmqqngAlS9mXhwDR8rISu4h
         loog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="ADXtthd/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=zqzuQv9fl4jYm+VYN8tMN9sBNNXUV8Rua/pSHRAvgUs=;
        b=VUr7C3pNO6YGL/iVdE0xeEcKiSRORdyzHkJjVIkOpkPLlG1Ji6NHqv9vHtv/h7hJm8
         2FLZST+R0UIDI0aqaa4XQmRoNOC2T9nBBlUycvtY8L5zF8lfmJWMGWxVb7z9AveMZjtm
         KY4CNL9j6rYyKgpEGTipSPHzo4ir2r1rfq/beCzwuzJDlxT9LeR45y1Vhw0B4kChwtvM
         SS4T3RPNaCy0jhZpXGErSIratxz09drodvu6LUCRKTHfd+Dfhsy6Q2D1sYgyl2od/XO8
         UAuVPB3339CjitVx035xvgi8EF89Ox7Sd5yxJxwBJf+n2UBzytYlveLKhD6zrPhJrClV
         9vkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=zqzuQv9fl4jYm+VYN8tMN9sBNNXUV8Rua/pSHRAvgUs=;
        b=kSLkmkYiy7LrRXMeiMLZoKu5rRnMMCBbFVhHoFYQy/v6fo/ZyfUUuspQHqAf3Vxno/
         psTxuQAbLfLTp8Zi5yEQyHwWMF4PHMFOn8atfaYjCAsoq5h0qX/MQPo7Ct7SBBWyhvaX
         qu0HDRvsEH0a7L0GbSzaQPD4Meph0UKczRf5WOt9p0/mjhIJq1U+ywuZTBsRV0WDGEDG
         3lifEr8eG2vdLyGX/zbhYGKeUmNQ9AfMmvrGVTRBwqN1XMZFgPNg7yY5a9e05POVrkwf
         p3v0CPmXKIVmRnEsE10g5BiBQElnr8I2Cn/24O0AHg3LPuge0n2dKe4hmglbSHLa7JQq
         MtBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf20gh7CHuC9Z4smzqEJzqTclj4K4EXxZsniSsQmmBsidgugDDOL
	VqXDXkkMOfZWcIG52X8o6nw=
X-Google-Smtp-Source: AMsMyM4qXgAgaWJrwHaQskc3AqB4Popl12IZ/qDCmYdnA+zgWnbZtAG2rO4sjOY23Xz/5nyk0tQVsQ==
X-Received: by 2002:a17:906:4783:b0:780:5be5:c81b with SMTP id cw3-20020a170906478300b007805be5c81bmr12585734ejc.76.1663582638761;
        Mon, 19 Sep 2022 03:17:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:44e:93b9:21c8 with SMTP id
 w12-20020a05640234cc00b0044e93b921c8ls4361019edc.1.-pod-prod-gmail; Mon, 19
 Sep 2022 03:17:17 -0700 (PDT)
X-Received: by 2002:a05:6402:3550:b0:451:473a:5ca3 with SMTP id f16-20020a056402355000b00451473a5ca3mr14994653edd.48.1663582637536;
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582637; cv=none;
        d=google.com; s=arc-20160816;
        b=cNQhXiNnrKMUx0MKgu40X3hhuJASnXPMaIsyj+d4vH253uo59fa1YSGY/lbK41ks+Y
         7t4nF/9HLoS1U7HquMunUAb1vPELcl6AYg0nNBpSEuVC1p/qIQvYQIwoewWuRjca7JtC
         yC7s/z1JW94hbsmqINATgiO2OcPvnYs1uUPIeau1JfK2wbsvDRRL8XUGzcMtQlM9ipL/
         vD/b4T1J2u6snJsW2n+EPQkQoRj3D34fQSyoWlz56r3DliZTlatgl9u+2hVmVuz5IltL
         8jTaTk5ZuPfngkF3EB8IPtpC+jZItHkYBN4SEXm23lcIqMvZbwuIv8EgOkYaG6nhUeI3
         VlKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=wztoayxqdaRhc3fzwYQuz0RAh5ZT6y7bJFX0CXMuNy8=;
        b=oPzJVneKMM4nhE9vD0EdNLZm96BPC8pwzF9psRGezMBXE9G1t2uHIlDtf5X1ellg1f
         hTwy0t+FU90jLdTsxsuFCO151JqeqloW1zlVgH1kABbTt+DF7kn+Xo/2aT56UklU6fDI
         IXF1b7gpqTwV3G8RwfdM7xYDOjzske54xB9BXeapg6kxLEe3CYmZTmuoHgNnB/Y3pP78
         wXc6cVpLbH01VvZf62a1b7LkbBr428UFkIKh4woanGkD4d30plcb/x7dpc9bQ3RuszXw
         +HQpZJogLSLVc1NtcMX7vgh7yyhKsf3E5S+AzbKnwvweJjwCR7kB4Xpt9vV/zT70rjoi
         yOxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="ADXtthd/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a4-20020a05640213c400b0044608a57fbesi177672edx.4.2022.09.19.03.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ai5-Jc; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 961F3301FC4;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id D336C2BA49039; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.602636221@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:43 +0200
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
Subject: [PATCH v2 04/44] cpuidle: Move IRQ state validation
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="ADXtthd/";
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

Make cpuidle_enter_state() consistent with the s2idle variant and
verify ->enter() always returns with interrupts disabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/cpuidle/cpuidle.c |   10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -236,7 +236,11 @@ int cpuidle_enter_state(struct cpuidle_d
 	stop_critical_timings();
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
 		ct_idle_enter();
+
 	entered_state = target_state->enter(dev, drv, index);
+	if (WARN_ONCE(!irqs_disabled(), "%ps leaked IRQ state", target_state->enter))
+		raw_local_irq_disable();
+
 	if (!(target_state->flags & CPUIDLE_FLAG_RCU_IDLE))
 		ct_idle_exit();
 	start_critical_timings();
@@ -248,12 +252,8 @@ int cpuidle_enter_state(struct cpuidle_d
 	/* The cpu is no longer idle or about to enter idle. */
 	sched_idle_set_state(NULL);
 
-	if (broadcast) {
-		if (WARN_ON_ONCE(!irqs_disabled()))
-			local_irq_disable();
-
+	if (broadcast)
 		tick_broadcast_exit();
-	}
 
 	if (!cpuidle_state_is_coupled(drv, index))
 		local_irq_enable();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.602636221%40infradead.org.
