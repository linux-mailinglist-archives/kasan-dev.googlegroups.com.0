Return-Path: <kasan-dev+bncBDBK55H2UQKRBYMDUGMQMGQEDGHNIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F6865BC6D7
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id o25-20020a05600c339900b003b2973dab88sf14987794wmp.6
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=anb1Dqkof0R4mZnqaaasLCubC1+d/jC0GP0ulSQkZ6Yv9PVPuVJfaz3yzC5zY0Kf0a
         jsAwoiWNJHsMBaw7rQWPggR5ZuddqDo9IM8iHsxLL32Rix2cy3VrDSrPLJKYB6c8hKjy
         1QppC91hwMHm0BlTmG6FYuDR93SLikJnXH1eUpMDPWlPvtIr286VVe4yohodkMwZB91H
         IIXMD5Cv+7PaWn/M+DxNINYOTiA/6C21Owyi2vH62YLCyaAWtGYnzjMFRNgZ5KP2Wh1J
         QrtEEHTcQd2BYEay2py5cW5YpN+b217a+0qY9HifLhfYfogqOFfl90Y3AFrLImhmPV6l
         eOGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=jPPH1eK9UZV7nDIWsVEFxZO9F6mocVeDxhukoeP6u40=;
        b=ycRV/dcsdiair/Qet5rtgNWzWAda5yIFS3i24fNqU5/NVyAV71v4orC/FtL7616XfK
         zR42Ndh4XuWNxMLnxGoRZeYIFEahIAQ3igwzUP/SQDr4PJf+ek+M5YTGXJshq1Z3aFgx
         HWBB1snHYViZWeAviP6RLoQv6yRdr48EbkOo9ecLfXgWp8K3x6abK4pM/xpTDzHnpG3p
         c5KYOQpCrCbNS6yHK59q3gbv5eE/pI32V7S7gU/pbaMV+s+Wp/2rQdds/HWUqH5klHZB
         QOw+Xj0dXUwAsnMxKDw0h9K5H5jHh8/UzfU77PlhLY2Xk6qxZKYS2MbQXQDsP8cHfnBr
         znrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dhBNASMj;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=jPPH1eK9UZV7nDIWsVEFxZO9F6mocVeDxhukoeP6u40=;
        b=XloTioXkjgeQmv1p3J2n4NBP4/IKcaYh/6ukuSCxzYqpP1yHB3CwQVT4ikEajOeLJd
         Zo/4Ihao4UxhzX0B7ryeBmAc5NtqtzxS8R6w5WI/mgtGPm0jAhSp1qAPPbXekjQs5TKN
         rqYBbA1bLhOyZOFIPPHM6LFBMTBrGAWVIxTA1h3+biE1zi9xIC8BcdHJ+DpIQZTrpKgY
         /7Dfl4nsp9W4CEYU+ClpTHF+hzMT3nuPQ10GVJ7J2zLdkRdMke4RPZbCPxrdYzydiAdE
         MWI8TNuQLu3SziXiVV1hzxiHVkiD4ol+MUqFmFQhmjwmfHOeRrbajXnIBuntMZ0BC+b4
         28Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=jPPH1eK9UZV7nDIWsVEFxZO9F6mocVeDxhukoeP6u40=;
        b=T7Xm0lTl/KW7WW9fdlZfWZPwWtmTvJH8fwyfEy69eL7RxV5fTMVxWoTToRUeHlUhge
         2txpLMbxtjJpbd7abJLlWmUs9DsvN4nao3rywlpTIOOkj1wWYpWAgJOZNviVsnbc9qBB
         QKiEMfpj9Bm27q23zxAp/MeyR4py6catgBeMAwohwKYQyZdFyppMQn88Xy9dKFc4uxEG
         aX6vnWvYX6TK04RnDn3PZW8Q9VD4h7oWtC53ct9v6/TIPD+9D0BOu6BLJ3ztydMbhXAX
         yJHDgwCHJmbq8ADjpozIfY7im/DrtNn++7UMC6ZHSBIB953uQy4yPeRp9V9+F0Ptjpvs
         eR2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0g5RGtubvv+fP1+Bmwm8kWnMU1bLEuGrzrwbN/RzPTR8JbplFH
	qLZ6Vy1Wy3aQQSh9C4yvOJ8=
X-Google-Smtp-Source: AMsMyM6Ksu2teZLaC+oEEe1O3+/SFB1XKC6ZJB88b2/Hd8JqkuDkS5Uv/YbNu04ffNzV4mqEaBiW2A==
X-Received: by 2002:a5d:5a15:0:b0:228:cd90:ccd with SMTP id bq21-20020a5d5a15000000b00228cd900ccdmr10879478wrb.658.1663582689205;
        Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:490a:0:b0:225:6559:3374 with SMTP id x10-20020a5d490a000000b0022565593374ls7610250wrq.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-Received: by 2002:adf:9795:0:b0:22a:f421:5d0f with SMTP id s21-20020adf9795000000b0022af4215d0fmr5545475wrb.644.1663582688173;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582688; cv=none;
        d=google.com; s=arc-20160816;
        b=V8g/f/ETrrr/pN2TYNq2jHf63uvZGjxePSO6YWZghlIQVLVY0AIcyBinkI3SCMglCZ
         1CjZpe30thiDH1xrueAC4R3A73K/VLjzB51gVd3qWmD9P16xGg+1aDuhU/8BqiXdiFSQ
         XvZT7MD9MHOZOFeBWGMC5d64c4w1UR9CKl8pDSZH/ajlouHNEIx3Utz4geI+cVG+RoD/
         MpIfTjJzmiO5nLH8OC3YR967zZVbJcza7Tx0hvFxM47K/lNDTDmKwxWhH2cOQj133RVE
         7eoir5ys/6m0ZxzT0CrSJ0dTtXkXy9VN/exC1fFNXJuoPni/nD+esRGOqGOrTl69jxTa
         TC6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=RR6lW9yNo9DZO38N/e4p2MZQ6Q7RTpDFv4YAvZRPRqw=;
        b=Iic91JSlM87I+tuM0Gn4/Bno4f8LdrzOwGP6nSfkA0w1yTZn9oJThYBxoZ2KYVJoQW
         nqJgqxfFr7kAhQrK3NnXlG8szLEPa8Hh6Dma4Qwu6AASlfvdfI1/JuN8660Zs5urzP0C
         q56D9MKffn8pCfNwQQL7pF3+K/84STKVL/2l7pvq/VKfvgbEq5yHpiUY6qoBG7FPm8w8
         OykADSzwIcTVETCsfFXXQFu3NSPgKHOUSjmClYiZ9j1/JvIv5v7cXRMpy9Nwy1xvQRQV
         ffeSnFI0jGTG9j7KOT1B7id0WANjivS0FNl48bwHiF45gVs6RKleNmT4Clbxrxwpm2Ul
         ah6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dhBNASMj;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 65-20020a1c1944000000b003a5a534292csi295142wmz.3.2022.09.19.03.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq8-00E2Br-Be; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8FD45302F77;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A2A092BAC75A3; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101523.110221113@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:20 +0200
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
Subject: [PATCH v2 41/44] intel_idle: Add force_irq_on module param
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=dhBNASMj;
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

For testing purposes.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/idle/intel_idle.c |    7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

--- a/drivers/idle/intel_idle.c
+++ b/drivers/idle/intel_idle.c
@@ -1787,6 +1787,9 @@ static bool __init intel_idle_verify_cst
 	return true;
 }
 
+static bool force_irq_on __read_mostly;
+module_param(force_irq_on, bool, 0444);
+
 static void __init intel_idle_init_cstates_icpu(struct cpuidle_driver *drv)
 {
 	int cstate;
@@ -1838,8 +1841,10 @@ static void __init intel_idle_init_cstat
 		/* Structure copy. */
 		drv->states[drv->state_count] = cpuidle_state_table[cstate];
 
-		if (cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IRQ_ENABLE)
+		if ((cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IRQ_ENABLE) || force_irq_on) {
+			printk("intel_idle: forced intel_idle_irq for state %d\n", cstate);
 			drv->states[drv->state_count].enter = intel_idle_irq;
+		}
 
 		if (cpu_feature_enabled(X86_FEATURE_KERNEL_IBRS) &&
 		    cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_IBRS) {


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101523.110221113%40infradead.org.
