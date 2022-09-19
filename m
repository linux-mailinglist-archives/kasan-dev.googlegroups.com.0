Return-Path: <kasan-dev+bncBDBK55H2UQKRBZ4DUGMQMGQEEJPOGKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C5B975BC6F7
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:15 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id h4-20020a1c2104000000b003b334af7d50sf4463335wmh.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582695; cv=pass;
        d=google.com; s=arc-20160816;
        b=HX4MOunABL5u+XaYI6Ex15TS6R0Qpk4LEetF4pdLiKopswhRl3UlcqOIWB+5mMR2XB
         butMeczJU2KWN0f1vBnXfnG7iye0NGW3vAAHjbcQ9clqQSoAeWXxj7VABHJsYkNP6QJ5
         b2n2VsdUejPgrSbtWhMD2/Cy7owJyoh2+TV8tch4FC993W+IqMf4QnaUl9Hb0qam+pm/
         GFVZaqZCss3OPg0+OkHnQxbR6alPIDi3D6NEV8dpHJL5sGfdOLa3u/UZKiaWS2EgrR0h
         U0WrhrIkfzS9DY4hNyxkgfF76E0QZ2lCOa3rIKo75v1t1ngU1H5aFO21eG9yI30Z8yJo
         R6+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=LBfr9eDU1fxjQqjq5AoMhiyMijk0grk57xAHjK4iSFk=;
        b=gyama0VrtIm5lN5giJGUyc22h6KVGzhkYAF+9yewhc4NZ75TZytA9YygYYiIzofiO6
         8baDgyPTbP9/HEQQc3fJCNntnMK9aojDgCAjh88ksVNmw5FW23YRI/xPkAcEqGU2nqtu
         dp4yrNyVck1NcnFxD7Igm+aU02Truqou2Hq58tGhrKWmFRd+HP0yJh6aFjbciNqv7QiU
         c41Q3INKMHzkomG6+0kkjof9+EXPJXCEpfoy58CrjL1d0/4OwDBFQUI/v9jiU3SkmxIg
         Z9L2tlAIPECKxhik0QC3GnVJmMNZaqCu+rAuQUwlbYiwktBRBAwNkBxOJ5TosaIopkpe
         7Jig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=iR1EPRig;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=LBfr9eDU1fxjQqjq5AoMhiyMijk0grk57xAHjK4iSFk=;
        b=CJp9I7TTQUb/HSDtJN3M+g1XAMnCOK3kJcasOGITa4JmgbJjUYdik/AlXTXkNNmk/H
         e6bx5RE12cGEq1WTjQGXl/Rfpvs3qY/xwTXqhf80sTxyKyXU3e59wVgj/sst04bPxDpB
         nbQ1T9sK3jZulAxQ+8Ln/0XCMuQp1HHLyCuN9Z5ZXLVCGvfhIF4TKGSRHozs6Fem2ykx
         ULoXqUpQj+EWptL35zWbqbcIsrDB4TF5hgmXqkbYaLmikXznR/3mbqFRMEOvKLCGaOsV
         R3s1EroDBx+jYovDcCjXAC14vTw9DYFU/FZjwifmKehVCucsnbGKH2hkS0cehvFSozG6
         zdjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=LBfr9eDU1fxjQqjq5AoMhiyMijk0grk57xAHjK4iSFk=;
        b=H246BNQgqyp/j+cwVaJhiWNJVbEK7J9+GeMYEgStU5XDlCcpNzJRVpOzxwq/lJXmtG
         GTJecC/aus+zVGno0n9Xah4ZNeQMXSCIir+etUzGozvXoyRS3qEtmvchbrEHlrecOu9w
         h9yMl9mK3rgamPQbJVcLdrorTEfN0GB7SCXN7UaLnKx7J8lHllbA78zhg1loOVOudXWM
         7lpAUre+QXB9es1hdhm7Gn3xBKfwS9Zyf1kPwjfsCbXLf5DEjf0o2nVSYdRhPji56qEB
         AkzgfZPQNfq/BmI/E4hpOKrC43w4csOqBeRVO9k0RDsSW9OZ/5RJEd3yVDF8xp3VY+OL
         P2sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo05YFXD3bFugJSmF0Ueb6Yy2Qy0j0jgKjo1nc8W4cBCtQabMTmU
	aT8t6gLiZ80a6pLPW/ldvug=
X-Google-Smtp-Source: AA6agR4+b3dLn2yKdOkMWxTGg5oGA3Cfhp7mCv8a1fCpaVdUHpnSIKpKeqMBVa4XloSn0eiGoRonXQ==
X-Received: by 2002:a05:600c:524d:b0:3b4:91ee:933c with SMTP id fc13-20020a05600c524d00b003b491ee933cmr17880254wmb.100.1663582695439;
        Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c5:b0:3b3:1ac5:fc2c with SMTP id
 u5-20020a05600c00c500b003b31ac5fc2cls1735816wmm.1.-pod-prod-gmail; Mon, 19
 Sep 2022 03:18:14 -0700 (PDT)
X-Received: by 2002:a05:600c:229a:b0:3b4:810a:8b4f with SMTP id 26-20020a05600c229a00b003b4810a8b4fmr18797394wmf.117.1663582694405;
        Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582694; cv=none;
        d=google.com; s=arc-20160816;
        b=iUarcedbxgD6OEiz/BYCkmmq2Bn4o/xSIJDBZkrd78r/ZcqY5/rVqXOolswXFN31Hb
         O+emrvE0VEVzG6iJzV7jvo7Zk0mazQGxHuLNN7hRsYCiQ7hCE+7VI9lN73uuhwNCtGmj
         sQAktA+U+MBT+9Y5uqTmu6Mqji9RwlpGAfmYLW9U6IMU8GISzImBRLVL/C3eu40aRhD4
         6bDW71MI5DKz2oqB8LEzU9DYpHPg2mx6uPVr86Cfb5w75HQNbOQsmHkFx4eGyNnhoD+R
         w8wJqC5JeyVSrX09y0e7bXzLAjtJquoqK/khDfj3xc72P4/ebbrPGRIUe7yaZmNxO3/r
         nvhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=opcA1/Y+HqbqHoKXfaoCivp+Xr552TiTgo8o6IEPi68=;
        b=FkY0aukXOQLA/1usZo3MDhRo+rFqMMXmQaPbn0qwhI8HeLjhFCecw9R8nJJ0e53ybk
         teoP7ahC0Mm5yMQ1SvM3JCrve4eGdsCfVnnUQvadnuqUsSSFHx8Zt7IaJLWUN8v2s0Vh
         ocAM447NRZIiI43t8E5Y2lfP7ZaOLj4ciXCxzKLS/Q4Y9aSwE+rMQUFAh8EqbH5GGeMO
         mU1W4YYeQJZ+xYwchbayJlqf1XNFjsZGbRDqT8OgdEkLeOqfxAN7wtCLoDCyzxfZXgHx
         f0/uZHucqUpgyeWjsir+DwA4V/GuXrc+/Y0Vt7oTvHnYonSs3a43nDUuFiScVa1KpGlW
         DAyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=iR1EPRig;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay4-20020a5d6f04000000b0022a5d8714b3si378826wrb.7.2022.09.19.03.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpE-00E28y-Oc; Mon, 19 Sep 2022 10:17:18 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D3172302E85;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id F01612BA4903F; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101521.004425686@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:49 +0200
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
Subject: [PATCH v2 10/44] cpuidle,armada: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=iR1EPRig;
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
again before going idle is daft.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/cpuidle/cpuidle-mvebu-v7.c |    7 +++++++
 1 file changed, 7 insertions(+)

--- a/drivers/cpuidle/cpuidle-mvebu-v7.c
+++ b/drivers/cpuidle/cpuidle-mvebu-v7.c
@@ -36,7 +36,10 @@ static int mvebu_v7_enter_idle(struct cp
 	if (drv->states[index].flags & MVEBU_V7_FLAG_DEEP_IDLE)
 		deepidle = true;
 
+	ct_idle_enter();
 	ret = mvebu_v7_cpu_suspend(deepidle);
+	ct_idle_exit();
+
 	cpu_pm_exit();
 
 	if (ret)
@@ -49,6 +52,7 @@ static struct cpuidle_driver armadaxp_id
 	.name			= "armada_xp_idle",
 	.states[0]		= ARM_CPUIDLE_WFI_STATE,
 	.states[1]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 100,
 		.power_usage		= 50,
@@ -57,6 +61,7 @@ static struct cpuidle_driver armadaxp_id
 		.desc			= "CPU power down",
 	},
 	.states[2]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 1000,
 		.power_usage		= 5,
@@ -72,6 +77,7 @@ static struct cpuidle_driver armada370_i
 	.name			= "armada_370_idle",
 	.states[0]		= ARM_CPUIDLE_WFI_STATE,
 	.states[1]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 100,
 		.power_usage		= 5,
@@ -87,6 +93,7 @@ static struct cpuidle_driver armada38x_i
 	.name			= "armada_38x_idle",
 	.states[0]		= ARM_CPUIDLE_WFI_STATE,
 	.states[1]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 10,
 		.power_usage		= 5,


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.004425686%40infradead.org.
