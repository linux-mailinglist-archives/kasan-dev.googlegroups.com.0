Return-Path: <kasan-dev+bncBDBK55H2UQKRBZ4DUGMQMGQEEJPOGKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id DEF255BC6F8
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:15 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id v7-20020adfa1c7000000b0022ae7d7313esf810808wrv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582695; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZsscOsaA+jSs2A/qiKzKX0lBxroV8JJU5DDlmc5XGcq5dj0eNJ8EGJDTqbwxzMIucy
         rEjmeAWIPtqpKZ9Sg2mk6tcjd8BOCcA2KJOAY3gtlBC8z3Oodfk9uK3zJM8nq1LZa2Md
         z3Qnr9Zi7wrGYwRoV7oqhdKgQSbzIpgmlLwWuku81ktXErFfXw+pIR9hZdzQ4a03P2EY
         VFacYFG6kMz4fchSUD31Rh79pPk+7pjSjVrlpfSQyC1V+0Iuqd1G3WAcnojyY/ReRBfY
         4fXLeDbqD7cgzPDNuBzqGmq8m/l24/mbKtRpcBwb31nCAdqVHEVdib9WfbfQ+6sqeBIf
         iZHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=SxjTV54NUyXFuT/CUc7ZVQ5NPQcrAS92gUqJn5PdgBg=;
        b=DPtQEhAKPzo2bEj5M4CFknC8pLs8wepH3dwaZezy/oQtP+WrR44x1O9p0uAkyS4Scp
         0K9UuxxdA4FEawrCWiE0dWgft2SaqVJ00/L2j/LbomhlzBW5YKFTbgU0wxiS9TkgsiaZ
         bBs/0+yOjJA6NDnJFBFwz6ORxYAiK1WpPbxvMXBOCjrCkRKkon7kvhD1OnmV14q75Tbd
         Ot9hSzdy6zrSjnf10ICu9zaqDex2PuN7AS0glmUROUODAoExt50Mbjxrde/VI36Letva
         dEZHE1uK59Hrexs3dZxgabFEEN4EXYA4Ynw+QBbScJYSgoOjHa3NoXtuiNNRmMLfkETw
         ygqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ayjCmoqH;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=SxjTV54NUyXFuT/CUc7ZVQ5NPQcrAS92gUqJn5PdgBg=;
        b=F7z+56xIy/mrk5XRRJa27u+Q0K0XJ0hhnmcgYsOzZlDjXF5KxCDW1ESRH+zhanWFv7
         kX/DJi1PA4dDyNtyBce6UrLSVIvN+IZ/Hpv18KRKiNMSnNTwvyULKqU+e6ChwOM8ETr1
         Kg0ok0sgk5MOh/p9hoy+rq9qAbXY+mDsQyojQaI15b3+gSGoYLyMfDYtc6LJE7UEG0oo
         wW50LZ2xB952dDo0CbIz5DpOy+pekyn+lBFyCOspMZB1BtudrcixHHOBOtqfBXM5YfOL
         68uviL10ig9aGA6v0IQdTf9ZzNPbZCV4sVr+fvqPWCOsmDt317MnaMbvEm+WB8idlKwI
         vkvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=SxjTV54NUyXFuT/CUc7ZVQ5NPQcrAS92gUqJn5PdgBg=;
        b=enPBFhSKOTZx4+xY0cuh0RUIBlB7dOYMCt8AuhtaELA9Mc7i7cc2hKjYOVModOAGjc
         j0Q0Qkyn0giKcWKPryea0AWcyLwYrB1JIhYRBuRkZdb+oFE36Q1Pdy+BtRz/Eqdbp5uj
         S3iMdXLawTFNDYmcOUjhbijCHb4NRX0WYjUY9UymxJvjbI8Ptdkp+VChjtn6YqVXMOMe
         +d+/gw3M2s7xJ0fpyg2RPC/G4X8zam7sa4enOvISRKa29+jzZ8OeXVFJR1N1THz/Zf25
         VRVcVkO+Hi5FhAS0IL7/9kGZqv2FDmKTLb6JxXoEJzXvp8l3ZfE4sItXP+iasUyEuyJK
         kImw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3L5FD6fiEafG4fO38QPzrbgnuG5V7Vilblgyz7iMyfkxrqQsAw
	GEN0qtad67xvcuX36rp7pTA=
X-Google-Smtp-Source: AMsMyM4eQ70A9J32coGL6NlmNZwwy4dGmglG/7+GXUjFkqltd4w1XJKttoKAvBkvo7iDXQX1shfaLw==
X-Received: by 2002:adf:dd8f:0:b0:22a:84ab:4be3 with SMTP id x15-20020adfdd8f000000b0022a84ab4be3mr10014077wrl.40.1663582695678;
        Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20c:0:b0:228:ddd7:f40e with SMTP id j12-20020adfd20c000000b00228ddd7f40els7612441wrh.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
X-Received: by 2002:a5d:4887:0:b0:226:ed34:7bbd with SMTP id g7-20020a5d4887000000b00226ed347bbdmr9672255wrq.561.1663582694616;
        Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582694; cv=none;
        d=google.com; s=arc-20160816;
        b=ywKkIfuYpyF0YUUtLz8aPGcDDDepnqZDM7WL1eLjJuiN4LGqfErETUJhcr1I4fiU5Q
         muNEHQ54kcCGbBC4giivlEeuvXeEYr4ao/HHhIz+7fsuuA0u9Jx7FrN7QqVw+0KgpNza
         bDfF7lu8d0+b9mWrLL0AqRdhqrJYE/ONWNYGD2jKZP4HfwhZAiX5fI6R9/nYGXHzm0Od
         B1gKpwQ+XuI5pvGLLBTgmZ8OS/VJy0/Q31vcY/XBkstEpg8l0grv3tIToW9/wHqpsRbv
         Lw4DsrZGq89COeuHgfOGkjSW/0rENl3aIzk/1bq/N7RHKwf//uQUhJZ5V7fhcfZHqW5a
         GKhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=lz2MUgDITA4yYb0U+PMz5bsqmEWyVbYbLXt1grP5wdc=;
        b=B3d5hsa2Kv7LogWOuC2or2XaeT2vN2tABQFtz7Uauncfbw5If+3iXpyHAUPYy/K/pv
         SdURYTb14VfZKgam11VyXKIpkfkJR3zQwmbnIcZ+N8uSGyd3xHxwsN5T7mGF6eE1V6B4
         zaT8xnER5EDPFi7tw+UsMuv2Q2RxsoQ46Y8rJLx2WYQNRMYxZyn2NHpa4niXfoS40zJH
         yS2R4BN9Z2xRGETDLnoWeBveOPGsGfFAxMSsRHVHnMZ6w0xSBsFRFmyZubZxov1D+EEf
         qahxs53Non5L4Z2j7AYFnPOpFi9Un0Dm+acorIeBU2KSNK3KlP9Ekbmkzc0ZtlVkcm5q
         U8Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ayjCmoqH;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n66-20020a1c2745000000b003a66dd18895si312395wmn.4.2022.09.19.03.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq7-00E2Bo-Ru; Mon, 19 Sep 2022 10:17:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7C1D7302F6A;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 96B742BA49032; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.975285117@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:18 +0200
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
Subject: [PATCH v2 39/44] cpuidle,clk: Remove trace_.*_rcuidle()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ayjCmoqH;
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

OMAP was the one and only user.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/clk/clk.c |    8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

--- a/drivers/clk/clk.c
+++ b/drivers/clk/clk.c
@@ -978,12 +978,12 @@ static void clk_core_disable(struct clk_
 	if (--core->enable_count > 0)
 		return;
 
-	trace_clk_disable_rcuidle(core);
+	trace_clk_disable(core);
 
 	if (core->ops->disable)
 		core->ops->disable(core->hw);
 
-	trace_clk_disable_complete_rcuidle(core);
+	trace_clk_disable_complete(core);
 
 	clk_core_disable(core->parent);
 }
@@ -1037,12 +1037,12 @@ static int clk_core_enable(struct clk_co
 		if (ret)
 			return ret;
 
-		trace_clk_enable_rcuidle(core);
+		trace_clk_enable(core);
 
 		if (core->ops->enable)
 			ret = core->ops->enable(core->hw);
 
-		trace_clk_enable_complete_rcuidle(core);
+		trace_clk_enable_complete(core);
 
 		if (ret) {
 			clk_core_disable(core->parent);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.975285117%40infradead.org.
