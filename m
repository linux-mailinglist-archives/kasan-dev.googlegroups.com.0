Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C4CC3667FE8
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:34 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id b6-20020adfc746000000b002bae2b30112sf3801038wrh.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553514; cv=pass;
        d=google.com; s=arc-20160816;
        b=AbTyGPWwDlNkCyU+ZHSLCr/HydOmWnVFPDZywmTFZbCYJKU0SSQsdRwpH61fmEqvTd
         fH0ppMsFR0epugzNPec7eEqV8zuXpOTstdwHHj3vYiDqOjlBFqYp0D7p4mKQ581eT2KK
         +TpZlMqhpbcJ14XEHyabf6sTutOWA5QDg+ocaGwxL3PGliRsr32hks7xWRG8CeqLzYOa
         mSN+3AbcnvW/HZBUSZfeWdDJGuOIwhuxZxEaq9pEdsvyRSCuavT0i2yxFjPRMJ62cM6D
         oAO9KqljZn1G7o90ezUg2eV8ndLPDER3C3Vg0KO77wXxzEdGLU4TaLb1QVFGFTW44TeI
         Krjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=Xc6bEFQuv6RlURusgw3uU5Ii6NKd/j8LKSTPFEacpLM=;
        b=wVA+dHbNl74LF+/Jd7dRTiY+WrRHi+wTe6AUzqQ1fT1FoSdftRK6Riz5h0GGweNAG/
         jMFjPnRTDlUJirQxYc1rAPpHU4AFMKgjz5pX6ukrmZVCPvIU+ur/Yw0IeoSnp7fHU1n4
         xHUs+EGF+bAbu2AWUQEq2ywxut2xuzyiqHluMzUb+Ja/ZXSVVs9kYnCgTsDRhI46dfe7
         hJ45pGlvX6UwvQ0kJSPRgZrDty0YreIMukappQQjG7RgfmTBivd11LBXRFgxTQSLKIKX
         8qn850hKsFXQxXTZcUwK9/iIMEBvRX+SARgWUcPZceOoPF5gUtXZx8Z+jJ/B0u+zIgZg
         RRqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="t/UiPYxu";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xc6bEFQuv6RlURusgw3uU5Ii6NKd/j8LKSTPFEacpLM=;
        b=HcFLCd4MKS3BqUxqpkuwulR4DCD1NRtGjr1vcgjGmtXFVrmwu2/PwRqBIz4YM16oh5
         FhlIKzv7Qf6bH2Sr28Y/CSPIo3OiehlmnuapZuDzdoCChGD3JKvDIdiUOpIMMVMZaM8H
         2lFH3FCGuTkQFSXpXBPcViCmebsOQk0YPkqgxwVZMjYAesfExAT5Fxi4e1Ijf4Yc8QLR
         Wx4xPVTAecky5WcWq4BPS3kPC9MSkf/a3z+tekZhrezCbYYWA3rKXv5ypsSgbnWxheSa
         S8u8uZjYjIbBynsGWnL7m2/lamWZx4raZ3EOc5X24D8RpFc8LA5in1RnYPSkcspondDi
         4zEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xc6bEFQuv6RlURusgw3uU5Ii6NKd/j8LKSTPFEacpLM=;
        b=YhD83WAEv7nNKxNSDBsxOus83t0WXl5CHku7WUsdf/2iu1TaqH6eZsjpcAgQkAj6/m
         zAa5BVsE+NHuAElq+Y5XdaUybz3UrmpHcEnYzY6sJkuJUMsA4AuTluMlKotvhvsO3Ktz
         /BfK742zvG4EF1E6eUxpSG1IiXwklNNtBCkNp4do7d0SQ6bv0f+H9XFBnWgGYgwsKT5A
         9Vq145cIuKHxz2pB2sywo6tYwEsBboB3tlcJgnoFXt8xhf4kES9TfpZTwSCHr61+nciO
         0cR/UOUdpVTRMp4/fMMZfuPXY46tdxnb76xTKs71Brs25u7zhB63m38xR4QXcn9WmM0z
         +HFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp0/FXCCeSuMq8go2mAvvlwNrQFcdrISM/tf7MY9eZ95hemUJwd
	YSZm/CUb2eSWkFkg2pTP1nY=
X-Google-Smtp-Source: AMrXdXtjazJt69Un2+xN3YVb4V/Ai5eHLZQBCQa/gqm9By9POvNRte324EPdtSYpxDaq4F3UzUfRxQ==
X-Received: by 2002:adf:cd0b:0:b0:28f:cd14:e36f with SMTP id w11-20020adfcd0b000000b0028fcd14e36fmr2726832wrm.616.1673553514387;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b0c:b0:3cf:72dc:df8 with SMTP id
 m12-20020a05600c3b0c00b003cf72dc0df8ls2948677wms.0.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:a05:600c:4e09:b0:3d4:5741:af9b with SMTP id b9-20020a05600c4e0900b003d45741af9bmr60139463wmq.0.1673553513268;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=OJFZ5CEdDnnjbiQS/oLB2IB0T5BDdNuBX6uSM2BQxXkxFJIc+RO9so+LYWQtoG8QdK
         GchlCcPbt39xJL6NotXNpgYzfOFMkXPVA5zMj5eLwpz+licxn12ZpHFJJOYs0UV1NdBW
         B+5ssyRdwCq8T37WSyWtyOkgA7d7le3W65ZZRk/YsDp/3ZCoymlG/UM21+OkljRK0PwQ
         zIoEtR7LPchQxhwUR3/+Hm9axwMIMOakbdM6xq8TZxLNLLi9nKrONyU4w96kITpbIchn
         Lek6McCNCbb2A3uiHJdBK+juniu+KlDClesQSIimuZjPgfzhwqr39Ts0VidYNIszVqL9
         Uzew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=uRuk42rt5J1sC1gDxlIXH9yiXjv0To5K12rtksbRl/w=;
        b=b2MLPaG6qEDHULnpDuuXzKt8/h5VK1pm4pqgJSJd+7RIr3qMOUtYSAGZ4s6bhy0N/N
         fCfpAtouWLf3K9JL0r0rEIld7GDXE9Y9MkVp/umFwjcSG598diCgnwd4jLGTV94l1xEP
         XCSFhOMzFCY2F+e2f3p5Co9Sf/zfsJkdvrMAwKGmxL5LhgiV0+CjLVRukKl7eKBY8gYq
         Anb6+tXj+Gx2Jmktkn4w2F83LiFFi7n180eeHJYNAInMSi8NjGr5YxNczFXYOnK6ETA6
         MhfWAAMu3hspTJXTxRJUBsNiQhMK/Iyf4kfAsRfb3e65icX4AbphcCRIdF8iyNkgS8z8
         wUPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="t/UiPYxu";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bh25-20020a05600c3d1900b003d9dfe01039si460674wmb.4.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hh-005OkJ-5g; Thu, 12 Jan 2023 19:57:37 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 04C58303467;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 520F42CD066C8; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.844982902@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:55 +0100
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
 Ulf Hansson <ulf.hansson@linaro.org>,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v3 41/51] cpuidle,clk: Remove trace_.*_rcuidle()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="t/UiPYxu";
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

OMAP was the one and only user.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.844982902%40infradead.org.
