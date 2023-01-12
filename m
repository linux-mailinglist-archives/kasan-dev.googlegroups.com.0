Return-Path: <kasan-dev+bncBDBK55H2UQKRB3GMQGPAMGQEEHHDFPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82FE9667FFE
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id bu42-20020a05651216aa00b004cb3df9b246sf7305736lfb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=hUvs8uneby4txC55t/tSRRY1N6bD3lzE0rf1fCOB0H1ZZeGs+/oi5yQdM/Fex0DqLJ
         L4TW1jLikNICNS364sO54UKc7bU0poMZ41A7Oi0SYUa2gsD7HkJBN/8UVOBKWrMaM+uL
         Khf4uNP8/D01NSUSHGNIBYCBo9SfmiKec3sABAHvO+pzNODVponnqY5QQFmAi8gpj+fc
         fZvM5L/HhMDFuO/BxpRXDG2z5YYevcvoOTNnPnISdZZP4FemCFubowoT6CnPO1w9/RtK
         ZVnv54D4uoYKdFbPclrIwDVas9kAsTlhJUqp3f1Y4CQPh3ccEHWvTM/cVRx7yqhgIcVI
         nu6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=AYEbwHDto1u1V7+kqpFL2m8GfkBVzZ46C7wYlGKmsKU=;
        b=oFxmQ46co+cZLWm4/WiYiWTtdzLQkLNB31bQxkLK9U2+wg9XCRWlqqhUpKunWeb3dQ
         r7MB6iE0ZfOq+VDquYeoxFZsG+1D5DnAAQvc8QWQlGW63vWkbZcPeegjhz0+pHZJZyQS
         l3cFhjr/94FQAfuEFFqQjkYRqbP0VfhRZHY7BizRx5P/7Ox++MZWlrjfZtDn8Z21V/+T
         bjs646wVX49GbtL4CZ5bXxEDyL1iSObQq6RgFJAqVGtBA/X+a5n+BEKekyfa+0Bt2GuF
         jKXNzHXwIFzc6G7N3OjTV0tVyYziKWA3UFrM5EdTsMD4yJ/5ec62deCD7KGKjulPCiEH
         An4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=d9VgDAL2;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AYEbwHDto1u1V7+kqpFL2m8GfkBVzZ46C7wYlGKmsKU=;
        b=AFstRPQURkCCDjLe9OyE3P/C1Hl7suroo7X/4JuM4+ZLJBYPs9O5V5mDF2K0Hz5NIL
         V1wAV1lZDhbErVplK9BdkScj1iIiKymr4QR5myV0ZnNFBsT84CMyXjx8gMjqrGZWTFFR
         XhHFfbeE2VVkoN2wNtsB8duJEQLCcl9QAyq5ZUrD4cr56zXTvTdgojdO2hnCPgYobeuA
         qWj4vuyYOdYsnIARbIJJPfWHGzFY0dMQYrV181I4c2dWZm2glGfBmq9RLqwiOFn7l2kG
         u6YkNdYkR+Jco4eiai67KvGXtLnV3zwjySSU0LHWciNzczdqLJzGHI8Vwq8IuWY1BUtg
         ofug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AYEbwHDto1u1V7+kqpFL2m8GfkBVzZ46C7wYlGKmsKU=;
        b=kWrgiV1pCFSL3psbqBE0pH0tpbwhGKtKzYhsbwV0bBpX6t7iKe570iJvqY00pikw+s
         f7SUAhor8XTLWkbFFgD1CRdZtPgoJ2XN/X84ENmZeavHA9WLxeDEqLk92aqiz//Y5rmG
         kPxP61c0Q3jpiUW8HL7wsTpgEBG0ZVleyLBPQdz6UHL3R8740QBmrH7L3t0c2scj26X+
         25PLskDd7dXNSNXCZxTdWJGxhWdCypaR8MmXAljYGcFZ45uJAlRLbqhQjkhDI66QEH82
         T9eSZdKderQiwQU3YqCra0D/sf2zPbKb2n4M/2bK0zAGqivZ3F9aslgzzUzq+DCu40Vs
         nhQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpP1uvofDUhl0STpfrJ1hHrVVn/BAuWKGbw+ZDN/1dJRPHDWLwm
	KvvtszcpfiJbN2ESq5n/AbM=
X-Google-Smtp-Source: AMrXdXukFC6/aNBk9S+jqFCxUxa17Mi9O0RTGXRC6wSFs4ufiXgUXhDY36jJneiElKn3frPs55r4fA==
X-Received: by 2002:a05:651c:229:b0:287:e806:82d4 with SMTP id z9-20020a05651c022900b00287e80682d4mr839003ljn.1.1673553516970;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls1755126lfr.2.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a05:6512:1049:b0:4b6:edce:a192 with SMTP id c9-20020a056512104900b004b6edcea192mr25335870lfb.4.1673553515753;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=frnI4z9IZFJclywtwNv12vfCHOoppS8DPHduO7Me2mW2hCTqqeBBMVlFG6tkBEngXM
         qfv0kuHg6PEopC2REvQJG5ZsHdSycsbBkSbuQ7NA8EopLDLJtr99HAGQ3GWIRbvg3mu/
         XjsRIzWgdG6BqDoqEbadpJOKhAeolO+OQo1LjpLk/R4OOiBQGTYS8IidqBTmdU47JBfS
         pumT0bRJ0/UmLC+0/waxlUOHrIjeDUGxPxezWYz13q1GEsTvXr+IhH/p6s3cwSie548w
         UXnXlCPJJPggkdqZVlzHnGYaJTrlRn8GmUXlpYO7VtuM/B4OSczbU64uuN1D3ZHL6hB2
         7UGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=1NaK9G2/I/OTlb13IaE2Tqn3F/yijw+kp1Wy55f7+Ak=;
        b=bLLJrQlPBvbe7AE/NG/6Jeu6d5SBd6HpUHQeSL0bbiKNcWDBuEt1gVTvJT3fjlDL/D
         xlGUrJsm7jI1C7TpL8XYC++E/O/IijiKPlIB4iD0fNTQ/zzyHdx15ORUIX++A47hgcEx
         3OEvoSyyJsv33xMGpzPRwTFL9Zcx/eKoHXDnkaf80CiR4vsfFTHbfV1HE0x9LXkp9zKC
         QwfQh23UMEMBZfDbtdXQh5nMhKLZX469lu3u9kUnUG13yYNorn4L0cqqIFE7RXh6ucmJ
         HHaerbbie0mZ7xqb6jvR9p4yh+wSwlZDLbOFVq4j1s2HlKoY3gm/w3nPs5Q9x2+nxGgh
         AHIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=d9VgDAL2;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id j11-20020a056512344b00b004b49cc7bf6asi863042lfr.9.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hZ-005Odf-Ny; Thu, 12 Jan 2023 19:57:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 45C8F303418;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id DAA122CCF1F62; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.312601331@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:30 +0100
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
Subject: [PATCH v3 16/51] cpuidle: Annotate poll_idle()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=d9VgDAL2;
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

The __cpuidle functions will become a noinstr class, as such they need
explicit annotations.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/poll_state.c |    6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

--- a/drivers/cpuidle/poll_state.c
+++ b/drivers/cpuidle/poll_state.c
@@ -13,7 +13,10 @@
 static int __cpuidle poll_idle(struct cpuidle_device *dev,
 			       struct cpuidle_driver *drv, int index)
 {
-	u64 time_start = local_clock();
+	u64 time_start;
+
+	instrumentation_begin();
+	time_start = local_clock();
 
 	dev->poll_time_limit = false;
 
@@ -39,6 +42,7 @@ static int __cpuidle poll_idle(struct cp
 	raw_local_irq_disable();
 
 	current_clr_polling();
+	instrumentation_end();
 
 	return index;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.312601331%40infradead.org.
