Return-Path: <kasan-dev+bncBDBK55H2UQKRB4OMQGPAMGQEML4QINI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D072668016
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:42 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id m4-20020a2ea584000000b0027a02705679sf5166151ljp.4
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553521; cv=pass;
        d=google.com; s=arc-20160816;
        b=LENs0dMGuG9BnqVIJFtFMsiTYYfCR5rqe+L4oqJW8b3SumCxblxdyQa6cWwl5yXv3j
         /OfbZdnHn+VayCMY2xCGYWwsL5v7pGOS/Mm1+RX4RuDeH7qrG7D05E2NkiAznPlRKTvD
         0RHkCqQI+JL49FkziZNlY5fQCdQSq1YArsNCOvDB8piCG4UShTbeEdFLEkRZMjvW1Mky
         w14B6wIvEBfB57R/d6WJxMf8C34cKGEYeC1ZSZxfk3ETE4uHXf1wI/kGGdWt5L0d8ial
         DQtDGjbOg33NOgbzfFNDoYUBYBAweakYovM27W2+YU5LYsoQ/ZfC+GFA9l+h31wpwpeT
         xj8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=By97+t3lqWVKeMmj6mSkx0cFjyNv3kHoUs4GqavQS1A=;
        b=U5EuKgKKvbGVtD2sAe4YRIUWpv8Fh+/M9x2HPWqek83VooLY8Md9Ucnz75Ex22NPaq
         R71ryaZjJKVw1NNjyC8KhQu87lJamazsF5dNkDsl9FPYysxcQiGADUJdoqxM5ZHzRXSI
         moic1B5LC8fv0hSeaEBhtf8PwgzZcUydSgh/gnn3VQlJvf2WffXxCVWS/DEIeK5a1Rky
         CfSaPrtmHLy8fUAMxLwDwsPKVYqA34NV7rJl5zurSaHsiyftwGEUlxij3VS0wdQDEqPA
         ZENvoAEn6vz70VnQQ4K9QVhJMzpbtD7PyOcX/sn++e2qSA0vmV/qW1pdJ380kEAD996O
         ZDcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Oi0kUglc;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=By97+t3lqWVKeMmj6mSkx0cFjyNv3kHoUs4GqavQS1A=;
        b=OpXwKcMaf5TWkUnf/dWIJF9qs7/3wQrcEW1wPMHZVbf1ZJw3V3ZE34F6ajtA0j5o1K
         PPUxTbEmO2elR01W/BUGwKNyb/GDtnhbZ0r78KCo56Ucl6mmyfa+o7dGUz1J941BwxGR
         oT/cmLcMFE/R+ESkMtUBU4psey8mScO84kltM6kSJiBN5TDdPK1/dLaNVFDNH4pt3XCH
         6x/a9vk7lI8BC56aCmtPgf644aoi0BHF7NOYtImWPFNhslhUVvB0jmBg3ajHDp1y2Agv
         1H6syDlKUi7n69oI1zqN2+Rvf6IeB8oAPO4BcCKoDMWT+oobVEbEUenvuuh0btoeDNNe
         fBPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=By97+t3lqWVKeMmj6mSkx0cFjyNv3kHoUs4GqavQS1A=;
        b=ldWsTo5qOHADZdD4GiWvGoSkTXppy9cGl6gzEkvztT/fEnAJHFnmdgnqHunlImgIow
         h342pAxBZI+LOrWLEFhJAjYzb0eZ3oKKejKUMHecKk2uccuqkivDLJn6YUMvimvjdrzH
         rAm5N4DB/AvUwTDwMNaBc68jhIwMaBKlVgSNVu1oFAH5UurqcID2Plx1RD1EMDt7xAUw
         D9/sjxHjR1Y2/Sfs9UZflJtle6xt6M6FQtzelpjcNU+bUKMirZlLhZEiAr0h2WVlnlBy
         1JhZ9O97+mV2j+QjGIJJlOG7UMMrVwStj+OSKFUUf9RwXpIRfjUVwJORKOvlMzQUCaHC
         7NYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koAqAFc9blOU6nXU7aU7OQDyn3pbSMo7ViBpmO0UzCkQbYs7D6l
	ec0fO/mx1ko2rZdcgHo6b/E=
X-Google-Smtp-Source: AMrXdXtyWoq5AefoSDmL7uM8en9JVCrBKKr3JH4R/SFlG//A4QQwfTjzp2DgElAUzJnqRdOOZMtZWA==
X-Received: by 2002:ac2:5329:0:b0:4cc:8940:3359 with SMTP id f9-20020ac25329000000b004cc89403359mr803561lfh.521.1673553521727;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314f:b0:4cf:ff9f:bbfd with SMTP id
 s15-20020a056512314f00b004cfff9fbbfdls13260lfi.1.-pod-prod-gmail; Thu, 12 Jan
 2023 11:58:40 -0800 (PST)
X-Received: by 2002:a05:6512:25e:b0:4b4:96ca:7280 with SMTP id b30-20020a056512025e00b004b496ca7280mr20434980lfo.37.1673553520513;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553520; cv=none;
        d=google.com; s=arc-20160816;
        b=aORExt4seoDgNSSX9vvFa2DhDEHwAc29b2PZ0nuxibRaOz9/eYyM3ppvnpwACFO8LL
         fj0zJABz1K8+14T+9lSwf3EnydoKSueRZTXKpT8YwvoMtfsDmeWF5UBK17uWmP+v1AFY
         xNEf6burgHlWdxWTDlCp/d9ZEqzS8QUXNqyki85JzFce3ghsTkaTcUYNP4WC5pXb31uC
         Vb8Qk0JFv49hDFueEBBakmeoPYakJFrh+t/urOVl0R2Vd7dtx+ig4ZsN3pJJIrvOJBzW
         vrF41XuxacrrY1aZhqE/VoO4k3EqkNuvVEMUwMbBwKjDQ767vmpjn/A9FXKAE4Fzh9gz
         bTEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=H++Izq9gHCigzm3jyfqVQx/OXXHHURXAPu4rHKpriQs=;
        b=xo+UkxEqPQJvsXecwFgCadOYAbJ02rGTVPQkG0qHfDOxfTXsx1eJ4a71x98P5dT2cH
         lisEKcqJ4diD8kPmXCsWGgMSZCrUGpIUfhsA0rIYSEJkQRjzeB/eoatvFBV5elXiBQF1
         yOv+rNfMFFgyTrow0q+OLp8q/jcVeFHIMxH65sC64Ayd+MGHviO8IaaONFPmacJEb1Vo
         FC0j9gcg/GEmDsJbNdxItoQop+IzNx46dYe4SGVuYHXj8zXegXyadhrpNj24g4DnTLKD
         Et6E/rqgwUJfwhp3hRg09Cp2fuOm1rZwNg+g/4lvL2MUWOFNQPB3Ii9YBASLiv7QAKsz
         v74g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Oi0kUglc;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id a14-20020ac25e6e000000b004cfe6a1a3e7si4481lfr.13.2023.01.12.11.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hG-0045ot-02;
	Thu, 12 Jan 2023 19:57:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7E559303430;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 0D9AD2CCF62A9; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195540.804410487@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:38 +0100
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
 Marc Zyngier <maz@kernel.org>,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 24/51] arm64,smp: Remove trace_.*_rcuidle() usage
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Oi0kUglc;
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

Ever since commit d3afc7f12987 ("arm64: Allow IPIs to be handled as
normal interrupts") this function is called in regular IRQ context.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Marc Zyngier <maz@kernel.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm64/kernel/smp.c |    4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

--- a/arch/arm64/kernel/smp.c
+++ b/arch/arm64/kernel/smp.c
@@ -865,7 +865,7 @@ static void do_handle_IPI(int ipinr)
 	unsigned int cpu = smp_processor_id();
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_entry_rcuidle(ipi_types[ipinr]);
+		trace_ipi_entry(ipi_types[ipinr]);
 
 	switch (ipinr) {
 	case IPI_RESCHEDULE:
@@ -914,7 +914,7 @@ static void do_handle_IPI(int ipinr)
 	}
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_exit_rcuidle(ipi_types[ipinr]);
+		trace_ipi_exit(ipi_types[ipinr]);
 }
 
 static irqreturn_t ipi_handler(int irq, void *data)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.804410487%40infradead.org.
