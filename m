Return-Path: <kasan-dev+bncBDBK55H2UQKRB5GMQGPAMGQEYLP3ECY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6467D66801B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:44 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id bg25-20020a05600c3c9900b003da1f6a7b2dsf190788wmb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553524; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wif0aUCRWcI6d38zPpQ8GIW1nbtlCpW7KYtdHBz71rdDQIcaSJbRfpUi3SHqIk65WS
         U4Z7CYhTNHjyhxtlYxd/Y2BD6XiEpKgrXUzCYHR8b8ptR/WPIEGTXBYtHKqgHGhhw2Lb
         EotyrLPd7b+cWxbQtMhWhHpQ1C1i1v8KMdzxMwSbUTFf5JHT3o6ARNZA2zY4iMF8H4uz
         hPPdfDZFil+ODxqA5ssB9PUkL24z7pqoODX0pm77s2i/pGQsq0LStbE0QHtvQVS6LMHI
         XLBgNdwN1Qk9poF8q9ulhrXISgCVxK2ee8xbfUqSOG86bHiu7TtnZsDEg+ERKQphY+sD
         mgJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=1DVJZJ6YXyCrOqsEtKmeuCFU5UZqs37BIHJx54lHH5g=;
        b=h/teiB0mX7GBweOTU17iqT+1kvB8Viwpe3MLrnGV8u6J3WljrY+8MoYFwzRALesoGO
         C2htTRIUMVYbEwLTchb0XvoouTI9lnrdZ/EbG7lJFihJSHX10KbvGqf/RB4raPvPLLx+
         6ijOtd7DXa1YC5dN1QaOIigXATsA2ihcKt2+nMINfZwZd4obLavA09gBcGRu05vqAGvy
         x7sLL1TYxesucYMJ7f/e7ATWH8cq8JJ68aNqI1bosw+HJcyEnkWsyn73WOwDnnvZK5Us
         71eg2YIZJF6ALShpxbxSvoPukKE3tXQI5dmEV91sGwSJFQhEultaQyr5VgigFmpj220d
         G7Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Cm0cZvx6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1DVJZJ6YXyCrOqsEtKmeuCFU5UZqs37BIHJx54lHH5g=;
        b=CtoI5bdtOInkT7jzb1ZPLro3AQnj9ZNgigPHBGCsr8UFXoC+LdBPXMrDoXfnIBiM/X
         tyVVY5ktYai34/9RV3eyoLd5ui5bS1ry2qCVIk5CvMXgaWlznP2ltmLh4+gFkr7AJn8x
         luDly9FJsgTEpRgkZZXR9WnIfaGWv93Z+0fK6igfhzhTDZznQHdJDLcaxJkvgNOJx6nL
         VZN8cN/6JKLanvc1EXwgCAZVmeAsuuS7sGbsvHqUuc+2jQ/zhLaBbQ9OHl384d5tegZf
         dskgbhMfLsbUyW1LOI7TaEtXJL0fgJhtZ8vwqz43fMm+KyBz2+1MGG/sQwd5X3J0oKSD
         WZZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1DVJZJ6YXyCrOqsEtKmeuCFU5UZqs37BIHJx54lHH5g=;
        b=K8uHdbg9TBn4pvTyKQbQ4McT7EMMZyiqOAwkCICSVpN7KXoIGburTejgcY9iehcvb2
         9pqCm1Y8B9g/jSdH0OHj/VmnnlF1rp4xVX933FkEp9/7RlnlZWCCMxjTVY/1GLkWjiv+
         qrVXFzkFNe3CrMfpmZc6fbGLceTcQ5SHIuFAk28HwoA7ThMAifZMLuHqy1V56BgsIfaN
         7Oxx2HGiDCS1bg2zpLg12Y9OiK7bHHwFxzuUc/zuiNSm6IgXdv1dJm358XIV+QT+LX/o
         crJrMZLZHU8niXa4FgxD9RDuP29/89VHX3qCJYWkVPq9ZPbOdTJfHxYOwpPSxBXZiRYm
         1PDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqPj1kxZCB93HaSqcR7AhWin/YnCImaBFaA9BvccrIhiYqEdTJn
	LKKGO5b0E3KTyzXOkSE69/k=
X-Google-Smtp-Source: AMrXdXv1lVVwvnHj6oeTqSScFqhCmp5GVPO/NswdpE3E0AhrKlVLiuwXnXo8blvJz9vFh3JOdnxAag==
X-Received: by 2002:a05:600c:354f:b0:3d0:5160:c81b with SMTP id i15-20020a05600c354f00b003d05160c81bmr4712403wmq.110.1673553524189;
        Thu, 12 Jan 2023 11:58:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d93:b0:3cf:9be3:73dd with SMTP id
 p19-20020a05600c1d9300b003cf9be373ddls2939857wms.3.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:43 -0800 (PST)
X-Received: by 2002:a7b:ca4f:0:b0:3c6:edc0:5170 with SMTP id m15-20020a7bca4f000000b003c6edc05170mr55883989wml.25.1673553523143;
        Thu, 12 Jan 2023 11:58:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553523; cv=none;
        d=google.com; s=arc-20160816;
        b=HxFVS+OxjO6GV8Hq+mLT0qWo4HRvAgaIK43yT/Dj1ijDHP7ZWkOfA6OLQdnyoF+fpj
         HONIN7JB1dZn4+Wyx4PulyuUSGv2pBW4ANCSIM+u+QzPkWX39ItLGpREZSq+6KvRZpFl
         qvQdAV/Sixukh2PVagMvK3MeLAH5Y8hXoxjRPdgPSq4ihAUZOMZigzhnfu862vKILUrk
         qRI3pHDAsyLeU/QRXFePXQsqR9cCDim5exa4BAIvehoTbK7nGpi+t8Y9HmuCX9KGjOaQ
         2gxghceP/veC9CEPYVw55itL+HRm0EwJw/ahLJdnWf4FRSFqIkiExcVQDSLMJKl1LNG8
         g0Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Un035BTYhsjREpZ4dpy/MHkkoifcKtLiH3nYidAuKL8=;
        b=tpyysNk5CsT6gxHsmMUsjJPfr1UB6mxjcJpheDXYqpQoD9eQimIlrljSfa/FauT+wl
         szj4pD9eydCDe8c0DBeq2uFlsL6c208DvxtAdBk4NEm4GtPGS1D0iJ/BwrtIECbRlmIi
         lNpFcmB14Z4A6s5Sj6+Uf8SugMT2GTziyn1b3Lats+onbkZr2PtdQYGy+cOtYbf42UsS
         7N1rIIkEvbpJ1CpjH6KoEHqgfUvDftHvsATrOa0RD1+/C20kwBDMDp1gysHy7ZQVop7k
         J7t8gt8qAt0tAVni/fkzjsN8tPFcVHByxObjYF80pPXllzP4J6FPk4uGcnGD2xpKrKFB
         U4mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Cm0cZvx6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id fm14-20020a05600c0c0e00b003d9c774d43fsi520702wmb.2.2023.01.12.11.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:43 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hZ-0045wK-1I;
	Thu, 12 Jan 2023 19:57:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 44D46303483;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 7C19A2CD066F8; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.397238052@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:44:04 +0100
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
Subject: [PATCH v3 50/51] cpuidle: Comments about noinstr/__cpuidle
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Cm0cZvx6;
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

Add a few words on noinstr / __cpuidle usage.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/cpuidle/cpuidle.c      |   12 ++++++++++++
 include/linux/compiler_types.h |   10 ++++++++++
 2 files changed, 22 insertions(+)

--- a/drivers/cpuidle/cpuidle.c
+++ b/drivers/cpuidle/cpuidle.c
@@ -252,6 +252,18 @@ noinstr int cpuidle_enter_state(struct c
 		instrumentation_begin();
 	}
 
+	/*
+	 * NOTE!!
+	 *
+	 * For cpuidle_state::enter() methods that do *NOT* set
+	 * CPUIDLE_FLAG_RCU_IDLE RCU will be disabled here and these functions
+	 * must be marked either noinstr or __cpuidle.
+	 *
+	 * For cpuidle_state::enter() methods that *DO* set
+	 * CPUIDLE_FLAG_RCU_IDLE this isn't required, but they must mark the
+	 * function calling ct_cpuidle_enter() as noinstr/__cpuidle and all
+	 * functions called within the RCU-idle region.
+	 */
 	entered_state = target_state->enter(dev, drv, index);
 
 	if (WARN_ONCE(!irqs_disabled(), "%ps leaked IRQ state", target_state->enter))
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -233,6 +233,16 @@ struct ftrace_likely_data {
 
 #define noinstr __noinstr_section(".noinstr.text")
 
+/*
+ * The __cpuidle section is used twofold:
+ *
+ *  1) the original use -- identifying if a CPU is 'stuck' in idle state based
+ *     on it's instruction pointer. See cpu_in_idle().
+ *
+ *  2) supressing instrumentation around where cpuidle disables RCU; where the
+ *     function isn't strictly required for #1, this is interchangeable with
+ *     noinstr.
+ */
 #define __cpuidle __noinstr_section(".cpuidle.text")
 
 #endif /* __KERNEL__ */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.397238052%40infradead.org.
