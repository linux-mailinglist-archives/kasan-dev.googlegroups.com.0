Return-Path: <kasan-dev+bncBDBK55H2UQKRB26MQGPAMGQEXK2OTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EA0B667FF5
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:36 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id qk40-20020a1709077fa800b007eeb94ecdb5sf13415311ejc.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553516; cv=pass;
        d=google.com; s=arc-20160816;
        b=qMfgv94kLbxavT/gwxkZ29XmI6TD6gokYiiHCXkFBRQG2sRKY/qtJ8V8USUTVykjq2
         K5V/r588G/tkBTNOgYnSdFuDeNjrlInDxFh/ganULo4lHWghOym9jil5lB8YU43FcPHR
         PogRyKRNAhT0QMrOw6wIgSQEoUARNfKN9v1Esuj/whOwrBmHgR0oYOJ3ATJci9/hcSZq
         TuU0PGUiprBgoveTCEzZxfSEHL37ZcuHXNpNYV4dSj+/kePaHBR40bMKjkDg7mGcl9vU
         VY3HRU2GyliIpHjrjAnTbr2i9T3HCxjua9SbUXqsBqP3l2EvbntJiSe1a+jFVkDc91mD
         u1RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=O+KUHtRXLrfuYSucaM+DNokf30Imdve7NM0bzCIN4Pk=;
        b=WI2OaOdtkjNRSoRSjPleVXL0oadd6Z++R/xwu5aImvLSurnrlgGUiz2B2/cixrNhg5
         nSeLFNEem4aI84dlN3v1I9VtgJurck6BEfXyTDc8H21x7chLoSponZtVxToaCSpb2S93
         iRlWAxC7+1whz0J4DUPXR9ddurYc8yiJ8QUhkN5zry35VMR0U+jh2EyEUswnH7z5Sq+W
         7nOm/XuH9R4xPWXgcyF+ejt8LHUVmiSyUns/e8XBGhUYt2VPJdosYnuBZd6saP2Vb5xX
         hfG4wfu71KnivIVk7Acxsm7CKmXlKxk4PdoDwP9rg5wic4HIyYnl//fahcmo+nT4bOvY
         OlQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=MtUDAduu;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O+KUHtRXLrfuYSucaM+DNokf30Imdve7NM0bzCIN4Pk=;
        b=fc6SzOBTieD1YsTSDTu1mZ0Ru3lfCd758cjehTGKxHjZzIBVxXOna6LgpnbMPMhG9Y
         RBR5ycHuhK9Tr5wS7Dw2ig/0pa9WTgWobmXTMLj3ivFLP/eYJcZLiL+WKuS3RqeX0qLu
         adS7MwS1e9InfNaLOUT7NEebDTChO2Rq5GDyIT+kmB9T7Y3f86L3yXu/PCIebx4PDi8F
         Qtf7wrHujjH5Ce/KXHYjOh/JPNVJo+zBA7eYOGvD6KLpTFvbxTlxzG9jvlZ6wa23ZcSk
         QQE3IVXQRscee1niCDaGZKUI/ZOv7FAWkr0B/EbONC6MqL4y3GO7BtlO1fpjAZnWleuv
         5KTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O+KUHtRXLrfuYSucaM+DNokf30Imdve7NM0bzCIN4Pk=;
        b=CLvjfHbw2CyVSTau4AN19a91TB80Bo4hzIzOKxPUN4FneFwDzLEJ95hQip4MUBHvXT
         +Ot0pcExoTvgC0vfXG4DdeEAV+mM045NEOVwLbcsZVVNa39xGnHhcW+OlG5rDEfEv2I1
         GS4RHOnLwEZvkaBvArhKWVvV7ssvpvFLAItHCYzNuNZFqXJ71YPjNv883/frVFNyNxSW
         T1xDmd+kAp4HoL8JmMPifbbNKYKEykpPL1l0vUBCLmX2hxNC/dsWmIK4Z+VYpbXnJ/kh
         UpmFJa0mbjv4/VXs7usou5Gs90gIH4cLvUGKPx/Wp8yoS2uHHn9cJQ3QuzWEdFrj7HIl
         XORg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krGh2s82feeawgHYcdbSFJ+dxAMd6RCExMgb1tSRSKcLgaP8mSZ
	oPrRhB23GX7x3nK0r1lErZU=
X-Google-Smtp-Source: AMrXdXtUCiOP/yCEX8ZZ2xJUMvb3yemELU0s9NpSHGI7VPoNsuD3tm7P/7247zCEeG3GJ4Ry3e2uQA==
X-Received: by 2002:a17:906:b304:b0:84d:4dc6:1c08 with SMTP id n4-20020a170906b30400b0084d4dc61c08mr2163336ejz.421.1673553515866;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a004:b0:853:aa55:97e3 with SMTP id
 p4-20020a170906a00400b00853aa5597e3ls2030506ejy.6.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:34 -0800 (PST)
X-Received: by 2002:a17:907:c292:b0:7c0:aabd:fef0 with SMTP id tk18-20020a170907c29200b007c0aabdfef0mr583441ejc.17.1673553514578;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553514; cv=none;
        d=google.com; s=arc-20160816;
        b=ckcuArAtAEad6xqGfsLbtF/NDHruimRA6CvWlTbgfBGUEG7iZZgrZ1yScALMwni0v5
         Mcc58kSzhC8dzoGOlFFKLt/NKT7f/nhTTwtiWRgmS/UT0Lz2mdKHALqf8D6d2m/rOYxP
         uqzJKz5EQyqBUMHzX6qmsA6XulVk0LC/dBRMo696/JGzhi/ITvZwVhD0Ib6CrAQtHuTv
         d2puvjAjdK/7SXoHql8CBeB7rvrGd73v+Z6uEG+Jg5CX64DijVSSUaJwMJpW/zE+Wc+V
         Qp6wrDji4mlWYu6Lw3fg04SQC6ltJgBtwlLrOjiGr0bWYvsnv1cSqnGB+XGGHih+vsxt
         G5Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=57ZArFmnIQzaVihzbRCoRwr2LaVbKaf8OfuJB2z1dTg=;
        b=AN23bVR15VHs1RydGQyrrsm8P+q4jh3heQ2Q77I5c1biShakWGnVnQzizzav5GbAlw
         oZCO8WXf3P/slCrnPlfRhsoWEju28nAe6JldTXTh/pBDRKKCSlnNwNSe5gxHeeTR46QE
         YIvpMPNVxIkuswtta50c+dGzClcj193bSf8mWoGXZXFP+URyLq+rIM3ytHtBQSFSCxZA
         LEETK526puLi288CQ+uplG+fQ7YbrNJHiCdw7P4X18KHeN2XrwcJBG9fekEe9jKp4LS3
         21ymH9k4es+6BfVlfliQGW5oELmOtC/2NdoUGGr2I5wdbNmWFk2nR84L6RlsoF+YhnlU
         zE3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=MtUDAduu;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id hx9-20020a170906846900b007ba8b8a416fsi882034ejc.2.2023.01.12.11.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3ha-005Odv-ME; Thu, 12 Jan 2023 19:57:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5E405303424;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id F0FCD2CCF1F7D; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.556912863@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:34 +0100
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
Subject: [PATCH v3 20/51] cpuidle,intel_idle: Fix CPUIDLE_FLAG_IBRS
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=MtUDAduu;
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

vmlinux.o: warning: objtool: intel_idle_ibrs+0x17: call to spec_ctrl_current() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_ibrs+0x27: call to wrmsrl.constprop.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/kernel/cpu/bugs.c |    2 +-
 drivers/idle/intel_idle.c  |    4 ++--
 2 files changed, 3 insertions(+), 3 deletions(-)

--- a/arch/x86/kernel/cpu/bugs.c
+++ b/arch/x86/kernel/cpu/bugs.c
@@ -79,7 +79,7 @@ void write_spec_ctrl_current(u64 val, bo
 		wrmsrl(MSR_IA32_SPEC_CTRL, val);
 }
 
-u64 spec_ctrl_current(void)
+noinstr u64 spec_ctrl_current(void)
 {
 	return this_cpu_read(x86_spec_ctrl_current);
 }
--- a/drivers/idle/intel_idle.c
+++ b/drivers/idle/intel_idle.c
@@ -181,12 +181,12 @@ static __cpuidle int intel_idle_ibrs(str
 	int ret;
 
 	if (smt_active)
-		wrmsrl(MSR_IA32_SPEC_CTRL, 0);
+		native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
 
 	ret = __intel_idle(dev, drv, index);
 
 	if (smt_active)
-		wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
+		native_wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
 
 	return ret;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.556912863%40infradead.org.
