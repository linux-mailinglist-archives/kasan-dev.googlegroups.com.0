Return-Path: <kasan-dev+bncBDBK55H2UQKRB2UDUGMQMGQELZK2HCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA1D75BC707
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:18 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id qb30-20020a1709077e9e00b0077d1271283esf8140080ejc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582698; cv=pass;
        d=google.com; s=arc-20160816;
        b=zRPhmLqkWFw1RKPtuhWVpUKNvu7vnc9Vsu4sqbWz8VNSZQnYYft8NqTkAg5p3MShO7
         1RUkMCSgMUx0y3+QgZPDnwAoRrJI0hTL3JwiCAXNmhq6W0D2qyil/gN1K02+YGAlInFu
         n4vvWVz47j53daWyxELCwKgy56uR5EEuoH1tByaYCLqtYMubq1atCk3auwpwrqBdm0g4
         A5szLrcVcJsyFDljCWdvUKLHBRDlCsu0Za958Vb+ft2qY7P6DGlxIbPzkUyxlhG6I3j6
         8Rmr1qVfugKkb0s0X7axCRxjd/ADgWuxB8pBPcxcBAu0Vid/HuW1tEkBNJ6ZCCUCG7De
         WXFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=OKPqHWfBus1bW7zUi5iVFRNlE/9i4bLrYy4q9Y0G50c=;
        b=rMh/89StO0zLuswsZBY/IgHweZ4EGhOgXSPE535rSyV/DkjStUmh5mMCAAdRpc+6QP
         /1o0KB50zZNjbnQDW78QD3K+aESRvxP5dJB6/aRgxKSvH96T8aysHOzEcF5UHS7Ijer3
         yLGIAiTt6rHFTod+82h6/H67edQnvNHkbzgj+Wo4G3WJSnKcm84tjb287G7SMZ3gUCEj
         TbzNbjdHUCAaykREi5WMbYXe6Q5FRDiIdEupo5+4aBAno3ZwGv5ho61dsDnSmANH0bek
         5PDUNS6jZigo6sTGoUoyWn6yPRmEdjm+zLk0bJxpNewd3X18q08HonPSqk6K5GZes2kh
         rZvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=j7VwHdvJ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=OKPqHWfBus1bW7zUi5iVFRNlE/9i4bLrYy4q9Y0G50c=;
        b=Y7YJmkA/CprbyKSiOYaOLosYFxq4DjsIh0leVwyIGLkifSzZDyQ6SnSi8dFmFi2q3f
         tkG7ex3GpJs+Bkxt5JIyxvx+Tka3jdqiVDCONthOfI795duCncTfK0FVnAjD+ickPYlD
         gZZA89AVZNtJ1iqvCiOvE+QhbDHyJqjdP6Q+6uEd+HOCKnYSNGX5uR1BTcMh2yHCDSQp
         yKEEcvMzm8h2y9jp0qxizEXVSh9e4ymBZreP94ieCYXmRbRnpKCfEh/VBkoLfAla3PR/
         GAlkIS70WpYzR6s+517Muo/anZkkimuPu0MyOb1zfrql052YZaAoqKEgZF66HjrFoij3
         H9uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=OKPqHWfBus1bW7zUi5iVFRNlE/9i4bLrYy4q9Y0G50c=;
        b=ctiOWzrjBAIse4pDmhRQOIe97E6TX0xZkOPzomEX4Gdmz8K/OD2MTmGpsn5YnMZV0n
         RRtShf5XfPt2kF3/9IUGxmz/pZjeXzjoEp34uZO5AoUycAfywx4fMf61hASTde8ku29E
         Y+jvsbmA3hNJu0QD+U4BlKkMMaRijih6FA1iPUCvgbFsfmJClUEmSran3APqJu235Ywe
         CydMNy7U6bgTPPJ3Me+NlKYHQQjT/j3cWuHasNHY/fqLXaqC5ESF9UDRDsgwubCxbPid
         OfJ48fQX7oCKc8Dnqpf8BOZgNxdwTQ8AZqAP6e1povjK+/fyZKhUnrWpRV7kGjNi5rSA
         xEoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0r9mx/Uxnw442JfzRh0Jm/LD9aoKAwf7uB3qB85/SK/4bofJ88
	lh4TWkB7VF/K5wuE1JZ1UnQ=
X-Google-Smtp-Source: AMsMyM6EYjCOJJUSFYT1ehpGc+rMKS4XFmxy227DCIUR70e2ohX8z4Sx+yiY0paUsTT20IvdJI0gPA==
X-Received: by 2002:a05:6402:3552:b0:451:2037:639e with SMTP id f18-20020a056402355200b004512037639emr15050657edd.136.1663582698507;
        Mon, 19 Sep 2022 03:18:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f895:b0:780:f131:b4d9 with SMTP id
 lg21-20020a170906f89500b00780f131b4d9ls1751694ejb.11.-pod-prod-gmail; Mon, 19
 Sep 2022 03:18:17 -0700 (PDT)
X-Received: by 2002:a17:907:6090:b0:781:44ff:443c with SMTP id ht16-20020a170907609000b0078144ff443cmr3954552ejc.485.1663582697281;
        Mon, 19 Sep 2022 03:18:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582697; cv=none;
        d=google.com; s=arc-20160816;
        b=cK5+Hj3sP6f/tSlOTwbmUcD9awCfGtT5CDjxo1daUiUcASqA6EJSHvM47VhI5m4wsz
         TvPfU/lPfZLXcrEYilGQNBbcdbK9MmZBcM6mb4a7pn7Qr2l/wG3pJb1VWlmKPMo6LJ1s
         OzqLSj9RW6/QhmfEZDg+XXc1RbjxKF6gwitdu58WYCAhZY+pgQ2RcB8UCTt8lgEVDXtX
         LQbUQY3yAWkOh/sLsD23b5CSJxVZA5DLVIX91aCDYmFigeogmIMIfd31U6GTaMWvUiW2
         tgOGUmq5g9+DGgaR2J5+5x+b8lhV5NawBpipTGeJ0M3fpxRX03jSdIm9hMiNyCFovSyY
         7PSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=rYkYazBjkfDgerhAXoQmSQo0bqbhUZdR/pxZJBUI/ng=;
        b=v38iINiFEpGYDJt4myNTC0MbshQTbytKQTJmvjAXNeNPCpsciwNWzv0b5Q7CteTV9S
         s0KUt8wyYA09ZhKg0QPHy5jD+67RUXTX3BGVZRDKb2TvyRF9HZTH5sbe5zcEqFSahKNz
         tH00XDFCCXysNyRCOpI729//XJDFLHJ/bDLnQFcOv2DaIHiYzvPUXQ3WfOdg9zWlalza
         MkvRrtjafAubl4PZe/hlZBiO9gVXwNhLBuj8VqyzoVpyBZ7a2Wy/m7UI5IqeiycnJBFr
         Gp3timNATzQ05K4wEekefclmgaGGyziMSex4sBOoHy2u/OHDgsy+crBm5ndlFtOysddC
         1aGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=j7VwHdvJ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id s20-20020aa7d794000000b0044ea33a8ac8si1069988edq.2.2022.09.19.03.18.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-00E2BJ-Vb; Mon, 19 Sep 2022 10:17:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4F39F302F49;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 6E0182BAC75AC; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.426692140@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:10 +0200
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
Subject: [PATCH v2 31/44] cpuidle,nospec: Make noinstr clean
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=j7VwHdvJ;
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

vmlinux.o: warning: objtool: mwait_idle+0x47: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_processor_ffh_cstate_enter+0xa2: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0x91: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_s2idle+0x8c: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0xaa: call to mds_idle_clear_cpu_buffers() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/nospec-branch.h |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/x86/include/asm/nospec-branch.h
+++ b/arch/x86/include/asm/nospec-branch.h
@@ -310,7 +310,7 @@ static __always_inline void mds_user_cle
  *
  * Clear CPU buffers if the corresponding static key is enabled
  */
-static inline void mds_idle_clear_cpu_buffers(void)
+static __always_inline void mds_idle_clear_cpu_buffers(void)
 {
 	if (static_branch_likely(&mds_idle_clear))
 		mds_clear_cpu_buffers();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.426692140%40infradead.org.
