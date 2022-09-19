Return-Path: <kasan-dev+bncBDBK55H2UQKRBYMDUGMQMGQEDGHNIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F03505BC6DF
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id t11-20020adfba4b000000b00226eb5f7564sf6442976wrg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=xgZIrWbISOECrQz/IYnrzdxHZtxgueLfwZEl3ALIUkuXRwERYuwROtwNQzLUlUJc73
         Aaiq+NszQEIDWWSeTx03uYg+1rjEhA/NdoNweuNL8gunB9eb7nznJdx/nQOaCdOz/wuI
         DAY+dbvP0oecClkMK3p3pkOgUU/8eAVWetX4OuWByjJK6I5Yuktg8TrYikfbwUWSlwBt
         B/GV69BoLS80enQJ1xaSvwQKP8zTSbfjEH+mb2y0CafSYl9vF3XeC9pIajFABTorCp+a
         8/DE8wFYww+28tggyNpLdLwLQNwFCwTcvVUYU1jxVQAby9ict9N8rj/ivOoDJoLW6887
         sS1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=8d60y+ETkz30cuAuTe0PwdK5XklslXf7DCp6/upecDI=;
        b=qLQlA4gTBK3s8sWWV+k0HRBip1lXdSFMKbjPOPh7UR5va+ptKl7IGS7Y3HPNJL3aoK
         fCx8s70g94+qWlceHKiCqKbSXJ4BraIxiH5Nb3R/vd/ZoFGnc77gWkHZMGaEpUWpJG7s
         HbXi0ENPVyCp7OoUy6iCN0Oki+OQ0nw/OKpicNYkxjinc/iOc1qovQmDV/KwNVX4ves/
         b9dpCBUBKwiYayo9kgGYgjmSuJYT2Dq50B7VSDnKWkn0eZ2fJoZUOrjTdpWqgV14q7sr
         di8oOynhINJtXPgny0tmb7RrFpT42bV98vwJgDfV8upclnxASxqdvdQos+x+W6OmLiKd
         YRvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eDRmeX8n;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=8d60y+ETkz30cuAuTe0PwdK5XklslXf7DCp6/upecDI=;
        b=krLOMgK7XJzgmakufKJuNyEqtFWtyedO85kMmDeTOeLPUzqcJ9NqiuBiGkFB2cE7MB
         MDNg9bTkn733A+LAxtD6yLNsDZYrlRrcS8nwRMlWLePpag4FXVblGpeRk5QKgsAh1A5C
         yt3nCn+Ff54kkR/Zpg+m0hoi3QY08ixanxFihppQdJ3oV1RAPJqW2LS8f1uhSHv/uXx8
         HzhBevuHYS3A9xFqsp7qAQrEDjSnaLfnFGKCPei+XtNENcmyxlf8HkEbeF0kuKIAKBsF
         fdQCKzdwIR8+UzI7Ip+Ziraf2X7VCq6rXypd5Nt6eDnv83Zs8j8iMLWN/QCvJWTaMyZb
         y5ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=8d60y+ETkz30cuAuTe0PwdK5XklslXf7DCp6/upecDI=;
        b=NiKBP6bO0jYmAccXFaEPNqHOod7evnn6YUP4NiwDPjSepAIipwnCLcK3uRDTFK1VHe
         0CG0XlHB/ppBz0Gk2AXvGpjZLJXmjG8UYn5BYZopkuSITibbN3RnqdYOyAMe8ShWndH7
         skrGNmWljmqaNiRL7iQe8YVPb98AOvXZ8ORyWh6Ojbnw+gg5x64mfbNYcLal+Us3jjX/
         rS0elin5XUvT6kfMy4VQ1lvhfi89DoWmM8hv0iyDTIRgmj0ybQR5o9K7AoH/K/u1r75U
         Y3ePGCG/Ph4hNoFAG7CUPjNpAftfdWFBhKjoE6+o0fsOV+MWVSnvva4uOa12t0RyHLoE
         p1hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf03egCxEepvnc2xcQZCrxMEkppl56/W6LgaJDmLQXYdaKwwR4xj
	oXojOeA6W++leWtNBo25wCE=
X-Google-Smtp-Source: AMsMyM5HSZBdBG4HAg3gJ5wIL0uBVb752w8Mpgk7/jN4LHmiqjtrDgvsL+T6onSs+vsldZz2N4wYEA==
X-Received: by 2002:a05:6000:108f:b0:228:c680:47e4 with SMTP id y15-20020a056000108f00b00228c68047e4mr10608648wrw.593.1663582689595;
        Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7306:0:b0:3a5:24fe:28ff with SMTP id d6-20020a1c7306000000b003a524fe28ffls1699647wmb.0.-pod-control-gmail;
 Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-Received: by 2002:a05:600c:255:b0:3aa:2150:b184 with SMTP id 21-20020a05600c025500b003aa2150b184mr11792462wmj.138.1663582688440;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582688; cv=none;
        d=google.com; s=arc-20160816;
        b=fMNgVTvgxQFx+akSlpn8HIL6d54zK2IL65XJMvk2lgd2vNHfbULZsFuBlUBjUWlM4D
         RHzV+0VpiPQeJhzUAwwHCkv3gg/E4PBt3KUxffUragqaZLm8QDEMIfcrDs5zbp/GaZih
         YqVa9AzZbNaHQ7T9zOvbJcCVTdB5xu5cCNkvj/icJdIXCvMpovibml0oCqeRLZmZMHr6
         lPdOswvv8OEJstQewGNPMToX7iMuQUuRlckE86eVg+FOMqEBqnw6r/BLVw1d0/X6HE+B
         ogpHTFIanMKFtd0WVfrqNruG4V87uxH/rnVBuHw4taeDdeQiWdFwm0edYSM8z8KG/FT5
         iZ1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=rveYe0whW8HL+t/HGSaazkf4IJzq2XAc7vdeRKjh+gA=;
        b=M/lC2uQB3/DYjAov8r/JD06UOZPXH3/PEwL7Lbv6wqLVNy9drhYyCOQlbrPKmCYssM
         Bv3I+Tyb5t2EXSzDuERTovv5L6K3m8efy5SxgIJyUszpFnsGpYMmLGPZlJr+F6odExak
         VkiIBKQsDgW3z86+7/Hl9WbuXta/sc4TSYqBQrKYPoK2243nR0BEVPKj337WfpWCUA/L
         BKt4M2cQtMdmjIvrm8IccERCjoogfSUNuOqlDYFsz1iA+9qomf/F5GMRX01vmy/1hajm
         n2i/rG6o1hUgYuTs/Q/SftTWXzYJPXEMbQ7GJvcThHab+PxrRL0PDG/sIRmxewiMYhkI
         uZ7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eDRmeX8n;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bv26-20020a0560001f1a00b0022afc97eb06si83868wrb.1.2022.09.19.03.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq3-00E2Ar-Lq; Mon, 19 Sep 2022 10:17:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 21444302F1B;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 45A1B2BABC0C2; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.886766952@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:02 +0200
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
Subject: [PATCH v2 23/44] arm,smp: Remove trace_.*_rcuidle() usage
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=eDRmeX8n;
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

None of these functions should ever be ran with RCU disabled anymore.

Specifically, do_handle_IPI() is only called from handle_IPI() which
explicitly does irq_enter()/irq_exit() which ensures RCU is watching.

The problem with smp_cross_call() was, per commit 7c64cc0531fa ("arm: Use
_rcuidle for smp_cross_call() tracepoints"), that
cpuidle_enter_state_coupled() already had RCU disabled, but that's
long been fixed by commit 1098582a0f6c ("sched,idle,rcu: Push rcu_idle
deeper into the idle path").

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/arm/kernel/smp.c |    6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

--- a/arch/arm/kernel/smp.c
+++ b/arch/arm/kernel/smp.c
@@ -639,7 +639,7 @@ static void do_handle_IPI(int ipinr)
 	unsigned int cpu = smp_processor_id();
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_entry_rcuidle(ipi_types[ipinr]);
+		trace_ipi_entry(ipi_types[ipinr]);
 
 	switch (ipinr) {
 	case IPI_WAKEUP:
@@ -686,7 +686,7 @@ static void do_handle_IPI(int ipinr)
 	}
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_exit_rcuidle(ipi_types[ipinr]);
+		trace_ipi_exit(ipi_types[ipinr]);
 }
 
 /* Legacy version, should go away once all irqchips have been converted */
@@ -709,7 +709,7 @@ static irqreturn_t ipi_handler(int irq,
 
 static void smp_cross_call(const struct cpumask *target, unsigned int ipinr)
 {
-	trace_ipi_raise_rcuidle(target, ipi_types[ipinr]);
+	trace_ipi_raise(target, ipi_types[ipinr]);
 	__ipi_send_mask(ipi_desc[ipinr], target);
 }
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.886766952%40infradead.org.
