Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCMY4P3AKGQEAG57UFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 12E211EE25C
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:14 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id c30sf1948009ejj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266313; cv=pass;
        d=google.com; s=arc-20160816;
        b=accXT3BtAMCLZ0KcPbZE0M+7vbsh4BH0J4p/Hf/F2YTogbxS2sGTz7gOEjLbie0tlT
         f9tvH1DNr+Z9HgSexf457p6Ydzv6lSvsdFJiiBe4sDXxh/0jHrLFW1B9F3IHWnZ42Gz6
         15S9JaJjKLiK9SE9rQ7gxaqDmxDjUadQ7ouJBWCFI5YgoFlm3zLf+QEOMW4PzukWEJKD
         8pjCQFW0+XuJnz0m50CE6CWll1+tS7TWcMIkAybnkr/z+B7FZskXsP6KT6qGduh6Bxor
         iZPxwaPrWBH0JFXp3XceeUtETtoWzd3ldwZ6A0JFKEJCJl2wPWEp/2JP0qAv6mOnskFF
         ATSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=kVcPVIMb6I0LBvdnn0g1HqpdOz7whmIepbYesak6iY8=;
        b=DcstqKME6mfySaUnUNJqG8mDr2e0wf8nZx14WctISQ8U7wbWJLVJpJNXrI2kg9WeZS
         CMr1ZAhvF3GeQwBgrua8xxAYYiuCL2yoj58KnexfqucP/baYrv4p1wB/OBibssMjAvGb
         /Hjo4jzPWlNuY6hpQHIVxESMNdO+pVwLQLdaahTYi7vxA0JLsCr3WCP9eGVLEOBQfH/i
         N42iiL7WMGfx9efrRZQbczMJqBsKX/PltkmQtp/X+GH3Iq2A3kHMlatSJtPIs42uKWlE
         Uslz/kGEExnXPW4S27sSCwyZkjmAOXXA2Gch+zM3kjHYLWRjaA5Jz6I7KvKZrUEJKETD
         +3Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bi8dzwz+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVcPVIMb6I0LBvdnn0g1HqpdOz7whmIepbYesak6iY8=;
        b=RluoO6FV0Qb41olxY+SykDdkqamibJxS8nT+W7PpVyWcwrIvJZ5g0G7pxV/lwKcDVS
         QSSVdcZASO9e9HFZ+yZ0nKATvevO6PIZP/zqZozyU6pw/eCt3DP0Y1PqP7x6lAXJvpkC
         5okTrAmY0yQbkMuYsLp67FWcq3wl47saPBqtoFiOl0UJf3itJOkPQl/FkkG8JzfOe8kk
         G5IkNXq4Vtm9FXZX/x8WYod36cnsyK18l7MsDYFe9JeDRYi86xaGuPhdv1ePhVVXa3W7
         yIkcI40ckCdoZwaNK3/Zfq8prVNPVO0zmFYnz2yy8btCroPqci7yaf9o/4XnHxNWYWji
         dtUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVcPVIMb6I0LBvdnn0g1HqpdOz7whmIepbYesak6iY8=;
        b=GVkrVDN+4lC1ZQIgGZuPdr+tMGxk15DBFcZJFASBoR7bpm5Nz8diUU9IF60epHU88Z
         oRc7SEHntTIiKBIGXprCkJmIqx1VTAfYsQm6q1nRt3tsK+VR61xt0Qw1F7EUQ4gczibl
         LT41rLkUBe95EWm7m74wcZiCd2jHsdGUaevVssFlqbFrj1JqZVVyxMrx8wucYrHOsEIB
         yL1c2pcME4rqs1sBpPKhoMW3GR0Z9lhwoT+BGJ01yEe0TywvwzPPHUwmJa02fXGklLQD
         euintNJwvTHOZQNXHSWjwGxJb3BOOkr5p9hTqQs/VZQZ+4y6fMv9znj2ELEfFPQHEGhb
         giGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531i563RKO7QyXNZUEB6nLUrbn8W689mM3v9VtTJOFokfDdr5b0Y
	Q6AVMfCCp7Hbt0XHVNYmhQE=
X-Google-Smtp-Source: ABdhPJxIxFwDe+yHlc4nVYQHdwHJtVHb2iHynxD+LewbTzVWdhUv6NYbbYXpQrcoky2CWhvCu/Q0jw==
X-Received: by 2002:a17:906:5410:: with SMTP id q16mr3341797ejo.103.1591266313772;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a82:: with SMTP id y2ls2261472ejf.2.gmail; Thu, 04
 Jun 2020 03:25:13 -0700 (PDT)
X-Received: by 2002:a17:906:3041:: with SMTP id d1mr3313543ejd.7.1591266313316;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266313; cv=none;
        d=google.com; s=arc-20160816;
        b=wIpDMSPUEfqzBEf6aWURCes3O1EKmiWPlluKtL887374D5LADzBU5QrzP26i2baEao
         Dz/R+yyNRf6DYUi5NdqZU7CBdAlMwwFxdPotCwJ4JTy2JGxhjDP2t71e94g/Pflr9X0x
         9ZtsbZiJIiV+MZK256Rlao7HcBIxiVEztJmsQjgEyIZlvyHkR2+YFqpwZvPjQ1Vwhogj
         vNDv8KazFNpSUMNvMysfUoXl/TW7Ys5R1AQfq7ZouKyRsG+rcN7eVjvREWN6lH/jv1rI
         8ClKWEylrMVVnraH3qadXech+EGepzfKL9nwYakHz9btBMe57UeT5K739dqlCj0yi8cN
         H1eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=rJwPalFYVnWeB0dUXsd0mLDO/aHiuwnD6jNPC91vIKI=;
        b=huhtVGi0uV/lCxO6ZW829oB7+ZWZnjaHICTGIaxgizSHmiQ1wcxpEjAR/k4GblN0pD
         FleoyUTUOQs3s4I7A77nxijGX4pGQ02O1BFnkfpsEDsq+2Ae+mWVLx/oUKzK7Z0B3Hhj
         wkZDBUBhYCpmXEYJaUG08+iL3PF3qV67KJstqKYg+ZavIYvizuBz2jXbGqly/WpnREXz
         ti+qxSVQRsahsOYfovO8USVOOAyUU3vmN3ys92CLO244nIHK0r/gHgazfbb9mAXikF7d
         4NIzmy7bgMyxvtYZmwun9djfa+K1dx/Oc3WkWzx4ZnKoyq8tjXczShqyh/mZ8N3X6Pew
         kwIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bi8dzwz+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id p17si146178edq.5.2020.06.04.03.25.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3e-0003tm-Jw; Thu, 04 Jun 2020 10:25:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0F011306BB7;
	Thu,  4 Jun 2020 12:25:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id E51F020CAE76C; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.250420698@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:47 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 6/8] x86/entry, cpumask: Provide non-instrumented variant of cpu_is_offline()
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=bi8dzwz+;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

vmlinux.o: warning: objtool: exc_nmi()+0x12: call to cpumask_test_cpu.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: mce_check_crashing_cpu()+0x12: call to cpumask_test_cpu.constprop.0()leaves .noinstr.text section

  cpumask_test_cpu()
    test_bit()
      instrument_atomic_read()
      arch_test_bit()

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/cpumask.h |   18 ++++++++++++++++++
 arch/x86/kernel/cpu/mce/core.c |    2 +-
 arch/x86/kernel/nmi.c          |    2 +-
 3 files changed, 20 insertions(+), 2 deletions(-)

--- a/arch/x86/include/asm/cpumask.h
+++ b/arch/x86/include/asm/cpumask.h
@@ -11,5 +11,23 @@ extern cpumask_var_t cpu_sibling_setup_m
 
 extern void setup_cpu_local_masks(void);
 
+/*
+ * NMI and MCE exceptions need cpu_is_offline() _really_ early,
+ * provide an arch_ special for them to avoid instrumentation.
+ */
+#if NR_CPUS > 1
+static __always_inline bool arch_cpu_online(int cpu)
+{
+	return arch_test_bit(cpu, cpumask_bits(cpu_online_mask));
+}
+#else
+static __always_inline bool arch_cpu_online(int cpu)
+{
+	return cpu == 0;
+}
+#endif
+
+#define arch_cpu_is_offline(cpu)	unlikely(!arch_cpu_online(cpu))
+
 #endif /* __ASSEMBLY__ */
 #endif /* _ASM_X86_CPUMASK_H */
--- a/arch/x86/kernel/cpu/mce/core.c
+++ b/arch/x86/kernel/cpu/mce/core.c
@@ -1083,7 +1083,7 @@ static noinstr bool mce_check_crashing_c
 {
 	unsigned int cpu = smp_processor_id();
 
-	if (cpu_is_offline(cpu) ||
+	if (arch_cpu_is_offline(cpu) ||
 	    (crashing_cpu != -1 && crashing_cpu != cpu)) {
 		u64 mcgstatus;
 
--- a/arch/x86/kernel/nmi.c
+++ b/arch/x86/kernel/nmi.c
@@ -478,7 +478,7 @@ static DEFINE_PER_CPU(unsigned long, nmi
 
 DEFINE_IDTENTRY_NMI(exc_nmi)
 {
-	if (IS_ENABLED(CONFIG_SMP) && cpu_is_offline(smp_processor_id()))
+	if (IS_ENABLED(CONFIG_SMP) && arch_cpu_is_offline(smp_processor_id()))
 		return;
 
 	if (this_cpu_read(nmi_state) != NMI_NOT_RUNNING) {


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.250420698%40infradead.org.
