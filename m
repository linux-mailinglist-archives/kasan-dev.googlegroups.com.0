Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDXHVL4QKGQEHXKBSZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id EAF9923CAF2
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 15:26:38 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id f13sf3497717ljj.15
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 06:26:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596633998; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBwDiwGdwfsYHCkJAAN99sTanjkR0lozmpXcxD5emtxLvAL9ZPDW1TcxDCDjPDKM96
         PS2p2TAvO0ckS+by+Pu7d0ZeqFF05rkTnmBc5FxdeHU8HAPXkrmSJZOi0ViwOjUxmYwo
         zqEU9yt1YgDeWo9LyiEHs6FbZdPknhX+2istEySgjYg1NHEA86mKYsrLM50OK3Q7pRT+
         qjCMG+qB1oZj40zNqEuyrdPMQqGWlBxANg/xj1AEiYdkiqVoeL/ec67mWJwnxqPAWtNo
         CP3sBv1eqBjHK/Jrv/oCjLROjfh8AYVy3lKJR2ANMlhYzByoYk+fcmVKcNvVHOzRTvqY
         g0cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=sbd5rgO8EwtjUFWo4vkfgNj0mEXe6/b1MVemTpLXJRI=;
        b=j6T1Z8zceMwqbekge3GO1k+Mzaf/nyHPxsumfD0zSc8wg+4kL5/ATYy9mZOHstgyzT
         NHFpeQOIlcAqkt1O0GSOqs1QgSXp7lOmtXLnD4QqPP+trbsL88Ar7ewwuyV9D6qQZrmQ
         oSmwInpk4Hcg6YwpTdEHTA/AgEwFkpgIAWDmzQ3YBkbC0krA3qEc6NmLNf/cIoRxUqBS
         WTTbDunVvKqEy31txLwXyDhY+zrimJRt0hJkP+EKmGlqUoV3SgryX0WlzI3CmJ329rLZ
         35CAJ4ed83LOJnNRE8epTcw+AihKuuDZXF1hF7xf7p85a3YE5WXjhJK6lhtTPcEkSfqG
         3BfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F7rF0IMW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sbd5rgO8EwtjUFWo4vkfgNj0mEXe6/b1MVemTpLXJRI=;
        b=OI/PDIAfNfjNnzcmIFqaFSZzH13rySokUEEyDT93A3EZfedlCBk4D8E98h7mfh4Dt8
         VctauD67Q+fA41EX/E9cCYgsf2uzBpCOPoILi9qesOj1VtgRL8ViqdOh6c7/PwNO6qdZ
         uSb7XWa8e3d+nPAAyQkU0gWpzQ64OarNJMoOwAeKbMgIbX8EPI4zAmITRNDBUdn/tPN0
         +1XkOWTgqWefEXMm1d1zG/v96kuosrm9W0C/DSYDa44do3rv+ocBfDDQQ1aBEOl3BWhW
         277anRP/NkcsiJy0uAgTV6H3Oz1ZX/BiJc7qKqo2scR4U+Q5/dJhKM318x67jmQepme4
         E7fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sbd5rgO8EwtjUFWo4vkfgNj0mEXe6/b1MVemTpLXJRI=;
        b=Nst64hcXX3oGqMBvfdFIOnd7Ls9kLQjbClDVG4vpPzr4bveJO8jmB7IS7DR4GNeLkw
         iQ1tZ15SwP1fPm6yXoTIfoyMVzwyRHJCoSWMb+DcpZnDzzP6GDRGVUpCA0ec/tF/T/aJ
         OHzcKB0Dlqy7B/oQ35jmAmmFDLTOma0vc6l3mJASaYGnD1kRvj5Qh2F9jOgBk3cRueBo
         PkwWgtm8TafVq2OH7BKjtsreyhKdgPRM9Y3iPtZVQ90PYDWxK9ItRMb2XBGVJjY4CQ8c
         QpvSoxU7btun9msYOdn9zzW/K4f8oPMpTq79TRRf2YXUpZRZB2SZJ6TZBHSKiqgSAlkF
         lJQw==
X-Gm-Message-State: AOAM533wFvYspUbJZd8bFlCfnwbW1JVM1Ik3YXnjQ66oLk/sF8V0MLCc
	5wIzSOKa/Y/j1WVJE82DeFA=
X-Google-Smtp-Source: ABdhPJwPOEIu0wWOj+IubL9mrwmX2QQ5Z68RF1L/y+Ir+oaJ5UBAb/J6j2KJDoY54xAIhNA2KZhHog==
X-Received: by 2002:ac2:5624:: with SMTP id b4mr1585772lff.131.1596633998499;
        Wed, 05 Aug 2020 06:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9dd2:: with SMTP id x18ls454172ljj.5.gmail; Wed, 05 Aug
 2020 06:26:37 -0700 (PDT)
X-Received: by 2002:a2e:9843:: with SMTP id e3mr1494235ljj.57.1596633997765;
        Wed, 05 Aug 2020 06:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596633997; cv=none;
        d=google.com; s=arc-20160816;
        b=Cw8jWoa4H6qcNRbwOWR+zJAzwuFbBbOsX/fKf6Ulj/LXAuRhYdvmE5phMWBfXXjGU+
         x2BkZM6ZPnPQRcIFnjaB9+ReiJdjWwhlXB8KMIOBU/4FHGPgLHYZf2oRiraX+1Vigenb
         UWeaz8hyyriLGvY0v9/mnjfbmfMR/A/lw1hJwm5qhKeOl/XKwxbrX/eLHqDMJozg0yqV
         0qi8aE13f1aHEHs5lnf7pEAh98XMyp+CzowqSWXqNESX8s0rCbUmlnQiwg4b4lRVNvb7
         GBivfcdA7EsEsw2ZrSE/+nPwf+z599hX4SaB5M/JdJkV1NvZzbAXxasEXbrqQJNZdbVp
         WAPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rz+460zN+OkszOn8+vBru36XCbCu8scZ/4ePoWYVtUg=;
        b=NpmDhawfoKzCHCnrJo/llFg858OeVELAj/oaXEGiGK9Sx2lnX7o+OaqKUyNin1sBBv
         EUhuehBrRs14WvOimKP845ZN2I6axYrlhltpRKdvb2HMkVNEU7tv4k1DAYP8L1CCz8um
         hX0DC+QfxcqzU8J9vZOMV+QWkyrrMZT5FkGca1lEzgagtT5iu6W1TgrNy+EfnSHVnSTw
         oYrvzs8hlCqMfYN3N/CGyaOPKJvOphqY02oGOu2FONlA+W7QDuhlNwY30JAwqsv3Pred
         HKUkwA8ivG3iOutpMKeAUVKmyi/M+GupdNiPNgkvJ+8OqxJn6pG+Q0s6OgWejrmaDATJ
         rlHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F7rF0IMW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id t3si115042ljg.1.2020.08.05.06.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Aug 2020 06:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id y3so40701907wrl.4
        for <kasan-dev@googlegroups.com>; Wed, 05 Aug 2020 06:26:37 -0700 (PDT)
X-Received: by 2002:adf:cf10:: with SMTP id o16mr2613948wrj.380.1596633996070;
        Wed, 05 Aug 2020 06:26:36 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id p15sm2718271wrj.61.2020.08.05.06.26.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Aug 2020 06:26:34 -0700 (PDT)
Date: Wed, 5 Aug 2020 15:26:29 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: bp@alien8.de, dave.hansen@linux.intel.com, fenghua.yu@intel.com,
	hpa@zytor.com, linux-kernel@vger.kernel.org, mingo@redhat.com,
	syzkaller-bugs@googlegroups.com, tglx@linutronix.de,
	tony.luck@intel.com, x86@kernel.org, yu-cheng.yu@intel.com,
	peterz@infradead.org, jgross@suse.com, sdeep@vmware.com,
	virtualization@lists.linux-foundation.org,
	kasan-dev@googlegroups.com
Cc: syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: [PATCH] x86/paravirt: Add missing noinstr to arch_local*() helpers
Message-ID: <20200805132629.GA87338@elver.google.com>
References: <0000000000007d3b2d05ac1c303e@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0000000000007d3b2d05ac1c303e@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F7rF0IMW;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add missing noinstr to arch_local*() helpers, as they may be called from
noinstr code.

On a KCSAN config with CONFIG_PARAVIRT=y, syzbot stumbled across corrupt
IRQ trace state, with lockdep_assert_irqs_enabled() failing spuriously.
When enabling CONFIG_DEBUG_LOCKDEP=y, we get a warning about

	DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled())

which we had seen before due to KCSAN-lockdep recursion. Due to
"lockdep: Prepare for NMI IRQ state tracking", KCSAN was changed to use
non-raw local_irq_{save,restore}(), assuming there is no more
KCSAN-lockdep recursion.

It turns out that the arch_local*() helpers in paravirt.h were missing
noinstr, as they themselves are used from noinstr code that is called
from lockdep. When inserting debug-code that warns us if lockdep is in
the stacktrace from KCSAN, we get,

	RIP: 0010:kcsan_setup_watchpoint[...]
	[...]
	Call Trace:
	 arch_local_save_flags+0x11/0x30 arch/x86/include/asm/paravirt.h:765
	 check_preemption_disabled+0x51/0x140 lib/smp_processor_id.c:19
	 __this_cpu_preempt_check+0x18/0x20 lib/smp_processor_id.c:65
	 lockdep_hardirqs_off+0xaa/0x130 kernel/locking/lockdep.c:3801
	 trace_hardirqs_off+0x14/0x80 kernel/trace/trace_preemptirq.c:76
	 __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:108 [inline]
	 _raw_spin_lock_irqsave+0x48/0x90 kernel/locking/spinlock.c:159
	 wake_up_new_task+0x2c/0x270 kernel/sched/core.c:3338
	 _do_fork+0x27b/0x4f0 kernel/fork.c:2474
	 kernel_thread+0x85/0xb0 kernel/fork.c:2502
	 create_kthread kernel/kthread.c:315 [inline]
	 kthreadd+0x427/0x500 kernel/kthread.c:634
	 ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:294

pointing to arch_local_save_flags() in paravirt.h, which is called from
noinstr functions in smp_processor_id.c, which in turn are called from
lockdep.

Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/paravirt.h | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/x86/include/asm/paravirt.h b/arch/x86/include/asm/paravirt.h
index 3d2afecde50c..a606f2ba2b5e 100644
--- a/arch/x86/include/asm/paravirt.h
+++ b/arch/x86/include/asm/paravirt.h
@@ -760,27 +760,27 @@ bool __raw_callee_save___native_vcpu_is_preempted(long cpu);
 	((struct paravirt_callee_save) { func })
 
 #ifdef CONFIG_PARAVIRT_XXL
-static inline notrace unsigned long arch_local_save_flags(void)
+static inline noinstr unsigned long arch_local_save_flags(void)
 {
 	return PVOP_CALLEE0(unsigned long, irq.save_fl);
 }
 
-static inline notrace void arch_local_irq_restore(unsigned long f)
+static inline noinstr void arch_local_irq_restore(unsigned long f)
 {
 	PVOP_VCALLEE1(irq.restore_fl, f);
 }
 
-static inline notrace void arch_local_irq_disable(void)
+static inline noinstr void arch_local_irq_disable(void)
 {
 	PVOP_VCALLEE0(irq.irq_disable);
 }
 
-static inline notrace void arch_local_irq_enable(void)
+static inline noinstr void arch_local_irq_enable(void)
 {
 	PVOP_VCALLEE0(irq.irq_enable);
 }
 
-static inline notrace unsigned long arch_local_irq_save(void)
+static inline noinstr unsigned long arch_local_irq_save(void)
 {
 	unsigned long f;
 
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805132629.GA87338%40elver.google.com.
