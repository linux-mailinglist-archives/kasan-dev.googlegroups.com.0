Return-Path: <kasan-dev+bncBCV5TUXXRUIBBMUXZH4QKGQEUQS4I5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF5B9241778
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 09:41:39 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id p12sf4333272iom.18
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 00:41:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597131699; cv=pass;
        d=google.com; s=arc-20160816;
        b=wsWnFx2m6gOL3Q5aud09Ei+5XhOfshIUbjG/ce+SUxtVcF0KlJtOzmIOszlSsuDqY6
         tRDXD1hEXtQRlWXDMNQh2FjtQVZrdEOco0+7+xvkLMr0SE4IGDXYFs1BHzVAA7cmWjS8
         QMQ6stjGSuzEhorkDLDBd32C+Xclx71l47M3qY1yN1DtzLt0O1BPHeBGsWrSo2yOmm1j
         aA0ifRz07GRqKqMJytj/4NjIro72xHxTe94V6IPowotmorNaAjH4cuU5K2UnKLSwmRfV
         flAkKHj3s4tLTBoarpUaiXOooqTRLp8gA3c+zRQDYZNQOECwBC41stsgwR4psdUwevus
         7LUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=HRn+lrpzN6jDBHYP9ZYcKw9QUD/11foabWlL8fFKsME=;
        b=pnOMabOFAXzgHD3cL3afnwNgFm8all2ZvFj/94gFt4nAywSjZ9w0MeynOW+skBq8ct
         9wGTeGBPoqca0o5DjhrYn0CktXXAAdHF1tNAgpFrM7ueSGoKEBTVkb4q2p8EQiD5k33/
         QmHVFvH4So1mKEV3tLX8ReKETdzYrNJt4LjrTf0x6q8q9inTgnmwjxMG42mAyvDys5jU
         3X/RfowJcaYWPWGstvCo1JANgihQDZIu8c1/HKiYRiiFW0Aw+POrNuTzDdj6/0L2GLSJ
         VdyCYbhQ2PVF1Wq3IT9BOdJMwoAIAkjg71mS3mZ8QiHnrLzJB5XMwvylWp+XSOSFy2uG
         qxgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=c46YpCUa;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HRn+lrpzN6jDBHYP9ZYcKw9QUD/11foabWlL8fFKsME=;
        b=CJVIY1vZE1jQ03fViYclYuhKkb/sJgFhRg+qVZLxHpeTUSlH6tbpGSyuF4GQOCGm/I
         13kHt6RzlLYqxP8lpZINfOoozkYwK1nEa1BphWrtrS4tiPZh1LN7hK/CRYbfBYUwFeeT
         bGWnH/c7R9KztMPigb3rlg1EJsOTeJvi5X74HW+1QHLqIThYlkl50hVNh+kmoyZAgYay
         HaH3XZNLtTVGjU7qqk7LfytzTE6MigzEapgBK7ekYj/MohFqiBWa9ivsQo0nroHLXs4l
         Z0HUXi0/Dr/zr+cXWJcl62ICvjfqjqLiKLRrMmd0IgMJ/Q5ZTUT1/LiKx+CWjVrMdz7O
         5uHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HRn+lrpzN6jDBHYP9ZYcKw9QUD/11foabWlL8fFKsME=;
        b=D2ip6dBxVWEmt0+WiUGGCu21DQUHW15+qzzYWlSAIVg81ZiA5jaE4Hs6BgIXa92Kn0
         WRrM2hPhZ+B6cUajY+DHBcfVjN/2je3bR9VTq0Ou9DYR0+JczzryzkToNbIP1nkn64M9
         gBMjXpyUv6H0JmEoX91fzM3Lz11e7S5Tza7QaMClidLZbND5gXwZ5wAE9G+aQNNHhTl9
         Lkr9JvRFLsn3YmurC8Ule1SVOzahhFNSrxCPlDEyFulLTXWollzhbAppLp/VSkKCVXD1
         kEUgKFzrpZQVcNQSlQWUyY6VhjapNJPOCOF6yDt/GEYcXuN6+34ZcbLtMWiL/ParFXKe
         mDGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531W0AaKuBM2MuF5K6vat8koGlMVOLCKIwlZuThSdk3MvzqbYqoa
	dQXk5+dnd7QuWJ2U1nks+dg=
X-Google-Smtp-Source: ABdhPJyoHAt5mz5+yHzNjYOtZrNX+TDXL29IkMP05AHw29p3D4HlV2egTTTT79g3PsrLENUTKK6hrA==
X-Received: by 2002:a05:6e02:92d:: with SMTP id o13mr22149445ilt.76.1597131698898;
        Tue, 11 Aug 2020 00:41:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ab10:: with SMTP id v16ls4851389ilh.10.gmail; Tue, 11
 Aug 2020 00:41:38 -0700 (PDT)
X-Received: by 2002:a92:cd42:: with SMTP id v2mr22077255ilq.241.1597131698180;
        Tue, 11 Aug 2020 00:41:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597131698; cv=none;
        d=google.com; s=arc-20160816;
        b=QWh7XyMyxYm7OPoxn74joFZQk2yKCEfupuRc9Fc3/itiTUYtk7Scb5Z7CskNfxJFEp
         TCsK/JEge0Zflh/F0cmCIluqlupOofTjA9uDCHUzXbkc5IfVGq3J9UfGlV+Gwfii1xjA
         lECJiZAG9llqL2P0yff/GRdDLaQyocOmxoe5oovrZKvFd8+AmcpTX3evdLovKg6CvhhW
         g5gqJg3zkcgPiIPFD3646EToxyLHQKEK+P3IouvGXlDTBU5gxmp0IS1KI3zIp37hYyst
         it0tjKTwrU8b7YkCILWp3X0tQ/Yve3SqcpsX7SFWX+rbwR/sdEKhEO72HbzdivzXPW79
         id3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=H1ur41PMwJaDcTMSo/nD4VartbQ+qRn6j+If8bFfsJQ=;
        b=fhFro5gO3Omb69mbXqDBh3hHU2lwRQBJDZNn8ZGCmsirUq9T3KJDaM63rWJLAc52ZB
         M4hFBFAKcSqAG9KF2673IjFFsBh4ERVyyiTrHvDMZ8G1RpGt6ax4L7ocNgzbgKa75CZi
         zp7tsFeqy6F5p94HiVT7pK1/1Jm02rl5ofKGNY3X5z6NBctMhZaGrF6L5hcleaNP6syo
         kdfqoY4YFsms5zwwDRq7K3vaoQ6gu0MBTu0tnN0ybSU4J9cO25EaVSo9w3Nv/0cbokq9
         9RXqEa9L0YNHCL9fniJDVSuEbQmrlPQ+EdNRZXtYWQsvEPwOfr6nsCEWx3iAH5lKNlmY
         n/CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=c46YpCUa;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id o3si167065ilc.4.2020.08.11.00.41.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Aug 2020 00:41:37 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5OuZ-00067x-1O; Tue, 11 Aug 2020 07:41:31 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 56841980C9D; Tue, 11 Aug 2020 09:41:27 +0200 (CEST)
Date: Tue, 11 Aug 2020 09:41:27 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200811074127.GR3982@worktop.programming.kicks-ass.net>
References: <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200807151903.GA1263469@elver.google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=c46YpCUa;
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

On Fri, Aug 07, 2020 at 05:19:03PM +0200, Marco Elver wrote:

> My hypothesis here is simply that kvm_wait() may be called in a place
> where we get the same case I mentioned to Peter,
> 
> 	raw_local_irq_save(); /* or other IRQs off without tracing */
> 	...
> 	kvm_wait() /* IRQ state tracing gets confused */
> 	...
> 	raw_local_irq_restore();
> 
> and therefore, using raw variants in kvm_wait() works. It's also safe
> because it doesn't call any other libraries that would result in corrupt

Yes, this is definitely an issue.

Tracing, we also musn't call into tracing when using raw_local_irq_*().
Because then we re-intoduce this same issue all over again.

Both halt() and safe_halt() are more paravirt calls, but given we're in
a KVM paravirt call already, I suppose we can directly use native_*()
here.

Something like so then... I suppose, but then the Xen variants need TLC
too.

---
 arch/x86/include/asm/irqflags.h |  4 ++--
 arch/x86/include/asm/kvm_para.h | 18 +++++++++---------
 arch/x86/kernel/kvm.c           | 14 +++++++-------
 3 files changed, 18 insertions(+), 18 deletions(-)

diff --git a/arch/x86/include/asm/irqflags.h b/arch/x86/include/asm/irqflags.h
index 02a0cf547d7b..7c614db25274 100644
--- a/arch/x86/include/asm/irqflags.h
+++ b/arch/x86/include/asm/irqflags.h
@@ -54,13 +54,13 @@ static __always_inline void native_irq_enable(void)
 	asm volatile("sti": : :"memory");
 }

-static inline __cpuidle void native_safe_halt(void)
+static __always_inline __cpuidle void native_safe_halt(void)
 {
 	mds_idle_clear_cpu_buffers();
 	asm volatile("sti; hlt": : :"memory");
 }

-static inline __cpuidle void native_halt(void)
+static __always_inline __cpuidle void native_halt(void)
 {
 	mds_idle_clear_cpu_buffers();
 	asm volatile("hlt": : :"memory");
diff --git a/arch/x86/include/asm/kvm_para.h b/arch/x86/include/asm/kvm_para.h
index 49d3a9edb06f..90f7ea58ebb0 100644
--- a/arch/x86/include/asm/kvm_para.h
+++ b/arch/x86/include/asm/kvm_para.h
@@ -30,7 +30,7 @@ static inline bool kvm_check_and_clear_guest_paused(void)
  * noted by the particular hypercall.
  */

-static inline long kvm_hypercall0(unsigned int nr)
+static __always_inline long kvm_hypercall0(unsigned int nr)
 {
 	long ret;
 	asm volatile(KVM_HYPERCALL
@@ -40,7 +40,7 @@ static inline long kvm_hypercall0(unsigned int nr)
 	return ret;
 }

-static inline long kvm_hypercall1(unsigned int nr, unsigned long p1)
+static __always_inline long kvm_hypercall1(unsigned int nr, unsigned long p1)
 {
 	long ret;
 	asm volatile(KVM_HYPERCALL
@@ -50,8 +50,8 @@ static inline long kvm_hypercall1(unsigned int nr, unsigned long p1)
 	return ret;
 }

-static inline long kvm_hypercall2(unsigned int nr, unsigned long p1,
-				  unsigned long p2)
+static __always_inline long kvm_hypercall2(unsigned int nr, unsigned long p1,
+					   unsigned long p2)
 {
 	long ret;
 	asm volatile(KVM_HYPERCALL
@@ -61,8 +61,8 @@ static inline long kvm_hypercall2(unsigned int nr, unsigned long p1,
 	return ret;
 }

-static inline long kvm_hypercall3(unsigned int nr, unsigned long p1,
-				  unsigned long p2, unsigned long p3)
+static __always_inline long kvm_hypercall3(unsigned int nr, unsigned long p1,
+					   unsigned long p2, unsigned long p3)
 {
 	long ret;
 	asm volatile(KVM_HYPERCALL
@@ -72,9 +72,9 @@ static inline long kvm_hypercall3(unsigned int nr, unsigned long p1,
 	return ret;
 }

-static inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
-				  unsigned long p2, unsigned long p3,
-				  unsigned long p4)
+static __always_inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
+					   unsigned long p2, unsigned long p3,
+					   unsigned long p4)
 {
 	long ret;
 	asm volatile(KVM_HYPERCALL
diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
index 233c77d056c9..15f8dfd8812d 100644
--- a/arch/x86/kernel/kvm.c
+++ b/arch/x86/kernel/kvm.c
@@ -779,7 +779,7 @@ arch_initcall(kvm_alloc_cpumask);
 #ifdef CONFIG_PARAVIRT_SPINLOCKS

 /* Kick a cpu by its apicid. Used to wake up a halted vcpu */
-static void kvm_kick_cpu(int cpu)
+static notrace kvm_kick_cpu(int cpu)
 {
 	int apicid;
 	unsigned long flags = 0;
@@ -790,14 +790,14 @@ static void kvm_kick_cpu(int cpu)

 #include <asm/qspinlock.h>

-static void kvm_wait(u8 *ptr, u8 val)
+static notrace kvm_wait(u8 *ptr, u8 val)
 {
 	unsigned long flags;

 	if (in_nmi())
 		return;

-	local_irq_save(flags);
+	raw_local_irq_save(flags);

 	if (READ_ONCE(*ptr) != val)
 		goto out;
@@ -808,16 +808,16 @@ static void kvm_wait(u8 *ptr, u8 val)
 	 * in irq spinlock slowpath and no spurious interrupt occur to save us.
 	 */
 	if (arch_irqs_disabled_flags(flags))
-		halt();
+		native_halt();
 	else
-		safe_halt();
+		native_safe_halt();

 out:
-	local_irq_restore(flags);
+	raw_local_irq_restore(flags);
 }

 #ifdef CONFIG_X86_32
-__visible bool __kvm_vcpu_is_preempted(long cpu)
+__visible notrace bool __kvm_vcpu_is_preempted(long cpu)
 {
 	struct kvm_steal_time *src = &per_cpu(steal_time, cpu);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811074127.GR3982%40worktop.programming.kicks-ass.net.
