Return-Path: <kasan-dev+bncBCV5TUXXRUIBBLEZ333AKGQEWGEJL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 46EAD1ECEAE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:37 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id k13sf1220601ilh.23
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184556; cv=pass;
        d=google.com; s=arc-20160816;
        b=hHVoqtdPxlWxwzRetRRpnxKbkd118kp2DA//zXEEjVajkow+eQzNTvW9c1h6TasaA+
         YYXVtiZrh4eSvnxh6gYuScPo/g+WmmWlXfQAYzn7/CMAozfbur2Mqd5m4m3uC0YdauQ5
         hdN2CsPkYceCwS/3HC5ge9iiCO4IQOxAnSpj/0P7gVX1fEkCLB7fiKwzRMbs1JJlX/1F
         JUPLrFHprxXHvAV8L9DZbFmGh5+EPnU5Foqn7sAEtC3t0VTWg9xBAYaUECuUnzW7uQ9i
         bzM1/aVg2njUAn2UdWosQhKDQnq11aDufP92vKMWXc666Eo+DRr5ochaixipiQ8EFWFE
         FtzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=IEK2lPIs4PFYOGvhU3SZI0uy/Er3ZgEt7A2WxAEha9E=;
        b=bFbnzZXt3YZ0SFEEppy8OwNM9SSt7SqQ7asMq2bLftSj3u133z5kvmevZQJQd1i1Rb
         ziJipW4t5dLSHZNji4hTpgL64kw503ZghuUHtELlpN+T18WUWeb5hwpDw7VN6/UxWVbB
         vbt8JXaTS3AlFp9F3EOlYcy2ijrOgfxx5j9syYsRkGmEfQmSXW1S/Nyc4m56uZ5FPxep
         21xTUp6jTBKvhFf9CI3ZrIFk7k5W4AffglDuppfDqwEHltdDPvcuBO3GaLACcaRUAEad
         PBqfjcBwDmEBJMdQN5fACuE+1Gk4oINUl/rKp/VuhonXoIN0EVO4aVRpHhSs7grraJ/R
         BEVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="KVH/fv2R";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IEK2lPIs4PFYOGvhU3SZI0uy/Er3ZgEt7A2WxAEha9E=;
        b=cqO5rwu82cPYJxFpmDxd3TUkezd2pzQtcvbdcR0XhFeNx2EL2CQQ/6vlcNWT/mFpPV
         0VuV/sStSn0Kmd5X6IallG6VQhlNIeWtKJbWpir5H6gFBLyLy8Vy1F9dhEfTixEIcwg9
         tCjgeIn337PME6RyBUWdCUcT2ezOJXgP0O4LntXpQA7KjuNYdAXQQMdab5beySroPCFv
         OOUwU/d+VQItly5hJwUHkLaG81f3DtFfgM/hDQgEMNTbPr7SheV7Xsc2ArPsZj2cRyW+
         ZPlKVRM5KjbL7+wZpsZZQZ/B6Bd0/jw8PFBaFWEL0pO+y4WD8K5iFGuDpVhKgV8dD7Sw
         jd/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IEK2lPIs4PFYOGvhU3SZI0uy/Er3ZgEt7A2WxAEha9E=;
        b=YvuiZO23Iyg5+HvcNCpkkYTCqYkaBF9JArEUVvqQN3sR4WPjMQFdLuMd9R7schASUA
         l0BjeAETN693qg1b8OIopowxw4K4UGRa+PGVVMCsP7hZ0f+Mm4jj+lQ/jXBhPQtgiYmF
         dMxcStQ94SRqwgMc8XjS4bXKRcjHyeDSKzPCT13jPJn6fgmwZw1NvOlTTmAs41O3uuH9
         5+AYi1srr2YilSE8+z+VoKO741+XdEnPS4o9LeM76LTzrEBfvkd9Erbp1AAyJGanbNim
         O5IQqWqwpRSR2/tRI3hvRrjR4e6ycnqCWipjQnjiopwvUK2Xu7Wj4eh60PQ88aPWDFZA
         On2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hgUb2EW4IWsIeYkCDgheHXwCJolYaa1YzcgUum0pQLxpk5exc
	lPj5J+RIZeJ2AjN3sfVqxsY=
X-Google-Smtp-Source: ABdhPJzoycG7j4uF4YI61xF5pc6c6zHxlnrU5AhxBPPNv+k1JTSenGuRBc7mSRWk/erASbZmjWvkNg==
X-Received: by 2002:a92:9ccf:: with SMTP id x76mr3434818ill.50.1591184556328;
        Wed, 03 Jun 2020 04:42:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:820b:: with SMTP id l11ls285792iom.1.gmail; Wed, 03 Jun
 2020 04:42:36 -0700 (PDT)
X-Received: by 2002:a5e:8b43:: with SMTP id z3mr3198159iom.62.1591184556024;
        Wed, 03 Jun 2020 04:42:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184556; cv=none;
        d=google.com; s=arc-20160816;
        b=oQ6fZcFTSuCWNfI9gOSC0y6zeCEXTQElZVd7uHODSlAHYDKq8w3Npp4HyK+Wpi4o6w
         DHtm4tJj3SBOgwx2iPtTTknglJn98r7bwFCzLcedukkG4jCkJuQe0oAsa1RICSVtOQNk
         ZeeRFHsJQDJkkoz+S1rCPtMYVOvQG+UEQ0NAE5QK2HvPKdxogp+oxNHWP5zP+UTpZOZh
         zH9rf0d1N3b8Plxm7bYKYtoJ14Sj07rJrZLWLBsn0oxf/SPPfFytUiZY2tgeZz+y8u5l
         S0a/xqsBkbgk9UHbKrBSirmw8bJJREzoDUk0KYfL5z13KiXvWqHL2w8k0p0crF6TRhte
         GlFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=qNhYv2Y/S8hWOcHSxiTZb5nzE+u9vWtPn8+l4Z+FKJU=;
        b=yQvO11dEybvFhi5hkUI8yYhAFqeQB9mWecMvuOomHnMrqPVP8bxtscN2lTGnlZgHjm
         TiW9UMNbVe3Lx/ZjE576KeCVuMfC8DF/28wUw/qaRiuDR85cfmccmQ1GCMblVfjLEFwD
         Nzfv1DtkeRYEhVoFC3sg5zn3aVIZdwSPIUeDJjsbODbXDO7wEIG8L/5xqQNPy30IZX6n
         OOWayJmeAd2UvmEze8iVY4Ae3YarA1ioeNrjAVTXHDeRNU3YJzMMqkQiv7MV4mNaxLI1
         VrjoPj/vPaMLZmGnz78H59sdZ68qC5Hn7ysPb9GHIg7ZUAgmIe9Mu/WcdqlLm7vsA9SB
         zI0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="KVH/fv2R";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id g12si78345iow.3.2020.06.03.04.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRms-0005oh-Uh; Wed, 03 Jun 2020 11:42:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BE803306CDC;
	Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id AEE09209DB0C8; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114052.012171668@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:18 +0200
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
Subject: [PATCH 4/9] x86/entry: __always_inline irqflags for noinstr
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="KVH/fv2R";
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

vmlinux.o: warning: objtool: lockdep_hardirqs_on()+0x65: call to arch_local_save_flags() leaves .noinstr.text section
vmlinux.o: warning: objtool: lockdep_hardirqs_off()+0x5d: call to arch_local_save_flags() leaves .noinstr.text section
vmlinux.o: warning: objtool: lock_is_held_type()+0x35: call to arch_local_irq_save() leaves .noinstr.text section
vmlinux.o: warning: objtool: check_preemption_disabled()+0x31: call to arch_local_save_flags() leaves .noinstr.text section
vmlinux.o: warning: objtool: check_preemption_disabled()+0x33: call to arch_irqs_disabled_flags() leaves .noinstr.text section
vmlinux.o: warning: objtool: lock_is_held_type()+0x2f: call to native_irq_disable() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/irqflags.h |   20 ++++++++++----------
 1 file changed, 10 insertions(+), 10 deletions(-)

--- a/arch/x86/include/asm/irqflags.h
+++ b/arch/x86/include/asm/irqflags.h
@@ -17,7 +17,7 @@
 
 /* Declaration required for gcc < 4.9 to prevent -Werror=missing-prototypes */
 extern inline unsigned long native_save_fl(void);
-extern inline unsigned long native_save_fl(void)
+extern __always_inline unsigned long native_save_fl(void)
 {
 	unsigned long flags;
 
@@ -44,12 +44,12 @@ extern inline void native_restore_fl(uns
 		     :"memory", "cc");
 }
 
-static inline void native_irq_disable(void)
+static __always_inline void native_irq_disable(void)
 {
 	asm volatile("cli": : :"memory");
 }
 
-static inline void native_irq_enable(void)
+static __always_inline void native_irq_enable(void)
 {
 	asm volatile("sti": : :"memory");
 }
@@ -74,22 +74,22 @@ static inline __cpuidle void native_halt
 #ifndef __ASSEMBLY__
 #include <linux/types.h>
 
-static inline notrace unsigned long arch_local_save_flags(void)
+static __always_inline unsigned long arch_local_save_flags(void)
 {
 	return native_save_fl();
 }
 
-static inline notrace void arch_local_irq_restore(unsigned long flags)
+static __always_inline void arch_local_irq_restore(unsigned long flags)
 {
 	native_restore_fl(flags);
 }
 
-static inline notrace void arch_local_irq_disable(void)
+static __always_inline void arch_local_irq_disable(void)
 {
 	native_irq_disable();
 }
 
-static inline notrace void arch_local_irq_enable(void)
+static __always_inline void arch_local_irq_enable(void)
 {
 	native_irq_enable();
 }
@@ -115,7 +115,7 @@ static inline __cpuidle void halt(void)
 /*
  * For spinlocks, etc:
  */
-static inline notrace unsigned long arch_local_irq_save(void)
+static __always_inline unsigned long arch_local_irq_save(void)
 {
 	unsigned long flags = arch_local_save_flags();
 	arch_local_irq_disable();
@@ -159,12 +159,12 @@ static inline notrace unsigned long arch
 #endif /* CONFIG_PARAVIRT_XXL */
 
 #ifndef __ASSEMBLY__
-static inline int arch_irqs_disabled_flags(unsigned long flags)
+static __always_inline int arch_irqs_disabled_flags(unsigned long flags)
 {
 	return !(flags & X86_EFLAGS_IF);
 }
 
-static inline int arch_irqs_disabled(void)
+static __always_inline int arch_irqs_disabled(void)
 {
 	unsigned long flags = arch_local_save_flags();
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114052.012171668%40infradead.org.
