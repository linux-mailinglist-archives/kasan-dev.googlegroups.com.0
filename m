Return-Path: <kasan-dev+bncBCV5TUXXRUIBB3MLT33QKGQE4SEWGSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B1A171F9A2B
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 16:30:05 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id p9sf7143214wrx.10
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 07:30:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592231405; cv=pass;
        d=google.com; s=arc-20160816;
        b=b46xO0zf0hONAdVDO0+RRFZEDMDWTk2951MVHsAvwPOw5o2EBz+ceBKDAVkWC1zIRT
         I2AurHZBfC9Ks7nsmYvadpUOy+KrOXgxJSwoWlwNpewCTwkO65VzULNVQFxAZMw5vgbw
         VniHYWeITIU67/IYud1tf44hfk1NyjidDYZqKybXJ6xvX31YJbmXD4jw2VmgxF4rTUT1
         GNjn8UlLzNyrE+yWwOtZHuZRPxpyBeY/md59SOlpjOCCUEgQBy2RXAN6JOv7D3OrbLge
         2ZKylAtDsgYdT/TegmLvsmVR5W3PXAqUHoR5fAupLsBM7XzNCZ3hp8VVFSQ+9TTcJrmb
         19CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=REbjxFVRXZJHckEtut+G9vShKU2grwraQ2XQ0BWakDw=;
        b=O6ihXQVA16YkGA76V7SYD0N8Uley7ZOA1+29yw8B89zAPnYSmBacD410mGjXyg52Q1
         UkIErC/71CtJ8O9gpjAaEbSM5ZqZE1V+c1h/ZGtOxv7ioQxJ9zHkjwwhHEzURI4D59tE
         a9dbedd/IDC8Zd10TlUNR7eysS8DpoEdVEt+Ayw5W2CzJcqXmNJtDX+xlzy3YmB2IRS2
         tf19jmGplwj7UqIrTrcsFuYLXfrLDOFG0WsJ7D0xdbfX6R0P5tnwg4H8cmpv6Rwi+aTM
         Ww3jGP4kWrUJ2yOhQjqpXeUhOhX9PJSzo7x/VQCkX4N9+prDtkZud/AbySmWcYxytc2R
         iHHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=RCpCMYm2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=REbjxFVRXZJHckEtut+G9vShKU2grwraQ2XQ0BWakDw=;
        b=QxKMwmRvPyYo2C1lne1NUclVFrABKPyJlLLLWVxSFyqlBP5WqtCHo95bAFpB+eyN82
         fNbmQC5sJ+K4Acrja1j7sI3PvQHm/z4Wre9qQumhAnh2/gAqat7WwzvEqSNKc9T1pRlg
         0nhgZsCq9lWSdLcMC60u9AlrObv6SMzZkjOscT6ToL2xiqgbuTaZL7M6hpXFkqkyReOc
         hIAdKlYkEcEIKwInx/FB/vNtJCaWN4x2BhvExQ0A1mPUkyCFTA/Cdu0H+HGiEGQIecnx
         oICil+2MSZN9tASb8vHVOpqDcmsuOtwyPhrT50M7vV7K1WxhzovTSguF6LLlwm3gxmG4
         pmgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=REbjxFVRXZJHckEtut+G9vShKU2grwraQ2XQ0BWakDw=;
        b=FpSTm9jwX94FJeODP/Y1TP3NZda4gkj6DKc4mvIwbsKmO6JtauPoIAaB8UqGDa29hH
         RYaE1gOV9uX4W+n6lfYGM569p7NUs8Cx1hSjf05bPWStqmh9GdHdIB3SkSoNTxXMywYF
         ndkgATxbyil14Y61jGUmJGV1Kv1QmKyK+qx+yU0PQOg/3Lfvyp/SAP1uleSr1fZjKB61
         cAVwl0YhtPkJGpHQRCtYfHoWRlv+9UC3PD+f4uCDpygwy7ZOmug1oSKZ4LD2PO3VkP4Z
         607yqO7eDKcsK1W8oPRQRh5t2quP2yoI7DUiolU8MSSEzCWVQIPHZ6evgIoJGUUooTly
         JDEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fg1E4ECCirbnqUw4yB4mtnaHB/7PCLsUMFhDI7NyBQLBDXYM6
	lxQPA96TE/uX6AxkkyfLGsc=
X-Google-Smtp-Source: ABdhPJyHHrzxw7RPuLVMxBOEg+KbiLEtlJ1pKhOBJOpS3xu0k16yQ1q68C1c3wpN1zs6PwwqZRdTmg==
X-Received: by 2002:a1c:230f:: with SMTP id j15mr13812508wmj.100.1592231405426;
        Mon, 15 Jun 2020 07:30:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d84:: with SMTP id d126ls7635346wmd.1.gmail; Mon, 15
 Jun 2020 07:30:04 -0700 (PDT)
X-Received: by 2002:a05:600c:22c9:: with SMTP id 9mr14471249wmg.68.1592231404883;
        Mon, 15 Jun 2020 07:30:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592231404; cv=none;
        d=google.com; s=arc-20160816;
        b=m68cu2FyLUQmc/jU28ECj3Q/e5MZpVKPDuxtlFUb4XwyaKecjGynehBI1J6IbpwdCM
         7xWeYZzOJdyxbRegfIiGZgLxe8XMrI0SUt2Tq0gvyrVZHGvzapRKYMv2R2XTPyaqO7IL
         /dzYlwHjbGl3C6Ewx3XwBiWVixeTZWSJ/a9BYPx4ni4veuVsy39ThZE/8KxppStCifW/
         z0VOouidfIg1m1S8DQTxHoHPxC3UHLUiS7k+F35AlJhey158svqSXZ7GCDcu9zAslyOH
         Vpw3MZeZD/bfe11yWoybdEDN5saRxQ+uKEHDhzi06iirgwCNiVXsBP05rclaZiU/nMhv
         1i8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iVtDey7osCTiXRlBck0DMsdzE3CHMm8eourPYCpuPzc=;
        b=jPAY/Nmuq6xLoV4MA80am5PA2f4yfEVuiwTWiFiIHGl393mOZsYGTvENfA9AxBwwTi
         iWicgKOiyjW+4bQD2QEikmP0HjHw0eRxzullj+cD9hwH9Qz2N+OIN/xv6WwDkaQooJNi
         9XZEYKf2nbQLK8e9awkWPNx/vQ2zkQm2n727dhc0k+fU+TB+Fi7iVkoRBfGw4W7bUD7K
         66Y/KUOgjouzgmBzzI+uIYilBrDKjGICZ7lWOZ36VhjwTSqJsAVbxBuKhEgm4oLZ3Lk7
         qIChp53D7DOxriCIFJDb2Crjttp364fm3E+FH+Q3DqQaIylZ0VAjBgLAuus8tsLVXKnr
         U+hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=RCpCMYm2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id o195si758574wme.0.2020.06.15.07.30.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 07:30:04 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkq7W-0006Eh-6c; Mon, 15 Jun 2020 14:29:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1BBA33028C8;
	Mon, 15 Jun 2020 16:29:50 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 09DC3203B8172; Mon, 15 Jun 2020 16:29:50 +0200 (CEST)
Date: Mon, 15 Jun 2020 16:29:49 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200615142949.GT2531@hirez.programming.kicks-ass.net>
References: <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=RCpCMYm2;
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

On Mon, Jun 15, 2020 at 09:53:06AM +0200, Marco Elver wrote:
> 
> Disabling KCOV for smp_processor_id now moves the crash elsewhere. In
> the case of KASAN into its 'memcpy' wrapper, called after
> __this_cpu_read in fixup_bad_iret. This is making me suspicious,
> because it shouldn't be called from the noinstr functions.

With your .config, objtool complains about exactly that though:

vmlinux.o: warning: objtool: fixup_bad_iret()+0x8e: call to memcpy() leaves .noinstr.text section

The utterly gruesome thing below 'cures' that.

> For KCSAN the crash still happens in check_preemption_disabled, in the
> inlined native_save_fl function (apparently on its 'pushf'). If I turn
> fixup_bad_iret's __this_cpu_read into a raw_cpu_read (to bypass
> check_preemption_disabled), no more crash with KCSAN.

vmlinux.o: warning: objtool: debug_smp_processor_id()+0x0: call to __sanitizer_cov_trace_pc() leaves .noinstr.text section
vmlinux.o: warning: objtool: check_preemption_disabled()+0x1f: call to __sanitizer_cov_trace_pc() leaves .noinstr.text section
vmlinux.o: warning: objtool: __this_cpu_preempt_check()+0x4: call to __sanitizer_cov_trace_pc() leaves .noinstr.text section

That could be either of those I suppose, did you have the NOP patches
on? Let me try... those seem to placate objtool at least.

I do see a fair amount of __kasan_check*() crud though:

vmlinux.o: warning: objtool: rcu_nmi_exit()+0x44: call to __kasan_check_read() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x1c: call to __kasan_check_write() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0x46: call to __kasan_check_read() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x21: call to __kasan_check_write() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x1c: call to __kasan_check_read() leaves .noinstr.text section
vmlinux.o: warning: objtool: debug_locks_off()+0x1b: call to __kasan_check_write() leaves .noinstr.text section

That wasn't supported to happen with the __no_sanitize patches on (which
I didn't forget). Aah, I think we've lost a bunch of patches.. /me goes
rummage.

This:

  https://lkml.kernel.org/r/20200603114051.896465666@infradead.org

that cures the rcu part of that.

Let me go look at your KCSAN thing now...

---
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index af75109485c26..031a21fb5a741 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -675,6 +675,14 @@ struct bad_iret_stack {
 	struct pt_regs regs;
 };
 
+void __always_inline __badcpy(void *dst, void *src, int nr)
+{
+	unsigned long *d = dst, *s = src;
+	nr /= sizeof(unsigned long);
+	while (nr--)
+		*(d++) = *(s++);
+}
+
 asmlinkage __visible noinstr
 struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
 {
@@ -690,13 +698,13 @@ struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
 		(struct bad_iret_stack *)__this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
 
 	/* Copy the IRET target to the temporary storage. */
-	memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
+	__badcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
 
 	/* Copy the remainder of the stack from the current stack. */
-	memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
+	__badcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
 
 	/* Update the entry stack */
-	memcpy(new_stack, &tmp, sizeof(tmp));
+	__badcpy(new_stack, &tmp, sizeof(tmp));
 
 	BUG_ON(!user_mode(&new_stack->regs));
 	return new_stack;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615142949.GT2531%40hirez.programming.kicks-ass.net.
