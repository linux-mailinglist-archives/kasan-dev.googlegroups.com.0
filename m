Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6EWT33QKGQEVHRZYTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EDC91F9AEF
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 16:53:44 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id u15sf5008590wmm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 07:53:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592232824; cv=pass;
        d=google.com; s=arc-20160816;
        b=UURdqz9gmk0LtctBJ19nvNIcYOcy1VqC/2iQnxMPpQUYx1f0R1Jd0PM+srnIW2X7DE
         /ZLDg62Szz5N1hNFwtGNiU5SFgaHCqG0ZEu2C5qNREv4q3iEsV6l2Ol51v8ukskIiIe9
         7Fw+R99ZPrWEyEaxYqnxAsoL7IBVyUVWJCUFoDb0R+M0fPISjQSWyONIjC4FrnbJb87l
         N3BPM/2gDzlHapRUXglVbvE6BQNuL9Rv2ZK/7p8pkeduliB9SxBzFWUNsn15DuoDecQt
         +NjlJ+TzqLEB2GkYpXlRRv+tVmjD0D+eDN6D89gz52inVEY72YgfR80UIsC9hiPJPadt
         WaIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=L9mVgS1FnhwoQC/DZeZkCMv5rfKmbbshslLM/Qi98Vk=;
        b=hCro+j6I+IDXErk1N2IKqo7pdcPKpZ9TLIOIYzOsDEjG86+5wqXsilJU790bxQ44iD
         jc3qUbBDqrLf1CFQy3mIzOfHibEFa6rts9JhyTRfzbVeekJMWKimzBk6Di+9JuR1u+y3
         PjFizWmGsb2ueWngxqitHyv1Xubc+1pOVFbC1vY227Fq8KJpvbhnM07OUn0IDx0vO7Tw
         X74IH4uV8pa6NWD7u2A9TNks0DU+ziBPQs2fB7RTtC4tWXN3UMazsUFdSQVTVxUtjz2p
         mn1nlb2dF5/D2ZoDDXtV7JDUOgO41SS3qXe5xkAPeHPLkPfhoPteoms2aaf0YMfPSV8b
         PXhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pGbdVD61;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=L9mVgS1FnhwoQC/DZeZkCMv5rfKmbbshslLM/Qi98Vk=;
        b=owWZf8ctD5yOfXLV0ryFalY2yevwYyVu3qCgguWBr4wBPSastWcMIdTuiMiS0t2exT
         anMKvd2OBJ2ki0KxY8juyM9/SW87YbghhA/9dqs18oflMx1TmyongMrx9Ow4j/VAq/eZ
         8QFrr9O5dwA1pzt895VKrO6gi4X3kj8IjWjxEU340ZlTK36O3JxC1vTMsESZPz1B9rEv
         63PYXimyU4RCzEZdFUN6hEgOyFgdh/05LTXeKY06CLRPw3bFW5EXSwvnaldvX1SsL/JE
         ORmxwcdO5B1GpGDd4QXLpRNv6lInSswY63rK2V6xUofZn9PYKbQzqD78HnITGFuwXrQq
         V1SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L9mVgS1FnhwoQC/DZeZkCMv5rfKmbbshslLM/Qi98Vk=;
        b=JZXMxiyB31vJEVEBxV7eF8RmfhvM897OFKtcnJJkeSkKqaBjz5mzZuxBuUdeN5EcwE
         VEz6+ErrlRM8sXlD414FWHp+t/Pn6qGgVeZSAmriQmwv50EEP4ffRBvWCnDWAZmLm0hR
         rptY3BNjycEPBl6MYP9vNqLbZ6n089Jbc+T3bjiNrMLBWha8efB0/g0PmMwXmaogy5sJ
         7WNO76aDwsKxajbx8q29LEX6IO4kCyDsTZ+SFg4KAsgNRLmPkUeCKf9aiBRGZhoDrUOu
         h547bHs0uZSHE4ApZMHVog6QLYjR9kKvVcr7f43QG9fKPt8ffwBEt9tBuwY+fARSR2Nb
         SFaQ==
X-Gm-Message-State: AOAM53149Uk+9+GHbZX00ckvb34XaEDWVTV/bJiqHXAw0qtTBIh9srEo
	2Upf6Tmcq2bSyhJMnZBv/zo=
X-Google-Smtp-Source: ABdhPJxg6Ytbga3baEj2mCdhxgKd5q0k+kJ11fBBvLrInOpRaIxviwY77Hvsbjn0ebeT+v6xB93WPA==
X-Received: by 2002:a1c:6a13:: with SMTP id f19mr13993415wmc.142.1592232824150;
        Mon, 15 Jun 2020 07:53:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d84:: with SMTP id d126ls7672552wmd.1.gmail; Mon, 15
 Jun 2020 07:53:43 -0700 (PDT)
X-Received: by 2002:a1c:1d16:: with SMTP id d22mr13933058wmd.174.1592232823661;
        Mon, 15 Jun 2020 07:53:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592232823; cv=none;
        d=google.com; s=arc-20160816;
        b=MjhWk5p/E3T/4bHYyBFg/I448/WcAKPjSlRlPr0HcKlopL3AzBa+a/h/1zt4oW9mKG
         trhnWVFqq+PnuIljPdKbnYC2ImhvnzZ6uJBzvORstU1iz5uxq1oZpQgcaCclVSymPHDt
         vVGae0DwLOlcqyjtTSw2tIPUmpeOdR7QkoylL2vhmoOnqg4FVBLkYRbUdXJZwtVjrAVh
         1IEtvIPEKiI28SrWXf88KXbSRMCpzCP7YcR62PhkqQhL9LF34R+IuT8ZwVtHL1N6tYZv
         I9LdhZHMh1aUfQQLzbvypuClCL+WP7nF/eF9D9oyt6lMTF3swn6gDGQ51nxBV5ZrA2z+
         /MAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=TO/UlS5nQwaskSKkWnxhtbr58cxMAZAbeQDdoacE6pI=;
        b=sSq1X5dG5S98JyOkbfqTXLo4ZwEK/tWv99DoP9rv/sVwaOv/49lpBWGoO8eGnuOaM9
         eR4uRDBe47J2H1kgHF23sSJBdak7YImR9dB7OWELodl+s/V1gB38S3O5x/5JfZmW4fYN
         UAKZpEO2TpS3ogxUqTXPihYnPwoNz8X5CuABK3myxTsgF8s+RcQNxTR1S32PnQc0PNfN
         zW3i2EqInveFdt43THzeGnnfHUo8Q7tKfEA+VNwrElrbYhwFUAAkte9Vm7IDxXrvO6kM
         ODJbW96vLyN4jG2VqK+3DSKAo19JKnfyduS8jbtWUstrtlyA9rmxOhbh+pMkB4YwFEZ1
         XX+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pGbdVD61;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id 12si12551wmk.3.2020.06.15.07.53.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 07:53:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id u26so195376wmn.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 07:53:43 -0700 (PDT)
X-Received: by 2002:a7b:c76a:: with SMTP id x10mr13701463wmk.16.1592232823049;
        Mon, 15 Jun 2020 07:53:43 -0700 (PDT)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id s8sm25864689wrg.50.2020.06.15.07.53.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 07:53:42 -0700 (PDT)
Date: Mon, 15 Jun 2020 16:53:36 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20200615145336.GA220132@google.com>
References: <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615142949.GT2531@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pGbdVD61;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Mon, 15 Jun 2020, Peter Zijlstra wrote:

> On Mon, Jun 15, 2020 at 09:53:06AM +0200, Marco Elver wrote:
> > 
> > Disabling KCOV for smp_processor_id now moves the crash elsewhere. In
> > the case of KASAN into its 'memcpy' wrapper, called after
> > __this_cpu_read in fixup_bad_iret. This is making me suspicious,
> > because it shouldn't be called from the noinstr functions.
> 
> With your .config, objtool complains about exactly that though:
> 
> vmlinux.o: warning: objtool: fixup_bad_iret()+0x8e: call to memcpy() leaves .noinstr.text section
> 
> The utterly gruesome thing below 'cures' that.

Is __memcpy() generally available? I think that bypasses KASAN and
whatever else.

> > For KCSAN the crash still happens in check_preemption_disabled, in the
> > inlined native_save_fl function (apparently on its 'pushf'). If I turn
> > fixup_bad_iret's __this_cpu_read into a raw_cpu_read (to bypass
> > check_preemption_disabled), no more crash with KCSAN.
> 
> vmlinux.o: warning: objtool: debug_smp_processor_id()+0x0: call to __sanitizer_cov_trace_pc() leaves .noinstr.text section
> vmlinux.o: warning: objtool: check_preemption_disabled()+0x1f: call to __sanitizer_cov_trace_pc() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __this_cpu_preempt_check()+0x4: call to __sanitizer_cov_trace_pc() leaves .noinstr.text section
> 
> That could be either of those I suppose, did you have the NOP patches
> on? Let me try... those seem to placate objtool at least.
> 
> I do see a fair amount of __kasan_check*() crud though:
> 
> vmlinux.o: warning: objtool: rcu_nmi_exit()+0x44: call to __kasan_check_read() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x1c: call to __kasan_check_write() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0x46: call to __kasan_check_read() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x21: call to __kasan_check_write() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x1c: call to __kasan_check_read() leaves .noinstr.text section
> vmlinux.o: warning: objtool: debug_locks_off()+0x1b: call to __kasan_check_write() leaves .noinstr.text section
> 
> That wasn't supported to happen with the __no_sanitize patches on (which
> I didn't forget). Aah, I think we've lost a bunch of patches.. /me goes
> rummage.
> 
> This:
> 
>   https://lkml.kernel.org/r/20200603114051.896465666@infradead.org
> 
> that cures the rcu part of that.
> 
> Let me go look at your KCSAN thing now...

I tried to find the stack that is used by the crashing code -- which led
me to entry_stack? So I tried this:

--- a/arch/x86/include/asm/processor.h
+++ b/arch/x86/include/asm/processor.h
@@ -370,7 +370,7 @@ struct x86_hw_tss {
 #define IO_BITMAP_OFFSET_INVALID	(__KERNEL_TSS_LIMIT + 1)
 
 struct entry_stack {
-	unsigned long		words[64];
+	unsigned long		words[128];
 };
 
 struct entry_stack_page {

No more crash. But that's probably not what we want. Just a datapoint.

> ---
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index af75109485c26..031a21fb5a741 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -675,6 +675,14 @@ struct bad_iret_stack {
>  	struct pt_regs regs;
>  };
>  
> +void __always_inline __badcpy(void *dst, void *src, int nr)
> +{
> +	unsigned long *d = dst, *s = src;
> +	nr /= sizeof(unsigned long);
> +	while (nr--)
> +		*(d++) = *(s++);
> +}
> +

If we can use __memcpy() here, that would probably solve that.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615145336.GA220132%40google.com.
