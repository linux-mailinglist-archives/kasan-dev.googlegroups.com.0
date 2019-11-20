Return-Path: <kasan-dev+bncBD7LZ45K3ECBBJ6C2TXAKGQEWILIJSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 73AD910388A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 12:19:03 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id l6sf16159790edc.18
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 03:19:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574248743; cv=pass;
        d=google.com; s=arc-20160816;
        b=X1vNQv4OthW8vs49q76ZU58aBWRqok+rfHRTEczSl97TqIUWwZsP9CouOKngBYxp74
         332XoojTxF2407uaUanHkowwnVQ9DYjzTxl40o43F3QNWVlz5yOVMIUiSmRFUUiCp1cm
         DtZMdCf5G1diGKzmtUB8wXqCKmNB+h+k4tA1EW6T+5euolVxqrT0QD83wfSrvAguYxX/
         HpTi6zNoX/wsFYgEHTD4JW3NUgooml7OzMVrNlv5c7q1QKaT7/qReFGv6bbZ4FhWDtc7
         +ZgyBJ1kfW0YM1hIkXmxe4Wwo5c6juLDVpqMHBAiy/CAz15qSTZX4O9JF5X6mMxxp/8X
         IKYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=02lqK0L/WqLQfOz7Kg6BJwmANhb3WI92R+vPi5sW+hA=;
        b=xb5S2a9gYZSjMBUdhupRrBwtxO2CVVbhZAhLbst+ny0etd11+hPZBYNf/c8Sd9kC0U
         TiPuq132+3eDfUZLhqz349qq1R9IZInsGpNLMdkuUUkkboEvqBDlg7VDv/keEqTvav42
         L03JgclkCEe3cVArAX5Bulb32/PusYLok/euqDUwQdCz7A7ZjpvkeQXoeodP+JC1eVzx
         E0JcSUir9B1XWRGSSWsxkSrvYmfQm504bNQz4uLBzTrz2Z8j3kr2ktcMBw5eeh7IS1qS
         XHhel10WT+MsPrz0Y7OHIgW/ioidLgv74GtTyQ4mUh4Aws/5HnFRfkLDuAiTNW3SqCZd
         96fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="deKA/Qnx";
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=02lqK0L/WqLQfOz7Kg6BJwmANhb3WI92R+vPi5sW+hA=;
        b=GLke4TxpWfCcy0zcuFnNZaDhLu8+snEeKSyICb1wP0sWM0xK5AnUui6oSQvqY2Pnhi
         Sc9G5TWbTDJfkkbH/E2p5D9k450qz/L/kI/B2h3HVQ8hiGFhgvhqJfFxAtH9QhPgRHc4
         CT8XI5NCnyINaOaAsGeSW73gAlaf57NmkEzVZAOrzQW/TCxm+7k6w2/iFt19ThK4zdoN
         TuByrbdDTnEN4kpZQmuxirOmP7Ace6+tXOxGgdUOrdvTliXGZdKNmcLg2d2FsxxSxnoY
         IX58IhqsqwWu91CULoRwJkZ0XDINE10Yj8gi9XVfoARo1VPhROhwi2hBzaEx1jhXNCAZ
         978A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=02lqK0L/WqLQfOz7Kg6BJwmANhb3WI92R+vPi5sW+hA=;
        b=XtqEFXZjK5+bOikK5+pAF01XHqTC878cqfb2fxHWTAlxlAFRFDsSczQBKdlCmMQE9i
         3qzAKbjlYum92IdtmVzuHVeHjCk+45ahq58ERjaNeA3YNXy9d8N5es0GibbdKG3YNK1N
         8XPtK7CIQh1xrKbrk+UhS+oguJiO+wBu9VStAvxJhU0VWAZS4EddFwg6tP8zWM2Dj/nd
         Oado2gYg02AYAu3RWqQEEbYT8A7sbXXrkLLaRCyP9i3aEwdNTZhWxQ8deJ8ECemHP/cZ
         e0UFO+gJQDN1j5lkd/S5ATTB4n9Qx+S5D3NYbOcw8evfS5YT2T/fw7v8gstHWraLtHfo
         Ho0w==
X-Gm-Message-State: APjAAAUr1AofnUEyuK6ukxG2bDvh5tp0IEJzez6fiOjcSMmAhaQVnvSD
	HtebzDknbsp2eJSexVeJUEM=
X-Google-Smtp-Source: APXvYqySqEH8n+nAh52PlXYk5dJqJl8gnIOdaifWlAuJblaI8UVdWVLwmbNTQtWqZbvFDz6Cm/gOlA==
X-Received: by 2002:a17:906:6a43:: with SMTP id n3mr4716759ejs.31.1574248743134;
        Wed, 20 Nov 2019 03:19:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:80ca:: with SMTP id a10ls954146ejx.0.gmail; Wed, 20
 Nov 2019 03:19:02 -0800 (PST)
X-Received: by 2002:a17:906:245b:: with SMTP id a27mr4857118ejb.192.1574248742473;
        Wed, 20 Nov 2019 03:19:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574248742; cv=none;
        d=google.com; s=arc-20160816;
        b=r15+RJ62jP4IFZx8FWUELgXttGGg7f/+WOG6e3YoVaHR7SZHy0jwi39afKz5SvKAye
         01uUGgFaxFIy8FQY7PdeGwzFi32ho9HMbxSyC+Wmk2wrZibQqFHiklrXs9cE2PU81ey7
         ulCacri9yLjxa5lTJqw+HQgz+8Qm1APt0juH4LonWB6kk4KDmB1NWfu6+DpTTyMjKnnG
         IOkXjrEV6UNaIV7SQ9d/JlTAFGzlidyMz775sntY5wEYuQbl3hkkHbvtmb1PmH59HIHM
         48VSCpw3BrlaC3nGGjC3N6e8rQc6rx2AdnFw2UsUR7H8soy2dwW786EauSVrPwKxf9Fc
         5sLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=IehKOdRvP6ukM4yKhwxMCQI34wVSt7ku4o5K+No94hY=;
        b=Qi7WxPSraQb2GnfS79gYjXEeDa2CQRqpAPQUONwM/w14GvhlVQ+yMfuAQLLRyNIZvn
         ECg1E+zwxZgjrPi1seGohzPEx/MSnTW1DeF0nuqsN6hofasdFJgIKQvoH4FOcu79wKAD
         pZOSPTnIoSFRSbLRkTCrPOeZ3SGClDMZ3DvBDkhEYP+xrSSOFnBB2HGO73VuQc/vTNfU
         vgTqO8gMDFIahaaDlIjnyLQACsTKDBMoFqeH8iyylG9749kMxkHnX6pPAuaDtytqukx1
         kKLJmZRmzC83wR9kGw0r0XbQcrPzhDs/1At+OfgBj573u+9A80AJoJZiscPyRrJ2Lnan
         ksjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="deKA/Qnx";
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id x16si178156eds.5.2019.11.20.03.19.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 03:19:02 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id z3so763732wru.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 03:19:02 -0800 (PST)
X-Received: by 2002:adf:9f52:: with SMTP id f18mr2498126wrg.51.1574248742163;
        Wed, 20 Nov 2019 03:19:02 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id d202sm5873847wmd.47.2019.11.20.03.19.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 03:19:01 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 12:18:59 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120111859.GA115930@gmail.com>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120103613.63563-2-jannh@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="deKA/Qnx";       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Jann Horn <jannh@google.com> wrote:

> A frequent cause of #GP exceptions are memory accesses to non-canonical
> addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> the kernel doesn't currently print the fault address for #GP.
> Luckily, we already have the necessary infrastructure for decoding X86
> instructions and computing the memory address that is being accessed;
> hook it up to the #GP handler so that we can figure out whether the #GP
> looks like it was caused by a non-canonical address, and if so, print
> that address.
> 
> While it is already possible to compute the faulting address manually by
> disassembling the opcode dump and evaluating the instruction against the
> register dump, this should make it slightly easier to identify crashes
> at a glance.
> 
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
> 
> Notes:
>     v2:
>      - print different message for segment-related GP (Borislav)
>      - rewrite check for non-canonical address (Sean)
>      - make it clear we don't know for sure why the GP happened (Andy)
>     v3:
>      - change message format to one line (Borislav)
>     
>     I have already sent a patch to syzkaller that relaxes their parsing of GPF
>     messages (https://github.com/google/syzkaller/commit/432c7650) such that
>     changes like the one in this patch don't break it.
>     That patch has already made its way into syzbot's syzkaller instances
>     according to <https://syzkaller.appspot.com/upstream>.
> 
>  arch/x86/kernel/traps.c | 56 ++++++++++++++++++++++++++++++++++++++---
>  1 file changed, 53 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index c90312146da0..19afedcd6f4e 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -56,6 +56,8 @@
>  #include <asm/mpx.h>
>  #include <asm/vm86.h>
>  #include <asm/umip.h>
> +#include <asm/insn.h>
> +#include <asm/insn-eval.h>
>  
>  #ifdef CONFIG_X86_64
>  #include <asm/x86_init.h>
> @@ -509,11 +511,45 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
>  	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
>  }
>  
> +/*
> + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> + * address, return that address.
> + */
> +static unsigned long get_kernel_gp_address(struct pt_regs *regs)
> +{
> +#ifdef CONFIG_X86_64
> +	u8 insn_bytes[MAX_INSN_SIZE];
> +	struct insn insn;
> +	unsigned long addr_ref;
> +
> +	if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> +		return 0;
> +
> +	kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> +	insn_get_modrm(&insn);
> +	insn_get_sib(&insn);
> +	addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);

I had to look twice to realize that the 'insn_bytes' isn't an integer 
that shows the number of bytes in the instruction, but the instruction 
buffer itself.

Could we please do s/insn_bytes/insn_buf or such?

> +
> +	/* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
> +	if (addr_ref >= ~__VIRTUAL_MASK)
> +		return 0;
> +
> +	/* Bail out if the entire operand is in the canonical user half. */
> +	if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
> +		return 0;

BTW., it would be nice to split this logic in two: return the faulting 
address to do_general_protection(), and print it out both for 
non-canonical and canonical addresses as well -and use the canonical 
check to *additionally* print out a short note when the operand is 
non-canonical?

> +#define GPFSTR "general protection fault"
>  dotraplinkage void

Please separate macro and function definitions by an additional newline.

>  do_general_protection(struct pt_regs *regs, long error_code)
>  {
> -	const char *desc = "general protection fault";
>  	struct task_struct *tsk;
> +	char desc[90] = GPFSTR;


How was this maximum string length of '90' derived? In what way will that 
have to change if someone changes the message?

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120111859.GA115930%40gmail.com.
