Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU7WVL4QKGQE4Y45MAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D9B123CB4F
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 15:59:48 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id u68sf2493910wmu.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 06:59:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596635988; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQgwvPBlcjFRY25Xx0yflBj+AqbuBZe5398AECBzcddceZuy6rvKsKI8Esigr3zDqe
         MNxR9MUzLgGuSvbtHfykr+Yem23NC1ZPinKIefmrPb676lZPtPtIbi8Faz9lkXNycCaA
         Xd0oEabrgDE1UeC9VHpblwkTzhYJNBf58a7rndMOS+ROBfyuXu7Xilkee/eyaazhCVU0
         j20uL4P3uFh5HvhTGQFnTXOp+Ogfz0OabFwTZrFt0Gx3xNQ0wAdH/YAbKC8sY79anceQ
         IWEmepEZeTH1GvWlG0J7x8z0leFK3QOxd6RtZ7sGWNaXmft8ZA0N1T5XzFnbGHwLwVNa
         PeEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=C+3zEamedk9Lbtm//CsqZyxeDiNecDKtRnLXSC+0J/8=;
        b=Jmp/B6zLV9oyCmn/9gz0KpcXIQlMcgD24s+qxvd1LGDH1EfKSTnFX7n2m8DCoyRuHr
         PtwD6P7hzvZjFt3WfvnTA+q0XjxmNy1fspMMTBntWn0nfQtUghVX9PfhSMYXulN7cXvn
         i2agmXtz52gokap0VEBkOd7WxvMgKIAxGR+1RtrWrcwQwS1K75cp5kdoS5O4IsKKduXF
         B2A1cvX1mT5rjrRmjlW0Is4PYn4RAAKCXiEKiDCjZeU3UHI9USoGZLH8DhZg+05C3M4O
         zD4X+oi5oKyBfOzDh/05JSw9E+PlJLnUwr7RzPTZ0epjGVh8uPhnr14zomKK5Bbv3+TS
         Dnag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z5kHZzSn;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=C+3zEamedk9Lbtm//CsqZyxeDiNecDKtRnLXSC+0J/8=;
        b=VxcpJ/H0IxTvhXaxeiX/LZb0t589tT4k3r9JP/m/cvH9Qd/KpsLToLgSkZ98yIs4qo
         IR0W9WyuoT/lnwwhKY8VUvZJ/6FnZAjG1RZ64NwgOEjwCd7WiiWuLcvqEj1dCbauIeKX
         uPUhmJHh7colP1TLeQvr/L37ZORxTdfvMWyPru1Tz8oSKySq3ba8CASj52lqheKOG9fc
         1X8X5PBHlOrMA91LinAK8Ts7jhM07jljUoqglwnS/0UZc6HZbdRgjhZEG01zoKgiAF6M
         kiODhrL90yxvZgCWg6PKxSlJ43hnOcpqrQh/BIuqzpQzri7RlugIzEotnMQ2sOjB3AvK
         rXJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C+3zEamedk9Lbtm//CsqZyxeDiNecDKtRnLXSC+0J/8=;
        b=uiHPfpz1/l5vQ6tzmNeazXQGXpuFV6o6lgUhR257W3K2ixzR1wnfFtgYQYH6/Wol71
         i6/gRtQkzvoIxH0OhyI2lNwCkKCr0Y0h55DwUzBhmIPmM2vbPDS1xzFLQfDAfAMASwld
         iSs5vQ/dyWeP3mYEn93DUvH9Yj+4h28UNYr/aQF8x5iCuNkUNnnxl8pIiSTCz9eJZBWj
         8fyFg6/Rplra9HLrx1bnL49OVQUc72oyzYNDEhYOQvu2slnMqxMtqmHI8na4F9sa0eFj
         Hfxw9v/cDOj/JW1U25MrXim5wKceWrRKEwgBM3xwFJIknImG7HPu0JlIIvy+V0lMe6Gd
         4GhQ==
X-Gm-Message-State: AOAM532bOdjC6LsdJM8Kp+7Z1Q4kx3XOpwk1yqZIguGMV8ltUKhoaoda
	2ICV6CJ7Vq/jdD4tP8RcM1Y=
X-Google-Smtp-Source: ABdhPJweUB+UowLhnhYZ2O9R2Z3j+TaD2fUvGZfG1/ylSCO7YMWqQ3NCE55NlcYTptTKLJEj68CMPQ==
X-Received: by 2002:a1c:43c3:: with SMTP id q186mr3652546wma.144.1596635987822;
        Wed, 05 Aug 2020 06:59:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a3ca:: with SMTP id m10ls376134wrb.1.gmail; Wed, 05 Aug
 2020 06:59:47 -0700 (PDT)
X-Received: by 2002:adf:82f6:: with SMTP id 109mr3211378wrc.25.1596635987152;
        Wed, 05 Aug 2020 06:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596635987; cv=none;
        d=google.com; s=arc-20160816;
        b=RgebS1t7S56bnendXdw2WzLC03WgiSLfvIynDzIUZvELVaxrRVjsh/O5ftS+sVfS1p
         rw9xWiZHeuxEgy+1V+xHDT3zE+X4pMQbXRv9POJT+ZGA7rKmAMojvDUAaQxtcNKV090t
         6oVukhCDEuLbT7YW9rQ7qPiNQlj6rlGcyyjzwYhPkr2oQ3h3m6vrrkI5qDY+aaHpdPFv
         B7ziCvLwOc1veB9Ay8KfCO2dhUjlEDDPKcWH6V+eOFyL1AVxLGX0QrARjJAu2/xUnF6C
         Y2IUeHjw9nCG7ahWWf+vMUREt80pPUvRzQY2HpiRmFtjAdTGVfiHt+z+nTLkFcktonvz
         N30A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YePFlbgRyxtaEPeLEBJjJwQHaLa9kCxqtVKAjxXaA4s=;
        b=BCV27avaCIl1ep+WPY4kyiWgrAstdpnff9VOonCXBbhQmSaqJLsAFz3uUAyOu7bYIf
         7AR4J2IjI3IaoP2RamTZSScWohcaICeDjLqyRd0AXvr0H8CCxM6SgExZzYjP6rXjuX4y
         t4pXRUdYYjvciKemHPUg+vp2KblWb4v7honI9LiVQgrT+Y3cDC8aFT8N767kAGETzve4
         hZD6wDtgXTOtq2V2ASD8yuINIOIiukOBSxbBQ5RaJx1ybF900pijUpTevZqcZ+p0/3H/
         Gobpq+Z0X7mYWa7z9H5kPCj6p21ftCPf+quUExXzITmUkKXCWrbbPnd/TQI92FV6jL5Y
         n/4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z5kHZzSn;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id m3si122324wme.0.2020.08.05.06.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Aug 2020 06:59:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id g8so5921484wmk.3
        for <kasan-dev@googlegroups.com>; Wed, 05 Aug 2020 06:59:47 -0700 (PDT)
X-Received: by 2002:a1c:96d7:: with SMTP id y206mr3357845wmd.9.1596635986525;
        Wed, 05 Aug 2020 06:59:46 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id p15sm2823841wrj.61.2020.08.05.06.59.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Aug 2020 06:59:45 -0700 (PDT)
Date: Wed, 5 Aug 2020 15:59:40 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org
Cc: bp@alien8.de, dave.hansen@linux.intel.com, fenghua.yu@intel.com,
	hpa@zytor.com, linux-kernel@vger.kernel.org, mingo@redhat.com,
	syzkaller-bugs@googlegroups.com, tglx@linutronix.de,
	tony.luck@intel.com, x86@kernel.org, yu-cheng.yu@intel.com,
	jgross@suse.com, sdeep@vmware.com,
	virtualization@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200805135940.GA156343@elver.google.com>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200805134232.GR2674@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z5kHZzSn;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Wed, Aug 05, 2020 at 03:42PM +0200, peterz@infradead.org wrote:
> On Wed, Aug 05, 2020 at 03:26:29PM +0200, Marco Elver wrote:
> > Add missing noinstr to arch_local*() helpers, as they may be called from
> > noinstr code.
> > 
> > On a KCSAN config with CONFIG_PARAVIRT=y, syzbot stumbled across corrupt
> 
> Cute, so I've been working on adding objtool support for this a little:
> 
>   https://lkml.kernel.org/r/20200803143231.GE2674@hirez.programming.kicks-ass.net
> 
> > diff --git a/arch/x86/include/asm/paravirt.h b/arch/x86/include/asm/paravirt.h
> > index 3d2afecde50c..a606f2ba2b5e 100644
> > --- a/arch/x86/include/asm/paravirt.h
> > +++ b/arch/x86/include/asm/paravirt.h
> > @@ -760,27 +760,27 @@ bool __raw_callee_save___native_vcpu_is_preempted(long cpu);
> >  	((struct paravirt_callee_save) { func })
> >  
> >  #ifdef CONFIG_PARAVIRT_XXL
> > -static inline notrace unsigned long arch_local_save_flags(void)
> > +static inline noinstr unsigned long arch_local_save_flags(void)
> >  {
> >  	return PVOP_CALLEE0(unsigned long, irq.save_fl);
> >  }
> >  
> > -static inline notrace void arch_local_irq_restore(unsigned long f)
> > +static inline noinstr void arch_local_irq_restore(unsigned long f)
> >  {
> >  	PVOP_VCALLEE1(irq.restore_fl, f);
> >  }
> >  
> > -static inline notrace void arch_local_irq_disable(void)
> > +static inline noinstr void arch_local_irq_disable(void)
> >  {
> >  	PVOP_VCALLEE0(irq.irq_disable);
> >  }
> >  
> > -static inline notrace void arch_local_irq_enable(void)
> > +static inline noinstr void arch_local_irq_enable(void)
> >  {
> >  	PVOP_VCALLEE0(irq.irq_enable);
> >  }
> >  
> > -static inline notrace unsigned long arch_local_irq_save(void)
> > +static inline noinstr unsigned long arch_local_irq_save(void)
> >  {
> >  	unsigned long f;
> >  
> 
> Shouldn't we __always_inline those? They're going to be really small.

I can send a v2, and you can choose. For reference, though:

	ffffffff86271ee0 <arch_local_save_flags>:
	ffffffff86271ee0:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
	ffffffff86271ee5:       48 83 3d 43 87 e4 01    cmpq   $0x0,0x1e48743(%rip)        # ffffffff880ba630 <pv_ops+0x120>
	ffffffff86271eec:       00
	ffffffff86271eed:       74 0d                   je     ffffffff86271efc <arch_local_save_flags+0x1c>
	ffffffff86271eef:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
	ffffffff86271ef4:       ff 14 25 30 a6 0b 88    callq  *0xffffffff880ba630
	ffffffff86271efb:       c3                      retq
	ffffffff86271efc:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
	ffffffff86271f01:       0f 0b                   ud2
	ffffffff86271f03:       66 66 2e 0f 1f 84 00    data16 nopw %cs:0x0(%rax,%rax,1)
	ffffffff86271f0a:       00 00 00 00
	ffffffff86271f0e:       66 90                   xchg   %ax,%ax

	[...]

	ffffffff86271a90 <arch_local_irq_restore>:
	ffffffff86271a90:       53                      push   %rbx
	ffffffff86271a91:       48 89 fb                mov    %rdi,%rbx
	ffffffff86271a94:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
	ffffffff86271a99:       48 83 3d 97 8b e4 01    cmpq   $0x0,0x1e48b97(%rip)        # ffffffff880ba638 <pv_ops+0x128>
	ffffffff86271aa0:       00
	ffffffff86271aa1:       74 11                   je     ffffffff86271ab4 <arch_local_irq_restore+0x24>
	ffffffff86271aa3:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
	ffffffff86271aa8:       48 89 df                mov    %rbx,%rdi
	ffffffff86271aab:       ff 14 25 38 a6 0b 88    callq  *0xffffffff880ba638
	ffffffff86271ab2:       5b                      pop    %rbx
	ffffffff86271ab3:       c3                      retq
	ffffffff86271ab4:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
	ffffffff86271ab9:       0f 0b                   ud2
	ffffffff86271abb:       cc                      int3
	ffffffff86271abc:       cc                      int3
	ffffffff86271abd:       cc                      int3
	ffffffff86271abe:       cc                      int3
	ffffffff86271abf:       cc                      int3

	[... and the rest looking of similar size.]

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805135940.GA156343%40elver.google.com.
