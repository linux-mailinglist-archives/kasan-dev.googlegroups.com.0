Return-Path: <kasan-dev+bncBCV5TUXXRUIBBT7OVL4QKGQEQLCGKSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C14D723CB13
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 15:42:39 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id c204sf12269770lfg.16
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 06:42:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596634959; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5mSCiljyulMhjWi5YviS3NmAEQbaHLsW1K0eE3OSnLpLA/wGSR5vf+huaLyPWp5jA
         4aYapoqAdKcILB9Fje5c36NeYjA1c3vTXZc2sid2YK0vdOeCNprzU2clgqhK/yE4m/RD
         aCvoy7VbBeyjAUbABUax/P6nr60gxa+sdc49nEzaFP3xYYTbKQ47x2rG7rpT82NS/OKz
         LwgV2xEVExTb20VVbd3QpfngpLNUHEAark3PLY+kVKMGK2CVdgLndrtqDFNqSxegYXyc
         jKybO1NcbppnmIBGUz7Uc9CN1p4ZUEeRESVwxIcQB2mrc56WYfB05CEHIzRj5ZLlmGma
         uMyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Lx17CEeRc5UulJ7UO82/vBePw5Csg9RW/3QaeQafuI8=;
        b=Bx2aQ1VumNIw0ZV8CgnHsAIuib2bfyWPJpv+1a+r5RG90QeRnD553jz25Ds81DyNGR
         H/+aBd+8uU4YwBvgy4tW6wfuxr3MMfbR2GuA90KuyKqOE7SYS7igstLHLUTEurqk2b3U
         V0GllYFT0uJREiumCJomWyKdiGwZET2qcMTffQUpJYnY0nTS25+abMcwpu+DjPH+K0gt
         D+TxmLUiqMRfzmGvMRFgpknFzvsMQ4RQw7ovcbxlNl1FxmQnRyUYcr3g+hKbTiH7+yZO
         wRpb+lAKA1S6e15fuhIb14hCm2RF+jYLhWPEjDT8hsv+iO1tqEjkCDUkEBnNzcwH8feV
         g6PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DxVHatqg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Lx17CEeRc5UulJ7UO82/vBePw5Csg9RW/3QaeQafuI8=;
        b=Uzi8FvI6GwDflSQjMtmvxRTALB7+Z5amIXYEEPpoou+k13IGbl+bN/7Xl0zWWdRTiN
         NXG0JNjLvku0L11BoB1+wHhs6jNmZNegNh24wN3nO1YKqjtuD4bj4HsXkHBFzAd/yehj
         bqltaCWbMhIxafWEhb5pAw6NgnxH0ZmT89aT2qPjzIb8pbkIz/mRmy5MHnxgDtsZ07LZ
         HJSZnQI3r0XJdPkxrWAe1eMhlivy9fLXiw2sQ9HCEtYoC+uouDv2Du5MPTOGEO1lSu1v
         szr4Vp4l4hCuYArGa67djoqHYs9R3xJqSruXRvgYGmuXB7F7uGImlghOxd8o/Yw1r0yz
         +oBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Lx17CEeRc5UulJ7UO82/vBePw5Csg9RW/3QaeQafuI8=;
        b=TvIcDYLXZaNQELXaFXf+mw+9lHatfRGwwi4J83cZetN8h4d6LEBGqU5EheH4tXd6pb
         miP/UadkRq+/4p0Fd2yNBsuZC9OdO+TnYxAtfl4IJHp8S4miVNTTXq4HKZ9Mh1SfI8YO
         NF/LyG284PPYFI5Q5u2EUx5AnawaPVXMZSnvrcv90IKk57dsNqHDJR+aYr1LvUndATPl
         5ojT/wzSD1YD2EPwfuuvgVoBUF/07wqWiQnEGAMv5dMosTOUH6KGjrsRCQzFWxCuYuDi
         H4/Pn/Kt6Pnej4sfloOvSubrwSYtZzUE4erufPUygn0UUddn/B8Kw0hb9o0fS6R3TFq2
         T6ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iCCt8VnS77S23h2WVpSGOnj+2/WKGxfnwf3pqLOFPn28QXUFu
	3g7/upKHdLjycVsiGNLT/Kc=
X-Google-Smtp-Source: ABdhPJwPC8pBhb6iAr/vJewhJAbRdnK7L2sfORPqRe5NSCC0mWNbHJWlzbiI83uigkhHYd7mc968MA==
X-Received: by 2002:a2e:910d:: with SMTP id m13mr1630848ljg.240.1596634959306;
        Wed, 05 Aug 2020 06:42:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:300f:: with SMTP id w15ls292054ljw.1.gmail; Wed, 05 Aug
 2020 06:42:38 -0700 (PDT)
X-Received: by 2002:a2e:8105:: with SMTP id d5mr1504884ljg.299.1596634958744;
        Wed, 05 Aug 2020 06:42:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596634958; cv=none;
        d=google.com; s=arc-20160816;
        b=xS9Ldf6TS8H96Ui6UyY/81uE1Jgn0GPZCVfCztrGsuzBUSO0zspp+HIYHP+yItU2tu
         A9XP3KPLiJ2BRs/RnzMbHAjB0+DsxLXVYdvjXzgKVlR0LugzPXBAPUcxl6KtpIBPXffi
         bODVd9kcES6gMtm9I8MDbHHx55TYIitxmReKsuaauG57wcnf3rVextQKr/ml2tZH2GjD
         O25B8tUjoA1GYYRjGCnMhnwGtklgmrFGmvcAURQbv/INIowrJNPMEPPBov1tmldGuJVR
         2ZcGtuqvV52CkiYlCiHrZvHKSHAmBuARg1s/0yjzJ8ZBfzztBKXcU2pbuCDpa2JmqBgw
         RI/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+g3sbWo8Ja9JxjGyq6mVY0ZEJVqeXUqG7DKAaCqdzBs=;
        b=k+GLf9OTbblakjzPOV9CjuqYuBu6GgiO86/9Mc9vkY26GX2gXD8nvtIAHyLAZ7IXpi
         8Ym0mHLNm15QAOkdldKAVuUBTsTAEa0cbPrFrPy8tpWKp1JLXmNXC5AxBXvKKuRwdSId
         O/IcIw1b2Le0Tk35IUvx0Ar3n2irjX2MwZLkxp0bcu/pe3iX5E5BaQKny7L3F5m1Ptem
         fDXONRpT0zFwyR3TZp1r0M4jDGlYS74hD4+cWQ6SOCmfDMIgIAFyta7A6dvtA70j/sua
         FiUEW8mnYVdgbZZ1pkFKu5H+rybzFGRQh8JQyovkq+yQlC6dtpcpBfoJFgwsWbhNUl3E
         tvow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DxVHatqg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c27si127277ljn.3.2020.08.05.06.42.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Aug 2020 06:42:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k3Jgf-0005Ka-Cp; Wed, 05 Aug 2020 13:42:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 846953012DC;
	Wed,  5 Aug 2020 15:42:32 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 71A9A22B957CE; Wed,  5 Aug 2020 15:42:32 +0200 (CEST)
Date: Wed, 5 Aug 2020 15:42:32 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
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
Message-ID: <20200805134232.GR2674@hirez.programming.kicks-ass.net>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200805132629.GA87338@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=DxVHatqg;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 05, 2020 at 03:26:29PM +0200, Marco Elver wrote:
> Add missing noinstr to arch_local*() helpers, as they may be called from
> noinstr code.
> 
> On a KCSAN config with CONFIG_PARAVIRT=y, syzbot stumbled across corrupt

Cute, so I've been working on adding objtool support for this a little:

  https://lkml.kernel.org/r/20200803143231.GE2674@hirez.programming.kicks-ass.net

> diff --git a/arch/x86/include/asm/paravirt.h b/arch/x86/include/asm/paravirt.h
> index 3d2afecde50c..a606f2ba2b5e 100644
> --- a/arch/x86/include/asm/paravirt.h
> +++ b/arch/x86/include/asm/paravirt.h
> @@ -760,27 +760,27 @@ bool __raw_callee_save___native_vcpu_is_preempted(long cpu);
>  	((struct paravirt_callee_save) { func })
>  
>  #ifdef CONFIG_PARAVIRT_XXL
> -static inline notrace unsigned long arch_local_save_flags(void)
> +static inline noinstr unsigned long arch_local_save_flags(void)
>  {
>  	return PVOP_CALLEE0(unsigned long, irq.save_fl);
>  }
>  
> -static inline notrace void arch_local_irq_restore(unsigned long f)
> +static inline noinstr void arch_local_irq_restore(unsigned long f)
>  {
>  	PVOP_VCALLEE1(irq.restore_fl, f);
>  }
>  
> -static inline notrace void arch_local_irq_disable(void)
> +static inline noinstr void arch_local_irq_disable(void)
>  {
>  	PVOP_VCALLEE0(irq.irq_disable);
>  }
>  
> -static inline notrace void arch_local_irq_enable(void)
> +static inline noinstr void arch_local_irq_enable(void)
>  {
>  	PVOP_VCALLEE0(irq.irq_enable);
>  }
>  
> -static inline notrace unsigned long arch_local_irq_save(void)
> +static inline noinstr unsigned long arch_local_irq_save(void)
>  {
>  	unsigned long f;
>  

Shouldn't we __always_inline those? They're going to be really small.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805134232.GR2674%40hirez.programming.kicks-ass.net.
