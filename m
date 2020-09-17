Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVNLR35QKGQER5DRONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D2DE26E176
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 18:59:03 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id s2sf1726855pgm.18
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 09:59:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600361942; cv=pass;
        d=google.com; s=arc-20160816;
        b=fVDHkjSBdc0TP9W1CMTrzDMNptEdMDYHH68C701+kVRlnURuZ9kEsUcZ0Xw28O9IDQ
         ybuq7Fu0NWu4OdNR+naIWYV317RtOnlDz7K0Q9UxG5Wx97DZr6jNiQGYSkxFZweorqRv
         meQf+nXcK7y7ni1zsuNJSikkEAlJtJfD8/Y2ITb4eAegPW6UpP77juUBq8Zl+fqpUp7o
         Rxt7ytK5kcafoejV+ozbDoGHExiBQvQO36/oUdYSndcHPojlsJfTpvtCgUzlavZp1yAy
         GASfMiVa28uJiK2D+5IC86WlcSbi2nAPZlY9sMyrYqolxoqIRMSiKJ2ZTXEzmAJ/My2H
         +ZDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ZmdjZSTDy1spKv3WI42SNbq1eDejcUeoYGHdUo3/BqY=;
        b=hOA85JKvMQE8xnXIjGELbyFzPSQ7XNb2GvE/wiZH9VCqnndMQ4lmH0MWwvBdtEArXc
         WYYTGGUJ6DEI7QAs/hlctQlIFIewTUj/7RnpSmAaRfIhd9kDdVHRE+fAiu4C2hDitEIP
         x1pZZNHKgv2yE5aDf++urNDQKKw7+iMHtnDfTcAQ8th/1NV4Z1FmOlJeVcLvy2qDBEN5
         xVpiVYkFED015I3+wgVUb/v1xyKRpY7OWp5qCrFeygmtCLeajk200vI051lJAfd89mt1
         Tb/LZ7wCKQK7F42qxeJOcRPrk8Ldzcv/lFmAMvMvmxGXiOIV/a45cXF4arfvFKU9ged0
         phVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZmdjZSTDy1spKv3WI42SNbq1eDejcUeoYGHdUo3/BqY=;
        b=hN5xM7jj8UiXvojnqM8gXEDdzklz9306DkPNsTHLJqf+8oQjwAHL4M/w8LaMVOnY9S
         DXrs+jiuW2SjWahMMG6qgCdDlDwk9cYse9l3g6RwR2/WtgpnukCJ2H/9E9kBPIpYEFUB
         ZsNr1pp25my7+GFuVDSZJfqs0QCFLpwI1H3wUklRo2Sm8Km7iOWMDFEqHURuzBMwrXlI
         iThizhqSOwSZ6hBLxCmuhXVdCt2RhNhUbVj58nmqfRdfruRCbsZUJfAeVjYW/YqxZ/N4
         EjiwMDBH4ZkDIxLnR4MJVn06vQL77D9/IIaFtyI4S32/UA4/XLZ6sZRCQH51WBFtDjaV
         DaZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZmdjZSTDy1spKv3WI42SNbq1eDejcUeoYGHdUo3/BqY=;
        b=fSFgzveob8mhmbuSZaypeZW+A9/izikyyeHRB6l8R3foCfIxq15uUwVqo/6wkn2jRT
         5L+qLR4kWe1Dt9Rno4yjL856rpetYndI/Nfd+eS03fHB1loGnDHXoSajri719CQYOokb
         2Y/PJCFJULQC8twPPuiPFq7JbL/15QHRiHJwD58D1gxzfcQkog5Ta5JKDSHbMRhcJVLh
         SegVJ7g0nj/6fIcexOqpUl8iE+WVzswjVjstX/U308YgN9vsHekMQrXnYKSyXYx/TyJ+
         NMaeHI+xWN8bAi6Y184B0MGBR3GMLuf9s4dp2nwZNOaTBJ/OWDnOrHOIQfv22NIF6+1n
         iaKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325/qV7yjSEnpDODczkoGNNi+R33Wf9jphARW7aN6iq0M+uETk5
	gahw33rFpKqlhciZwKCqPGg=
X-Google-Smtp-Source: ABdhPJzKrcK933hqZk0YGrjn023BcvT4nPW6PKs/cWix8wVBFmNC8dfGEAcgjQhU54ZGGddv7Ybhbw==
X-Received: by 2002:a17:902:6bc8:b029:d1:f2ab:cf6a with SMTP id m8-20020a1709026bc8b02900d1f2abcf6amr7074165plt.14.1600361941846;
        Thu, 17 Sep 2020 09:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:368a:: with SMTP id d132ls1036562pga.6.gmail; Thu, 17
 Sep 2020 09:59:01 -0700 (PDT)
X-Received: by 2002:a63:841:: with SMTP id 62mr23420819pgi.35.1600361941177;
        Thu, 17 Sep 2020 09:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600361941; cv=none;
        d=google.com; s=arc-20160816;
        b=EqbJNfuaCu5hKzNmbjBPVpM+dWx8n+P4VMZxcGDOj2q43Mx5Op802oOHLit8wwDFYx
         GoGCrCoY7h9i9NqN3erMZHqP12kUNGf5Yp0zFaL4BD/4/f0sNugjUuF7TpAC+VTGJJJv
         mSjOXdsOjl0jFVzK+/NRWjY9nxl0jQcw8GgBZnFgZkvV6d/2bfkMxb15zxQ8E2YeJu89
         z6VBDW9w2fk5uKElnUnMsOxD0wviLAglHsmUdeyL9LcqOTMLL0Lplxk4sPgXnf4rOlEC
         fF61BDyRATEtMt/yyvGkMm4VpumCvILLH8A2V8C08uf/RSaCMxDwenBXysla0U+2xEtB
         Nm1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=IvLGN3TDYrsNAopphcWkHa4rrb2YiWr7IDo65oq286w=;
        b=jGXAB01xukXfHwMEW5icnhU3vpzg0IuZaa0Ra+lGJRPEObmKEdC9tTB6szqdpEnv4e
         kxqx20vQhwmbs8gfn/4qPFBYtU8ZC1LvwXS7X419xTYRFdPnw60Vd9ibDQMaGu/b6Tts
         +0UQHzsBYH1d0Dacf0JLaVeLo+cbzzflxu+LnNK1g4wy151T12HFKyH5VQ8yYogwd1R4
         nzEDip8Us8STrXUv5Xxt0wSnJIiXC6bRfoU2QqtQwhQKt/07qOihIuSNNu0QkoOyWkMQ
         r2yV/LUf24fH9MVu8MPinQZBcJx65VSui/76BxC2+6OIJczamfM5qiqHkW9hKOgie39p
         KP3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mj1si42517pjb.3.2020.09.17.09.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 09:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5906E2064B;
	Thu, 17 Sep 2020 16:58:58 +0000 (UTC)
Date: Thu, 17 Sep 2020 17:58:55 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: linux-arm-kernel@lists.infradead.org, Marco Elver <elver@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 27/37] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20200917165855.GH10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl@google.com>
 <20200917165221.GF10662@gaia>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200917165221.GF10662@gaia>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Thu, Sep 17, 2020 at 05:52:21PM +0100, Catalin Marinas wrote:
> On Tue, Sep 15, 2020 at 11:16:09PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> > index ff34461524d4..79a6848840bd 100644
> > --- a/arch/arm64/kernel/entry.S
> > +++ b/arch/arm64/kernel/entry.S
> > @@ -175,6 +175,28 @@ alternative_else_nop_endif
> >  #endif
> >  	.endm
> >  
> > +	.macro mte_restore_gcr, el, tsk, tmp, tmp2
> > +#ifdef CONFIG_ARM64_MTE
> > +alternative_if_not ARM64_MTE
> > +	b	1f
> > +alternative_else_nop_endif
> > +	.if	\el == 0
> > +	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
> > +	.else
> > +	ldr_l	\tmp, gcr_kernel_excl
> > +	.endif
> > +	/*
> > +	 * Calculate and set the exclude mask preserving
> > +	 * the RRND (bit[16]) setting.
> > +	 */
> > +	mrs_s	\tmp2, SYS_GCR_EL1
> > +	bfi	\tmp2, \tmp, #0, #16
> > +	msr_s	SYS_GCR_EL1, \tmp2
> > +	isb
> > +1:
> > +#endif
> > +	.endm
> > +
> >  	.macro	kernel_entry, el, regsize = 64
> >  	.if	\regsize == 32
> >  	mov	w0, w0				// zero upper 32 bits of x0
> > @@ -214,6 +236,8 @@ alternative_else_nop_endif
> >  
> >  	ptrauth_keys_install_kernel tsk, x20, x22, x23
> >  
> > +	mte_restore_gcr 1, tsk, x22, x23
> > +
> >  	scs_load tsk, x20
> >  	.else
> >  	add	x21, sp, #S_FRAME_SIZE
> > @@ -332,6 +356,8 @@ alternative_else_nop_endif
> >  	/* No kernel C function calls after this as user keys are set. */
> >  	ptrauth_keys_install_user tsk, x0, x1, x2
> >  
> > +	mte_restore_gcr 0, tsk, x0, x1
> 
> Some nitpicks on these macros to match the ptrauth_keys_* above. Define
> separate mte_set_{user,kernel}_gcr macros with a common mte_set_gcr that
> is used by both.

One more thing - the new mte_set_kernel_gcr should probably skip the
GCR_EL1 update if KASAN_HW_TAGS is disabled.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917165855.GH10662%40gaia.
