Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5UATKAQMGQEOHXM5HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 97729319FAD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 14:19:51 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id w67sf7277549pfd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 05:19:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613135990; cv=pass;
        d=google.com; s=arc-20160816;
        b=EC3AaSC/uJ1kZrYKZZmcWwu/RuXE+nx+PqxSORwvWyyyKc7TOmhJn2A1Rg3Vqe1lJi
         vZL2GtcHVCrSnl7s8BKv3737TZ1i72+AKgSYrgzxgo+KZBpKH0sau7yvMOtjaXBDQ/f8
         eb97KzGfR9ErGp0hjwUFbQ/xq6TTHRLJpb78PhajocI9rOi8AiGexfz4Gm5iMQ1NQwwb
         oOfxNBjgEmMcw9qAlxoCW5+jcEyMQ5kAvK930H8F1tgNN4dbUP2bgz8nBuS4f+nqCVZD
         xznKYyF/iUarLQqj57NfjIlhSLFJsqNgf0KMDOpeCOaTZLgUspbqtCah+eBjNJoSlOgn
         OiHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FVyyrDKLzMNDT6eqe3Ojh/5OlaGH0u6nUFi+JspX0pg=;
        b=bpE3Qe8dnmq6/i4Z3xl5Abubn85mfsYUiwis0ZggozJlU+eSE7l7sbrqwu3RLicQ4w
         EZ781VE0gwjVhU5fJW6iJtJ39ed50GeGM80yyD9zzY0tdLP5sbcxOE4hZseaz1s/LRqO
         tSbwkyMx6CFwD0fp7YRePW28Cc29/xkl0Mt9qaJgaKFW9r9irmHXnv+nns7jZL1nymBo
         aYQ0dmpHA5jRTmPgRVrZp0h9Oj4cGPvS0oJWMtKDJZW7GJBs6+3tHfD2HadSGk8Z37fR
         p9FloRgwpGFo1tNDGUNy+goCmU/EMgdZMVdYsjWMcAgEzdajtXP/JFWM3TcbzvIgXycu
         FNRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FVyyrDKLzMNDT6eqe3Ojh/5OlaGH0u6nUFi+JspX0pg=;
        b=EaRNJ0g+nf1u7lCscHLWN2rxua50qZuq+Xc42mzFcdH+TyXIbQReZzQIg/AnHCriC7
         tLS/lBqMtWvHTKhzr+rwcVDklhNOh71H+SDD46kYu5VrkFi7VH5bM/Zn3/+r+HNRS4ty
         /q8gy4+TbExNcBCe4DJpEGzwcHZpavTUi4GwLCY8J0kPcEJx3VXXtJH6O+FgwlqtOzD6
         +F5l59AFmKr6YD6srCZGFTQlpCQ8VXmtAwI1QOwCLqk/fAKZNbCniI9x0MjRD6Vf34zc
         NIhsBpTa2Eeinmn3cCcYR3KW49jZM2Qf0rQdPXXlH8cZwtUQfPCQDm2hfeChX55namzT
         3RiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FVyyrDKLzMNDT6eqe3Ojh/5OlaGH0u6nUFi+JspX0pg=;
        b=axpAnMHuXHUFaWOsm/frILgb/fhpcKyV8Ys7Bpl3y7UDYXykhJ5vpacF+h1/n7uRlJ
         BEbm557v++aDvuVi4A5YQ89zEie5DSmFn8b219QE5mHHujiQ8p9PVpskWxufs/MSumm2
         wcKqXbXLPIBOKhyvxiB8cK/4hplbxinFrrEZ72d7QquPPdsdNF7cB73Y8ElooNJhb8ZY
         hnlwDFx0HZ8QLD9i+wucUv3t+pD4gxLrYBJObVJQ+BnWE6GWXugoFSVDyaPUY4O92X7q
         r222Xny4GCXcBYZmJMmhiKqvYCeb7pDJGE9Jg4A2ienc93X0RTK3cPoz8mQmy1ncBKiN
         Wdpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SlgxhQMK1PjZKURH7Ak9kpGoN6HqHOrIkJxrRAnfQLZBTosM6
	xg2WA3EhQFAJ0UJHQbTIeKM=
X-Google-Smtp-Source: ABdhPJyrCAX6RxDqVDMoG/B3haCLTvYf2pJEY5GZn5CQ822T0qDcn1KJER8kYbpYRUETLsrAdHw7hQ==
X-Received: by 2002:a17:90b:110c:: with SMTP id gi12mr2738052pjb.48.1613135990317;
        Fri, 12 Feb 2021 05:19:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:412:: with SMTP id 18ls3517925pge.0.gmail; Fri, 12 Feb
 2021 05:19:49 -0800 (PST)
X-Received: by 2002:a62:1dd6:0:b029:1e3:33c3:7517 with SMTP id d205-20020a621dd60000b02901e333c37517mr3049262pfd.17.1613135989579;
        Fri, 12 Feb 2021 05:19:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613135989; cv=none;
        d=google.com; s=arc-20160816;
        b=msipk+4OyYSMzqpqoYfjGmF2ZpKiLNcqFV8DqQw88kmmZacqOWUXdZFz1G4AhrSAfJ
         VSc7aXkKcdmsSFL2DZGEJEQsL93BbxzpD8DFH5kD3bigLEKKtNMvjnYHCKzaHzgCYeK1
         CNApptfScOb0Atf4arIg8A0mI1+OuQzj1JgAbHAbO0JAvtO+KTL9byKQFjRh1OKfjGta
         FencpxGQFoosBivMjYrE1Xa8fgSowQr4FSvtGS097AhDqp5rGoW01kfDeHM0uZB717Iz
         +Zd8JbuH20BpDkI/0C87xlSjUniXCkmvJc24NF40xJ8BzhEfnb2xEgHl9LeIbMqnkC+t
         Y+RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=qAlFUFyppuD/ZizOk/EjjXiFxAJkVe5koEsRVfvz8vI=;
        b=dNqlrNGKPbRtfvIO1Ob6ZK6aTTEyKv8i6+SHYcZN/52BVOIwsBMuz+NHACbLVr48I6
         V90aDMKV+Au0I+ixPyZr+Mbt9X5i45RpaTtRgZrwRFSk//JjTA8237YPY7Jgf/2URrgc
         XZzMb8X4YmODi7lwuUUr0FDoM+U5EyR1Tgm2a1Ux8gwq7b89GBiuLMzo+V6Xqx8JKSrH
         7wuxYcEZUYgew2SFUC+13Ed9mVq3PpCX19DYrZxSa64uFXO61j5JobRqIU2tVJmyzLzS
         vQyevNn8BiZArcbNzGM0W5YZKzD+2768iCpbKpfjGF4At/wARwWhYZsU8A5QMAGoKP00
         CSoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w6si421765pgg.1.2021.02.12.05.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 05:19:49 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1457064DBA;
	Fri, 12 Feb 2021 13:19:46 +0000 (UTC)
Date: Fri, 12 Feb 2021 13:19:44 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v13 6/7] arm64: mte: Report async tag faults before
 suspend
Message-ID: <20210212131944.GB7718@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-7-vincenzo.frascino@arm.com>
 <20210212120015.GA18281@e121166-lin.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210212120015.GA18281@e121166-lin.cambridge.arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Feb 12, 2021 at 12:00:15PM +0000, Lorenzo Pieralisi wrote:
> On Thu, Feb 11, 2021 at 03:33:52PM +0000, Vincenzo Frascino wrote:
> > +void mte_suspend_enter(void)
> > +{
> > +	if (!system_supports_mte())
> > +		return;
> > +
> > +	/*
> > +	 * The barriers are required to guarantee that the indirect writes
> > +	 * to TFSR_EL1 are synchronized before we report the state.
> > +	 */
> > +	dsb(nsh);
> > +	isb();
> > +
> > +	/* Report SYS_TFSR_EL1 before suspend entry */
> > +	mte_check_tfsr_el1();
> > +}
> > +
> >  void mte_suspend_exit(void)
> >  {
> >  	if (!system_supports_mte())
> >  		return;
> >  
> >  	update_gcr_el1_excl(gcr_kernel_excl);
> > +
> > +	/* Clear SYS_TFSR_EL1 after suspend exit */
> > +	write_sysreg_s(0, SYS_TFSR_EL1);
> 
> AFAICS it is not needed, it is done already in __cpu_setup() (that is
> called by cpu_resume on return from cpu_suspend() from firmware).
> 
> However, I have a question. We are relying on context switch to set
> sctlr_el1_tfc0 right ? If that's the case, till the thread resuming from
> low power switches context we are running with SCTLR_EL1_TCF0 not
> reflecting the actual value.

I think you have a point here, though not for SCTLR_EL1 as it is already
restored. GCR_EL1 is only updated after some C code has run and may mess
up stack tagging when/if we ever support it. Anyway, something to worry
about later, I think even the boot path gets this wrong.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212131944.GB7718%40arm.com.
