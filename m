Return-Path: <kasan-dev+bncBCXK7HEV3YBRB3PJTGAQMGQEPOCH2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 32923319E62
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:30:39 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id h185sf7105374qkd.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 04:30:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613133038; cv=pass;
        d=google.com; s=arc-20160816;
        b=o2XAg8MHUT7jrZEB7TTOEEwCzID/yiSPcloz5L0NipoGIjbu9KC4uu20llqIOSLtzh
         GeOGT747knmTDSg+9Rr2hwEthXIjEuaasdPmuRkA8C9Prsa1C/BxkI4bq47QF+ftR61L
         hr3U8L+F/1nXD6pmMISwOUm2OoSmLMmB/UHZTkLj5hesdpK2hqDc7dFS8/HLbUzPblbO
         WG+7r4pbbm6G/ZlpiFudZLY6NbHNwUm3jGf0YkNPWiGRYHEzNqcf92WzjKPsXftkLt1d
         N6qSYIcO36PcrIxHPmmOn97uulu8twiohPhIi3RArebE2ss2B9amuizY5p0TVXbg/T8i
         /75A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=bKEtSmaW6pfkngMlsgr+YCxFnb/PVbQZPN9NHZ5meds=;
        b=u/28RLpLAWwhu16ZHxY2CiAMIYw85SuFku7CYrOCB0uwg57YVi2LwqnoIBdBWKx7vr
         fXB65eET9uvlfSnR+y22QyG4PVfQrdHfP9ZGUMOIfGYyz8i/PiQcP+CfBwGaOWEa7ym1
         NoWs/fXWE+LGbazHXLdjtedwoPyvS5SmKiLL0h2D6axVaizzrQvgtDEw6kieplCrTf+3
         qba/YF0CojkcsVF53sgQEjFbtDm11DywzikebRv7ZuSuQX9ws6OPTFTWEHAgWg0w0zT6
         4udR8wjGhjOpVyXlMfSOrYfPxt8zDCpphTlyzUOsPjjpB6AV0HXCT0lmubAaWLSsQ93Q
         t1YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bKEtSmaW6pfkngMlsgr+YCxFnb/PVbQZPN9NHZ5meds=;
        b=qpoxms47ZxWo953qPonjQNbZ0gdhBpW/pygyWOyCKu/pF8Kthden/zLf173KkcmZl9
         u4Z3V31KAG5clJpBXUDAn6nvdxGYKLmowvk/gNp7InZAlhnYSYBQ5pRUJBouAMB7WWkk
         rSvNp6j0+O47duvtp9Wm7wR9crEY9I0Gbu/DmRVfGaDQmeEXdzuPeZGQ8kAVFMGjM4+5
         CGMgAD5fpHqwJlyPI5mR4cTdqmKFF7ETv+ervMW6Y0GiIFq3a27tH2k7dNjDdMMBHqDH
         EtvWI7NrQb7j51v70TYq+ZBdIhHsYLCpEYoKwVIyHQTZ9VujZCh4A5mPme0A5lxWpEAH
         mVRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bKEtSmaW6pfkngMlsgr+YCxFnb/PVbQZPN9NHZ5meds=;
        b=mzfw+CLi0wudEoZn0tDXg43jlNEmiW38h4KZTA+/drgSl6vwa4jc99fjRVUUsnYrky
         YuzOgdltp7E/MYDTk/B/pEhNKDJTsEkgXceUo673EE2H09Cocks7udEx3cWiobz/Ej4O
         SP5AYHVkmTVf5QolKUo3toKB8ts2FeHqjc8eHPOAltPktpo4eFskuNaH/wTkJbQA9Dff
         v/gWOUmH6W7Bne/9925vSFxo/Vzhr+wi0oGMiPpxIt8LY/S7IlJHeIsIyfFeDMwZ8mRA
         SQ/mjyNFU6f27Vha2VwOVMySTO398TJj6z8S6KaOUyUyscviKcsRsLqi/20jVwppSEbN
         /sHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53379JcY++QlOUPyOwVXw2UfXDy2S9qKdQmi9Uz2Add4u2RfKo4S
	mxgHULXz36id3owqseKp1eg=
X-Google-Smtp-Source: ABdhPJyGJ8epE3GHQ8aYSQNWLAhURj/4prSpgj6wKKpO/T85hdLe3siOeX9DJGIAzBxoWy2C7qVqBA==
X-Received: by 2002:a0c:bd8d:: with SMTP id n13mr2254394qvg.48.1613133037142;
        Fri, 12 Feb 2021 04:30:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a608:: with SMTP id p8ls4494418qke.4.gmail; Fri, 12 Feb
 2021 04:30:36 -0800 (PST)
X-Received: by 2002:a37:8884:: with SMTP id k126mr2273455qkd.104.1613133036729;
        Fri, 12 Feb 2021 04:30:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613133036; cv=none;
        d=google.com; s=arc-20160816;
        b=pjGcsJCzbraO6ypbiwcKvlHGocvwxC1F7mcfrDQYt5W3yejytVcAH3OIfrLiLxrSiJ
         t2mXOreskVj4uzHzd2Rho/YPSD4A5W6LEG/qaRWfW5SLsqIqrR2r7kg/5jbPF32w7+YT
         mYFqUChYF+oe2f0SmJ3B68fmN7XzgGH7scYHvesXNiggwdOgq+cERE6WAvBv8kL0IQnB
         ZMY8OS+yDjy6nmR6jhbBd49c5dID+QBjUORHh4orMIA2mjWmf8ugIAbnmcMetrUPZta6
         Ji+EbkNbAW34z3Sedl8RaXDMf27CHMhVTaaXhha+B/9aweTm8H7h9Phlx7/qRU4EmXEa
         r3YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=fY1yUqTQqsxn5ge/QyVDnjOrMNWOsUQm93/gcZGKei4=;
        b=uZIv8sjJ2d/pU+dl/jQS5LcqbXdk7SktxgiZGs4AOjVcHlx3qenK9lKwWzTAaoT0iG
         UuWqMMllZglpPOZ2bPEt/ocWD3X8fMrA8EpWYtt39KdCHwT8C/gRKbzvtqR8yUEJr2RS
         rKMZrfW7MfjbA2ETp7p7dtmYiskJZ599tevtKlk+jroXhvOEsPRj7DOxcIY416yESs0T
         r6BFBkjw9jgnZg6ukRmGCVaGDB7pl4l/NY7akf7HLMqHgtSJS2Eq4VKjkFUceg2bCJND
         DKHme7LdVaDh9uz3Rx9FyIVN5RfUF7ZjIojSyf99cuZBx9KxNKk/qf95qbJ1fnjd+Q8w
         Qtww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f10si432639qko.5.2021.02.12.04.30.36
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Feb 2021 04:30:36 -0800 (PST)
Received-SPF: pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CC7491063;
	Fri, 12 Feb 2021 04:30:35 -0800 (PST)
Received: from e121166-lin.cambridge.arm.com (e121166-lin.cambridge.arm.com [10.1.196.255])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0FD9B3F719;
	Fri, 12 Feb 2021 04:30:33 -0800 (PST)
Date: Fri, 12 Feb 2021 12:30:29 +0000
From: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>,
	Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v13 6/7] arm64: mte: Report async tag faults before
 suspend
Message-ID: <20210212123029.GA19585@e121166-lin.cambridge.arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-7-vincenzo.frascino@arm.com>
 <20210212120015.GA18281@e121166-lin.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210212120015.GA18281@e121166-lin.cambridge.arm.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: lorenzo.pieralisi@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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
> > When MTE async mode is enabled TFSR_EL1 contains the accumulative
> > asynchronous tag check faults for EL1 and EL0.
> > 
> > During the suspend/resume operations the firmware might perform some
> > operations that could change the state of the register resulting in
> > a spurious tag check fault report.
> > 
> > Report asynchronous tag faults before suspend and clear the TFSR_EL1
> > register after resume to prevent this to happen.
> > 
> > Cc: Catalin Marinas <catalin.marinas@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  arch/arm64/include/asm/mte.h |  4 ++++
> >  arch/arm64/kernel/mte.c      | 20 ++++++++++++++++++++
> >  arch/arm64/kernel/suspend.c  |  3 +++
> >  3 files changed, 27 insertions(+)
> > 
> > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > index 43169b978cd3..33e88a470357 100644
> > --- a/arch/arm64/include/asm/mte.h
> > +++ b/arch/arm64/include/asm/mte.h
> > @@ -41,6 +41,7 @@ void mte_sync_tags(pte_t *ptep, pte_t pte);
> >  void mte_copy_page_tags(void *kto, const void *kfrom);
> >  void flush_mte_state(void);
> >  void mte_thread_switch(struct task_struct *next);
> > +void mte_suspend_enter(void);
> >  void mte_suspend_exit(void);
> >  long set_mte_ctrl(struct task_struct *task, unsigned long arg);
> >  long get_mte_ctrl(struct task_struct *task);
> > @@ -66,6 +67,9 @@ static inline void flush_mte_state(void)
> >  static inline void mte_thread_switch(struct task_struct *next)
> >  {
> >  }
> > +static inline void mte_suspend_enter(void)
> > +{
> > +}
> >  static inline void mte_suspend_exit(void)
> >  {
> >  }
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index f5aa5bea6dfe..de905102245a 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -258,12 +258,32 @@ void mte_thread_switch(struct task_struct *next)
> >  	mte_check_tfsr_el1();
> >  }
> >  
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

Forget this, we obviously restore sctlr_el1 on resume (cpu_do_resume()).

With the line above removed:

Reviewed-by: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>

> Just making sure that I understand it correctly, I need to check the
> resume from suspend-to-RAM path, it is something that came up with perf
> save/restore already in the past.
> 
> Lorenzo
> 
> > +
> >  }
> >  
> >  long set_mte_ctrl(struct task_struct *task, unsigned long arg)
> > diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
> > index a67b37a7a47e..25a02926ad88 100644
> > --- a/arch/arm64/kernel/suspend.c
> > +++ b/arch/arm64/kernel/suspend.c
> > @@ -91,6 +91,9 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
> >  	unsigned long flags;
> >  	struct sleep_stack_data state;
> >  
> > +	/* Report any MTE async fault before going to suspend */
> > +	mte_suspend_enter();
> > +
> >  	/*
> >  	 * From this point debug exceptions are disabled to prevent
> >  	 * updates to mdscr register (saved and restored along with
> > -- 
> > 2.30.0
> > 
> 
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212123029.GA19585%40e121166-lin.cambridge.arm.com.
