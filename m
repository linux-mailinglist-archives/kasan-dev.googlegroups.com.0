Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYME3ONQMGQENG2OR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0496262E983
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:23:14 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id sg37-20020a170907a42500b007adaedb5ba2sf1910058ejc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:23:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668727393; cv=pass;
        d=google.com; s=arc-20160816;
        b=YsPW6ov5JatsDUF1JNrLnyP2w29PEcLGJi73B6lhjNPdZ+PhE7+5kRrFkRANPISLr4
         Ys5UK8Ckr2/XKmW+ceDBxNGD9crSBJGuGEQcQAcEAqLpZj5uwg/szONpTHpRmKXiqiyV
         eym/R76nsmf13TtHl/yyfkyCIMi7XM7qjDi5222/DabcZ76Uai1ehUFUlfXntuvTwzdt
         O4DgoqTa6uhiuQnKzFrxnStyfA4H766t3N+U3O1lLved7CVC+TR43DuYul4sUBjUns0M
         ZOtsQd1e3ho9ZeQNpkbqiKRhao3MaoHPUB425NXw69TOj+3tc1AppTmEO+HtW3IhWke1
         XXzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jbRuadt57sNYG0+E5uQSfE6lFc19RSPa+PFoZZhsWJw=;
        b=ujg5TxYxWRbdkdZu+wTNwuY+SJm+VBql8vPrX8kV21/HSoopT7yclbcpBd1AMc8xIw
         DMonuYCkaIymiaTju+WERBXk2x+afAfPY/5o+5toh5cuWGMqeNNlF/0Yr18Pm4X1NOAs
         jTm55cO85DGpzXgaYgcfN0cGEG8Gn5kbH5MXmc45kDdMUL6LfLtR1bKncF6MZ+OxbEn3
         Nb4BJR77Z3plqi94ncpdYv5TYxW7JqR/cxJLu8MqMIVKmJlZWCR8sBUd38akNIF0hlLy
         Qs5ERRB6mvgXMoTexkdexZv+uuH3PB6vjUAHrnpeQlqxyoZexAdTEtk+Vt1r8p0amMUC
         0YIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qpqdZ0sq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=jbRuadt57sNYG0+E5uQSfE6lFc19RSPa+PFoZZhsWJw=;
        b=P6ClvaB0LbfSAyC59SiJDjAXG02JiHMS1H6k6VgZJutgRNiLVNHBH8zDgjEy2pSaLV
         mMsA8V3vcdC7EcpB+xuNZkQXL17tnQR1ZKme1QlhIJPGx6/ALufr7CYcGqpkbD0u/ZIN
         KqGQj2U2iCGBvENBJD7THfeBDyObpRdq1Zuz/xHyT/ds7Az2OflVjM7JUe86jIQxWKi3
         HsSdtY/Mug85Y0OPeWEFjCSh5/VdT7ElzLXoXzaVSiIALO9ZSr6nUE20efvZYxtq2u75
         2RGKBxveq6PZNCkxAVQqBL6UvLeVmwGwdjBO6VuPBE+/v/n/CLJtpLYlegf3O0RbHTVK
         YqgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jbRuadt57sNYG0+E5uQSfE6lFc19RSPa+PFoZZhsWJw=;
        b=79sMhmAEpuhtZuWUrAV28hFexOkfGwL4XITPhvfEMltmbcjFdBpowbLw7vxVYKHOHd
         ATHsOl8iSj3DS/TiLPr7RcxZ7uM/IK5UhCbOSGkPtUi2jaX71klr/quNlLfYe45u8tU0
         h8iIIhvzTRnX3u0QWbDJGaW7/F7f2bDL2xJuT/RVsckbmj17g2az6W9O/PdUOUIFtUNS
         nlg0jU64Rke2qEZqzgiXJfa5qfHFyhL6QVmUwNlXZe/djTmtc8NclD4D8RJXxAPQWy9K
         GAqnKj9xNybLv9Jllzyyw+NoYt0CSpPhF4/5c/X0eZ+ltHJLhmU83Wr4NyYj/ELI3rTa
         foBw==
X-Gm-Message-State: ANoB5plVTExYr0ovBXvagVoSWfGiaYMS9MtXtZeemO9ArEI77fu/DXgA
	Jv4w5TiMgbWCjEUx/EZLagA=
X-Google-Smtp-Source: AA0mqf5kTv74CJOxGe96TNOs4E9CrUZZ/LrsjNCUrdGCUVy/Ucck+HSmvCV+w+Ghh3j3pogOTYidOw==
X-Received: by 2002:a17:907:b60f:b0:787:8884:78df with SMTP id vl15-20020a170907b60f00b00787888478dfmr3834183ejc.246.1668727393444;
        Thu, 17 Nov 2022 15:23:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3f8d:b0:7ae:83f4:3bed with SMTP id
 b13-20020a1709063f8d00b007ae83f43bedls1854758ejj.2.-pod-prod-gmail; Thu, 17
 Nov 2022 15:23:12 -0800 (PST)
X-Received: by 2002:a17:906:af65:b0:7ae:41e6:9076 with SMTP id os5-20020a170906af6500b007ae41e69076mr4003914ejb.321.1668727391889;
        Thu, 17 Nov 2022 15:23:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668727391; cv=none;
        d=google.com; s=arc-20160816;
        b=nEw681kmC53ytg/7ZwzXMflBAn7krhIwJ3nm/W8jWJbwnAXGm6K+knQ2FMsFHdCWG2
         k5izL68ZrXvME3Fq+Ao0dXypV0+My+bwGkR4fMknBouzPsQbdnNp1jppBeRiqOyE6oqU
         Qjx4c0iTYUuNlAjPwO/T/ZSo2KAG8PhqSPHfggfWLGAxWZWraniuPQsBKebJv/Mbkq7l
         Mcoegq6m1HT3GURTSoHz84V+JDKTqhd8c81yYmRXoc85UiO7dGp2C136RLWeDodMCWbW
         7XFjXLViEVFMZCrgbST/ljuMrXol+ZlFAzifdYyDCPYjnJwQtfEpRIAC3TLCpbW+SXXa
         RpLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=To+1hKZHNGliAAsi3sjlLMbkRpr0UyHLDkyr8XsSEH4=;
        b=QK4lp0wATVomFDGcCjzQNP2HESfloLCaTueCFNnU9UB0EW+OYNOWs8YQd9/v336b31
         5CDQ7CHdKSEai4q0KnPd/EPnPsw7fD2p12+Uao2atHHAvjV4+T5qJpLHonwDx21TWjI1
         TF36rsKTuFZsK99Tvhg8LijXwit3mjozWZD5SjfggjEiqj5zhn+Qogto/6RwKtHc/s5I
         +14g3JUb3w7fYkVq5cVpGBLIspP5vSisSdMjoOg26nwmh9LpXk6jLfUqDUjJM9vrCOFH
         +EtDnPdPtDyzr+fPMbF5rxAF9hSiErSJ1jILZF9LS98H5DSXy0xaqFhoEKT3aGGju5SV
         gVpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qpqdZ0sq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id b16-20020aa7c910000000b004690f5e1f46si9440edt.4.2022.11.17.15.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:23:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id v1so6358931wrt.11
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:23:11 -0800 (PST)
X-Received: by 2002:adf:e103:0:b0:22e:3180:f75a with SMTP id t3-20020adfe103000000b0022e3180f75amr2743740wrz.340.1668727391387;
        Thu, 17 Nov 2022 15:23:11 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:4799:a943:410e:976])
        by smtp.gmail.com with ESMTPSA id k1-20020a5d6281000000b0022ae0965a8asm2062148wru.24.2022.11.17.15.23.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:23:10 -0800 (PST)
Date: Fri, 18 Nov 2022 00:23:03 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@intel.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	linux-mm <linux-mm@kvack.org>, regressions@lists.linux.dev,
	lkft-triage@lists.linaro.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46
 kfence_protect
Message-ID: <Y3bCV6VckVUEF7Pq@elver.google.com>
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com>
 <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qpqdZ0sq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Thu, Nov 17, 2022 at 06:34AM -0800, Dave Hansen wrote:
> On 11/17/22 05:58, Marco Elver wrote:
> > [    0.663761] WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
> > [    0.664033] WARNING: CPU: 0 PID: 0 at mm/kfence/core.c:234 kfence_protect+0x7d/0x120
> > [    0.664465] kfence: kfence_init failed
> 
> Any chance you could add some debugging and figure out what actually
> made kfence call over?  Was it the pte or the level?
> 
>         if (WARN_ON(!pte || level != PG_LEVEL_4K))
>                 return false;
> 
> I can see how the thing you bisected to might lead to a page table not
> being split, which could mess with the 'level' check.

Yes - it's the 'level != PG_LEVEL_4K'.

We do actually try to split the pages in arch_kfence_init_pool() (above
this function) - so with "x86/mm: Inhibit _PAGE_NX changes from
cpa_process_alias()" this somehow fails...

> Also, is there a reason this code is mucking with the page tables
> directly?  It seems, uh, rather wonky.  This, for instance:
> 
> >         if (protect)
> >                 set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> >         else
> >                 set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> > 
> >         /*
> >          * Flush this CPU's TLB, assuming whoever did the allocation/free is
> >          * likely to continue running on this CPU.
> >          */
> >         preempt_disable();
> >         flush_tlb_one_kernel(addr);
> >         preempt_enable();
> 
> Seems rather broken.  I assume the preempt_disable() is there to get rid
> of some warnings.  But, there is nothing I can see to *keep* the CPU
> that did the free from being different from the one where the TLB flush
> is performed until the preempt_disable().  That makes the
> flush_tlb_one_kernel() mostly useless.
> 
> Is there a reason this code isn't using the existing page table
> manipulation functions and tries to code its own?  What prevents it from
> using something like the attached patch?

Yes, see the comment below - it's to avoid the IPIs and TLB shoot-downs,
because KFENCE _can_ tolerate the inaccuracy even if we hit the wrong
TLB or other CPUs' TLBs aren't immediately flushed - we trade a few
false negatives for minimizing performance impact.

> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
> index ff5c7134a37a..5cdb3a1f3995 100644
> --- a/arch/x86/include/asm/kfence.h
> +++ b/arch/x86/include/asm/kfence.h
> @@ -37,34 +37,13 @@ static inline bool arch_kfence_init_pool(void)
>  	return true;
>  }
>  
> -/* Protect the given page and flush TLB. */
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
>  {
> -	unsigned int level;
> -	pte_t *pte = lookup_address(addr, &level);
> -
> -	if (WARN_ON(!pte || level != PG_LEVEL_4K))
> -		return false;
> -
> -	/*
> -	 * We need to avoid IPIs, as we may get KFENCE allocations or faults
> -	 * with interrupts disabled. Therefore, the below is best-effort, and
> -	 * does not flush TLBs on all CPUs. We can tolerate some inaccuracy;
> -	 * lazy fault handling takes care of faults after the page is PRESENT.
> -	 */
> -

^^ See this comment. Additionally there's a real performance concern,
and the inaccuracy is something that we deliberately accept.

>  	if (protect)
> -		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> +		set_memory_np(addr, addr + PAGE_SIZE);
>  	else
> -		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> +		set_memory_p(addr, addr + PAGE_SIZE);

Isn't this going to do tons of IPIs and shoot down other CPU's TLBs?
KFENCE shouldn't incur this overhead on large machines with >100 CPUs if
we can avoid it.

What does "x86/mm: Inhibit _PAGE_NX changes from cpa_process_alias()" do
that suddenly makes all this fail?

What solution do you prefer that both fixes the issue and avoids the
IPIs?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3bCV6VckVUEF7Pq%40elver.google.com.
