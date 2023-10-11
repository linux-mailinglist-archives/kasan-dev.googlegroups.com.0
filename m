Return-Path: <kasan-dev+bncBDBK55H2UQKRBVNFTGUQMGQE2AJ4S6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 871AD7C4C3C
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 09:46:31 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5056eada207sf6129485e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 00:46:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697010391; cv=pass;
        d=google.com; s=arc-20160816;
        b=CuPO6sS/vH0x59nIYy0GEsD9RLJ/Y6fPcSKBAchH6RyM5YVSOXGj8eab4uM0hZSBjG
         3tIc6CV4fFqMh7uL16UpHY0q7cJfQnVtHnen+HCsglQzl3JztiyORRgjW0GdDyoSZ8x4
         hu79nt7VACwwvOSj8nrWybzz0D6upYFvDgLwuOigKDNYTOVhn65uDfG5Js3HlMz0/p/y
         /UVT3Hk2/aTjKJOjnar7ND+DPIsfx9E9TjrqwNGc+g3SFZ385o/dzebRq8Famzz3A5KL
         m+v2B/LbsqMpHTzexCLJKH8O1phni8aG4sXZFJeX/kHFeDjxdPWNc+5PE9wX/1lnShP0
         OYSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=U/fl2IjW981qG4Q8twq5UcB4/Ke7Z+e93XxWdr8Wd5Q=;
        fh=0jdiGLdX2nZnZBw7jbPihs/xBeWIj01/5aUTE880zHw=;
        b=qvBKqm2+62+63aIweN65FoEMroZFLlq/fxeuRhYur3FMu/QJV2iv0c9gfx4yZVrDaR
         O4Hp+6DodYT4dFnKyZpuwf+MEBQo9s1PFSaqijzWYOsB9KgpL9DJC84iJ3wrqOvYCEGI
         somqbrGQ6+6bdIRAIHWftkeTSkrqTj28Vz752iqC1OEp5gvBH9mYa2UT/aKKhYwwoTGP
         lnZUJvrj/KCFdMk6cOzPQyunFxcGm/lbGT83YGmTtM940JKPiuYObQJRec8N1vIXo/4/
         xm5CHMJ5wmhzbvAq+6qCa474PDgWayUltFlfietXLLUOgGHfCS+WsV3pLPrbGce+kMCg
         kv8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jwICPp03;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697010391; x=1697615191; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U/fl2IjW981qG4Q8twq5UcB4/Ke7Z+e93XxWdr8Wd5Q=;
        b=xkEl9qJ4Pg2xUmHOvfZLrvZy2vh954rH+Mx6k+VdBKXbrklYqbMVTSnpd9398YILag
         RAbliXkQ4obHWNeKY7V/l6Epnb3cdLs+wjtKchw5/vj2bzciAKGpdJFyrZwtq5MAorgO
         DPUJzHjsdd2G2rjnFzpsdsBB7TJDsN/H9ROBpmRs7lHx73WMwL+mDgt9IM3xiZoNlr/t
         9DkHaHzh+FiusxlNG3X0APyD/A6hBQORpHkKJtZGXSuFk+opili8I3ZDVkC0S60GHc/1
         fVnY+SkshmnxiIPrfG5cXps9dpCFxyYCNMdYOzj4kOT9F0zJHAT2Y5HaZvOx3Wz2kcUt
         KxDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697010391; x=1697615191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U/fl2IjW981qG4Q8twq5UcB4/Ke7Z+e93XxWdr8Wd5Q=;
        b=j6yFErEwATSFF75BnYo/uRLLwPz/joQRYYZwXt/S72PgoJaV/9s4/AmWw8cvFFEIYi
         whWssKfjeZqdB9iU+8n9kB7VQfV5G3HgqdeL/WDjUYPbTisgfgZ8sDOGCoyVhnrb1Z9v
         4JJxy46REDPYReArUA/0X2TjAMWYoShxdmFoqGynpnKvJjAkRVGUTCkLHTVEwC0wq5cp
         V+0ZTq82voGAoKhOCpEMrsoigIv2/qqsA5vWi51vNXSQJgG/vtX90V91VTNEDgppkNP0
         vtBTD5PDw/X/A1bT1Ddw0QiiOnkPFQxkFkVtyLJFpd36sqP73nhBcww42+LN6xWOOnnv
         wBOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxRYXdcZnqWes/lkE4Bi56k1W5d0uZ5BiUyqYuHLOCPNlrEVAJj
	7ZeNGjJPx7ZNerx4zHKRf6s=
X-Google-Smtp-Source: AGHT+IGuQTj+4Raw6WNjgsa/VvoE3SAdt29frI1pzUA56KTccclL9mfbyMGvNiBRq9W8l+Dq1v3K3Q==
X-Received: by 2002:a05:6512:210c:b0:4fb:bef0:948e with SMTP id q12-20020a056512210c00b004fbbef0948emr15076305lfr.5.1697010389399;
        Wed, 11 Oct 2023 00:46:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a84:0:b0:319:7a47:8a59 with SMTP id s4-20020a5d6a84000000b003197a478a59ls2519190wru.0.-pod-prod-04-eu;
 Wed, 11 Oct 2023 00:46:27 -0700 (PDT)
X-Received: by 2002:a05:6000:369:b0:324:e284:fac2 with SMTP id f9-20020a056000036900b00324e284fac2mr16986204wrf.5.1697010387346;
        Wed, 11 Oct 2023 00:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697010387; cv=none;
        d=google.com; s=arc-20160816;
        b=EscO+hSFr8eONBgMkZxQ49FEmbaF7StH3U+joxCvStoifL5H8MBivwsa/S9iYolj1K
         f0zrox907rPf1Di9JUP08/c/l2dokFtXXpkm1loA81rw46iISGtV+G0gs/cB4DuBjW8I
         ZG48isMLSDgqu2Y7yZTIcgiZacBkieGJAM7fFT+R9I2qUEaND1vIuNQWIzFJxJhj0RYN
         o3FJiqG90rkB7Irv8/FdDuYZOc5RfNML/SN316U7mluz/FoSu9d2T1Fb7Vwb8wpw6Q+0
         p3xMH7an5MHDTXZaM/s1KMAxZ/8d4jKYSC54S1nTa0ttfl+ZTQqPpxJpFVfazFjhIB1x
         w/Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=61isM1aH9tWSRneo34EFdKetusAPfy8ZA6xHY6hutnw=;
        fh=0jdiGLdX2nZnZBw7jbPihs/xBeWIj01/5aUTE880zHw=;
        b=T/PPsokb9vD9fkh5UX6MpV2smuHLyclzevfGoVWhG/Y3iMTYVYbz5ojML/HpoxXtXN
         Rz4u14BMno9j0NbMFdtEETGNmgTpoIvGrPkB/8mn7DJh7pRGjXAjFXoOoq1rdHsajRH8
         1iELaSF0ts/1OIu7r8Hfztf4MjnAaJjOUtlZQXsLqxsbFvRXVUBNt0efYCW7TfsHAjGY
         T1ElUi/K6cUtRYUprjQ0pv09S3O+TUMkhytViG46S0zhR0w71fMERpu3sQ5N5Y+FwnNB
         Uxm4Ui+RfNiwMUhMBdfXyKgrAwEcL4J+pX3EbBg2AX6frA1509FECr/GsfOaNBIIGx4K
         6JVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jwICPp03;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id v6-20020a5d59c6000000b0032c8861a1d1si199341wry.4.2023.10.11.00.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Oct 2023 00:46:27 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1qqTv5-0003uD-0t;
	Wed, 11 Oct 2023 07:46:17 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 63E7530026F; Wed, 11 Oct 2023 09:46:16 +0200 (CEST)
Date: Wed, 11 Oct 2023 09:46:16 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCHv2] x86/alternatives: Disable KASAN in apply_alternatives()
Message-ID: <20231011074616.GL14330@noisy.programming.kicks-ass.net>
References: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=jwICPp03;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 11, 2023 at 09:58:49AM +0300, Kirill A. Shutemov wrote:
> Fei has reported that KASAN triggers during apply_alternatives() on
> 5-level paging machine:
> 

Urgh @ KASAN splat, can't we summarize that?

> 
> On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
> got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
> __VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().
> 
> KASAN gets confused when apply_alternatives() patches the
> KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
> static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.
> 
> Disable KASAN while kernel patches alternatives.
> 
> Signed-off-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> Reported-by: Fei Yang <fei.yang@intel.com>
> Fixes: 6657fca06e3f ("x86/mm: Allow to boot without LA57 if CONFIG_X86_5LEVEL=y")
> Cc: stable@vger.kernel.org
> ---
> 
>  v2:
>   - Move kasan_disable/_enable_current() to cover whole loop, not only
>     text_poke_early();
>   - Adjust commit message.
> 
> ---
>  arch/x86/kernel/alternative.c | 13 +++++++++++++
>  1 file changed, 13 insertions(+)
> 
> diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
> index 517ee01503be..b4cc4d7c0825 100644
> --- a/arch/x86/kernel/alternative.c
> +++ b/arch/x86/kernel/alternative.c
> @@ -403,6 +403,17 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
>  	u8 insn_buff[MAX_PATCH_LEN];
>  
>  	DPRINTK(ALT, "alt table %px, -> %px", start, end);
> +
> +	/*
> +	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
> +	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
> +	 * During the process, KASAN becomes confused and triggers

	because of partial LA57 convertion ..

> +	 * a false-positive out-of-bound report.
> +	 *
> +	 * Disable KASAN until the patching is complete.
> +	 */
> +	kasan_disable_current();
> +
>  	/*
>  	 * The scan order should be from start to end. A later scanned
>  	 * alternative code can overwrite previously scanned alternative code.
> @@ -452,6 +463,8 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
>  
>  		text_poke_early(instr, insn_buff, insn_buff_sz);
>  	}
> +
> +	kasan_enable_current();
>  }

Other than that, ACK.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231011074616.GL14330%40noisy.programming.kicks-ass.net.
