Return-Path: <kasan-dev+bncBC5ZR244WYFRBQWFTKUQMGQEUAWES7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D71EE7C556D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 15:27:32 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4063ddd5229sf239585e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 06:27:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697030852; cv=pass;
        d=google.com; s=arc-20160816;
        b=V48iGQP6RXeku+u2asItXBwfEoxQotqIVHb+pRDs3XczXIjBVlpLToE4Uw1ZOJwcEw
         iz3xZaN2V6dBUvKLiCyEKwcAmD6r9B7BXwKiZ46MgajuGOjqOLoRNJXR8NEWLsXrmqv+
         TYre4tC/eHv2OENOcA+m9ozX8HNwGDMdGBv2RkjR+fPYLSjir+sYkkzfppEDs0dR67GM
         9jlgWpjBfjOfUJ1InfYVMPXPArhgBa247q697uYyy9whs7QS+dk50BJQrz/9NFvCAXH7
         gYXV+KHsgS6saBuY4+JMrNb4VTo2wyaLDgZ9P9VUNfyRuAlgUmfPxv10s2nXZoD8JwYg
         ae0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8kfnH1DjUPnliv4AK25X8H3oIIk6YB4Z+jZaZjsJiyk=;
        fh=fLJpdFXMrgkhIFph62k+jGdYXP9DzrA5vOfmQT1EouI=;
        b=KwYwVWXDg+HVBYLCYm5uM4tePO4Zrq76fAx/h3Cbj7xd99pMrm7r6qNdDxrv4dmNFf
         GQ4TszCTl4pT5FQiROM5u0uWGaE3rQjgrCzzp+8Vv4A1oUAyBQ7JsQ9tpi01MFPmSL87
         OZPCEAlkaFd1/QWyh1gxQwZJFOyCNw2VTEEw2JyZubq0N3Am0j+tHj+u+5DeyWOZp+09
         higF2EI40gmfSo7dWKMZVdEAvgsMnUTrraqBsmiaZo9q8NgEFETI0b3D8b6DGciELAuL
         KOBumllepuv4ptBZa5Lt5UTAlCn+fwDsr6JXc0zFsOZ7Wjn3R6FJgK0p5+8RgqInCA7g
         Sjag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JwQcTtXe;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697030852; x=1697635652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8kfnH1DjUPnliv4AK25X8H3oIIk6YB4Z+jZaZjsJiyk=;
        b=sRd0Pvel13z1yGuBlfV/d5OOL14c6n9lnYHxr4RWfttDUIx82LFknTqYp4oEqKl362
         vt0vjTgdBHjpC5mbuPhSLHoSd/Bk35EFTv8Z9lHeKpWPLRujCKPe0ugP5EY3HJaAcSRM
         1yVuKteHEciDMfN7zFcC64QcjTD5NvjOytUDAIQPraTGEjm5YuUfEhgYFYBdvVHfHsKz
         xD+G0OxW9Rwh0ah0mRy7h5BF/JHgDgPTeLVLa/Dq9J0dRx6jAKPqIsyrfMFKxpZeXqre
         0ebNonCnFi2AhPXXE3Q9o+MtT1hMTQq+y6bCVsl9UKfP4pJiKY7//PwfRwhdiTolJOSp
         jLcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697030852; x=1697635652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8kfnH1DjUPnliv4AK25X8H3oIIk6YB4Z+jZaZjsJiyk=;
        b=frF2rY6Fw8wUjy55rSO2LtsH2Es7OvCZ7XR6tH98IiE6S6KCdIuMYoJOLDtTF7vzCK
         ZI457UaZrMjp4UcUZcxy0PWcU+43hG45t+QFbhr/NhviOVtqgPDI3liNKlqjsvbKNlW8
         2e/cIR26r737Y3Cbfd3u+fgFQFcC6O3O3uAQ2q3qrNEQvOoB5E+b+093zAOhORCd50BF
         EC7D7dTQruJHPLPEG8LMmgY9OP0fQZgSu2Hj8xjGakQBRTNWCzdHPiZxfOfnBXfYrNH6
         sPxWyb7qHsk+2NxYx0lVaRAxrN+REG9uwh6jxXDt2sRAGBGDoaxBYarNbQAgB+ZDX+MW
         /IRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy4HnT+fGefJxMkuolqYQktTuJvsANRTg+SsgwIx3qZ8u32xP+e
	q4wuIjKuX6I/zNup3raC4ec=
X-Google-Smtp-Source: AGHT+IGtuHY4CYNhZXzlies6e9VkS/mxkCdbjJ33lV8oRWnByjomZNJtj/10mkNczX5w+ppmplFN2A==
X-Received: by 2002:a05:600c:1c16:b0:404:74f8:f47c with SMTP id j22-20020a05600c1c1600b0040474f8f47cmr86969wms.5.1697030851151;
        Wed, 11 Oct 2023 06:27:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:564b:0:b0:329:22d9:9fe8 with SMTP id j11-20020a5d564b000000b0032922d99fe8ls156351wrw.0.-pod-prod-08-eu;
 Wed, 11 Oct 2023 06:27:29 -0700 (PDT)
X-Received: by 2002:a5d:6c69:0:b0:32c:eeee:d438 with SMTP id r9-20020a5d6c69000000b0032ceeeed438mr5121917wrz.54.1697030849287;
        Wed, 11 Oct 2023 06:27:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697030849; cv=none;
        d=google.com; s=arc-20160816;
        b=DHNUV+u8s4ggH67Y8QST6h4nLHm09L+gWFVPT9Leuj+NJOYX0o4DShPTrEd7ATywaN
         FDgZnsWD4qKjaUyFEHsIWZUp+jK0MnmM7EAVDERjIHfFYt9APCUx7/1fJH4D/F3cT9Lf
         KP71WvJfoTdPlZAgiNsIMPsu5t6DSlC+NkvOuYFRE+Q5UoZoBiLcJGc4fhfxR6G8F9n0
         9rYFkn+vW1CJBXvPOHkGDCOzWjg/8AD9QkXnK8Mynb4F0v2CfvqiaDXbFN/671sP+SIx
         dfo2OI3tD3QrGuGULRzziMt0QtAhfWNyuLtJW+r2uCQMa0+dj5+6npl9q9RjXSyEUWLH
         hRGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eEAKmfl8e3fXJ5jIx1jPPupNKS6g/TnavdOqr7u8H/g=;
        fh=fLJpdFXMrgkhIFph62k+jGdYXP9DzrA5vOfmQT1EouI=;
        b=rByV5ugJgNlik8L9iTFK7HTjqN9v9UxWI04quKP/02h/aWMypLqffIL6m3oGmXBrjn
         tfN2H75p5JdIdz2EwXPHSfmfjEdSj2gh7KQS2uZ3muiGZYN0ZedhxRCOgQnQGWqM3Qvo
         irPXjiXs8jHC98DJMgiBrZQoEnuqQhHYJ8J/goZvfu7YFvaOv5pz8K4hUYdhfgUNGLRm
         N0Z1RlXY0TR9xL370VWdabHifjG6JShJHSHsuJqvHFDKqA8utojO4HbuVNqPQh5TnJFq
         TXATPOo/vbYvez2ms3odufGnSRhwnA7tIVLzn3o9HZ2oChNki4acPff0STKmHUE/XKFE
         Tp5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JwQcTtXe;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.9])
        by gmr-mx.google.com with ESMTPS id b1-20020a05600003c100b0031aef8a5defsi580291wrg.1.2023.10.11.06.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Oct 2023 06:27:29 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.9;
X-IronPort-AV: E=McAfee;i="6600,9927,10860"; a="3249912"
X-IronPort-AV: E=Sophos;i="6.03,216,1694761200"; 
   d="scan'208";a="3249912"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orvoesa101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Oct 2023 06:27:10 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10860"; a="897624429"
X-IronPort-AV: E=Sophos;i="6.03,216,1694761200"; 
   d="scan'208";a="897624429"
Received: from laptop-dan-intel.ccr.corp.intel.com (HELO box.shutemov.name) ([10.252.56.166])
  by fmsmga001-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Oct 2023 06:25:21 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id 29011109FB5; Wed, 11 Oct 2023 16:27:03 +0300 (+03)
Date: Wed, 11 Oct 2023 16:27:03 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20231011132703.3evo4ieradgyvgc2@box.shutemov.name>
References: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
 <20231011074616.GL14330@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231011074616.GL14330@noisy.programming.kicks-ass.net>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JwQcTtXe;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Wed, Oct 11, 2023 at 09:46:16AM +0200, Peter Zijlstra wrote:
> On Wed, Oct 11, 2023 at 09:58:49AM +0300, Kirill A. Shutemov wrote:
> > Fei has reported that KASAN triggers during apply_alternatives() on
> > 5-level paging machine:
> > 
> 
> Urgh @ KASAN splat, can't we summarize that?

What about this?

	BUG: KASAN: out-of-bounds in rcu_is_watching
	Read of size 4 at addr ff110003ee6419a0 by task swapper/0/0
	...
	__asan_load4
	rcu_is_watching
	? text_poke_early
	trace_hardirqs_on
	? __asan_load4
	text_poke_early
	apply_alternatives
	...

Is it enough details or I overdid summarization?

> > diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
> > index 517ee01503be..b4cc4d7c0825 100644
> > --- a/arch/x86/kernel/alternative.c
> > +++ b/arch/x86/kernel/alternative.c
> > @@ -403,6 +403,17 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
> >  	u8 insn_buff[MAX_PATCH_LEN];
> >  
> >  	DPRINTK(ALT, "alt table %px, -> %px", start, end);
> > +
> > +	/*
> > +	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
> > +	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
> > +	 * During the process, KASAN becomes confused and triggers
> 
> 	because of partial LA57 convertion ..
> 
> > +	 * a false-positive out-of-bound report.
> > +	 *
> > +	 * Disable KASAN until the patching is complete.
> > +	 */
> > +	kasan_disable_current();
> > +
> >  	/*

	/*
	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
	 * During the process, KASAN becomes confused seeing partial LA57
	 * conversion and triggers a false-positive out-of-bound report.
	 *
	 * Disable KASAN until the patching is complete.
	 */

Looks good?

If yes, I will submit v3 with your Ack.

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231011132703.3evo4ieradgyvgc2%40box.shutemov.name.
