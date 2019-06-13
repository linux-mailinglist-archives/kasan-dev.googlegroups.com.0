Return-Path: <kasan-dev+bncBCV5TUXXRUIBBHNLRDUAKGQEZBB3VSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 52F184349B
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 11:21:35 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id v1sf8970523otj.23
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 02:21:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560417694; cv=pass;
        d=google.com; s=arc-20160816;
        b=amUGSNYtmFOpOZwl1/PwbyCS6MdWF2fs0piQahu/v9amVf4N/uziSeHjr5Yr0j8k60
         jnVK9FMlXpdfTB3pbQsLa04nT3S1Iek107F+z9m0okrVi1pVEv3YRoym73BU1Smznnam
         X4h2MXJxfRsyqCNF+Po3zYqNZ1laADD6GDKeGNpFs/ESHcgRxByQXYQlb5Ej5R35ziX+
         3bzODgOpGJIPByu2G8X9V/J6BxQyGBHLfrF9bGE97L7dU5sVRseBzBkVXDPIc0U9MVwa
         //UrVpOCvaUZX/q5iMIpXGV0RgoTW/PCESSY7qV7ngDZErrNn6Oaa+Ex8/kT4KGVBjbh
         aFSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rrhqyk1oxoGxcZpUL+UywUj2g5EonVQm3Gvfl+EaPuE=;
        b=av3srDqmRGRImFAuEopF7qcay80mbTr7Pvw2iceQ3RUFNTX13UkvcTsJUtr4QatReK
         21UUFbSbE5zTPGrepbyYSp5pLbPC1A+eTh99mhiy2U3i6Y6Jw0hNF8eHJnoCLSxDbZjX
         UJyOWAtMRH4QjxgeO4ZDij+gde5Xc9gBAwJaTvpTuBE46q52/Zlgf5XNQ/L5NePkO+Dl
         Va3U3u3eOt+cKIln5myFMfABp+jcseALquI0bT3mYYPJ9J2Gm0W5EYDh3D3oZTS9F6EQ
         JA76o93Ir2I5Mi2UfPlM1p89nZlgy3zP3afue2SiBGcDCCUZFHfdc0/cb9IKH7YCf/m0
         0zMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=RvVfgl22;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rrhqyk1oxoGxcZpUL+UywUj2g5EonVQm3Gvfl+EaPuE=;
        b=facCbcn8LZ6All4xM9L/7eNaT+d8b4HV35loi95SqRKH108Oewsf60Q8vA70OYpCNJ
         oR+Hk7FsnoHn0BtV8uoNwUMrAbxTaChvwxQXktqgxYnxoT0WvXdLlfgACGR+fEP7I5z2
         zxphycxib00KuGElR9FHG5XDDDsBMO40fe20wQtd5sCWO/g6m01AlsFtrDTH76fZi+gq
         Zzl726l7F6qCbk+UUxBDL94F1d9Vp/Jcdths+U4ou+YqoHOhnwaJ4mSvvuQYbQFkC4n5
         sHZBqv4yXmwxe6aR083K1OMwBbBLcD3165J7NcBD6uYsxo9Ihmw12yv4UH86NrgtMKdA
         N46w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rrhqyk1oxoGxcZpUL+UywUj2g5EonVQm3Gvfl+EaPuE=;
        b=t14FJUEGLeFJWmeUk/Tkl3I7Pez0zIKLQdZnqmt0FtzT2wivOuD/isAls976WXpFBC
         bBfVdJNv7u3IuC8Zhgkb0SnNX3YG2n4+ttjSuEILttcr5cTf6tq37xd9cehFtp0RQm8b
         ci274JLG4PnZznHYmlx8r4Hw8os09lfvl3e56o8WMK6140GK/mVtr5TCGWrKUC2piv6t
         kpSJ7n1UuRUpa+AzrsOioK/l2N1sz44LpccgEoe+REfL8Cl/apJH/bESVWSz1rumh4LS
         SceMKhJwQpGceJXYSyt0Qp8AtevZAxfr1k6CXMlKmYmVk/k0ojz6FFU3FtSBe1068Z2B
         VGcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWvg0UftnQwaxW2MyHgV52tYP55oPwbJfBtKqdEo6pDE8Zu4j/X
	vmHyaHa5dHTHxrjhazrTjl4=
X-Google-Smtp-Source: APXvYqwmI8P2hglYxzQxCllc/arF3HfCpvcJ3Etv0357urmNctP9oNnbz46am0mX8tMokt2dyhtD5A==
X-Received: by 2002:aca:4f43:: with SMTP id d64mr2372940oib.81.1560417693861;
        Thu, 13 Jun 2019 02:21:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60d7:: with SMTP id b23ls941331otk.14.gmail; Thu, 13 Jun
 2019 02:21:33 -0700 (PDT)
X-Received: by 2002:a9d:51cf:: with SMTP id d15mr9072047oth.206.1560417693462;
        Thu, 13 Jun 2019 02:21:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560417693; cv=none;
        d=google.com; s=arc-20160816;
        b=h7+xrcMpfarKeIMinh/oxuKAXkbJJa88TKrhKyuoORcchtmtWDj0+etRtI5CUQFL93
         Gapxf7PQ/hgszH+sR2SRhhIErs0XAIRXy3Yw6JigToMqLOrkJ/h3kZvbHJjPjILWiTV1
         NVWc+WqikzhkABRI3RZC5lKVuRSdFf8nlLfVXAp8nhSPOqZYUmkg0cgk4tVyJtCdHo5m
         nh3dYJ/rnfZJb1QdQq4DrUuC7GybMW/3Op4Vi0eA50xUyNDMbYSedDi2oMCWhdcoOWHN
         a6P3kt9KOgl/c90r0LUBhV/x8XHzDMWz/wTuE4iSr3R0LV3lGJ/5KJr1MuhfVCsZnUar
         ROEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KNxPWlWuxnDwYXMMhXWadjBNeF5Uv67xMzgxslH4spI=;
        b=LISgDiq/eZnkuEAsl/QvRLUFX10NY4lCUswynnQRZPvgfnQSaj02TAgZurMJRBJb6m
         BRtuql8fVhInNNfB1Kv6XMzGVoAQsWETrBfeniZQaYwULF//kVYtZ2jTKrvLczgAkSPj
         qylau53x5UVfSJP9/G+GeY7kODBdNnIwgQnVMjFWxtvgijwXdBNiC8P2oEJJELKijbeH
         5ibrwuSHu1QzWI1CW7mofTkw86/gnnf/ObfRcd5c5TDZiKUFxErMTtxuq66xm9VsN80P
         q6ISlKK3KEq1Q8gcf5Aiz9HyweeTZms9138WM+bFYfgw5coPnGQQgguSKX+Nbdes8Zc4
         s0WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=RvVfgl22;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id m81si181930oig.0.2019.06.13.02.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Thu, 13 Jun 2019 02:21:32 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92 #3 (Red Hat Linux))
	id 1hbLvA-0000K1-OV; Thu, 13 Jun 2019 09:21:24 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 33A9D209C844F; Thu, 13 Jun 2019 11:21:23 +0200 (CEST)
Date: Thu, 13 Jun 2019 11:21:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com,
	corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 2/3] x86: Use static_cpu_has in uaccess region to
 avoid instrumentation
Message-ID: <20190613092123.GO3402@hirez.programming.kicks-ass.net>
References: <20190531150828.157832-1-elver@google.com>
 <20190531150828.157832-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190531150828.157832-3-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=RvVfgl22;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, May 31, 2019 at 05:08:30PM +0200, Marco Elver wrote:
> This patch is a pre-requisite for enabling KASAN bitops instrumentation;
> using static_cpu_has instead of boot_cpu_has avoids instrumentation of
> test_bit inside the uaccess region. With instrumentation, the KASAN
> check would otherwise be flagged by objtool.
> 
> For consistency, kernel/signal.c was changed to mirror this change,
> however, is never instrumented with KASAN (currently unsupported under
> x86 32bit).

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Thanks!

> 
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: H. Peter Anvin <hpa@zytor.com>
> ---
> Changes in v3:
> * Use static_cpu_has instead of moving boot_cpu_has outside uaccess
>   region.
> 
> Changes in v2:
> * Replaces patch: 'tools/objtool: add kasan_check_* to uaccess
>   whitelist'
> ---
>  arch/x86/ia32/ia32_signal.c | 2 +-
>  arch/x86/kernel/signal.c    | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
> index 629d1ee05599..1cee10091b9f 100644
> --- a/arch/x86/ia32/ia32_signal.c
> +++ b/arch/x86/ia32/ia32_signal.c
> @@ -358,7 +358,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
>  		put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
>  
>  		/* Create the ucontext.  */
> -		if (boot_cpu_has(X86_FEATURE_XSAVE))
> +		if (static_cpu_has(X86_FEATURE_XSAVE))
>  			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
>  		else
>  			put_user_ex(0, &frame->uc.uc_flags);
> diff --git a/arch/x86/kernel/signal.c b/arch/x86/kernel/signal.c
> index 364813cea647..52eb1d551aed 100644
> --- a/arch/x86/kernel/signal.c
> +++ b/arch/x86/kernel/signal.c
> @@ -391,7 +391,7 @@ static int __setup_rt_frame(int sig, struct ksignal *ksig,
>  		put_user_ex(&frame->uc, &frame->puc);
>  
>  		/* Create the ucontext.  */
> -		if (boot_cpu_has(X86_FEATURE_XSAVE))
> +		if (static_cpu_has(X86_FEATURE_XSAVE))
>  			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
>  		else
>  			put_user_ex(0, &frame->uc.uc_flags);
> -- 
> 2.22.0.rc1.257.g3120a18244-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613092123.GO3402%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
