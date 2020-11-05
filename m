Return-Path: <kasan-dev+bncBDV37XP3XYDRB75SR76QKGQEMU64DSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A1A32A7C4C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 11:52:48 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id t9sf565178oon.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 02:52:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604573567; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cs59Li7OCQUy9KNiPb8GsUsLvX23J6bTSDyG+LLb/etzF8arFAshWolZW5H9sttidg
         9rYWwR9DgOfXJ/0SoNbvshGPD8ktPcHE+EzawLs0DTjx/RhAlAjrGraNbxmyyXaBwOh4
         K4BhPaV1ZqscBpODc0aV3zJHfigyIm9wD6F4jox74qPyUFdFBvj9EbZvGd/fbFHi8/Tn
         MD6trTZilskRsCMRB+rmQEwPtOxdjnZIqt7eclWAHIjFDvHMSIJltYw7NmAjqafJlzxa
         c8ZfT4JjXGNQ57ayX0zRMOU/Sm4HxpZn8JPmazOl1+aecL8hTdEkwHmlomDG6NpblJyk
         dFeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SB2lPkZrKj058lcGKXjzfdAsMIuZ/2MkDqWjLLMY/Uo=;
        b=Z5IcOvZUoX58DM3PtspA2sHNI9dEsnlzs9s8QclJ9hnBnZcnL/St8Siid7Pc91Gyjs
         CkcOIDFY6d1rRzLL+eTwjc0kzYWDmDFgEYlVijVO8CwK8f79sxXGTsVAyx7dd+NV0oLK
         zODIwDdVCD42OaUvI3m511d7HgZJ1Io/qgkQFp1RPrl/5JhRIn77F65mHBY3QcqvshbK
         HZdORlhegs8ruv3aC+uiXqUkgi/ydrgcrjp6Fo5LjFzsZU1QAZMni6Jm8NhgadgMQUJY
         KsqalGw2Jy0TzHCr7bjPezwxwbKpKZRLQErKzl4x0WB7yqQjBnzgIJBbW5LRq6OzZHF2
         4nOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SB2lPkZrKj058lcGKXjzfdAsMIuZ/2MkDqWjLLMY/Uo=;
        b=jCpf3XSz0D8/E7sZ1e4xrTcUCuiMRnajp0s2z4XoallzwigXm56gfu9YtQZeDOQxXq
         K99OYwc6no/N17mZIkiT74otcp8loZe39E4+wfYOahfjX1hu0RvQ4TSEaLC2eAELRWjI
         GF0TZR6pWpKwN7PeSFbmAmMpAByLAUa7Y9DMYlrtNNBdRTTrMhV6Bnfmqh2nKcFhh7YI
         /bLlXfSBS/rUXoLlSunZfEf2ae47cAtpl3UUWBJJg3Dh7/QD9vqn6MBVzBeTMH5iBm32
         //K5Rzy0gJ4fl6ShqB1+Ve5ymXW4cKfjHGXaxG0zkTz+KV8XPyvCqmRpTR80oF03h1ke
         L5EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SB2lPkZrKj058lcGKXjzfdAsMIuZ/2MkDqWjLLMY/Uo=;
        b=O71dv1htQKPyvqjcBhzzhagpXJNvyzNeWknFeQtDeMhonVjmkH06+cXDNe8DoXXitZ
         oyUVEzMp91Bv+AUpwIoDYIgL830hZy9tT5ZhVa+HpJERAHyoh1901PbOLNbIepIdpBin
         hTf09mUfRzMvxardJE3XloIzRzL7rVm2fLmEXIUG2Nj0+7nT2PGVBzkdUK1N0S0t9b3W
         IECwAMt3JTY0SjxdLIAkRTe0bMAbNivRx/sqZH3Lg7ILreAidMQueJdO+ci0zr9yRCUm
         CjERwthPzeiyjHYacAux9RKrXZ3OjG/vXvDzmcdCwicWiONEHD8WI0U2jGr7kRW9WyGF
         sqNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326NIin16KYUtG2PQbRmQdeRm8ggkQ7YyoZQ9nSQ34CCNlGcTIW
	6gxmrWfnWioJnLlnRZ1N35k=
X-Google-Smtp-Source: ABdhPJzSVp6NUob09+kCC6eIRus5iO/7U9KB+99MZ5IKlWtDQBkg+GBNYxzPHtCwFjrcJj3zUXKrHg==
X-Received: by 2002:a05:6830:1e18:: with SMTP id s24mr1316076otr.40.1604573567140;
        Thu, 05 Nov 2020 02:52:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:198c:: with SMTP id k12ls327531otk.3.gmail; Thu, 05 Nov
 2020 02:52:46 -0800 (PST)
X-Received: by 2002:a9d:bec:: with SMTP id 99mr1315565oth.103.1604573566752;
        Thu, 05 Nov 2020 02:52:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604573566; cv=none;
        d=google.com; s=arc-20160816;
        b=sGIBnOzW4lit9wQeJlCAO5HPx0YbI2F9EcP8miUhdmUfYQLCDBxDfsz3L7m13xnFHv
         PZpcTwyPCr/SYorf7f4RfwC4Jao/XsjrejrFOV/f4vmp1rnsDlzTvSvdTVf7+ERuic1O
         H0j6aT/1k1ZXsZZAN7u7oj2j/KA8HQs5627nZX55t0YVT+tJPV7Mp7efrJ3WHklAOnTI
         Aoi1AJG+Xs5w7dhkY05C9Xl+ThzKTq4blwlbsUFgUIEFFcIA5VMG/itQ6cUKaF0/GXSR
         QB62zYIZpamHOTycE+WE6Fk/U5MCPY+dCNwm8rI2/yWN6vQgNgQ93FBaD+ECUluilMy8
         O/qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=u0NA5dPnRkR7m3lDgFsmUzkIoVs3muL8yffUFGL0FN8=;
        b=GkkGG/oakgrj9OQXslS11xhw7nDbFZdEsl5mCpbIZDMJ2gqz9p0gGAzD90szI5f+iN
         GsUGeiozMMl05RDuUVVkIjAg6X8eMyfNOkgvy8CJwTc2OYsU1HE0K1/HiG6U92QpyA1S
         A0a8JQ8nh3fMhP/1D6/Nf+p+861Qdb+oXCdNzsjuMRzzHSuTFV8+1RPTbm0CYsi73gRN
         0cixSXy8ZHXZsBQO3zKVMY0T2lO+xBoQnaTfmq9L3EJz9DqcGW0MRgFe5BI8046eouiQ
         pTkcYuKa76uZAFDusfyj3EtkOFSd3Hr5CdMys0ClAHLogYjIFhPJcdrlpMMzB3nylXmn
         mb5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n185si60736oih.3.2020.11.05.02.52.46
        for <kasan-dev@googlegroups.com>;
        Thu, 05 Nov 2020 02:52:46 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 63BAE142F;
	Thu,  5 Nov 2020 02:52:46 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.58.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 848743F66E;
	Thu,  5 Nov 2020 02:52:44 -0800 (PST)
Date: Thu, 5 Nov 2020 10:52:41 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, x86@kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kfence: Use pt_regs to generate stack trace on faults
Message-ID: <20201105105241.GC82102@C02TD0UTHF1T.local>
References: <20201105092133.2075331-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201105092133.2075331-1-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 05, 2020 at 10:21:33AM +0100, Marco Elver wrote:
> Instead of removing the fault handling portion of the stack trace based
> on the fault handler's name, just use struct pt_regs directly.
> 
> Change kfence_handle_page_fault() to take a struct pt_regs, and plumb it
> through to kfence_report_error() for out-of-bounds, use-after-free, or
> invalid access errors, where pt_regs is used to generate the stack
> trace.
> 
> If the kernel is a DEBUG_KERNEL, also show registers for more
> information.
> 
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Marco Elver <elver@google.com>

Wow; I wasn't expecting this to be put together so quickly, thanks for
doing this!

From a scan, this looks good to me -- just one question below.

> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index ed2d48acdafe..98a97f9d43cd 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -171,6 +171,7 @@ static __always_inline __must_check bool kfence_free(void *addr)
>  /**
>   * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
>   * @addr: faulting address
> + * @regs: current struct pt_regs (can be NULL, but shows full stack trace)
>   *
>   * Return:
>   * * false - address outside KFENCE pool,

> @@ -44,8 +44,12 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
>  		case KFENCE_ERROR_UAF:
>  		case KFENCE_ERROR_OOB:
>  		case KFENCE_ERROR_INVALID:
> -			is_access_fault = true;
> -			break;
> +			/*
> +			 * kfence_handle_page_fault() may be called with pt_regs
> +			 * set to NULL; in that case we'll simply show the full
> +			 * stack trace.
> +			 */
> +			return 0;

For both the above comments, when/where is kfence_handle_page_fault()
called with regs set to NULL? I couldn't spot that in this patch, so
unless I mised it I'm guessing that's somewhere outside of the patch
context?

If this is a case we don't expect to happen, maybe add a WARN_ON_ONCE()?

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105105241.GC82102%40C02TD0UTHF1T.local.
