Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBURXP6QKGQE73XDOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E98052B230D
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 18:55:18 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id c8sf4244322wrh.16
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 09:55:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605290118; cv=pass;
        d=google.com; s=arc-20160816;
        b=dDJrl8UKkB0XLMaZh3WH9ZYgltmlUDHRyjyFA8i/0oZp8eRu8UuD5p3a7+lOyhoFqJ
         2EMbl0uAcybGF7Vnqb0Z+VlYfdrUVJyNLjQcn3Y7F7Vn5GZWMsMedQF8pQLD+4YTi/GN
         FbqjHaV5Di+ow4Q/SQ6YAsG+nFm8+ab9aqgLgYfwHFBagpljg9hhXBNlkQD5esQeL/GY
         gIwSLx5bUUxVYMZiGkrJHk0esfgNVYHYU1nXloswmmI0gNIMuxwySUILGJDbZLmmzD3X
         HUQm0CWrQoHVosO7hl+zFOCjXiK5uzA2333HWrhjybaVZVINoNHwcYjndOfzWUTF6I6u
         scgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/f08wZzqV9qvHMv8kUa71aR6yGbVnqBCquMv9kizNAw=;
        b=ZTcYyiqGlUd1mIQHFOIoxAfeYXu7Lw3GZJHpMfaEZwMvzC4ZB+c2PyPHwKhfdRhW14
         BpDkYcojmFaDq5atlYl8Tw+PxfF8erBpyMueqWGZUJu/v7frVgVwGfs4E21M12kHBY1n
         LPavQBLOw1gSAPCSn+PrOxQaT5vKfbQZ3FGrDXAWwbdRE1GhAnEG6SaK7dLIAZUKZ0Qy
         14DKDy+GRroTyldKmJLZ/0gSmCwuSVHI/OmQVn/EnepdZwZbmExgf2leZZ+VHl5pE5y4
         89XB6JBawtLo8cidxU3dU/PKK1mRYEZkRWqM5RttGQCBnw21cGu55d8Q12dTU+275Ih8
         dBDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FE1+mMH0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/f08wZzqV9qvHMv8kUa71aR6yGbVnqBCquMv9kizNAw=;
        b=GJP/BlmJv51WdPOkd2w2hc4Zkst2yGr7iX2aUJkxoJLb28fH17+SFApoG2nWo7EtdP
         DrOE9R8T8CK7sBJPATPAe4dv6OWtX3uzwFjI75aLvwzn5FZsRXjXcisDq9A+G6wrnRvU
         kBtZ3BJOiSlDV7he85RyS3c3d9/au6Aq8Oa2vThqzpV6jYe5stdtEp7DXamE4ejYpGlV
         b06SsvRo5HaF/roOb88exrmigeXPb3LAICiJz768omttgXbLcr/iQMaZ7RjbBAEITnTn
         05fZ5NxiXth6MA6YcReezM7Z+sno+Sh8hoflm6LzrL+2IQohZjyTfyTir36aF4kKFTRX
         lXZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/f08wZzqV9qvHMv8kUa71aR6yGbVnqBCquMv9kizNAw=;
        b=B6gYZ4Io1Nxb7fwX6ar1vrz4IyLwBa5ozuYshnG/Xv4r8nfpLvikGlHJpbd0G2NRPi
         6ukBIHViTZM6wT5XXh+QjAm14i4g11qQlX+00L+Ab6IhCQA448dj4EJXAQUZWKgAUBmK
         4xDJeAkKM2BAXO7+6TXI+AZhNLtbhcLlMV22jRxcMNvm1uQBwQOLyPplsXoqjjNzaDcY
         0yKRdJrWuCBSttmhZJ3XR8k3I00/pVKVoEXwZLOckldwhI4gT2crSyIUpeANc0p8W/jX
         jZq9ll+zqabfg7tl5SgehFlAz+7aOnVAYlSq6SXkCINozaq5dYG/nkZJt6m5XQ4ibz+C
         k3jA==
X-Gm-Message-State: AOAM532oj2l0bVAyLYUG1n3SFcpiqB7Tk3lTr5nh1GoarPEqIec5PIin
	s+xyZ9Qcd9v6OMygEM2TXk4=
X-Google-Smtp-Source: ABdhPJwm1fEZPyqisbHKZQjnAUGX1Ggi37+UTQqHo7lXtzuuKOHPQktWycQ9UL3fFXOU7yx175s1oA==
X-Received: by 2002:adf:9e48:: with SMTP id v8mr5242770wre.55.1605290118713;
        Fri, 13 Nov 2020 09:55:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls6523066wrc.2.gmail; Fri, 13 Nov
 2020 09:55:17 -0800 (PST)
X-Received: by 2002:adf:e74d:: with SMTP id c13mr5085777wrn.277.1605290117755;
        Fri, 13 Nov 2020 09:55:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605290117; cv=none;
        d=google.com; s=arc-20160816;
        b=d08cN5pXRHnyYSmUsox2vk39+ton9YWutwBzqA0INGyxbGJLUksyisfCnCorHXKxTe
         Nl2TrS8ekGgkuZf/oJWduIpeQGXWSruk0magFhPhPTDHqZfUMl+4k4i/F+oiuHYsiinb
         uAmnbCAC3cJZhGLbvjtgbbmb+1UjyBVuCEAGWJUz83Dw97oxIN7FC3fn96lYczi+fArT
         U8LMjtN5ZeQYT4rXdEGN3jQ7f+YukG6qOBu9XJwHpp3cmENGQPAyxLbBqJHcJahll+Oo
         7PxCkzh03DQh/APAeY7kgkYmbgfQiv8IcxmEABM7hFCRbSXKAeVnNZsE2kxOTICtgn+c
         tanA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/+PMzrqEXwIpHSYqiZIonnkK0eqVZnv5ws8C/JpM2Ro=;
        b=fWw4tWewrqhJqX6W3AmMJjVlWwh+xTX7aEFFLP0SBWXIPrOA8J+UGxYQitExrDHJqo
         mDWdOJLy7VsDmU+bKzWprN5vpwbuEvgsG1YhDnO5ISYQA3sPXmvtn+XfgRkz1g01XuOg
         KyfWSNulC4QbGAgKFeVXEbh3j9DCPUDk/PccMAHlc7vh3Ww9cVXDeRY4oxxc8MCwI3cT
         D+xTGvqu3IClnIoCDF/+CYhrzNR8C00NZihlcnH5/mnU4S4C5Qk0fVcDv0PG5uuC8V10
         5VlHb3OkcU3mkbRTqkcoYvg/o6JLsd+8aVYYUr55n1YPNiws7FUi4t+IaxtGs/FNEta/
         93KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FE1+mMH0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id v10si282239wrr.3.2020.11.13.09.55.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 09:55:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id r17so10900679wrw.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 09:55:17 -0800 (PST)
X-Received: by 2002:adf:e607:: with SMTP id p7mr4796819wrm.93.1605290115315;
        Fri, 13 Nov 2020 09:55:15 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c185sm11477158wma.44.2020.11.13.09.55.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Nov 2020 09:55:14 -0800 (PST)
Date: Fri, 13 Nov 2020 18:55:08 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
Message-ID: <20201113175508.GB3175464@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
 <20201113175254.GA3175464@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201113175254.GA3175464@elver.google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FE1+mMH0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Fri, Nov 13, 2020 at 06:52PM +0100, Marco Elver wrote:
> On Tue, Nov 10, 2020 at 11:20PM +0100, 'Andrey Konovalov' via kasan-dev wrote:
> [...]
> > +/* kasan.mode=off/prod/full */
> > +static int __init early_kasan_mode(char *arg)
> > +{
> > +	if (!arg)
> > +		return -EINVAL;
> > +
> > +	if (!strcmp(arg, "off"))
> > +		kasan_arg_mode = KASAN_ARG_MODE_OFF;
> > +	else if (!strcmp(arg, "prod"))
> > +		kasan_arg_mode = KASAN_ARG_MODE_PROD;
> > +	else if (!strcmp(arg, "full"))
> > +		kasan_arg_mode = KASAN_ARG_MODE_FULL;
> > +	else
> > +		return -EINVAL;
> > +
> > +	return 0;
> > +}
> > +early_param("kasan.mode", early_kasan_mode);
> > +
> > +/* kasan.stack=off/on */
> > +static int __init early_kasan_flag_stacktrace(char *arg)
> > +{
> > +	if (!arg)
> > +		return -EINVAL;
> > +
> > +	if (!strcmp(arg, "off"))
> > +		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
> > +	else if (!strcmp(arg, "on"))
> > +		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
> > +	else
> > +		return -EINVAL;
> > +
> > +	return 0;
> > +}
> > +early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
> > +
> > +/* kasan.fault=report/panic */
> > +static int __init early_kasan_fault(char *arg)
> > +{
> > +	if (!arg)
> > +		return -EINVAL;
> > +
> > +	if (!strcmp(arg, "report"))
> > +		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> > +	else if (!strcmp(arg, "panic"))
> > +		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> > +	else
> > +		return -EINVAL;
> > +
> > +	return 0;
> > +}
> [...]
> 
> The above could be simplified, see suggestion below.
> 
> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index c91f2c06ecb5..71fc481ad21d 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -64,10 +64,8 @@ static int __init early_kasan_mode(char *arg)
>  		kasan_arg_mode = KASAN_ARG_MODE_PROD;
>  	else if (!strcmp(arg, "full"))
>  		kasan_arg_mode = KASAN_ARG_MODE_FULL;
> -	else
> -		return -EINVAL;
>  
> -	return 0;
> +	return -EINVAL;

Ah that clearly doesn't work. Hmm, never mind this suggestion, sorry.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113175508.GB3175464%40elver.google.com.
