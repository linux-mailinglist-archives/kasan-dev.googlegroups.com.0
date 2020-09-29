Return-Path: <kasan-dev+bncBDV37XP3XYDRBFEHZX5QKGQERGVICKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DD8B27D101
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 16:24:22 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id i16sf3863516pfk.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 07:24:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601389460; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rf+Vswtj+RrbRIksnkynnSF7hULQG+nu6fOVtGeEhpmgyplOKwMqohbd7VUfNhV+RX
         jmmD3ohlVgiq45N0rvn92nmn7BRSODZSalUP0B370LT+bGLtIsAbH96F1b2yNmNE7g/l
         PD1GHDvseCBffJnbObsDdH+0kXnaUoVqIlBSvMNtw83+MKMCzlpRJTjERml0Vh1Z7kzO
         AZlyUhmt4Njm+gIi23E4U8Dx18B9dJX19erZ+hIg42wINz2h9fmMhfGbwhId/fA2grEF
         8sYMKE4peyHa6YelbY7Mc0BRU5MyZhOYt/Dngpa099vbx7WHm+1Uv4IYH36O4Ad/nvHl
         lAtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EGMUJBtI7Lt336owloHt35N1Pbbo2ooDUuRnhgDCGW8=;
        b=NO26GmZqN7mTpwyfTPflEqXfmFgP9dmCooM26muW5btFbxzj16mmNjM8S74qM3LeYy
         GbtIia7fGDGjZT0UedhmI2znw+E6xucQ4+BJcqbPsgN2J5XePLYPf1QEaYUlGEmEh1+k
         Z4KON6a3Xb7iqzya61Mg5k9c801BAUv6zQ4zFVSY4z5FtBe8XKUR/h1ZDYlLOsAsZUBk
         4K+BUXcIkMyNceiJGM1HNROr+kOZJy/7aJOoKQi4W45KU52MLQU5YixwO/rDee3BSkFv
         EqKakv7/kZ4pjbx5Q9f+i70hUpU5T+ne96G1R1lUt7J3GV/qtdJBzSAsP4lpmkl0pLkn
         xLNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EGMUJBtI7Lt336owloHt35N1Pbbo2ooDUuRnhgDCGW8=;
        b=ODlzQZYKiVTqqLqWqQ/kNlX1c1yu/Yj+WhYUODq/aWbJVr3gJWOHZCIEUz5ZsL/6cW
         PdqjR8tkijN3rOOOpE2FCtI5XDNmIjvtWr4qUjcJvtHxcV67WpTnbrAHfwHR9zaVWtHQ
         /5CoJbtUCo2BEKbp50UTpTqze6MSKdDwfa0hWb8nb77X1+q1R51PHgYtmabc3RQCTOgG
         KTOLwqX2Wv7iTufSDjKVo4MxaqbalMXgwD6tkAgSp9zmYQXctAzaC0N8XYpLsyH48aoZ
         R4ubEgwpyLGZ7SVD/plyagnHomeQcHS1PDIzuyv48wlsjbyCIJFaMn/lQQ99lBEjSfOf
         nXkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EGMUJBtI7Lt336owloHt35N1Pbbo2ooDUuRnhgDCGW8=;
        b=hUnN0uWXXCh17kHE4ZQaZTnKtLO8TKlJbemfPolCCaNrzThJI2KCHHz6p0Lisx4Ho9
         C5EDYvVcMe4Zr5mxSpCYe6ckuS7yW2diLzvfDz/vi4PXQ2My8sNiQvoDXBFH5PUXCMOs
         zEiK4Y4KUW/QMnJeRPYiCn++QzA0KsgChhjtqI86MPyHtL1wdGRziUgeptZEXW7h112O
         rV98ccig/Wgm92eTU4dsepV5SEjeuv+ocbFH3JcZKjoDF6GQecEjOKXZoFPkgMSJt4CP
         zPqMYq8HXqhbDj65yS0/xq+7ebDsaek8hmrAxWlRvYX9eT1kI7SZ7lRhqYwUwxn9Y3w/
         w5DA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Of4zF/V7brT+QWL4BGk4bNox98qfi7AqM9FvMpfr/HBi4apU1
	4StejD4ka4be49VnANxKso0=
X-Google-Smtp-Source: ABdhPJxdtWkCQ5lDk/AXFrLZso/0LiXY8CDgZHxOc1nZmk0+AFCqn+5ghFEVpYuQIDCf/ECKfao80g==
X-Received: by 2002:a17:90b:a53:: with SMTP id gw19mr4232351pjb.53.1601389460720;
        Tue, 29 Sep 2020 07:24:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:562:: with SMTP id 89ls5148526plf.4.gmail; Tue, 29
 Sep 2020 07:24:20 -0700 (PDT)
X-Received: by 2002:a17:90b:357:: with SMTP id fh23mr4040918pjb.221.1601389459953;
        Tue, 29 Sep 2020 07:24:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601389459; cv=none;
        d=google.com; s=arc-20160816;
        b=DQaoyRuuIo1jpR1viDDMFaw1n3DEgVbXl7NPZUGjv+fv0GzTIXIz31n5ZXHltRPyer
         kIMwagUnNXLsuF3KMuv9P4sX4qRlflv5v+63VA9qyCz3S4dmRs3Ohx2LLkxBYOKhtNMR
         3IWLF42h1PtTAHogMb6Ydjdu4c+9Lw3HjVfkjBMpbJf87ljo0dZ9maPeljyOl2fP0Syq
         1qPKHFSSsXJoKkftf9Ttc5UG35u689F/FR7uP+6Y37+ewytW4MejDJaseOpamDe/ySEd
         u/+iBUOy6uqZO7qV5yl6wzEUleVdcqf3HETKMpVf9QXQWip++FtDjzWnhyRu9obbu0X/
         4fpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ZW+4NwmacTrZa2z5dSmMLmft55ZJ3zPWHeEX67t+K9U=;
        b=daqyTYQ+JDG+VChLqzqXLn9Natl2ucTiZRYkKfRY2A7I28qxpWB4RXgLSeczzsejM8
         xUU79L5RX1jFoseGJGR7WEcdcuwrQhRJEABlJN892D5cfb7bodRw8FQ6/Vig0UGeVjgv
         rztTSS73KDGBM1gTsud8WVnihOiuo9c/EpSQeCLBdezrqSLrGo9ZsgeY6dubJy/aO66C
         Cu347HsIDDoiot2Lxixi2LNp5vK+179pIqSvZme1r0LR5x9iadnTEJOstJMwa2V1s9t/
         LwVPRdJhjouk41m29f+SjkkgGbK2ZUev2RSPReZjnVv+ReH4S7a4jb2H1pujNDyM7WM8
         QELQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id mj1si722464pjb.3.2020.09.29.07.24.19
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Sep 2020 07:24:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C3E5331B;
	Tue, 29 Sep 2020 07:24:18 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D59CA3F6CF;
	Tue, 29 Sep 2020 07:24:13 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:24:11 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com,
	cl@linux.com, dave.hansen@linux.intel.com, rientjes@google.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	hdanton@sina.com, mingo@redhat.com, jannh@google.com,
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com,
	keescook@chromium.org, penberg@kernel.org, peterz@infradead.org,
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz,
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200929142411.GC53442@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200921132611.1700350-2-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Sep 21, 2020 at 03:26:02PM +0200, Marco Elver wrote:
> From: Alexander Potapenko <glider@google.com>
> 
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.
> 
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.
> 
> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error. To detect out-of-bounds
> writes to memory within the object's page itself, KFENCE also uses
> pattern-based redzones. The following figure illustrates the page
> layout:
> 
>   ---+-----------+-----------+-----------+-----------+-----------+---
>      | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
>      | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
>      | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
>      | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
>      | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
>      | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
>   ---+-----------+-----------+-----------+-----------+-----------+---
> 
> Guarded allocations are set up based on a sample interval (can be set
> via kfence.sample_interval). After expiration of the sample interval, a
> guarded allocation from the KFENCE object pool is returned to the main
> allocator (SLAB or SLUB). At this point, the timer is reset, and the
> next allocation is set up after the expiration of the interval.

From other sub-threads it sounds like these addresses are not part of
the linear/direct map. Having kmalloc return addresses outside of the
linear map is going to break anything that relies on virt<->phys
conversions, and is liable to make DMA corrupt memory. There were
problems of that sort with VMAP_STACK, and this is why kvmalloc() is
separate from kmalloc().

Have you tested with CONFIG_DEBUG_VIRTUAL? I'd expect that to scream.

I strongly suspect this isn't going to be safe unless you always use an
in-place carevout from the linear map (which could be the linear alias
of a static carevout).

[...]

> +static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> +{
> +	return static_branch_unlikely(&kfence_allocation_key) ? __kfence_alloc(s, size, flags) :
> +								      NULL;
> +}

Minor (unrelated) nit, but this would be easier to read as:

static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	if (static_branch_unlikely(&kfence_allocation_key))
		return __kfence_alloc(s, size, flags);
	return NULL;
}

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929142411.GC53442%40C02TD0UTHF1T.local.
