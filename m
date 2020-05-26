Return-Path: <kasan-dev+bncBCV5TUXXRUIBBTMXW33AKGQE6YXACEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C0381E3144
	for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 23:36:14 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id u79sf8493793vkb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 14:36:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590528973; cv=pass;
        d=google.com; s=arc-20160816;
        b=liKBSf2RHIY/zHx42qby+okho2gef6Sf91K94WWaUO8iZp6czHoOBeLrDI15oxpXop
         ZLezHuCymTIWz2aC5U8y7Mb9VlUsKcuE4GqGNCnS8hefd2dfl/lyH4C5K6sCUEUah/EU
         SyF6CjdJUo08k4wa1RMPd3iWlBFGGgcHJB6csKLQPJrFYYzVxkEygV1IrGmthcHyPJMD
         S2H5HI9ETBd1X8WA8arC/5WphdLCobnWGnVw8MB0R6IWN3V+939S86YCayYSi+Rahtm0
         1pqTcjZBHrfAKLNfH9+/xDGHq89c9kKEiQQXNGKzlUniJMC9EZiXA7XENNqr6AC2iiGU
         anyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3VaR60ac9RiLuYdwXENptA4jSccFzqEhf41u8qx7r40=;
        b=SwHroOh3F7L+F7MyTRoKyYwF5NrPgdrz5sXE+G/sHvEbUHlafx8gS07DSXqoSZ4tgt
         Lo08MdI2u6bo7I9bEh2GHGlQ0BxuknUVOavJNiePsf3FN+oGg3t45/S6yr8xceB0dFQ/
         +qnDOgSadl2JlqTUooDIeNgEkYFTocuAn5kE5pueFebCTNv/MzyjOByCh3BSE9eBuS5Z
         ndtJy+2BZaATpfDazsTQrrs231o7ZtLXoNISOuDWZ19DtNPHVRP9qOk9aDzi1vUyYsVI
         A7+dcUk2j+I4yFZUkkKByGOv9N18Gc8RWY73BtfSEAfTbZyienVSo85WN/apVRFECGTl
         XNuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=iuLiKeXA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3VaR60ac9RiLuYdwXENptA4jSccFzqEhf41u8qx7r40=;
        b=fiyF7e6FWof9ni0ONp+ob4BmIzNEMi58yp23yMzC5Wk50e6/3BkOgL0h4IhNO/K4GQ
         6t0MkGKMKgdnqex0EO7B2gyASocfMcUgWC+viaRzP4dhfkFTXPTGZrv4JCqGFZXmGwwl
         6sA/yuS8YEaRb8Hk4EFPm1tnj8wCy8u+8zFJI/Bwo+peOo03BQWWsQNtuXa0xsGPU/dH
         qIfn2f6hleDnLr7YPeEfuZOUM4nZuk8eWaMtOREkaqT00OIrLOtK+gJh/UJWeIfIxZG3
         NiEknInWTVZ1FejmlNtzaJKtNJapfCdLJ/n+0q+Gfdyt/tg/NWLiBo3VZFgsTM1ZC7TR
         G6CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3VaR60ac9RiLuYdwXENptA4jSccFzqEhf41u8qx7r40=;
        b=Ql6zHMiR/cqR6nDmVZ4WjKHJEK4SdNtAgCO6Vr77dKMLNCe062yTIM/NWOgK4xS1MH
         NhvXTABy02RsU1UZ8O6UtqOGD2vMZDmn6RYVi/Hm51FMQYmoNtWrlYubmiW1o9kCERHr
         H+lC/KU/39o0VUPPGj8PPLrCnVufiF4LOjxzrQsWkrRY6P1P74wGFzAnyM1uekhA2GSk
         57BlWZS6hfMHnUeNMdYBg0KbRTlcTdVBMBFPYOOO0QkRWGDg6kKOPuTOVfV5gkpeKb80
         GqCkSvxHqmRpYMCBFm8w8lhAxVp0sNNyix8ysaMEyjGJNrJI9freOv6rRyugbL/10vuQ
         RcMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/eg4t+mAK3QXU/el1+2x2vaKym6QZTauPo4zVI7Fm/1rNjmsm
	nsl3Wz+EGwBfajdKBA6IrO8=
X-Google-Smtp-Source: ABdhPJz0PSuq8oU6ZWtbaJUZrHA7u4V4vPfKtQYfKdPMt4LuuPyW2yn9+aqB3UAKK2Gg4pu5Bu5+YQ==
X-Received: by 2002:ab0:61cb:: with SMTP id m11mr2391768uan.54.1590528973412;
        Tue, 26 May 2020 14:36:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6197:: with SMTP id h23ls820782uan.1.gmail; Tue, 26 May
 2020 14:36:13 -0700 (PDT)
X-Received: by 2002:ab0:b13:: with SMTP id b19mr2653968uak.9.1590528972986;
        Tue, 26 May 2020 14:36:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590528972; cv=none;
        d=google.com; s=arc-20160816;
        b=oVuf/ozpwjvHZE84DX2btT/nHOuKPQsryhvohvOiDPKuqydRjizM3d39kDKgo4HsUk
         GUGRxkKhfOTxRldICzjPuQH9X1HGJKhPbfaLcXQSk4vxDaSrx/GJ3LIjmauNP94ASLj6
         JiJUfgYXD3TnX+Ts2DGRlm1m+sIgEh2kRdCP91OZ4VC4IFl34w+Ci0TDgN4zN1zxTXU0
         CIW0jl96m4xrH0Cg6XnCI1CSjMoY3SZLqhaDZFopcsQhUQBq2bq7H35lH5rl+G/pzEbC
         3jzQX3MM6+PIznBhj46SVwKczl/7pwDGgS1p18ezYetz08UaFodps/9kkMCsoRx0NNPZ
         aTSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pPz4T1JqBnfA3eSrgPWLUIAddODK4bFj5VmukAoBfaI=;
        b=kYPuANfmB58uoMXpRwYS3ET8V+BHh91qsZ90oHd6wN6VKkGnbS61xuNMsf8hgiqW3N
         GyXCKP8/QARWq1GIJevM0YqqXI8POY5KF2rzyabM08SMlr8tRt9fjmLjmG2iK/xNx0kV
         9227FJwtEwwMJATEkcKTPjiV8pu1gbL5fvwIO1vtyxuNKfmegebB6Y0HEBXU9g5P9DpL
         EhpvYYo1yZyGfR+qtDHcj9Fd5AFoY0ObuogofQvlR/gvIxLqh9asL2xGgGnh8L9m+iSI
         f5eLXCOKtAj0Hpw/ChdY3IEdnzIEk8Rf0NYAbyl5t2kG296DLjNI1XK5pVu1dtf1P1Xg
         PYNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=iuLiKeXA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id j5si137148vkl.3.2020.05.26.14.36.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 May 2020 14:36:12 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jdhEx-0005So-Ma; Tue, 26 May 2020 21:36:03 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id BA9B89834AB; Tue, 26 May 2020 23:36:01 +0200 (CEST)
Date: Tue, 26 May 2020 23:36:01 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement
 expression
Message-ID: <20200526213601.GF2483@worktop.programming.kicks-ass.net>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck>
 <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
 <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
 <20200526173312.GA30240@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200526173312.GA30240@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=iuLiKeXA;
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

On Tue, May 26, 2020 at 07:33:12PM +0200, Marco Elver wrote:
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 5faf68eae204..a529fa263906 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -245,7 +245,9 @@ struct ftrace_likely_data {
>  /*
>   * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
>   *			       non-scalar types unchanged.
> - *
> + */
> +#if defined(CONFIG_CC_IS_GCC) && CONFIG_GCC_VERSION < 40900
> +/*
>   * We build this out of a couple of helper macros in a vain attempt to
>   * help you keep your lunch down while reading it.
>   */
> @@ -267,6 +269,24 @@ struct ftrace_likely_data {
>  			__pick_integer_type(x, int,				\
>  				__pick_integer_type(x, long,			\
>  					__pick_integer_type(x, long long, x))))))
> +#else
> +/*
> + * If supported, prefer C11 _Generic for better compile-times. As above, 'char'
> + * is not type-compatible with 'signed char', and we define a separate case.
> + */
> +#define __scalar_type_to_expr_cases(type)				\
> +		type: (type)0, unsigned type: (unsigned type)0
> +
> +#define __unqual_scalar_typeof(x) typeof(				\
> +		_Generic((x),						\
> +			 __scalar_type_to_expr_cases(char),		\
> +			 signed char: (signed char)0,			\
> +			 __scalar_type_to_expr_cases(short),		\
> +			 __scalar_type_to_expr_cases(int),		\
> +			 __scalar_type_to_expr_cases(long),		\
> +			 __scalar_type_to_expr_cases(long long),	\
> +			 default: (x)))
> +#endif
>  
>  /* Is this type a native word size -- useful for atomic operations */
>  #define __native_word(t) \
> 

Yeah, this shaves around 5% off of my kernel builds. The _Atomic hack is
every so slightly faster on GCC but apparently doesn't work on clang --
also, it's disguisting :-)

Ack!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200526213601.GF2483%40worktop.programming.kicks-ass.net.
