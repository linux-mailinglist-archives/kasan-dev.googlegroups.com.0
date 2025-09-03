Return-Path: <kasan-dev+bncBCS5D2F7IUILF4O6YUDBUBG6IRBAK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E46EB41307
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 05:40:37 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-61cc801ac1csf5757757a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 20:40:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756870836; cv=pass;
        d=google.com; s=arc-20240605;
        b=gEq83cYNssP3Pq4kMK/HVp9/HHRvmlz38vfrVvv9bVy1jdMJMH+aR8SWM/QNZY42i1
         gZ59P4KsPziWPi8WJIDpeS9XaLrqHjGCf0nV9lZ9W7flXiRl9236pIbrRsiHk6ioEGq9
         xQDwmTRntnuJCLBs7iFDaKnzXFRnqImrhw+SO2ohUpIyDkTu+ta0Cx/pfyXhmkXLQDL5
         z9BP1zMQfoOuQtAPoY66Yux/dnNkVOc38YiZuYDJ1nWoGLDJhHIVbNk0Aumof1NwMcaI
         rAi2CAkmEL4bv4bUWTn7nChP2OxNWdUWtS7khqJHVjP/J9BBSuKUNoaQosae6KgnyA92
         /3Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mVXJ2DjPHkK3//zl2TTZu0UIk/qqNR32plw3GE2NnRU=;
        fh=gubaB2fzKs/38XnvlBUa4Ey9WpsfJFpoTpyQ+Giqhk4=;
        b=KaEeBHYqVv8F9400mE5qR6N0mAQtrgkdO3URRJh57mfJv0MegLeNKoBTRiJmFYCLp1
         6sPZTp81+Nzl4quZcXC1UI0ICzv3csaTSZNmIalTY2ZrTk+ooqzAUMO7hUOPqdeREtze
         aWDZ32DguhC9r9FP+eCCwh0VGYawqUwe66/eIYbh34wgBnavOfaJTgCv7XC4931XssBe
         +OEdQW9gFXk/mbHjX1jpw8SEQxgMvRUX7uXQmiGZYjrPkHt56B1QGskERkQBDoi3sBkZ
         BJeao84WIfsPaPmMkkDCUn1+P2ycuBjKkvbiVpVs246TBy7luiCC8MX9HRZVTFnVob/Q
         CAyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KtGZM1kk;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756870836; x=1757475636; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mVXJ2DjPHkK3//zl2TTZu0UIk/qqNR32plw3GE2NnRU=;
        b=UqM9ljlM8aOgxgbvxb1xpBtM+kcBDnM+/uu//HVT/vDJ6L3ksMZMdT/KYCPDGyqXeK
         7+i4oA4ToNiArhze4L6pQ8RLAPMQHl3poUEHGc/4rNG60l16orkW3YB73pwP80RzQwR8
         RZSef8JC9sqXjgu2v5LUQOrc7gYyMPrPeSUg94+qPvE8bNa6CHqMoOTi5Jawlq5MGirC
         HIiyF1mNRZD8RiLw7kohqkWyi+JJn/lhW8txVQn7uYm7BPRFP4/0wSJuQpwEEsA7SuEl
         21aeQp5IC/Tj2I8Gvku/PQ0Ohn/nROylM+HpDHXiUDPUK4YT6xevD4MJ/jKhemg80bR6
         HixA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756870836; x=1757475636;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mVXJ2DjPHkK3//zl2TTZu0UIk/qqNR32plw3GE2NnRU=;
        b=Df5DfAUQVNkJXprJ4BHBTpAnxIizBkNgEsvrqSRCFJ9Hz6H0sistudbzMD5gGLYuCk
         k/so8JATu89PDjLXdYjCWWpxjVhqCPbqqye6wmSZigiMuwnZiNGXjUKx2IwIr63iTSyR
         WqZyo9VgLRJ29rzJCeg5ST9IRnisr6/Z8fmGWswKjwAe51WhRQLJlrnPVXuoApQCxw1i
         iI0PMbVaP+tzAQi+u/axbk4co2yOFQ10QGvjvo5HNKbh/X1Kpo90Mtwlha4mBXvVez6f
         9ILkGIsVtSAYBrE4hUVJUbxZ4GjYS2IkiMSLEjA6Ew0VGS8WiHgLQwDkYzx7sdXs8Ht8
         7qcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWP95RhJ8nft+JLrUSFqKcV/ruXZ4n+d4dajPECX1JHjSqs9RCuEXEg7nHHom03bhUuiP995w==@lfdr.de
X-Gm-Message-State: AOJu0Ywg8VazeFXXucZTDz1F7tp3eB47jHbPoK4IolsXuuZfVXcSRVeb
	B7ji2RLVNBGxIiHC8ujIyjUs6GZ1W6ZsyG2QQIi37MXqWt9oHiHOK6al
X-Google-Smtp-Source: AGHT+IGExjJpYPOjqTNUK4q+8H8mOn0TbMY1xp/7WoEkVGDF4rJbm0Alp7etVtsh7XgY+JoprgHkRg==
X-Received: by 2002:a05:6402:510d:b0:618:20c1:7e61 with SMTP id 4fb4d7f45d1cf-61d26da44c6mr13780830a12.27.1756870835577;
        Tue, 02 Sep 2025 20:40:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdMcyOHIJxuP0xtiAZO5KTu/AtyEDVp5yW83KjUwBud/A==
Received: by 2002:a05:6402:3193:b0:61c:fd20:eea with SMTP id
 4fb4d7f45d1cf-61cfd201055ls3710324a12.0.-pod-prod-02-eu; Tue, 02 Sep 2025
 20:40:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXokdiM0Duu2018+mtwk/ZIxdM8hEtBaFGZmOLu3xALRdK9fetWtw+RhRYwufOI/K7dRiyS8So1F/Y=@googlegroups.com
X-Received: by 2002:a05:6402:5212:b0:61c:7f48:c476 with SMTP id 4fb4d7f45d1cf-61d26988edamr11955632a12.3.1756870832399;
        Tue, 02 Sep 2025 20:40:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756870832; cv=none;
        d=google.com; s=arc-20240605;
        b=gx6ARVXEse+fKMTVAfcn787LsChwk4ZdXjJeBQWsqBYKUqeTY6wmFeCz33+5ig8hJJ
         asBDbpEXl5MB/YKfPmv4LvJgmqg++A8CBNz+W/I/ciDPQv5Sp0vZwXHtQhQzndCb9D8G
         PnpLOo2oK+a8FDY6Mh5U/Q/polsG5uIhndO7KmiztnqMqGCuwRvRyclfjemY7KFtLfqg
         g9zoeDFeJ4d1tFk3Kl1PPw6KbMwbn+g7ImGlNJ+9VZlRdsgeiulKdRvgzbyeIFjRR9q5
         nuTgHGZf4DCW+sS7m8R3lf1U3Udg2HeAezyfkO0j6jq/UHIa9ICuCe8kri7ZEolPA6pY
         iH7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xS4AE9kCT2ByAtc0cNk8ehmD8+ovn4l5cjIeWujc7Gw=;
        fh=7YxW6ZpdQDrtnoGOBWWz6peg1yZJn6ECgv70qP6jptg=;
        b=KEeWZfjJv+xZz3CZgG2XVkd3kOar8RbmcZWMqjDecRRm5zxzaK/SEBPb5t9tMeo2Ga
         4+heA2Y89IiPPS9dG77nZBVZ9jKSggwZNvAPALnkdmSb07EGKdD2nAYnAYelOUDepebJ
         o5QypbNiF+rPfTeGTLKrY2CsF5w523YzYruDrJWOscmHbzBkFhCkkSqQIzRaCV50IGMA
         bP2hsDCaBVcmlLvzD9OCRWidJulFNZNaTeKfh+qAAP8PBKCEhGY/LJPfIzoHbfMvv5nk
         np7GiYd1Ffs2Id2HHDNHudGt8kp8CWEggg94PpT6pzNwtUAZKcAcXWK+SEj720LXbJJC
         JcBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KtGZM1kk;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61cfc9d9628si232609a12.5.2025.09.02.20.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 20:40:32 -0700 (PDT)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uteMJ-0000000Eh4P-1FE8;
	Wed, 03 Sep 2025 03:40:31 +0000
Date: Wed, 3 Sep 2025 04:40:31 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: clang-22 -Walloc-size in mm/kfence/kfence_test.c in 6.6 and 6.1
Message-ID: <aLe4rwzXhnypHSSm@casper.infradead.org>
References: <20250903000752.GA2403288@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250903000752.GA2403288@ax162>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=KtGZM1kk;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org
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

On Tue, Sep 02, 2025 at 05:07:52PM -0700, Nathan Chancellor wrote:
> Hi kfence folks,
> 
> After [1] in clang, I am seeing an instance of this pop up in
> mm/kfence/kfence_test.c on linux-6.6.y and linux-6.1.y:
> 
>   mm/kfence/kfence_test.c:723:8: error: allocation of insufficient size '0' for type 'char' with size '1' [-Werror,-Walloc-size]
>     723 |         buf = krealloc(buf, 0, GFP_KERNEL); /* Free. */
>         |               ^
> 
> I do not see this in linux-6.12.y or newer but I wonder if that is just
> because the memory allocation profiling adds some indirection that makes
> it harder for clang to perform this analysis?
> 
> Should this warning just be silenced for this translation unit or is
> there some other fix that could be done here?

I mean, it's defined behaviour:

        if (unlikely(!new_size)) {
                kfree(p);
                return ZERO_SIZE_PTR;
        }

so we have to have a test which checks that it works.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLe4rwzXhnypHSSm%40casper.infradead.org.
