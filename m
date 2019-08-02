Return-Path: <kasan-dev+bncBDTY5EWUQMEBBX4ER7VAKGQE5TBUMWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AD8F7EBB4
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2019 06:56:00 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id f1sf55987474ybq.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2019 21:56:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564721759; cv=pass;
        d=google.com; s=arc-20160816;
        b=G7ymFTll1TtwGWeexd/7MN3bchDaNzxpyVsZ1MTHMLeMqwFv7+5Ffb/afquxRHadg0
         rVxzntKkCLuh6rCsF/njJKfvSA3ZMhVhEoeLjr/7AbyfPFA1j6YOKKXM/9Kv0Aqk5AGF
         Xp5iapglvfRYqCecrGmzAg9NJYvX9c7KPMzROdd/4HfZcb3QXdRNEQMFInrJBU91zzOR
         Fd3/PJDM5BI/h5cijd9Hfezd80cZhNc89i9lDxucePERHTEU7xhZkAIImytgMxuBLlJm
         WyTHzAhqDo3Tpar1FOSpHK1KseC8EMvD6eGT4STt56RduM9WPOZ9o8FkGCuzK/tacZ2+
         G+5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=jbyTXF8o+nSNqrvIPiJ/CAVx7G0j6V18xyLR3t8sIG4=;
        b=nLTYddYTKDBpKPvXG3/usxYTlg2yKgW2BEC39FtzLdTcYib1y8OnZ/y6kWNkDog0Ry
         8/AFTSBa5cFhVG3u8RG6ddXG9p5Fqrv9vimGiOMFqpmckYFoPQIyyFTu+J93fTfKCucJ
         uOs6USkJc+XMX/fD3wtzGGzeWivk5OOhfJnObG0UMYHuOh/HC1Hs1a1cSI59337eJb4E
         kAQVQQYEXi0+t5NzL8FVjweNs4ndmNCDPzffjzx35WbaX5PAc2h6H6ngY61yi1xK0ZwR
         vf9of7Rvgy90B1YsmAagkWO4PKES/Ob/ugZDnWgCXXDy1U+kNJjAOxmdTpGpdp2HotvS
         KPRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of herbert@gondor.apana.org.au designates 216.24.177.18 as permitted sender) smtp.mailfrom=herbert@gondor.apana.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jbyTXF8o+nSNqrvIPiJ/CAVx7G0j6V18xyLR3t8sIG4=;
        b=f0EcuRA8DpubArVzt7gCWKDzva3CmSLjC8M4Ckv5zFd53prrkakqLycqeFeVvbUQyw
         YvbHvyxxoehsta2wqJsWMix2X7RVDDqv5faCIbwuna+sA3hbp+KBDPSwt51nZYzWGW5J
         N0KcxI0aXFzoxWtr0ZuvpgGgtJJiphljKMWibi970aczG2urF4+kvqoJdi/qiTe3RFvH
         T5Pev+9yfJEwBrRlXRvogPHW4s5/OmMIiPgJFi8U/IETG9rDE6Rw8Uc1n2wHp+N7itOY
         LPWvZyQFWt+LIRrtTrwvJmfizev40T14FcE9Q4JXOOHa1VxLdi39laZrC2s8QF69A2F8
         hf0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jbyTXF8o+nSNqrvIPiJ/CAVx7G0j6V18xyLR3t8sIG4=;
        b=MCCmXyHTWT11Wy7uhJYFmLQ5AoOEO38jzi0TrujCjVLzMpZZOzvIoRdxeopHMojH4K
         U1xssej5ur7EPOGPi8jAznF1ZAerErDjHhXGUuu+oqnPkqDtARYksx0qOp63SBOWHq8b
         Wymyqze1n2jiCysGDcL8lN61laTYQv3ur1/Cw4M18FMjnMYorqakv4+64Csg65+3GVxD
         19qxjn70osr3HxT3BXXPma5qCB3AZ3yRSWJi3aMUD+kAvUariK8mnIdQztIOseVGG6Za
         6l5FnGCqq75yFoCDBMr1mRczseKQ4zOfc1YEEtBymej68ONJsyBEhRWfF9NAUjt112RR
         tz1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVmq/DUl41zoN4nSVwOZInoXxfshJDF/pKNBm4MSAZmpXpw4v75
	GY8WWRRiWnmKBYAd9JghAas=
X-Google-Smtp-Source: APXvYqxZzshI8Ooi7+XgoXzdvHv8hYUzvDf4tm4IZ08yVyGYi6X+gf61g5XwxaeHCs44cbM7EfTyCA==
X-Received: by 2002:a81:a491:: with SMTP id b139mr83511026ywh.148.1564721759453;
        Thu, 01 Aug 2019 21:55:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:138e:: with SMTP id 136ls864746ywt.3.gmail; Thu, 01 Aug
 2019 21:55:59 -0700 (PDT)
X-Received: by 2002:a0d:eec3:: with SMTP id x186mr85309446ywe.510.1564721759078;
        Thu, 01 Aug 2019 21:55:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564721759; cv=none;
        d=google.com; s=arc-20160816;
        b=KaAlND4sXhy9aGyp63xAB2N/4R6I3tZp7qWx9iCXOIEDM76Mk7zeG23TJ8uTFOLzfF
         QbRTwLEh3N+Vd8dtPjeEj2Av8YSourldx/rUlLsYl0ZLKBkkBkytql/aDmkKSFKBbK0E
         2JB53ohwy/iRaK8Rg5+LzMYwAU9xVJjGX3VnR0RBVVAJWd2wLPdCqr32kKw7wVTs5Qdv
         cAgT4aVqbGVpjQ2dKHLSn0ivJdwAbROIqz8xscTqdqQVOjMfLWgheKawpkGn34TVJ+UH
         GiPKuEXWExI33huCneMTd+yPD7HsBmnbVc8+tFFNk52YxK7GpDiAOl6+kBcQCBsAAYj9
         4K/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=bbQd0YwDlBvOigeYv/34lLtbxkmkH6YCseDPDvCPEH0=;
        b=wjA5iDCy8hBbe1Y5BTPBWlk0KErUawUft4NuW7x9elkqQ+1MD95x9DPsXY5SDZIoF3
         zpycrHHsFrNk6TOUgM5isqItUoW6+LNZV9WztSLNqHvpu0X6TVJdJ/0W+UOgozhTFutv
         cWUWg2ilo397JkDw943cuE4Kb9j2CgPly+LkTnLMPZeFLq67pImu1zaXIfomAqZYsb+E
         M0oFfgFidBr8xDNIBcOvdgfh5ZuFQPaRJrfWSqHBXTN7t8l4zmxbC38UAz1qqgTBcmgl
         r5qzEVxBkR248FqCHzpwX26RUJj7jRnLkYSn8tbzVXyv2Di5xdTfPTWmjkuovhgJc26h
         0QQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of herbert@gondor.apana.org.au designates 216.24.177.18 as permitted sender) smtp.mailfrom=herbert@gondor.apana.org.au
Received: from fornost.hmeau.com (helcar.hmeau.com. [216.24.177.18])
        by gmr-mx.google.com with ESMTPS id f131si3057086ybf.5.2019.08.01.21.55.57
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 01 Aug 2019 21:55:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of herbert@gondor.apana.org.au designates 216.24.177.18 as permitted sender) client-ip=216.24.177.18;
Received: from gondolin.me.apana.org.au ([192.168.0.6] helo=gondolin.hengli.com.au)
	by fornost.hmeau.com with esmtps (Exim 4.89 #2 (Debian))
	id 1htPbE-0006IB-Tb; Fri, 02 Aug 2019 14:55:29 +1000
Received: from herbert by gondolin.hengli.com.au with local (Exim 4.80)
	(envelope-from <herbert@gondor.apana.org.au>)
	id 1htPb9-0004ji-79; Fri, 02 Aug 2019 14:55:23 +1000
Date: Fri, 2 Aug 2019 14:55:23 +1000
From: Herbert Xu <herbert@gondor.apana.org.au>
To: Arnd Bergmann <arnd@arndb.de>
Cc: "David S. Miller" <davem@davemloft.net>, kasan-dev@googlegroups.com,
	Stephan =?iso-8859-1?Q?M=FCller?= <smueller@chronox.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Eric Biggers <ebiggers@google.com>,
	Vitaly Chikunov <vt@altlinux.org>, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, clang-built-linux@googlegroups.com
Subject: Re: [PATCH] crypto: jitterentropy: build without sanitizer
Message-ID: <20190802045523.GF18077@gondor.apana.org.au>
References: <20190724185207.4023459-1-arnd@arndb.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190724185207.4023459-1-arnd@arndb.de>
User-Agent: Mutt/1.5.21 (2010-09-15)
X-Original-Sender: herbert@gondor.apana.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of herbert@gondor.apana.org.au designates 216.24.177.18
 as permitted sender) smtp.mailfrom=herbert@gondor.apana.org.au
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

On Wed, Jul 24, 2019 at 08:51:55PM +0200, Arnd Bergmann wrote:
> Recent clang-9 snapshots double the kernel stack usage when building
> this file with -O0 -fsanitize=kernel-hwaddress, compared to clang-8
> and older snapshots, this changed between commits svn364966 and
> svn366056:
> 
> crypto/jitterentropy.c:516:5: error: stack frame size of 2640 bytes in function 'jent_entropy_init' [-Werror,-Wframe-larger-than=]
> int jent_entropy_init(void)
>     ^
> crypto/jitterentropy.c:185:14: error: stack frame size of 2224 bytes in function 'jent_lfsr_time' [-Werror,-Wframe-larger-than=]
> static __u64 jent_lfsr_time(struct rand_data *ec, __u64 time, __u64 loop_cnt)
>              ^
> 
> I prepared a reduced test case in case any clang developers want to
> take a closer look, but from looking at the earlier output it seems
> that even with clang-8, something was very wrong here.
> 
> Turn off any KASAN and UBSAN sanitizing for this file, as that likely
> clashes with -O0 anyway.  Turning off just KASAN avoids the warning
> already, but I suspect both of these have undesired side-effects
> for jitterentropy.
> 
> Link: https://godbolt.org/z/fDcwZ5
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  crypto/Makefile | 2 ++
>  1 file changed, 2 insertions(+)

Patch applied.  Thanks.
-- 
Email: Herbert Xu <herbert@gondor.apana.org.au>
Home Page: http://gondor.apana.org.au/~herbert/
PGP Key: http://gondor.apana.org.au/~herbert/pubkey.txt

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190802045523.GF18077%40gondor.apana.org.au.
