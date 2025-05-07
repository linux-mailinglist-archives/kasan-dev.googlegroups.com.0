Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYHM53AAMGQETS7QREA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D4487AAEC40
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 21:37:05 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3da6fe2a552sf2687105ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 12:37:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746646624; cv=pass;
        d=google.com; s=arc-20240605;
        b=VayJ9Jwb2A6wCNCJTiY5ZgdCHR7AuE7uz+n6WmuuQOr61xmyuqFzSkhBfOOQcRUCr6
         F9tqFrKSnX+mW5epdzhkqP+PLDrWQsiraxSPQgra0xvz4fw9A1NjHIDHcGIzqihzgNHU
         jR64/kkpDsrAbYq5Rlucf/XhrtjcILqVs5SmxilPsW/OgyHsN5HmwH+iGbTKoedrdGpn
         HnqoBxATDcQ3tlzxczb4FvfUQeuja4pOaI6qQY/Ugq3RoB8bL7zs9tPyFsNhQYqdpgcU
         2SaZbkBuJmfjdK1Cyw7lEMmGJdcGjI3gxcPymm3/UEUFKDWCmON40cPlF3k6MS4+xn6I
         m0Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hS0aHjpguAp8vWTUx/65BmabQgqI6ClFkATuA1VAhSI=;
        fh=/y47iZvrgt2FDXta2yBhbuvxyvquSac0SIv38BfXaEA=;
        b=lSgSarkheG5+tpe28HGI9geeYjaxBKeK2kTeAVCG7VhgL2xcv+4Bsb7N7yI5bWkbFR
         qoSOiAltIEmYFs96DxpVgKaFUNElo0N+W+4gmAfF29Rk1EE8mNQq9nCl+kC89L/xz0uR
         8c5lfvuYJqKUSDSfsaXxX8Pm1LS3daCQm0titY/mmDGUUX62DaEUNJQRMRkSx1LMtRSy
         doDd2+2RYzcE3xJLKAkYmqRNNDOe7MZMkHqDJL0mz/Bco527dBn5EzHhCI0vWkatR3QX
         RbhxAebUVijLkK7NYRJFxqzlRRpC5371rmHP+/8DicOlRci9uV0Xs4RzwdhXrt/y3m8L
         eoJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=adEj+Biz;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746646624; x=1747251424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=hS0aHjpguAp8vWTUx/65BmabQgqI6ClFkATuA1VAhSI=;
        b=JHVlWjhygrJHT5kpFKE4qDHybeaOS/LAJ3cCkLRQGQP0whQ8jt0Q/subxJfbsj9Kid
         XkbBjn3hB0+7FJwRGHWvTyXAYnmt1SVd6AhyCUTqiVKiYrLHv5YDt08ALmpHcP71Bcki
         DHYdmyndI/E4+hGI9ynMZCX+v14pqClIj43m8AK2OPo7BZTtopYTzjNBBir43IE/4p7S
         6A3Kv3hCXCIp3gI2HPoBOc9/DX3Wjabj4PK36n3mMWGWsiVzPHMVQJMzWUr8HyCSvpoZ
         jxq969XU3rk5uRFDT2t2gEIZYQK5po18uv1GetfX3JEL2XqxkK2v3OKs9mGOsYwGNNYB
         222Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746646624; x=1747251424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hS0aHjpguAp8vWTUx/65BmabQgqI6ClFkATuA1VAhSI=;
        b=HTaFNk0Hper6Jc6Q3WTHBNKnZYIWimQrUU+OkPMP8IEzJkxW7IE12C5wETE0dGf7Oz
         neQtab6U8i3NPkH690EmBG2DzD98LODmMlLCYRZNaq146kVgQNNoVylX1Z5gTqT4xD/h
         4UkR3OXcI9j1o9DfziW50dvA3l11VD5A2Ugf5MBB9Af5AzA6JtZhZGE6LkvrAd2lySnf
         6+luEMTS9mCgmkF5e88jmp5pCKzo6Pm3ZYmmEUHI07PGcvipI+WIvFC5PZYUGjnP8O0w
         B9Cv1XLCbPuHu1VEpBAIqR7Tbpoj1LkTvnwVbUQgorSZ5H6dDPDKC+8XWpLEelT+KJei
         X2Rg==
X-Forwarded-Encrypted: i=2; AJvYcCWIUuX0uXwD9s7p5LQ1y49IyLfoWdZD0VqfaYf+J4CUND7TKC28axX2ZggA2Z9C/FyhFePGHA==@lfdr.de
X-Gm-Message-State: AOJu0YyXJX1UuMVXrzVzznU+TkTbXgpOBV3Y529+yPh2tiXjOSea/wMe
	Y2oVUf3lUezaKDM2/1Ehyf1oQPjrwzoOgXvx9XFtp2OvzDxCXykW
X-Google-Smtp-Source: AGHT+IHPAT3e0O9SiZpHM8jYYtC/PwwtRtHKwut4BTx2/iothznIYncYloun3n6L19d9DFkDjSAF2Q==
X-Received: by 2002:a05:6e02:1d97:b0:3d8:1e96:1f0 with SMTP id e9e14a558f8ab-3da785ae8f9mr13811685ab.20.1746646624359;
        Wed, 07 May 2025 12:37:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEqj7joOgvsYTX7/Rak0i/UUxQshQGzBNIVpDjqGgKPlA==
Received: by 2002:a05:6e02:9:b0:3d4:564c:718a with SMTP id e9e14a558f8ab-3da78549f1fls3581965ab.1.-pod-prod-08-us;
 Wed, 07 May 2025 12:37:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHteWf4yFO3BzczLwj+ObnYLp8FJoVBdKtbMJLYPXuRL0A8+TT+n+4s6TjG1e7R0a9UtrKh9B9TFw=@googlegroups.com
X-Received: by 2002:a05:6e02:2199:b0:3d4:6ff4:2608 with SMTP id e9e14a558f8ab-3da78567ab1mr14729565ab.12.1746646621454;
        Wed, 07 May 2025 12:37:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746646621; cv=none;
        d=google.com; s=arc-20240605;
        b=fUzC/0aDNscOl27etglRC9QlkVRQFHRQCCcX/E3tZggETcJ3kCwLmqoy0az82+74Cl
         k93mrwl/K2WqNNtjVQFh9bcMktpQFGyMAN2PyVzVMq8Jvmew60gTz9BqRoB51NNPfvOh
         wU+Ibw94W+hgfwhUJhCr2pin+sTMM7EfdaPGhF3EjX6L5ut5kZqDU/F1+rVSRRIa1BMi
         pYF3b9CyfWMk0NxSMesij0V+om7VxlUyMy+JVwgZHAqWQ82FmARLFDy/tmuuxnsRuH2E
         488QpxaqNIYmV6GcZbPPjVB93OYg4+h0SrnhexngFIAhM8tMrkQdbxih+gClaILqikJH
         W+6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RrhTrEhTqsq1bzwDJROXi4Wfcq2HDay/MnS7nv9NGZM=;
        fh=UYPtjGlWozE42FnSn0kTIOXSwvX/lGmBMvsX6sQPZGE=;
        b=U9o38mXPdeIrMF1iuoCjge7qJ/eDe4+chWJIQniZ0CEIQOJ1FJbdIbfQtT67oKbyOn
         eyg+SVOd7wK0Q/JqMp0lJ1XlMZthKehkWJ7mn7M3l/3NgowKOgpCxyPrhHpuvOrm6qp7
         YmU8fTPeFZxQsPobYJJLWzy9SWvp/CDoxFHwfqpGzy2S1Tf/2V+SrIOkd8HrKnJU+y8v
         Gz1ajeOh7Sq7e10uDR/8WH2pzL6wRt+L0Jd0SJebECztHUQVcLTWtbxsL5SCen5eB4sE
         u3CG5NgMSU6nZJFzFLRBvSM485sgpwLvQZI7b8Y98Q5J9nxx8FhBGIjMNxD57eGDllPR
         EYhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=adEj+Biz;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88a8c54easi434041173.1.2025.05.07.12.37.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 12:37:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D54FFA4DC08;
	Wed,  7 May 2025 19:37:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E255C4CEE2;
	Wed,  7 May 2025 19:37:00 +0000 (UTC)
Date: Wed, 7 May 2025 12:36:57 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ingo Molnar <mingo@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH 3/8] stackleak: Rename CONFIG_GCC_PLUGIN_STACKLEAK to
 CONFIG_STACKLEAK
Message-ID: <202505071236.AC25A6CC2@keescook>
References: <20250507180852.work.231-kees@kernel.org>
 <20250507181615.1947159-3-kees@kernel.org>
 <aBuqO9BVlIV3oA2M@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aBuqO9BVlIV3oA2M@gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=adEj+Biz;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, May 07, 2025 at 08:45:15PM +0200, Ingo Molnar wrote:
> 
> * Kees Cook <kees@kernel.org> wrote:
> 
> > -	  The STACKLEAK gcc plugin instruments the kernel code for tracking
> > +	  The STACKLEAK options instruments the kernel code for tracking
> 
> speling.

Thanks!

> Also, any chance to fix this terrible name? Should be something like 
> KSTACKZERO or KSTACKCLEAR, to tell people that it doesn't leak the 
> stack but prevents leaks on the stack by clearing it, and that it's 
> about the kernel stack, not any other stack.

Yeah, better to name it for what it does rather than want to protects
against. The internal naming for what it does is "stack erase", so
perhaps KSTACK_ERASE ?

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505071236.AC25A6CC2%40keescook.
