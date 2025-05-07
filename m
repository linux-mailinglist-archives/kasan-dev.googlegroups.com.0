Return-Path: <kasan-dev+bncBD7LZ45K3ECBBDXO53AAMGQEK7IMNFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C1932AAEC4C
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 21:39:59 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d81820d5b3sf2625745ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 12:39:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746646798; cv=pass;
        d=google.com; s=arc-20240605;
        b=kSgtihwlq9/4CFRS+0MNMpLfTT2n7Kugvlz1A05pdKJr/5Oe6E0oCR/+MdjzAGBZ/O
         dt7HgwaXTfwS+Ho1Y2/rVU1rvyQnMPYLMX5Yj1JR4X8ycVwNhZv8q0kJg0SSKCynrU7X
         mrSo9Tdcy8NuPKKth2waGy3mEsjW6Z4t8fbVfNgeG6yDFMbXxGMxCPGn5cANrrp4eE6o
         t7DZKRq5ymdptRPqgbqsToh2O53is4/x+HSvj9+4A2PaTM7q9V9SQx8MIHSqR/FeuHMO
         IBE0leEEmkgSEoJxZYxTQmkohw7UKhTdRPHwQnhx67ZGnEAotFtddpAsCS2pTGGnTxcQ
         kvlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=mkaIsSPrCes4BKu1xiAH2Tf2cK1pkg8rktLmYeVuDIc=;
        fh=l/ZJojqnNfBKAUV58INJ3pScuopBTli2O0pufWwU6S0=;
        b=S8VMgukY42PCmyn/ZmOM8iu+/il8Asza5h/bfyNyAnt9WdVMOWQGVrzMsOgHDiK77c
         oCZ7yO+N3mzUipg8O0bM3UcvZlGcxpbRB12NirsRdPUmo4ycwipRgDqld+EslMJyv6K3
         A16BI/3i869sW4iVYO12RbJ0o+4oESXV6eww75Uxlxs0s+L8uRo7Pws6gvJhnVoigBnJ
         S1zYBQw7bTYQ9kitYLHu19gK8EE3CLP7K94Q1FnGaZA8SC4E6sMS/i3jbK5K4/REscAA
         sAfRWPqiYj1qVo1Qg2slwo+ZgVx3UL7cRUmybxlXWfhpFkuPiLPUzySp90dCt4Lfrmxl
         Jb+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u1SqsDxB;
       spf=pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746646798; x=1747251598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=mkaIsSPrCes4BKu1xiAH2Tf2cK1pkg8rktLmYeVuDIc=;
        b=WMYYXfvTsZ1snH16twVbeiOYQv4tyVXkawdTAZGQhoLDOqzD7ldH3ASb6eBizYoXyZ
         V/Ge875anceB4kkTkDkUIlhle4fy4P8pkQ+2KsWqLw4KP3IYzbNjjVa+rUEjf61sS9f3
         MiCjsPTk22dp668p7EDj7GaVPc9b9mhJ+9EAHN9v1rNPQSq2qLFHcTsYTiSLkaPcZzkL
         yullKGsKMhhwk6dfkrGi6+kmEyET5TQsqoWADZeYEXEmSdazbBYxD0szEErQHWUyjZuQ
         8FifKdosWb/S8FROOzUVc3Qeg+Fj1cjHHOOwZQwFHDh7hqr0NGxHf7CtcqAZ7UMhjaoj
         eb/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746646798; x=1747251598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mkaIsSPrCes4BKu1xiAH2Tf2cK1pkg8rktLmYeVuDIc=;
        b=YqrWhHgVDFssymm/ZzMi8KeKIPfY4RzcYL/BWi2ganOMaiTcZKGLXAeC0ThMTEDWo7
         Swt+9qebRR2qthdr9pbnuNQ2+buzDBANSzyw0mGG0jxLHzhlZFsX7zgsnU5wG4ptZaGc
         /Vy+c5Kyf5drZTeb5J8bq6fxRAZ5Z8CZl+Cni6REfeWY4+qklLUoQIOFZHD0+UnlG7LY
         Razk/LRwFKrVIHO90f0IugYp4gSVzsK9J83cykpL0SGk6iiMOgr3g2A/iMZNkn3r8Px4
         ASFohPDchjoPrzpK/Zg8Fv4v6/jqyDiJhw8TXkNDE0g3oN5UjmouFaWgSys/O/yzAekv
         KWhA==
X-Forwarded-Encrypted: i=2; AJvYcCXFvaJEgWPPBuKiAsgzgGeB0uS/0hmJHp9dIIN0I0cZv6r5DDr0sGG3SZZBoQV5vGKCbJUmGw==@lfdr.de
X-Gm-Message-State: AOJu0Yxx8270YrL0Bz3eRwAD8hFIQRnF8Yi3C3WbTriBJTxwdWCJVh5j
	EqRKp3CuDSVNGJipMKFv8+yE3/GiaKBv3oq5d1XISp3U5nmgLJv5
X-Google-Smtp-Source: AGHT+IEM44BsnLPmKNYXhdH2KjeEGNU5cez5+KVuYkks+dPLdXKwNzHX0QTTErWgbUKW5PLHN1cN0A==
X-Received: by 2002:a05:6e02:1a62:b0:3d9:659d:86de with SMTP id e9e14a558f8ab-3da73933d7cmr51891535ab.20.1746646798556;
        Wed, 07 May 2025 12:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHYN9WowB9lVtUeKMNsflaceJ2vaNW3f3wpPTsYKjvWyw==
Received: by 2002:a92:cf05:0:b0:3d2:8609:ef86 with SMTP id e9e14a558f8ab-3da7854c4ecls1672335ab.1.-pod-prod-01-us;
 Wed, 07 May 2025 12:39:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGMpWbyYVBWDV7FSEZQTD3QslR3Hq7yWBAh+jONz9cEtH/Uxj9KiL89V4dJEBZ+4WDjcBmH3zTOHc=@googlegroups.com
X-Received: by 2002:a05:6e02:258e:b0:3d9:6c9a:f363 with SMTP id e9e14a558f8ab-3da738f9654mr44781405ab.6.1746646797581;
        Wed, 07 May 2025 12:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746646797; cv=none;
        d=google.com; s=arc-20240605;
        b=BZiVfxjcX2wa15ZUnGj1+PeVOnc+BofUJcugdTslhZo1W2MNwsi8bZhwCsFWOfIYha
         6YQfVI2tFPhLqmYc2B6PB4kxU/B7SQj0if/Ac8+7+9r48u6TYW1qeeWnHNfX8n7fsLBY
         T41iRhq9MSBO5igRFxDFY2mRlyi3DFQB248Da6gH08ukWz0mE4YTO8YdLc2GCdm8wmJX
         /WVimzEtwWU/QXNpMYS717uOUjz9OzPudSb7S40gKsgJorlChM4zG82flgwApacDMrly
         eE87DpBkrmbPSMqFKH3F4hnuNvnR9MIZzu4bKwiG91nEiLhZXbd9eyK4l99p245tBd5H
         OQpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=62D4jT8FqgvCQAvir88qqLUPmBFgY8nEPATu4+rGZ4M=;
        fh=MTOXfrUvzL6AqGN+vXIwnV771r5H8JfSEIOSq4Jqkgo=;
        b=Qu3r0T9nnYgXKlUzeGWtPBRiHci6m+Yh/nau4N0FOidMsQppoMX5j559sXbJygGr2f
         gBD13HVTuwWb1MZQC7BIkBLztyAoYFa7gBTxPQLaamaEi6ScvLHWkQUXLvvnM/XKRT4h
         uB4yPb1g+qarqQULLANVObWZEGd8Y5IKU9OsOYP9fJ1jS/sVGqQmUVBocGpm3hlvNy7s
         hO5w81MkEnxHgebSOcG2AikZRG5BSwQubYf0VwYgtYPlME5F4kio8r8a5KMe/oRvT3mN
         gRCNEZAgzB0IGk3GdlHO/ENQL0xfwrfy3rc0b815dVCnOE2wvYfM5lMsmQJowf0vk/nT
         RWjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u1SqsDxB;
       spf=pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d975e6eefcsi520745ab.2.2025.05.07.12.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 12:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 0E271629D8;
	Wed,  7 May 2025 19:39:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0DA0C4CEE2;
	Wed,  7 May 2025 19:39:50 +0000 (UTC)
Date: Wed, 7 May 2025 21:39:48 +0200
From: "'Ingo Molnar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
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
Message-ID: <aBu3BNS60PEw5Uwu@gmail.com>
References: <20250507180852.work.231-kees@kernel.org>
 <20250507181615.1947159-3-kees@kernel.org>
 <aBuqO9BVlIV3oA2M@gmail.com>
 <202505071236.AC25A6CC2@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202505071236.AC25A6CC2@keescook>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u1SqsDxB;       spf=pass
 (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=mingo@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ingo Molnar <mingo@kernel.org>
Reply-To: Ingo Molnar <mingo@kernel.org>
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


* Kees Cook <kees@kernel.org> wrote:

> On Wed, May 07, 2025 at 08:45:15PM +0200, Ingo Molnar wrote:
> > 
> > * Kees Cook <kees@kernel.org> wrote:
> > 
> > > -	  The STACKLEAK gcc plugin instruments the kernel code for tracking
> > > +	  The STACKLEAK options instruments the kernel code for tracking
> > 
> > speling.
> 
> Thanks!
> 
> > Also, any chance to fix this terrible name? Should be something like 
> > KSTACKZERO or KSTACKCLEAR, to tell people that it doesn't leak the 
> > stack but prevents leaks on the stack by clearing it, and that it's 
> > about the kernel stack, not any other stack.
> 
> Yeah, better to name it for what it does rather than want to protects
> against. The internal naming for what it does is "stack erase", so
> perhaps KSTACK_ERASE ?

That's even better, and I like the word separation as well. Thanks!

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBu3BNS60PEw5Uwu%40gmail.com.
