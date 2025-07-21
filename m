Return-Path: <kasan-dev+bncBAABBZNZ7LBQMGQE43GXZJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id CDABCB0CB3F
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 22:02:47 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-32b574cd23dsf24642361fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 13:02:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753128167; cv=pass;
        d=google.com; s=arc-20240605;
        b=ajEiknSh/42O7AwXeWMwotnbY1qBtWkRDm3sZsVbz+EY0OBrAK1UfQ4paT0pt46Gko
         AjUHx2Qw1rCVQpIk2cRj/CzAyWRqunJHEd3pL4/51kbvgnkZz5tWbrqmvtXJehe/ecvb
         QdXgR/QCMCym2+d/FgRlOKCOfKbDdgqX9sZcCfNDV7fMy1JzIqP24cE8NkJuOQUfxUx8
         DGv1QmqGyiUOrXurxL/Whdu5E2ibefXcOxnse3Rll5TatrCHyjQdqn/2/OoYbXnyB4gB
         D4dVkUMsV4yGsyufTdwVyakSeITfRB9RqUu2YnZpt4GeF35w79qwaMCXQl6OMXs/yRcs
         eXmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ymGWMVDWD4epROlDUXzKE39eWehUZZF+5mL9L0Bevn4=;
        fh=BhxO7cJAW8mP5F4qi1EgT40yHOMO9cmyRWL1Nkis29I=;
        b=X78pAK4MkdL2xF01wImkA1n6uJV8amylg4expMCxUbXutik+0+k2VpfNtsR8wep3mq
         PngoiIM5cfBxf0qeyg54AzdpVKlruILuNU1XkgUVVpCGwQwV7rb/zobPk6zEHXr5+DEb
         cYot6P/ttaJqBw6wFNIJ/37DPsLFVCw7bu2DpCEoaTWOX8lU677mMcm/hLspyjVNkj95
         ho+++8WUQ8BLDWH9RbUvwIXG/FeFBjmdWhGJUSalH+T1vZLxqVkqINK0b4aIQVkJ2Rqd
         4wJIaqUdJPzp5dRN5owx0rZxxevsFY8MB57IR1+rOSQjF/X+C1Pu/lDTcgDbWNhmqvlI
         f4zw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q8Bzke5+;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753128167; x=1753732967; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ymGWMVDWD4epROlDUXzKE39eWehUZZF+5mL9L0Bevn4=;
        b=FcIMN++XfXyoPoGoDYleglOaCr4uVIW98GVyg7qC1gSx1GLC/Nygy5Hn/PXQWyxO4b
         g6uOqp66zUnIxan2C2cVY8gc06iYGZu5PsFxSsgRytq9Xg57qJxDpqlx+V1yT3UGTt7s
         h1WVppXE+tfGLZ5yn+SnTMoAGghazqUiOAFujmhahyOIM2znyR0MfcPerlECY2JQfOzf
         Tti+jSaRlZ5ymzKTWS23zCOz0KC2mKJ2ZCdaGP0c/s/kB8CzcbwwS338Hrfy6izg0R70
         Fcjh46gipe03/AJx9vmXoA4bqm62g7CtFPBUhNPmFe5/uRGSMHgO58YeVrsyNLI2J7Vd
         xIcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753128167; x=1753732967;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ymGWMVDWD4epROlDUXzKE39eWehUZZF+5mL9L0Bevn4=;
        b=BQBOwgFzj2giaaifIdqkjJC0YvS5y6uZilgXn/JpXHGdYc004+3+lzrTuNqmuI3VPT
         SaWZNaLQkvU5OGZfrPmFXCKFhThfR0qAcUNVsLfNac17/GmmfqcQKfG0cUy/AeykXh6r
         5cOaOO1aD+kJb9pnMJ/uB/gINFU8BE7IZ155y0Yz74zJXUdVfvToyK+HqLJIk3LhzAjf
         AIgEyFIsrEXtIb90Ri4YluwJSHv82B+bBw7GM+dGIPnPtpWLjEnFHHAIAKVc9oiqkTV7
         Ld+RCqxQ1BKKU9RDpyj/fcLgVfEUSg+AtCrpMzImr6Nd685Cm7T+/twlBHZ5geHFS2yf
         3Dnw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxlx2BOjEVGl1zRb756jw2AweHMlYowWGPxHcl0r4ruQnhiD57DSmCySwxtR+RDjMjK/ZxuA==@lfdr.de
X-Gm-Message-State: AOJu0YxV09OBt9HUyCHwVO/Li5nlox2DhYjSK/LczDlLfzOx/0XoqUB1
	XO5CtCaiPOarvzuoRAFtadipDOiXBZ/mTtd0ilGLYFkTk7XSR+5G2wny
X-Google-Smtp-Source: AGHT+IHKyq2p0vB9jxNVNgCUFsTQnzowuJU7uaEZ+WKhPFpjhKMwYn5foj0lecwafXkUZ+F4cAajtw==
X-Received: by 2002:a05:6512:1046:b0:553:a2dc:6624 with SMTP id 2adb3069b0e04-55a23312f66mr6026025e87.7.1753128166394;
        Mon, 21 Jul 2025 13:02:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZedckCLyy6igZCwK/3lWKkh49K51NB80B4+qUZXHNfLtQ==
Received: by 2002:a19:5f4d:0:b0:553:d22f:f92e with SMTP id 2adb3069b0e04-55a288c10d5ls845581e87.2.-pod-prod-01-eu;
 Mon, 21 Jul 2025 13:02:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoXoNqLHGzbn1BFNdy3QOql5fy7LYex6sKCrlY7SzRbcy4O6GYEdqIrhYrwFVY3/SueI0uG6GqAWQ=@googlegroups.com
X-Received: by 2002:a05:6512:63c4:10b0:553:d910:9344 with SMTP id 2adb3069b0e04-55a233d9950mr4688707e87.45.1753128164073;
        Mon, 21 Jul 2025 13:02:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753128164; cv=none;
        d=google.com; s=arc-20240605;
        b=W4Z95y1ZZhR6YAXNAtWvVqf7sdFQe9Y1w7EniLR7ymuYJBW+jLSYO1wPzd4GjrrguJ
         wCs16EUVV9T2Cwf7J6yQgHGqrs2ndqy00cNnO5yoH+zVTpybri6SflFuCYKT1zQxZ50j
         hCXnLvjZJYSRSfG7zn7YnPL2lTb83/iQHfDOByFoZJWooVohG2Z8LAtE8XsBJhjxxVjt
         fODxcyhVHd4jW7QZQCtPssnNo+ABewcKc+5gsZ+zQCsmqGu8rTKMGK9R6emDxdWU8sVy
         MxugS2aMNQ8tf9M5LA+h2NKtMFZ/T2/oAhdx2cpw+YXi1aR39WXUdSAmd6wq4bKdbGYw
         VoqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=faRHgN5I3SJaokyooR8tND95TU4Zl2EbUy+q1BeFqEE=;
        fh=mXvrb47lNowf4BwEcCjERSVh28xsXFbawTDSxPtKyaY=;
        b=dAYStetSMEvHx/RjPH7njeepi96W1yIa4lzTVdS6LRc+pYzUMEh5uxVhZ0Jx5F9oYz
         fxLm0qVZP9JXJKsTSvmqA8IgzkLcisAAhqUDU+n+8txvjlAVzCoZxA0KQtGfCRFZRYrD
         kRta683G0i6yFC/6uYl1PfKwWicG3xkq97dfKAGmrKORalzQkADE71Bq/2vqWl6UMnXO
         pmNOP9LboJzvT4dMhgUgvK2GFrQ1APHcZwIBYYuyraWhq/FSezZQ57h5G/zJsXWRDI53
         BGgZCRBmS/GQPuWca3TuQXVhV1UK3W/yyVJsVx+kdHhEIrQ8z7Hjv5F7W2eaOENugv2+
         30Iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q8Bzke5+;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [2001:41d0:203:375::bd])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55a31a9c966si217506e87.1.2025.07.21.13.02.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jul 2025 13:02:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::bd as permitted sender) client-ip=2001:41d0:203:375::bd;
Date: Mon, 21 Jul 2025 22:02:36 +0200
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Ingo Molnar <mingo@kernel.org>,
	x86@kernel.org, "Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 01/13] stackleak: Rename STACKLEAK to KSTACK_ERASE
Message-ID: <20250721-spiked-adamant-hyrax-eea284@lindesnes>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-1-kees@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="cgD5lPAL2MBjPn/0"
Content-Disposition: inline
In-Reply-To: <20250717232519.2984886-1-kees@kernel.org>
X-Operating-System: Debian GNU/Linux 13.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: nicolas.schier@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Q8Bzke5+;       spf=pass
 (google.com: domain of nicolas.schier@linux.dev designates
 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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


--cgD5lPAL2MBjPn/0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Thu, Jul 17, 2025 at 04:25:06PM -0700, Kees Cook wrote:
> In preparation for adding Clang sanitizer coverage stack depth tracking
> that can support stack depth callbacks:
> 
> - Add the new top-level CONFIG_KSTACK_ERASE option which will be
>   implemented either with the stackleak GCC plugin, or with the Clang
>   stack depth callback support.
> - Rename CONFIG_GCC_PLUGIN_STACKLEAK as needed to CONFIG_KSTACK_ERASE,
>   but keep it for anything specific to the GCC plugin itself.
> - Rename all exposed "STACKLEAK" names and files to "KSTACK_ERASE" (named
>   for what it does rather than what it protects against), but leave as
>   many of the internals alone as possible to avoid even more churn.
> 
> While here, also split "prev_lowest_stack" into CONFIG_KSTACK_ERASE_METRICS,
> since that's the only place it is referenced from.
> 
> Suggested-by: Ingo Molnar <mingo@kernel.org>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: <x86@kernel.org>
> Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
> Cc: <linux-doc@vger.kernel.org>
> Cc: <linux-arm-kernel@lists.infradead.org>
> Cc: <kvmarm@lists.linux.dev>
> Cc: <linux-riscv@lists.infradead.org>
> Cc: <linux-s390@vger.kernel.org>
> Cc: <linux-efi@vger.kernel.org>
> Cc: <linux-hardening@vger.kernel.org>
> Cc: <linux-kbuild@vger.kernel.org>
> Cc: <linux-security-module@vger.kernel.org>
> Cc: <linux-kselftest@vger.kernel.org>
> ---
>  arch/Kconfig                                  |  4 +--
>  arch/arm/Kconfig                              |  2 +-
>  arch/arm64/Kconfig                            |  2 +-
>  arch/riscv/Kconfig                            |  2 +-
>  arch/s390/Kconfig                             |  2 +-
>  arch/x86/Kconfig                              |  2 +-
>  security/Kconfig.hardening                    | 36 ++++++++++---------
>  arch/arm/boot/compressed/Makefile             |  2 +-
>  arch/arm64/kernel/pi/Makefile                 |  2 +-
>  arch/arm64/kvm/hyp/nvhe/Makefile              |  2 +-
>  arch/riscv/kernel/pi/Makefile                 |  2 +-
>  arch/riscv/purgatory/Makefile                 |  2 +-
>  arch/x86/purgatory/Makefile                   |  2 +-

Did you miss arch/loongarch/Kconfig by accident?

$ git grep -Hrne ARCH_STACKLEAK
arch/loongarch/Kconfig:127:     select HAVE_ARCH_STACKLEAK

Kind regards,
Nicolas

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250721-spiked-adamant-hyrax-eea284%40lindesnes.

--cgD5lPAL2MBjPn/0
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEEh0E3p4c3JKeBvsLGB1IKcBYmEmkFAmh+nNwACgkQB1IKcBYm
EmlaKg/+Oulyjlzl6ITiwJiV1weZc0KBlop49wW3/ilmJ9U/16ChNrQlv9S6c21O
ytwj5NZ3lgiznFSMFUOkOxA6ctKIXVyGyNPSmJIUJ6Sqk9iHm3zMakHBxpr2uemy
DP6Nb6zORIiNJiTd3lVcdz1XQJRGfHfoMpUoW+GRKqQMtw4NyankD/eCESFv6mKh
T27cet3p0OMQg5S3lM/AD8uuhCxYlLXnD2LJ1XC7z5v9s2QMFnm2FKuEbwwRikgZ
k4V5IQ6fVjZRe7AuIZpAgOC2mWYkumx3EriVPGKNQu7L0MSQfUAjDF83NE4CBwIO
EKdR7rp9ZBpJXIQwG0SNnVDCG/xfryC0LzVorLlZOR65GUHYiONL5Eq+J2QE8zwZ
ugfv15CDaABIA5Rc6VW655EQePy0grJb6wQRpZAQRtsg5HQQfPgWXewm+OetC6sk
1yqSuYqUrmJ0j4usrxCxbZRrRcGzfdDuGAmg4XpUKrEJIZRxfsV5InrSJ+o2nA14
yjqgSeDRliPvyePCLddpnDyye4RgIyNgDQSuYJoivHQryIdrYJE3LIk+EoQdw3dv
c+5c9ea/sNADpeyyA/RAzDrLGAEXAh2qZFu/o71KZIUOwOLp6IjYtZ9MfI54KyhK
0TTlmcFody1uFinctfOk+8zBzO/foM1hkNF9knW0vJmnEV4khOU=
=dSeG
-----END PGP SIGNATURE-----

--cgD5lPAL2MBjPn/0--
