Return-Path: <kasan-dev+bncBCQ6FHMJVICRBB4NYX7AKGQENT7GHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 358232D4D20
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 22:50:01 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id s21sf620529uar.13
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 13:50:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607550600; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fg42mg70Zq5U9ahc+YuMn7g5ri+ojuHxKK/mLvFFyEcook4TArC1/jKdrgJEgQCJSI
         TCaeNR8FhPs052uKGhHxGhCJtj+rbXunP19lni3A7ZlCKsvzFniPbuGzpKJ8aZ9Pq39C
         0CUP3l+tYY/bsu24ctiJQmZLpSjYli0Uga8tT7XNuxAIpiPgKtznyovbnXs+UQknAB85
         mYCbP55eWhWa62M/OqYc780hTdDpaiurb2qca/rSznLXgsqF7oo98eAktLmUALQPuWNl
         nVD4kuoLQC0WwcPiKKe9tjolTJRIDIB9lVYfTCGpipf8QeMLZa05AR/A7hiQ1JjBbaMZ
         CNBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Y7MoiGc6YFhzKFkivUgRFTPPPV/4dtGk34pDXdwssF0=;
        b=wyDLEHJepslchxHEUhK534SfWfYSrv2ZBiK2ozLvLzBzcoI5e0wh66J4lkz+c5T8c5
         CYvyNpmtZ0J5B6m1aXAERpd88x0ol+QFi2PP+MYZ89sPgUy8aHCJ+FOGDMfs8zAJkbum
         C9Ho3c8B0rhip3LtbcPZeRCfOCF8gUNCKZ86h3G/ZE1rhSgmILq2T38kTX4VzKYEjBmW
         Ts9M6cHNzVtiDY1IMMQT+fV2tNvMnoI7MtBrnzFeDDwLojk+39zghlxfcZpgwYFGVzRR
         rwYQ76h6T7He+BOwTS4XUpND8wxcZbdc9kYQTGptZtF1whUVgFXClTiQjy2SM+USipmD
         wDqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b="e/iq7qd9";
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y7MoiGc6YFhzKFkivUgRFTPPPV/4dtGk34pDXdwssF0=;
        b=q9STy9bZ9D/9oO1wcMWO83muGErIMN9cNbLArTr3B/3CYn//Ph3ekRTkNWI/h9XsQ8
         uuQ1v6r0FXdx3fCA73xR22gtAZerIwReX9vIcddlCkdulyJEMfKfUkFYOQm/7C5Q/h1H
         6Hv7odPPtp7jaBqfEDOiEkd+AvV88wQGr0NNzk38CvQkyRSQ3o/I1XdRNBVpCldmnBDS
         7ew6vVjxBtKDueA0fm7SMnom/DkxkYiGK6/CCZZOwbht0Aol5Z6BnBHQPuEivP/Q4BDc
         CTsShCVVnsnZTp/5GtMbc1aMja9FACP1+/YwfKC5W6XTlTAJXbPtqcfMPCq1GJDMA9SI
         cxoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y7MoiGc6YFhzKFkivUgRFTPPPV/4dtGk34pDXdwssF0=;
        b=X2feKdGFafy4EGL7y43F6B+nC1gZIYphk+rUU2WP4oTuZfHAx4jYoXKZjVc7ecgqkg
         6qByoBY8Ko1ZrMEeP2yNYc9ZKRVKbEWcU7aVgmJmuz3eSSNg1D9Y2RCWauQZ3LHmP8rW
         58vcez69iX3GwQjaE60usz0CNK45xA6gzL2MwFkXAQMS8VkPy2vZRKDCduxBTsLuCJw/
         WqGzia896BzsS3B1lrn+ri3K74MePKQAxADuIdUYB8CtRJ0cSXZMQjdc11pxhW6SNMI/
         0Ncu6EUPE416wR6F8o2Ra2YjYEZ/9bV6hSIa027u0ANiz5znF/OOfYmLp01ZOJgSRAGF
         mhNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WlS5dD8zb/Cz/ovs/YB0uAzeg3E6hFp2PkM+7hiDT+GnZEJW1
	za23W1wpqH37WenjwbUnkCI=
X-Google-Smtp-Source: ABdhPJxEMcqmXb7NbCbWzZNuIM4cbcKjv/cMfaUepWZwjDZrFHjiLEC26QY7FQWxVCUHkJkwpgacfg==
X-Received: by 2002:ab0:2384:: with SMTP id b4mr4329078uan.27.1607550600061;
        Wed, 09 Dec 2020 13:50:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7485:: with SMTP id n5ls238200uap.6.gmail; Wed, 09 Dec
 2020 13:49:59 -0800 (PST)
X-Received: by 2002:a9f:24c7:: with SMTP id 65mr4243480uar.112.1607550599255;
        Wed, 09 Dec 2020 13:49:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607550599; cv=none;
        d=google.com; s=arc-20160816;
        b=nfUdmCEm0TNa4Q4XZYZAcc99bWcxJnTmo38kpvZzv5+bHP/0CNsXRBUYAzapq+gqpr
         pePckcoglc/C42PlMXqR7xQaeT3vL+rpSpTL3lLgRiOxC8C8KnubUWe0n+VyrQA+wmrY
         7WIDDUqAmyUORpyhdXHdEjfxIEG2+uTzg0wIwKChqb/BvaRj8nmS4AC0Gqfg7c2im3JV
         hcJEpzjRccmBEAPQOUU2H5ZZKGvxpye94VlO87HrA6dy19+5Dw72PjlWmf1dtUHLuHtS
         SaYviEdD7mzK7AhNCM5jcQ4TT/LP4dn/7aw94cSRpaRzHn4XBoo0Ef7jELTVMlGwt4D/
         LKsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=OHHxDSSIYug9tq7db4DVJ2jEUNFttu513hW2WCnClzo=;
        b=qw/nLjkiYx7YKi0c7hD9kYWHrrDJiNyfjSBikDWzfvvqFXMF9+jp2iDCXk+6rNLPrL
         7Sb9Q0sodXIbN6S7k9bO2gCHXL94Bopocfzkg98sei651IHEJ/jQ5reOq2eLwB7ll8rw
         lqq5ZhITVF7wySaDv6/T/urqUXZahfchCKsGctDYYgOTuG/Q8R8AQXKswkiQZXa1/85g
         y0jnaRw4hmz6ropwrBc4QIJEZ5mj7o57gZC0//+ePae+6yMToH3QDd2FOAmBDpqO5PqJ
         Wzb6N6aLWjmXWszhPSnPXpAkJlDrq9IHzWK1hClAmsFuBQcNZET6cMgXn6CcfguQpK/Z
         C7Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b="e/iq7qd9";
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id e2si275499vkk.0.2020.12.09.13.49.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Dec 2020 13:49:58 -0800 (PST)
Received-SPF: pass (google.com: domain of sfr@canb.auug.org.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4CrrLR0BWQz9sWC;
	Thu, 10 Dec 2020 08:49:51 +1100 (AEDT)
Date: Thu, 10 Dec 2020 08:49:50 +1100
From: Stephen Rothwell <sfr@canb.auug.org.au>
To: Kees Cook <keescook@chromium.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, akpm@linux-foundation.org,
 andreyknvl@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, Marco Elver
 <elver@google.com>
Subject: Re: [PATCH] kcov: don't instrument with UBSAN
Message-ID: <20201210084950.208c89ba@canb.auug.org.au>
In-Reply-To: <202012091054.08D70D4F@keescook>
References: <20201209100152.2492072-1-dvyukov@google.com>
	<202012091054.08D70D4F@keescook>
MIME-Version: 1.0
Content-Type: multipart/signed; boundary="Sig_/Bv6x0ikC3MH.6utRbkJsmF_";
 protocol="application/pgp-signature"; micalg=pgp-sha256
X-Original-Sender: sfr@canb.auug.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canb.auug.org.au header.s=201702 header.b="e/iq7qd9";
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates
 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
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

--Sig_/Bv6x0ikC3MH.6utRbkJsmF_
Content-Type: text/plain; charset="UTF-8"

Hi all,

On Wed, 9 Dec 2020 10:54:39 -0800 Kees Cook <keescook@chromium.org> wrote:
>
> On Wed, Dec 09, 2020 at 11:01:52AM +0100, Dmitry Vyukov wrote:
> > Both KCOV and UBSAN use compiler instrumentation. If UBSAN detects a bug
> > in KCOV, it may cause infinite recursion via printk and other common
> > functions. We already don't instrument KCOV with KASAN/KCSAN for this
> > reason, don't instrument it with UBSAN as well.
> > 
> > As a side effect this also resolves the following gcc warning:
> > 
> > conflicting types for built-in function '__sanitizer_cov_trace_switch';
> > expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
> > 
> > It's only reported when kcov.c is compiled with any of the sanitizers
> > enabled. Size of the arguments is correct, it's just that gcc uses 'long'
> > on 64-bit arches and 'long long' on 32-bit arches, while kernel type is
> > always 'long long'.
> > 
> > Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> > Suggested-by: Marco Elver <elver@google.com>
> > Signed-off-by: Dmitry Vyukov <dvyukov@google.com>  
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> 
> Thanks for chasing this down!
> 
> Andrew, can you add this to the stack of ubsan patches you're carrying,
> please?

Added to linux-next today.

-- 
Cheers,
Stephen Rothwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201210084950.208c89ba%40canb.auug.org.au.

--Sig_/Bv6x0ikC3MH.6utRbkJsmF_
Content-Type: application/pgp-signature
Content-Description: OpenPGP digital signature

-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEENIC96giZ81tWdLgKAVBC80lX0GwFAl/RRn4ACgkQAVBC80lX
0Gx0rQf9FjZqWLlSg8chBznagG08qJuEV4mhrUiKjKEZuLw403VfIKXJwqcVNGiF
nR1lISGeRZTgCR9jP+0nWCPucghMIdHsOhWv678HvEiDLf+IL0er45ht/2rjH57g
ILDRwH60FyWnEAFk3gnmfsugWfFLJQhOYav2SFfGSOBkUEYDUVWFqdRhRW5fyvXn
kbVEUowz+QGZWqwTqY8tBj36GCOttjyqn4n3g0sRRMkV2NUdRIFKbfAQG1u9JIr+
N0H/hdH+G79cr9oo3u6msxvVWd/y2tfRv6VrdL9VQZ42oUc1MuZ+Ds/K4kua2tyW
3c+mdPIE2Cg7BbnBCvwIpDBWFlO9Fg==
=giMY
-----END PGP SIGNATURE-----

--Sig_/Bv6x0ikC3MH.6utRbkJsmF_--
