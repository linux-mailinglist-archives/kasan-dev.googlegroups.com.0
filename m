Return-Path: <kasan-dev+bncBAABBQHNWDBQMGQE4BEIT3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id AC7A0AFBD2E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 23:06:10 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b1ffc678adfsf2469844a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 14:06:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751922369; cv=pass;
        d=google.com; s=arc-20240605;
        b=bVnO3wTQIavg01qSgzdkb56wfLxqTBUYtD7qq10S8476+MUrDETBeo6FBmnPE/TtsG
         sMyUZoGHuJ/ESbAKDd30E3Nrn5vR1dhTjRNlcjMsS2LglBonqseaUtxDIllVMdb3phlT
         4r0HW+I/s410kWcaDhBl8wURhW0cWdLATp+3+zFTdAqw3tCJ3ngK/7gb74lF8PgFLSQi
         ge7ShaOFXNjZ3uj6HLp3+aozZZY+updY1lEH5yl7ZlOOlVVWooGL/mPqsbRZvuuvr2z4
         6sa4jqsjEMtfO6HfOMHHAC4wk6h48QDLuKPpwHUbJ78QwB5pcyNslzYwR+/uauNs40G4
         34Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5b8KVR5dlnR4QK/NI8NMLXB+Fi/I0vcHyE8/pJ8BOVA=;
        fh=EzM8+uUWEMHSoHIC/apQ4cafbLKYrqCC4j56VhBvDWs=;
        b=gCMZVqGNKI75GOmOMEx4w3Ws9d9Qfe8nheeQosxxqXiRDBXKCKE9AyeYUPFGr33hd8
         lkyqS8BoKxg3Umg3FYy2PLX6n/+kPjKxTqxYOeBxerq1CsoP6FXXh+taETv2GgsjT7cv
         6Hk/cDja65TuhQ1hJwAZbqneJq5bbMrT8r/KD3HcStCRbN0S7fP/wz3z5QelfS14U6KP
         3lGUhKx3uIybRHDFtR4Z2T3cKNAiTom2sefHtccELZLO2gQWarY6AyENZ/HmVc/g625s
         eYoFxEyk5kzedZgEu98NslMcao9l9/I+Igd4hf/J2nYnPxXTR30YPmt/UYSPJxqoEGl1
         6nnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="GvKG/PDe";
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751922369; x=1752527169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=5b8KVR5dlnR4QK/NI8NMLXB+Fi/I0vcHyE8/pJ8BOVA=;
        b=Df7EYkzWWk7fbXIP3RuPFH/aOQphjXZpKihdwOYZ886PcRnL23Jyku7cgnn+z/KfJH
         p9sbnSOGEO0Eh8i9dcGPw9qjz1sZ245HqiBfRZhEbFNmwVORR6UMe/CrLl3iamK/526R
         vQJZ37+2Kbw3Hx3muXKaMy2NCveyW7Fxa9WHSQ8+lNKQ+cqsv0M/6JiWNSniG3LrWQcF
         tSb1fTNDlAT/7bn3Fs5bk79UxngZHAlxEzsJPJlrh3Y7HidzI6HvycELPsrLxSwwwx3q
         o/mi4ZijL/xE15Xpq0dK5q3zcYvJjrepzBR32nY8EbeHmFZo+6YhWBx/wY2bRg3XkiGZ
         gNXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751922369; x=1752527169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5b8KVR5dlnR4QK/NI8NMLXB+Fi/I0vcHyE8/pJ8BOVA=;
        b=c1/PBuFrQZwOOTBGbuIwptriRWMyR8UI0yLcn6lhtPuy/zSPwL9bZN59q9efFZUkSH
         cEA00/C4/TqfRwrzxkm8A3NJGaRks/VErRpH0Yo8B+31q4xVVeo5m5Rxf5cKiAXHUYcS
         J9whDlULJHrNv3xoTAPr9fhcLMPkLA2/48YXBjxLxXzMt6dm8rVW9H62MwDDHxgiC6mj
         K56QjCxUsm15LeaLXWvojkH45elnKUJYBoUC+G3d1uFlXAkkokDl/yvW8myL3bPrBaal
         sV5bFErAC3VKOJgjvc6l3JUo7v/oPqC+1AzmhjnZhEEV8HXqbpjyRF8s45w1JuCKjfmV
         or1w==
X-Forwarded-Encrypted: i=2; AJvYcCWrCXds7OO5gS2F/vkCUCmayq6nrzAJM5sWFt6MNY32eB/sK9NNMyyUQ0Xy4wBLQB/buVZOLw==@lfdr.de
X-Gm-Message-State: AOJu0YyW7OHabhqxexu72Vmym2pJndyZrviDAv1NQeR5eXIUW3bmLIMh
	hQ2Fokn1ZxZ18JA/cPUx1Jhx5xocgGIYUF1EMTDynwPKS5SRIFxg9/Xy
X-Google-Smtp-Source: AGHT+IH9wKtybEdO6VbgKpS++B8PDhDYuxH7v9BHXIJV0XQbXCEAmj9yBua6uM/vneB3IbiUJENeOw==
X-Received: by 2002:a17:90b:5447:b0:311:eb85:96df with SMTP id 98e67ed59e1d1-31c21dbb971mr727425a91.17.1751922368791;
        Mon, 07 Jul 2025 14:06:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdP2vas1+/sxVDHHuUKc+spghcmoCa4dG/KSrf3v2y7bw==
Received: by 2002:a17:90b:2283:b0:30e:b1d1:94d3 with SMTP id
 98e67ed59e1d1-31ab035b7d7ls2624147a91.1.-pod-prod-02-us; Mon, 07 Jul 2025
 14:06:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbXo8Gds5CZPTdCOL2D7dQlGe/0t13EotLjPGPrF11uKeeBrffaPEQc3bZSlGmhGZuQcPT83C/+Pc=@googlegroups.com
X-Received: by 2002:a17:90b:2245:b0:313:d6d9:8891 with SMTP id 98e67ed59e1d1-31c21ca6248mr564878a91.3.1751922367404;
        Mon, 07 Jul 2025 14:06:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751922367; cv=none;
        d=google.com; s=arc-20240605;
        b=GuYcVfST3lTO01jXaFFYvUbd08WNY/foK9rqdo2ZLRUXcttoK2w50oV1wyaxZ5y5NL
         AQnIlYVkQZt0UcOKWK2k38GXYcKGsLziFRnwZX+TAbI3oVEkH0gVtW193MvidZ+RWMm4
         UHO2qAvjh+S5SdxjEsnzqgPbuX3Cc0ElKADBQ5c8rmxUIWehGVq+Zu4MvaArV+ZOKHnv
         pZki1R2bsS6UVNre+w0ndaTL8FEnw9ZO2pIbn9JvFGH8BjQeIvYFZXcBAq97NkyKALcV
         VI8QBIRIPTkU+e0QDTPyQO21Fbjl2G6ih3IudQqfhRpKc81FrESWii5CXJCoj28y1d59
         WJiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kEJw0F0xAleam7se/T2f/RC/XL+KXhx0o9DiKvbNb0k=;
        fh=ZEmjEA+beua0ACHfvGG6b46BenHjaWFbMeK4riMguPk=;
        b=eVbIU+Owe/PJsFaq/5DOxlaAEK3Vja2+fd3sOm+fRc5i12qiBs9IHk/VwzcSlA+yAo
         zwX8CEGnQ18MSyI/cKG3duYjIcjOHyO7L4YsQmJzRn8SCNQC65j5hvsNZjsv/UmQwx1H
         nHDQ4P8vDejypT6/fSIoHApLLE4tKLdRs0T0/trTz8ExCDjrNkhX/fPs/ZchpW2Dig5x
         Aj3z7S4CdvIN1OcbP52Y54iJ2XO1Sk/5j85lnkIigK8RJ08TPAVHafnU7X63SNO/2KVJ
         kuNnBZS+e+v6wr6GLNTeT2S4GljNLrpZ0YC15aUhSEfZbTaNOCgSfpZLspd+nYoLuxxC
         pDKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="GvKG/PDe";
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c2202de9fsi13117a91.2.2025.07.07.14.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 14:06:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 97BAD61120;
	Mon,  7 Jul 2025 21:06:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9B346C4CEE3;
	Mon,  7 Jul 2025 21:06:01 +0000 (UTC)
Date: Mon, 7 Jul 2025 23:05:57 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
 <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
 <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="3rxu64vcup7p4zp6"
Content-Disposition: inline
In-Reply-To: <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="GvKG/PDe";       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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


--3rxu64vcup7p4zp6
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
 <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
 <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>

Hi Linus,

On Mon, Jul 07, 2025 at 01:49:20PM -0700, Linus Torvalds wrote:
> On Mon, 7 Jul 2025 at 13:29, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > I am in the C Committee, and have proposed this API for standardization.
> > I have a feeling that the committee might be open to it.
> 
> Honestly, how about fixing the serious problems with the language instead?

I'm doing some work on that.  See the new _Countof() operator?  That was
my first introduction in the standard, last year.

I'm working on an extension to it that I believe will make array
parameters safer.

> Get rid of the broken "strict aliasing" garbage.

I don't feel qualified to comment on that.

> Get rid of the random "undefined behavior" stuff that is literally
> designed to let compilers intentionally mis-compile code.

We're indeed working on that.  The last committee meeting removed a
large number of undefined behaviors, and turned them into mandatory
diagnostics.  And there's ongoing work on removing more of those.

> Because as things are, "I am on the C committee" isn't a
> recommendation. It's a "we have decades of bad decisions to show our
> credentials".

I joined in 2024 because I was fed up with the shit they were producing
and wanted to influence it.  You don't need to convince me.

> In the kernel, I have made it very very clear that we do not use
> standard C, because standard C is broken.

I agree.  I personally use GNU C and tend to ignore the standard.  But
I'm still working on improving the standard, even if just to avoid
having to learn Rust (and also because GCC and glibc don't accept any
improvements or fixes if they don't go through the standard, these
days).


Have a lovely day!
Alex

> I stand by my "let's not add random letters to existing functions that
> are already too confusing".
> 
>               Linus

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj%40wa3tidbvpyvk.

--3rxu64vcup7p4zp6
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhsNq8ACgkQ64mZXMKQ
wqk41w//ZtMNK1v7cKQ0lZlTUqTrnD/HJrjpT73G+qAbUCgmMraH4Xk+LYomGqUq
XJ5sCg2eHN76EUVvTNOVWQHCSLlmdMEheQSoIN9mpesMkPmmCMuvQpZ27WKvYUIR
y4yEZ4BWlX9kVxpacTa50QHVIg/BVEloY3lcUodp5rVvlqi6QWSp15/wzf6spfc1
l1PV/nmntBAq9XUv3XgNZ3T8nxNtBmaYW+PKdqQyi2xnt5TNOBff/E4sf4K+HUn+
T2eHsOg8VPHZ4Nz9/cAHNFb7ZHjXAIkCWzjwayQrPyBPP2zL6GaFkKYGmPNcDz2U
qmB0mJ6OQOk/lIuRr2K1CskmqUxRY0Ejt/5TIuzRQBR6Z1Dxaixp/DusKD/pcVlm
E9lTV/NR0E0OLGXRCuCqC3BmOBQC6sZJPDoNObStAjSSlhA5PVBGc5O0AtWGn/NO
7xX5gNtFWW4Yth0Reqd0HsZS3R5u5HaRI9q9KVEgVPKvSbizuSbKTEi4jRABdZ6s
ekfxn3t2f3l8F+yWPZ2QFyPf5/c6xADdvLe5iYQgbkbCHPgRKzdfQV/pY3jgds7c
Ct8TbV95pYM0xDnmS1P3FpyRfTrfkscJTfdilRdx8V0g/P9pG6A+rKDRJX3dFwG6
HsA2MA0KFcYR43mRRKXNBvzAGdMHWZfqumHJlaW1s67BIqeLn8Q=
=VDh/
-----END PGP SIGNATURE-----

--3rxu64vcup7p4zp6--
