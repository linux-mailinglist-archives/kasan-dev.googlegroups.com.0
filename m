Return-Path: <kasan-dev+bncBAABBTOPV7BQMGQEFXNTFPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1062AAFB759
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 17:29:19 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3e059add15esf35859165ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 08:29:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751902157; cv=pass;
        d=google.com; s=arc-20240605;
        b=OaEw+kv6Xqgz8oft3Ru5GgBQwjfHhRjlBmsZ2rkVEI1OMQzYGrOq5bH0qN2qCsblcl
         JctlExc+QdY2f8dIzabOFDFpJWTLUfDgLNcGo6lmFyNHfzmiBz8s60zntjqpxoJaBY6B
         7nv5FvUtr56kGOU0egCkGT2D53BU/P8/2zzGMOQ2m+6LroaNIt2RwuJ1a5pCp28TBu/L
         VVn7/lXruP8d2jdmVla9tiRh8IA3wS/CQo35+Pq0GpJcLDCxKb/cARqFqQEJa9JYHHrb
         rSgtIsvdordV5zKFjcrJI8dLaWLFKfloqjpbbqzqMctvKTE9bAyOreDfTOq7fgm6oKmI
         v9FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RI7I/Tm+Yv7WVSc+cbH8SAyFNCTlPVgbNn1/X9kahhw=;
        fh=968AbaiB1ImnlUFY4nYTS4VSWKy+rh//hJpXKs8gyrc=;
        b=cArBlGT8yhhUg4yPPyVFcD1BHFG6dYJtNWvqfMNNOleQYbdkgtzGWF4C2dNiBdX2z6
         dHVDaH8yLxQfiTRHfhiysfo/hcpAQYRaD1dtrDNOPoMvN1mt/EpnfjfLd7GSpI3IOn4Y
         cv4AeEksNZVG2LOBBMIPBLF+X5hpRhfQT6WMSzZH2hev+uO8frRYacn/qf5b/gB4C1fg
         xpApUkPAG4GWC0mRG/3UkUHQYezj53Y8i4WFylhNsSQsG05MynxtkYJpzvTnoqty+RHI
         HnBvDQTE0iD5Azlj8qUj6Zxduzf9p8XorlakESIQ8T9rJKJx3kVEjgknb7oXPrldgTbY
         K27Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LsZpo71K;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751902157; x=1752506957; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RI7I/Tm+Yv7WVSc+cbH8SAyFNCTlPVgbNn1/X9kahhw=;
        b=urvA8TfXY0noQu0XhDKCdGcHmDpcJSJU8vgr8O96UNbATP60Y3vWmuH2v3wdV8b7gv
         7NrlW4WLkp79paANbbIOMeOwxEu1Nmr4plyxBQaQcW1q+QrY0uQM/FJk4eZlI7VWeu1b
         6j8ZgP0YRkCv2+IrhOfV5L0CQ/B8ugRsrqPGrX8V/aUY+Uw2mKdV3v9JIVInXtnPe2+u
         hOLQZ/7TKP7VHAWCMGp3lvSvNizyqDY/H/u+q0uHvq6npWSEKw2eOwYgT+jMB6tPkGd2
         b94NpjpsgqIkjNT4SCIE+4QMQXY69T5Ao74ZDQ8s9SjIXG5XLp5WFXChVQwR/kGfIdHw
         gr0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751902157; x=1752506957;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RI7I/Tm+Yv7WVSc+cbH8SAyFNCTlPVgbNn1/X9kahhw=;
        b=eghWEZOXqjBGyawBzPWNtMP3tGGU65jL3X5QbIFkn+zt1V0hrWTi/YDyXRrNLk3c4u
         7zGJT2jynuSZock2qBv/bsW0fhzhkfo03xIydA9foyOe8FxVPRF8LUMu4aPRhVuVAEiX
         psejkJdyDsOMG7lKed2mLIQA9zJ11t0qrg2eVwuigt61ED8q1s/YmEwDJQI6ZBM1uEsN
         cUVL+Q6sdMwxxhf+5Wd5aUj+iyDlxgu5TT74FjwIUdHjSdcvfVXjjFanWnl85IZFSE6q
         xlSTj2qOVoxkeXSsuZtPUD+qx+Qgg1eRG0lb+E/nx3X4vduY70RtSVmrdkI7z8PmIFJx
         oDxA==
X-Forwarded-Encrypted: i=2; AJvYcCXL6VqO+MeBBsV1omFy0LgJAXSSJxDbnN4V12iv7oJ05Nykx87rFm+0w5U3yFcdyjyQ9FPi7Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy5rX/7axXGiSsuSnsVfXiNZ/9OpuVMy6ulNshY9y3BnJv/08jZ
	tRYB8A9hxtEWDyaCRVV+GYCcRZKo6aqV+DxzHHqbLRjkuumZXQGDlFKy
X-Google-Smtp-Source: AGHT+IHi8psPfQFvqhyr5YjuFBjUhj97eHjcQu8mqsrysWX6PjoOt9hhZXMdvxs2MY7EekOGJNrJ+Q==
X-Received: by 2002:a05:6e02:7:b0:3df:4046:93a9 with SMTP id e9e14a558f8ab-3e1538c75d3mr551675ab.5.1751902157571;
        Mon, 07 Jul 2025 08:29:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7jNqIR4+OtSzgWXjlQVlg0dPv4CQiW1p8oMGbUyRQvg==
Received: by 2002:a05:6e02:5e0e:b0:3de:f0e:a809 with SMTP id
 e9e14a558f8ab-3e13920087bls14732995ab.2.-pod-prod-03-us; Mon, 07 Jul 2025
 08:29:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9XeVYdeYvKImay4ADyPmcVThp4wgDrzs0FRoXEJdhOmezqODtDf4N8Msr9uMF7v0iqpVBY+vrYw8=@googlegroups.com
X-Received: by 2002:a05:6e02:12e2:b0:3dd:f1bb:da0b with SMTP id e9e14a558f8ab-3e1539172b6mr507415ab.7.1751902156231;
        Mon, 07 Jul 2025 08:29:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751902156; cv=none;
        d=google.com; s=arc-20240605;
        b=UYMek1liH1xo0+Yy2X3ZCeGlcXw31lf7AkwLdHLg3X1LicvSgaosE8f6HoI5hVS0te
         YweJd39ucYDHM+B0evGQype+SU7XKbE16Ijn+9qEYj0uXe+UMzEbPuNm2JD3L7QopDFx
         rNLzSe4EI1WRXfp5u6PZ6WYnCocX4gM3SHiF16AYrkuagvghB1YcRn/UraHtoGocnulx
         Df5Kff9D2GEndrijYU5IZ9EXM1Pf0L79Lz0JBchUsWzL2etzpTsgy8W+eAeduQW9lpVG
         W+ricQRzixQhfSk89BcB7dyuJA0LlfhzO6nTSq7hpz/8L4rVIj9kH6Sub9n3UCYuw1DH
         rbiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fTdd8sJWyIJaBvqIR33NYAg4qZzFD6tGPZPvwWlig40=;
        fh=1sxG5E/nygP/ZsLVCLHKsEzOAX3ljbg+Iz5HceMNGFI=;
        b=hPiKkry9EQZypua/dCDRUsH/CD7R6j73TwZlU/0awjSrrx0MwDdXbl7sLewwfUDeb9
         XZk7BqaegLW3EV38ypmJhu08xnHi1ee6CsKgjko49qTurS+PVWni+RvOeAFVusDrydSM
         gO/Sqg1SYy3eG7Xmyb37MNBPTbVHGQp4C7HLPWGX/1ytezvIYpyT6hS8TonlM7oxosZw
         68/4hytB8I3dMsFeOEe2BPVScFQuzg0KxaM8nHW07DVQbZnOnjNdQDnsudRGPfTG3HP2
         9QdhZZNEddgURLest9VHZASuOaRmtYIWD7iGl9eR5p6IFKKCoNAGKnBNB40tm1oKG6Xn
         bvAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LsZpo71K;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e0fe5f1cc3si3960885ab.4.2025.07.07.08.29.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 08:29:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A7657A52A5C;
	Mon,  7 Jul 2025 15:29:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F08DC4CEF1;
	Mon,  7 Jul 2025 15:29:13 +0000 (UTC)
Date: Mon, 7 Jul 2025 17:29:11 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Michal Hocko <mhocko@suse.com>
Cc: Marco Elver <elver@google.com>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Jann Horn <jannh@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
Message-ID: <gqv533xpsrup3w5zsx7cy22kso2gaooupiuv76y6yonng3qwzl@5rw3ct5gfndo>
References: <cover.1751862634.git.alx@kernel.org>
 <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
 <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
 <aGt8-4Dbgb-XmreV@tiehlicka>
 <g6kp4vwuh7allqnbky6wcic4lbmnlctjldo4nins7ifn3633u7@lwuenzur5d4u>
 <aGvjwDqRP1cPaIvX@tiehlicka>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="fbhruxyunokpupvz"
Content-Disposition: inline
In-Reply-To: <aGvjwDqRP1cPaIvX@tiehlicka>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LsZpo71K;       spf=pass
 (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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


--fbhruxyunokpupvz
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Michal Hocko <mhocko@suse.com>
Cc: Marco Elver <elver@google.com>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Jann Horn <jannh@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
References: <cover.1751862634.git.alx@kernel.org>
 <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
 <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
 <aGt8-4Dbgb-XmreV@tiehlicka>
 <g6kp4vwuh7allqnbky6wcic4lbmnlctjldo4nins7ifn3633u7@lwuenzur5d4u>
 <aGvjwDqRP1cPaIvX@tiehlicka>
MIME-Version: 1.0
In-Reply-To: <aGvjwDqRP1cPaIvX@tiehlicka>

Hi Michal,

On Mon, Jul 07, 2025 at 05:12:00PM +0200, Michal Hocko wrote:
> > For the dead code, I can remove the fixes tags, and even the changes
> > themselves, since there are good reasons to keep the dead code
> > (consistency, and avoiding a future programmer forgetting to add it back
> > when adding a subsequent seprintf() call).
> > 
> > For the fixes to UB, do you prefer the Fixes tags to be removed too?
> 
> Are any of those UB a real or just theoretical problems? To be more
> precise I do not question to have those plugged but is there any
> evidence that older kernels would need those as well other than just in
> case?

No, I haven't done any checks to verify that this is exploitable in any
way.  I personally wouldn't backport any of this.

About the Fixes: tags, I guess if they are interpreted as something to
be backported, I'll remove them all, as I don't want to backport this.

I guess having them listed in the mailing list archives would be good
enough for speleology purposes (e.g., for someone interested in what
kinds of issues this API fixes).

I'll remove them all.


Cheers,
Alex

> 
> -- 
> Michal Hocko
> SUSE Labs

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gqv533xpsrup3w5zsx7cy22kso2gaooupiuv76y6yonng3qwzl%405rw3ct5gfndo.

--fbhruxyunokpupvz
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhr58cACgkQ64mZXMKQ
wqki9BAAvHQwrHaCcDiSxI+2THA4Jsg/vj21yBLhCZwpJ665Fn9zdi+14iteStzZ
mqIseo44SZgGrHHsPB7dnBbSD1nj8P1DY494tgV39/+7Dy+evUvbB9zTvGu8CXGx
Qw64VUZEUhpQtS4Sml+jivrdZAROQJTOc/J6yF/LOVjBQW5mT2mg6ENyUEgsHMse
bVox0YUAo5RhZ+2DThulCBQB0qHwFXnF4askanGgBv+nMYe+se23pDO6mrj1l0Tq
1CoIbUGiM5GSZy1TYOQ1dEBMp7JgKCoqeFzXU2KmlIrHrzOepKF8dDYVO3NckVBE
pIsO+M05rXJEPBu1hGAClXQLzOXbasyB+Vp52xla7H3w6BKxaKWHQXglFNkxraZR
gN+GABYRoft0CsWuMMn+Aj3XhC98CjrskYaLglmFpDihpWC56D11zvL3+bKhIUQ7
2rcEqY1t8C00DEhB/e+YdTEfRoAVwMbX2nyU55Nh3Rxo+ZOvF4gWbZMbat0radx/
in5zVJ1LzQZoCgtapxE49ISu+IsxjM9GCuZvZHd+JXIBp4LwQ8HHKF/76bQ3DsBn
dQE5GDHAv7mX/PQR7jkmmcS3FB3yf6liTltATONX4QfAT4qj3fEHEL0/2GrjCoqc
x9vf5ihsa0Krbj3EQjXQ/8IFBXwaIakMfJklw9PLeEfyuSNOWcQ=
=W8Je
-----END PGP SIGNATURE-----

--fbhruxyunokpupvz--
