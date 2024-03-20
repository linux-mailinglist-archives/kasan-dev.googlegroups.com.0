Return-Path: <kasan-dev+bncBDM6JJGWWMLRBRNS5KXQMGQEJ2JIY4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id C81CC880CB3
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 09:07:34 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-221a9c0d2e0sf8526776fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 01:07:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710922053; cv=pass;
        d=google.com; s=arc-20160816;
        b=sPTgMbGYBS8e+UYk8bBkfyimkMGfqLEiMvT1bGN62AdiASlibM3sIYSQGriI8ERJIv
         Wrrqq9e9YnAjJiOUTd8qBh4FYlQLXmkb43RY0VEh0PPRXcyIqTy1Jmxynzfy/4GUt2PX
         MRPthY8xElF+Dq/+W/XXm9z2LxB2Kxq1tGEB9/veGLLLW2FubiMH0681k9q9mNtBnUK5
         X2nz+UO5h2XAws9bx7BRzW2prcgNCOExPU9+nkIvzmU4pMn+pNTCEXPAy9nOH65GEdo9
         IR0gHHEU9SfTgckPRQBL2yuYpRuYwnl3eiPs/DR8esj9AZA5gLkGHR9lCWPl1luUj0C8
         oRyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bPZfV1fhEScPNnl5svJHjIsoeN8AqTAx3f0/0RHUfQ8=;
        fh=bSZ7SeZH5nE7x8dhtFv3SQlwkXjitFd0Vm3zishsZ1Y=;
        b=KMcjZo/DGRx4bsxlPg506rTqDCJ4oUg0emenGTPC/KKtedyFr/BGKt5sk9bNhNoZ/x
         SfeHO9YZe/OajU8+dJjA2A1wqNwO3GNqKq6AoN2H0akRa2X5ienTqm5VHE0ucpNyHQdP
         Z1iimjM+4y1VzUvOW55CObfRDoll+Z8rn4aDVlGAF9lajaRsfu8bMdsEguA4CgVc6ZdO
         WeFRhnW4B8xnKbxpe1AYkrrTQH8Pohkz8UGQ5CTNB47dW22EFHpYwf1hu26sAXD1lyMX
         BuEeEAHo/GKocM+G9pjERL/WqQskT+OgUs7DFbinwT1z9V/dgoYB+5eAJuBXzI+HU7Za
         bZKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@microchip.com header.s=mchp header.b=YvJ4fXBO;
       spf=pass (google.com: domain of conor.dooley@microchip.com designates 68.232.153.233 as permitted sender) smtp.mailfrom=Conor.Dooley@microchip.com;
       dmarc=pass (p=QUARANTINE sp=REJECT dis=NONE) header.from=microchip.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710922053; x=1711526853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bPZfV1fhEScPNnl5svJHjIsoeN8AqTAx3f0/0RHUfQ8=;
        b=LLXsJxgocEfLcOltuB9S8tcGZBF1M337Wl93KP0OkLaUavcM+XpeFKwNRAtgX5pVbI
         Hx78m/hjMe+t+A0VDxgu4zHXTR4FGEkwzHUPi7yLuAeI849vqD8HjSdHd2Fo+S5YpEBq
         Myhy8z6aaGbC9Oopn/khxucfJOljB6j1toQYtjjgpOfbTTEASVNgA/KJMqYdpd4+H5Fn
         2jH592vCKWTdipH1WopEZmAz6LRAC4SbRinFAY/pJ2V9OY9rZZwRBNabe00Ro6ng8PaO
         35D5zoEjRnag0P8tSWScLPMVDU3f97YZ/HVsrDQ+puSbvDhKAa+EI5RwE2oSBqs1B4X3
         7mKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710922053; x=1711526853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bPZfV1fhEScPNnl5svJHjIsoeN8AqTAx3f0/0RHUfQ8=;
        b=E9CjH6RIklZzRFdRt8cUOEwkDzMeTyLu/WMZEvuMW0HSkZuVxhto8wHh8t3NO2XmAC
         iZ9Bv2yqNpa6+wascq0G4wxzgSCU3Z9H+w8/Npk4Nzfuv7CMXkMxgqRYCgFc1IujKz2c
         WT0ow36H7lAotU7fTRt3sYBPluS+ysMrSILETymVbokaXUwdrWtIPHKBcAr8dizqIKJo
         VS/hzDQ2n9juiFUAJWTQ9hTqgnwOrfTVv64WPzJfbonlSs/xMp7dnIHGQdqr5CqoD3ER
         8Un5qudFT4MB8yFA+BOLV6Dx1geMnU0Wwi8K/NlTlP5KDLFt/pd0dSCzh+ojnEFd+oo3
         F23Q==
X-Forwarded-Encrypted: i=2; AJvYcCUrkRvv+u+VosJqwHfzKCr8NMd4Fe0c9JIh0s/jx2M+7JxJypA3ws6Eb4ggHPxdxGG/aCHPQ+G511HiECj82nJgCRyCNKRKdw==
X-Gm-Message-State: AOJu0Yyn6S293L+uZdkkOz+QADjD/CnljZsasJKmzrzqOKVNHiKygcHh
	Uy/6sfNyh5Gb2VZ9MGhKsQoEo8fEqe5kxK1O4l/k3eQoBB5NHCPF
X-Google-Smtp-Source: AGHT+IEs+pozzA7YSG2x4uhwbyYYfizIdOErlEETYRcCHDPKr0PXxxbM0ED6H2lr73zqU9QxZXbS0Q==
X-Received: by 2002:a05:6870:3511:b0:220:8d30:8e8e with SMTP id k17-20020a056870351100b002208d308e8emr1309791oah.51.1710922053376;
        Wed, 20 Mar 2024 01:07:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:858c:b0:221:9187:9438 with SMTP id
 f12-20020a056870858c00b0022191879438ls293572oal.2.-pod-prod-07-us; Wed, 20
 Mar 2024 01:07:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUq/6VTInKcIIXM63jpOuaMhtRHBMiiLjrBYpf8aEGiLSmRKW5gqC6a48L3RluRcGO8tnBYo5k9EPx6k/2pywOMA87lYggP/Eq24Q==
X-Received: by 2002:a05:6871:740f:b0:229:9d05:c521 with SMTP id nw15-20020a056871740f00b002299d05c521mr1412534oac.0.1710922052213;
        Wed, 20 Mar 2024 01:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710922052; cv=none;
        d=google.com; s=arc-20160816;
        b=WIgXteYQcT/2FLobB40x18LShNneccNDzLbdzt94O5UaIxp4naGbj/TXOhLiLXFdfw
         NbN1svg5mCHm3fY7bMOk0EzsaSatFR+LoA2jkCpwUcjSpMizzMVrBbrqijofqPv0GuJO
         ROqvY4ZhsSagvwF9MEh/Fv59qHCjoozXoa5eXmg+27KnFpJPvf99XKVl2pCO2X10rlpj
         j/sTq0RTeRu6GFgZUiaWQouN4/Oxq4ezlhtqQ02yn6HXMi1cE7CBZZRGD5cXGOw7qw8B
         bIlPQ1Cdt66fTm5XcXjK37hYpNY0vdQ8Dthb6UHxHf7+HqgYQO4/hQwbittNtUhYdYxh
         hFtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qo2WFvFI+ooaSXfDj307OMcV56cuiGsV5SDZpCU1v40=;
        fh=JL/0fyzVWMrNfKjXDitWaeIkziClIwkZcvEfh8HTePw=;
        b=wsXkTtIzCcr39HVDyLvJyvyLah1AfDpcSi/HITkKhA7rdsKphF50UtUVxFMtj+oIya
         794lVOX7hVNoNuXmPy6XqVKgbwM21DeUBJbw71Bhax7JpJsPvwJPAwD3FE7MUVq6KYX1
         EAAC/KrtBJMoS/vp9olB7ziSL4+kIdZQXnB/R4qRjflx3HR0aPvtgHgY+FHb0oaafK1n
         TDwlR/KbY9MhE9OUO5llX7m3n8ib7+fa8QCiKSKEGQFwsXlO42czD4ZVniObpNHb4r45
         nfgtRfAwrGXMRHa9GoGPBNZHD9T3tqp2c9R5P2NUUfvbsr2wfmuBk34WwHi6ip8O7FC2
         Dydw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@microchip.com header.s=mchp header.b=YvJ4fXBO;
       spf=pass (google.com: domain of conor.dooley@microchip.com designates 68.232.153.233 as permitted sender) smtp.mailfrom=Conor.Dooley@microchip.com;
       dmarc=pass (p=QUARANTINE sp=REJECT dis=NONE) header.from=microchip.com
Received: from esa.microchip.iphmx.com (esa.microchip.iphmx.com. [68.232.153.233])
        by gmr-mx.google.com with ESMTPS id y19-20020a0568301d9300b006e6a4c1c931si180168oti.4.2024.03.20.01.07.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Mar 2024 01:07:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor.dooley@microchip.com designates 68.232.153.233 as permitted sender) client-ip=68.232.153.233;
X-CSE-ConnectionGUID: +2PKfpLTQGq2m0SEBNMVqQ==
X-CSE-MsgGUID: eSxs2JbuTmyaJCQMbacMkA==
X-IronPort-AV: E=Sophos;i="6.07,139,1708412400"; 
   d="asc'?scan'208";a="248659095"
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
Received: from unknown (HELO email.microchip.com) ([170.129.1.10])
  by esa5.microchip.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 20 Mar 2024 01:07:30 -0700
Received: from chn-vm-ex04.mchp-main.com (10.10.85.152) by
 chn-vm-ex04.mchp-main.com (10.10.85.152) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Wed, 20 Mar 2024 01:07:10 -0700
Received: from wendy (10.10.85.11) by chn-vm-ex04.mchp-main.com (10.10.85.152)
 with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.35 via Frontend
 Transport; Wed, 20 Mar 2024 01:07:07 -0700
Date: Wed, 20 Mar 2024 08:06:20 +0000
From: "'Conor Dooley' via kasan-dev" <kasan-dev@googlegroups.com>
To: Samuel Holland <samuel.holland@sifive.com>
CC: Deepak Gupta <debug@rivosinc.com>, Palmer Dabbelt <palmer@dabbelt.com>,
	<linux-riscv@lists.infradead.org>, <devicetree@vger.kernel.org>, Catalin
 Marinas <catalin.marinas@arm.com>, <linux-kernel@vger.kernel.org>, Conor
 Dooley <conor@kernel.org>, <kasan-dev@googlegroups.com>, Evgenii Stepanov
	<eugenis@google.com>, Krzysztof Kozlowski
	<krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, Andrew
 Jones <ajones@ventanamicro.com>, Guo Ren <guoren@kernel.org>, Heiko Stuebner
	<heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Message-ID: <20240320-fanfare-flick-3b38dde081d8@wendy>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="ZQuW/bL/DNtzlQCx"
Content-Disposition: inline
In-Reply-To: <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
X-Original-Sender: conor.dooley@microchip.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@microchip.com header.s=mchp header.b=YvJ4fXBO;       spf=pass
 (google.com: domain of conor.dooley@microchip.com designates 68.232.153.233
 as permitted sender) smtp.mailfrom=Conor.Dooley@microchip.com;
       dmarc=pass (p=QUARANTINE sp=REJECT dis=NONE) header.from=microchip.com
X-Original-From: Conor Dooley <conor.dooley@microchip.com>
Reply-To: Conor Dooley <conor.dooley@microchip.com>
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

--ZQuW/bL/DNtzlQCx
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

On Tue, Mar 19, 2024 at 09:20:59PM -0500, Samuel Holland wrote:
> On 2024-03-19 6:55 PM, Deepak Gupta wrote:
> > On Tue, Mar 19, 2024 at 2:59=E2=80=AFPM Samuel Holland via lists.riscv.=
org
> > <samuel.holland=3Dsifive.com@lists.riscv.org> wrote:
> >>
> >> Some envcfg bits need to be controlled on a per-thread basis, such as
> >> the pointer masking mode. However, the envcfg CSR value cannot simply =
be
> >> stored in struct thread_struct, because some hardware may implement a
> >> different subset of envcfg CSR bits is across CPUs. As a result, we ne=
ed
> >> to combine the per-CPU and per-thread bits whenever we switch threads.
> >>
> >=20
> > Why not do something like this
> >=20
> > diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.=
h
> > index b3400517b0a9..01ba87954da2 100644
> > --- a/arch/riscv/include/asm/csr.h
> > +++ b/arch/riscv/include/asm/csr.h
> > @@ -202,6 +202,8 @@
> >  #define ENVCFG_CBIE_FLUSH              _AC(0x1, UL)
> >  #define ENVCFG_CBIE_INV                        _AC(0x3, UL)
> >  #define ENVCFG_FIOM                    _AC(0x1, UL)
> > +/* by default all threads should be able to zero cache */
> > +#define ENVCFG_BASE                    ENVCFG_CBZE
>=20
> Linux does not assume Sstrict, so without Zicboz being present in DT/ACPI=
, we
> have no idea what the CBZE bit does--there's no guarantee it has the stan=
dard
> meaning--so it's not safe to set the bit unconditionally. If that policy
> changes, we could definitely simplify the code.

The wording for that "extension", if two lines in the profiles doc makes
something an extension is:
"No non-conforming extensions are present. Attempts to execute unimplemente=
d
opcodes or access unimplemented CSRs in the standard or reserved encoding
spaces raises an illegal instruction exception that results in a contained
trap to the supervisor-mode trap handler."

I know we have had new extensions come along and mark previously fair
game interrupts for vendors as out of bounds. I wonder if there's a risk
of that happening with CSRs or opcodes too (or maybe it has happened and
I cannot recall).

Going back to the interrupts - is the Andes PMU non-conforming because
it uses an interrupt that was declared as vendor usable but is now part
of the standard space because of AIA? If it is, then the meaning of
Sstrict could vary wildly based on the set of extensions (and their
versions for specs). That sounds like a lot of fun.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240320-fanfare-flick-3b38dde081d8%40wendy.

--ZQuW/bL/DNtzlQCx
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCZfqY/AAKCRB4tDGHoIJi
0m4/AP0UYPz9RdNLmW6g7L1tf8w83wsWZfBkuwZqh3A3w0Jq9wEA7t8mWVQ1YVm2
D9FdG5Y2+4p6MzgZJDv6xF67VncJZAU=
=unOr
-----END PGP SIGNATURE-----

--ZQuW/bL/DNtzlQCx--
