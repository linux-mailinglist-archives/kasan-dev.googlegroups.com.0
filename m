Return-Path: <kasan-dev+bncBCQ6FHMJVICRBFMAQH5QKGQE4WXGSEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B2EAA269CEA
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:16:22 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id m13sf1882841qtu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 21:16:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600143381; cv=pass;
        d=google.com; s=arc-20160816;
        b=O98wTMGeAzm9Ku8hiIdGr+ufKq4aC4VjT1jkOOU1sCvg7qULhaS1FK73FdohiMWr/l
         eK4RdHboYgzFJ9aGOqR/KJvmANuIoaT4fzZLm6D4fLjNHNy+MpN0lWUEAHzmcEW4/JCX
         9xNk5AWWm3OzRlP5B4XCka3qpSdP21yOr67eNmA0Rr0CDQlXr6neGWBI6DbEecpPVZcD
         P1SVyNvFjC+y98FA8oNHRxh14/D0OW7xtAelMMXvkRQcvlDKqWj/VL/62T2tkWH54iSu
         dIVsj3sxChKALvEbi32Iw/vFXlVDFEyDsUqUP7F7qghvqg6x7KNmwfXgugVCSBjxdUui
         ZyFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=r3LxTFtrQ+awtf690/+iVRtjq88T8YBCeyPdqFkjhVo=;
        b=pZ/7E0xc6t8JWntkNg934PmY8jl2sf9f/WLUDAYE5tTAWdmqfmWGJn1dkRN0Gg/Yhe
         YrKmIWyLCIukaI2l+GzJRl3XCWWl+Jic/oGm8xcu8VQ1gRQhUFgJf9UlNMOeVefwEEwH
         yQW8tJfCWEcbZg+UjmVHatVPrkLr4t6Kp3Kzz4uKNgszNVFvTnmWzbte0ect8yIX0Ab+
         6C/wtlpa1/Vak1RWGoKjW2bzas9J5LJYEdDRlD7ra7Idt52+6YfSUylmVGQmoXbQ0z0E
         1d75fqMvJgxNXaf0M4KrZQklMllbpnw5NgTOoXKNg93eCWFsFCyKUcrmoo0IzP/N3bTA
         rQlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b="iyD/lMZ9";
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3LxTFtrQ+awtf690/+iVRtjq88T8YBCeyPdqFkjhVo=;
        b=TAXeaRXe7jqtLR0nmFBAXSFE2+PtVehLWNVGrY4vyMEGBoCAGgvuqJ2CXZA5TBLqjJ
         jm+TgEbA9V1ap3U0LUwcO6jUp7+vLzFOGYEJwz3Kpx+gGPh+HVtMzW3yinyRzJfmgMHU
         cst0xM73WVCxvcUF8hcPuaoptaCq7Qm5b3Xo6Le6+DSDX8sPx+5l78RoI1SpdsaeGTyk
         JzTgdjprGnjC/IZb0rKrksoJxNIWlKWWGFnF7LT7p4z3wOIPuWaOKeh41vkjd1c7CUhX
         MSqdtSZaVXv7GL8AAC5HgFeGe9LOPGJhGAjO0fRLAMr675FSLBoLPs9MfddR1rkXDFAE
         Xijg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3LxTFtrQ+awtf690/+iVRtjq88T8YBCeyPdqFkjhVo=;
        b=fbSIH7Z8KlADkjBfRng462Hvi0hbp3bTrhGh89fYfu3PN9x63P9EY6Jqju5SxVgeNt
         PW/3Z2vtzUkPc+3s8B88GccPf61glvBxrqbcFu6GOacKjobonPu5uqsGlDWDfnIhAW3S
         /nhJLoqxOJAK7hNAXB3rdMtX6h3A5GJ0TR8W5y2knSDnKi8nGL+epsfip4e0hX4wJDzI
         Kf7IdvrgJNvZ3lIbGXsiw+lf8mD9iidrnxOTl16K6qih7Ga6rRjbCw2708J2G7oHx4KF
         Bx3eKU4pX55yaJVtZrkIoZ8/MW3blw7hD7/rWqi7pFl6jTbL2I+5qPPTuvDIh8zf+1Km
         28Fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TmyK076JkfT1fqwT+oMLgItv/pxH/Ei/Dl4SokYot5+pG1i5I
	jzqXqu0VdslVgtEwOMiLqrE=
X-Google-Smtp-Source: ABdhPJzrGx2TcZ9xjMeyPSmHAxaljKS0gVhVMHleMbmJmmVo/IMULJSCjAPCuUIevoy6ZKOhNRwSrg==
X-Received: by 2002:ac8:4e86:: with SMTP id 6mr15736407qtp.331.1600143381718;
        Mon, 14 Sep 2020 21:16:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1abd:: with SMTP id x58ls4834045qtj.10.gmail; Mon, 14
 Sep 2020 21:16:20 -0700 (PDT)
X-Received: by 2002:ac8:3845:: with SMTP id r5mr16638602qtb.223.1600143380864;
        Mon, 14 Sep 2020 21:16:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600143380; cv=none;
        d=google.com; s=arc-20160816;
        b=V8OZlD0jV4I1x+JHMMmiuzoYHCs1aCtJtqwHOb8q0+uGBzBZysZEDq3XrW4epUc6xt
         84xvJu4VfQlpqTuIboUWkovUoyhHn3VgRXFnhy2bfmfah6X/6/RFEhS78pG4oNEHeUzY
         hBbaqF7kk8nVzMSTa2ph/aI0Da310hg55maVWKABHS20HcKo5r+XQsRhteLzM7wsZ2Vd
         hfqkkA/9D7lfawGzqXthm9gAD3zpit7luMSyMYinIW+ls4VGiySFKfTEYyEqylZN+f5W
         RQcX0Z/BKkB6MErsUmxKGe2IY/upCaBeihNSUSPzSF5L7/9BOE18qEqVSnZfLpPKoWda
         pp1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=39NzKKl99oYkPv0qjsWaYZRqhmYdp5PgjEaFoE7+4mk=;
        b=w9nnKNUtXp77LODAdsEzuLQPfNgxGxgnfYt4gEO4kjE0X3C95AOCsFi568+JdFO+jE
         Vp2EbM1RiJCj7L7KUMoTjxcWZvofl2cuClovKs6zHysgy4EKMk8b79maLh+fFyoegRqD
         on7VWMLYH1wjc6QZivxaIwmdXe4KxLSTZmM8VW1zjZkM33GX9MnUrqnd8KfLg5CTQfo+
         Cdm3CUGwayJEzDv32F311n1/yEaMevR5lOoIUniRnxpgklLdNcGf0mxheg7seaXisYX0
         +rwv2GusRfkmUv4kGDGzfgd1QMzYTYsQ9hb4AXDNGx+MijLK63qjzD8Rpwg3TThXeLDA
         IOpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b="iyD/lMZ9";
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
Received: from ozlabs.org (bilbo.ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id n26si667075qkg.5.2020.09.14.21.16.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Sep 2020 21:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Br8zy4QyYz9sVB;
	Tue, 15 Sep 2020 14:16:14 +1000 (AEST)
Date: Tue, 15 Sep 2020 14:16:13 +1000
From: Stephen Rothwell <sfr@canb.auug.org.au>
To: David Gow <davidgow@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Patricia Alfonso
 <trishalfonso@google.com>, Linux Next Mailing List
 <linux-next@vger.kernel.org>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 KUnit Development <kunit-dev@googlegroups.com>
Subject: Re: linux-next: build warning after merge of the akpm-current tree
Message-ID: <20200915141613.09dba80c@canb.auug.org.au>
In-Reply-To: <CABVgOSko2FDCgEhCBD4Nm5ExEa9vLQrRiHMh+89nPYjqGjegFw@mail.gmail.com>
References: <20200914170055.45a02b55@canb.auug.org.au>
	<CABVgOSko2FDCgEhCBD4Nm5ExEa9vLQrRiHMh+89nPYjqGjegFw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; boundary="Sig_/z2knM/TUP8H9wxwd02Y46Ya";
 protocol="application/pgp-signature"; micalg=pgp-sha256
X-Original-Sender: sfr@canb.auug.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canb.auug.org.au header.s=201702 header.b="iyD/lMZ9";
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates
 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
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

--Sig_/z2knM/TUP8H9wxwd02Y46Ya
Content-Type: text/plain; charset="UTF-8"

Hi David,

On Tue, 15 Sep 2020 12:03:08 +0800 David Gow <davidgow@google.com> wrote:
>
> > drivers/mtd/nand/raw/gpmi-nand/gpmi-nand.c: In function 'common_nfc_set_geometry':
> > drivers/mtd/nand/raw/gpmi-nand/gpmi-nand.c:514:3: warning: initialization discards 'const' qualifier from pointer target type [-Wdiscarded-qualifiers]
> >   514 |   nanddev_get_ecc_requirements(&chip->base);
> >       |   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >  
> 
> I was unable to reproduce this warning: it looks unrelated, so I'm
> assuming it was attributed.

Yeah, sorry, that was included by accident.

-- 
Cheers,
Stephen Rothwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915141613.09dba80c%40canb.auug.org.au.

--Sig_/z2knM/TUP8H9wxwd02Y46Ya
Content-Type: application/pgp-signature
Content-Description: OpenPGP digital signature

-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEENIC96giZ81tWdLgKAVBC80lX0GwFAl9gQA0ACgkQAVBC80lX
0GxqDQf/fGxucLLY3tmR4qE2OIiFf7aAcXMvI5w1rjnvS8yH4ptRBt0+Iln2ov7A
2GFZ7QcsUTmMZ7a86pjnbu/3fyOcQQc8rTXZlPI04eP0+iRXOZLbRq73vsVKENdl
6aYcCDdDn092Et5C4C0a41nYiEb4lNi1l4DKS+DBnuBHruhsKUuUrH1Lhk3DgDHt
VKbnPOgcEHtu8W6uSU3rllre9qQ+OfQ6KRsSDFY5VLH9+yVvElk1e4ZRs0ZdRfVV
80ZfZDRnou09BMMY9C8Fk1+B/cPuAObvX3rGUoFwiUv0MYribQtrVLaI6gEhjTdF
UE4QNst1BeyAc7sd1AhkrZrbql9Isg==
=OB08
-----END PGP SIGNATURE-----

--Sig_/z2knM/TUP8H9wxwd02Y46Ya--
