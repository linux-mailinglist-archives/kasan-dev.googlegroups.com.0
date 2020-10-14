Return-Path: <kasan-dev+bncBD63B2HX4EPBBSOSTP6AKGQEWOSBNLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BF39128E042
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 14:04:26 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id l8sf1929037qvz.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 05:04:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602677066; cv=pass;
        d=google.com; s=arc-20160816;
        b=AMX0DmxpFCM8La6IX7J0FcsIhEgeUOjHiS7ZPMhuaAqEdKi7VZnJ/B2YcpPngRk30e
         LISDg/nf4+kiyWPguUdC6yy3Y/F01439J73P0gOTX7MRNaUJVYFAB0y8Ck/vO2xjefwL
         95btZamDWsZoJpJMsJvsJQcMBJrhOKkRV1Nr46NvvAvh67kG1ygKqKiVm3nNrkh4U/pS
         fHSTywVnH7kuultJiDoFiUjbJOxcm7hgyn2wl06I4pKvN1kOv+AvtHGRhVoubJEI1N6d
         ZqZ2zPgSOWCuVJa0Dlz77SnOGgiqbTEqVwm/ndQW7T/ntFB+SNjqp61E6GPgC1gH6R0R
         Jr5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=SECC/uatMPFRofgwzd0Jy81VyIq7EImK5YSPXuAbwQ8=;
        b=WKoFJ73I1d8+aEkTmkH6MgWYuQRYrDMmg/bsRUrOqXA1S+Twh4C7NqeLkkwfnpTGou
         sRwWn6Mcf4ezD2cAGjSeTLuxXJ9DaE2Sj2GTZ3oJgL9AywT5EOgejROdvAIjjtgabNa5
         KF/4lI9nicV1EN0oXXbOgCCEON75Z/uBBScC0hcMGK6ZToFG9YdTTZSsPU+/bk2zFTlH
         ZPKACWBzKPXOM5taJHrME++Ge1ViN4+Hukw1ciJNLIKNn6GHf2qQUKboabDXsEfWeb3F
         7nZbQrk+ycBYCX9QaeMFGmA8iBjMDLaH3TwymCZK3f0en+bD2W3jJDnGFb54VmnfUHQa
         TgSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=U2ZeIyPT;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SECC/uatMPFRofgwzd0Jy81VyIq7EImK5YSPXuAbwQ8=;
        b=fKPtE1UhAA8cDRheoaW15Fb8PjS+MkR6lUWvUrLEM1XAx3XhWTOXH+w7/0EUyN/fyX
         agHXQQnKQNlT8QXZ6iaIBfss8O/qX/RWqfnQaMV5N4/a2GdjcI0cMRZPAZcyu1cMLK3W
         Z/uMCFCmYAETSfB8A6mnFv/V3dxa5KfWeXqcvT/phPPiv6s22qSY8RvwHlrkv6TV5ysI
         ew7D2opeYNWYGBMsnIOzckWMQMvObRB1F1ogG8RIO9YjIQ6afPOKJ2MLf9JtwRwoTn36
         A4l7VQp4MbQmrmfh0rIBpG4pm3hzu1eYL/4s34Zs8+OTaZTCu42QKb7GlojwckiNphJt
         JM8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SECC/uatMPFRofgwzd0Jy81VyIq7EImK5YSPXuAbwQ8=;
        b=dg7kQlk0E4HMZ3LFSDUfURaWOMAIQZVO3JqqHzICOpXYWTbqbzkskXGVnkz1/+CDLk
         r8bdX580XPCCDlsNXJLbOSAvv6g8PbfJnzEQObalZ5kE5LgqMErnpxnQ/H/q72sjHb6i
         F4wt8OCYT8WTDSV53voV6TfoEPx90nZIsvQmLePPu1dr+QvRQi1lv2PXw0x/ZFWOi/8m
         qD57i4+d+PjqEfbLFXOlYUR9hDxh04VSJp79uEdX1Mx4O4Znb+Ut47NFWF4uyWBPScLf
         0j79L85078jgyJlSvL+BgBKWwGkrHxZeZBcQyqaY1BP2pGfpHwKsj00vNEkFn2xPr95w
         oKpQ==
X-Gm-Message-State: AOAM532Ue2sEF8kFITONSVxBesj1fn77i9r8giItuQXXLWHe6m5CZNfR
	K2b3FPJNFLacpfNr+EfZUHw=
X-Google-Smtp-Source: ABdhPJyjvm7O7IA2kFtxN4wCQ08G02bXDHXDdKwGhI0A37X767s5M32sMAJTKweuKiWnDhaHX/m3jg==
X-Received: by 2002:a37:9282:: with SMTP id u124mr4503389qkd.463.1602677065681;
        Wed, 14 Oct 2020 05:04:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:470c:: with SMTP id f12ls1143550qtp.9.gmail; Wed, 14 Oct
 2020 05:04:25 -0700 (PDT)
X-Received: by 2002:ac8:16d8:: with SMTP id y24mr4672106qtk.283.1602677065187;
        Wed, 14 Oct 2020 05:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602677065; cv=none;
        d=google.com; s=arc-20160816;
        b=ss7BO+l6KceErayz2JSFJ5RZCtWTDych7VYqvr2vX+dYLVMxh/W9iRk5uBTq7CVln9
         368YTTTa8XE9fOMUT/cMnsN98H0qgknBsfkdSR1cqWWqEnKh8yDoRHQgn2lXD2dc1XtP
         muEv1BasnY+fF/N4ZFXFveoy+x7bxovcSuXHCgA0KJ89ZWAQ0xJhMBDZqwxiemA+zx+V
         qUHl4uJS9M9gMBu4jSNUGN+PO9L2H1F5GhYD8PM7xjwA9sUVx6p4c78eB+/t/e2E0dRV
         PKDveHy8ul8g+bCw07YjjGOZHjpGS8vdt+8RhCfwPMNwmuNp+trX05XLpsRZK6nTznBf
         QWeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=LRA1P3vlDl+S+QVV3FLd1cgVbWm6+HP5EB113loJppQ=;
        b=wH0weYYvKE1bHoMce2cx7XsEeGdImWLDIankdSSzO7GYmcYXuKNXz8d6gou1MgfyxF
         7YMZPiVnGw9076dfiW6tC2sUmwV6uMeBnVGGDaRAqR/IWe+1zuOLCCAaT+BB91k2U1wp
         ZsRe9huWVEIYHQigK2lf6iBHmIBkEWUOWENJBGzyykpMadjEYZi4+pi9P5yqsEN9ROU/
         4Qro7EbDqpuoSuezY4XYipQAbitLtfD0zau57p1EjMpFbLGshiDaibbmxT5XDE5zPBhC
         OJbbCJORPauugtDMzRDGyFHJqUJP0TowubPCafv8sPGRSOtjmFOC0R6y98JU5x0UAtFg
         V1ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=U2ZeIyPT;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id z205si196510qkb.1.2020.10.14.05.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 05:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id e7so1824185pfn.12
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 05:04:25 -0700 (PDT)
X-Received: by 2002:a62:88ca:0:b029:156:2594:23c7 with SMTP id l193-20020a6288ca0000b0290156259423c7mr3958728pfd.12.1602677064383;
        Wed, 14 Oct 2020 05:04:24 -0700 (PDT)
Received: from cork (dyndsl-085-016-209-235.ewe-ip-backbone.de. [85.16.209.235])
        by smtp.gmail.com with ESMTPSA id o134sm3129288pfg.134.2020.10.14.05.04.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Oct 2020 05:04:23 -0700 (PDT)
Date: Wed, 14 Oct 2020 05:04:17 -0700
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201014120417.GE3567119@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=U2ZeIyPT;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::429
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Wed, Oct 14, 2020 at 01:42:48PM +0200, Dmitry Vyukov wrote:
>=20
> KFENCE (rebranded GWP-ASAN) is right under review upstream:
> https://lore.kernel.org/lkml/20200929133814.2834621-1-elver@google.com/
>=20
> It's already production quality, just last nits are being shaken out.

Awesome!  I will take a look.  Thank you!

J=C3=B6rn

--
All art is but imitation of nature.
-- Lucius Annaeus Seneca

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201014120417.GE3567119%40cork.
