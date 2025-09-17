Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF6GVLDAMGQEM7VO42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id B60E9B7C6AD
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:01:29 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-621cca96097sf3918644eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:01:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758110487; cv=pass;
        d=google.com; s=arc-20240605;
        b=RpbnNEPjo1qAOHV9lDnxJN2TrvS5CSF2f5rDIpx8dtlTgwDiSD1sMWTcZYLRummYDj
         UNnWab/9t2mAzUnbWK4JJWn2nVnhkG+lFDWYCIWPrAV5H/TO44XcLVHPf0eOsXiR2J0u
         WfbJZjfUxZujVAWwrKyw0AHuVcP5cuvp30+F6bgjSm3tfMXLaEzj8pVNnCdHyVouKBRA
         hP/C/GChOC+/mHFfm+e4zzz49FARtVYwTxysEZlY8sTc5f6PIHXYNxLEcRMOPECe8hot
         VJR62I0RW9HlNTi6ov4xfZEajvXt4F9dKNuJAChgyGkifFD/2pc2if06SkCpSRO9N2Bg
         yO7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7wcxOeAkCDodJQSqqGT1ps2VotHXIwoy4aOOHKF5f+4=;
        fh=n3uBSKT6bwIZXuQKaEq16G3ZXDQVj2gigA6OkTHZj6A=;
        b=agP+HdCSm+AOm8C1vhbaaGARct5RNyLzuSFofpCMVWkJYTqTTjQeB7c55B5km7viZe
         8gYV+fX9WVANlFYgIXMNpwO3gBTcRe/IXPJjUSEYikhkJWKsU6y6qMTgaKrvjIgFPajQ
         xWfKjO4wt3ldGXDSgle631G3HwqPzzN36Ip2d8t4qDz1BCC4VB5CjsTOWHxlWxmG7Yhz
         m/VghlCZR5F3GVcSw+BQRn1aNEVJscdslaxz56XNkNPVqpNzlUKQU5Z9bmsTnJjBqO/L
         cXn1bCS5TJjxIeUJ/nZqjmvWZT2QX7H69FVLZqHAEWMah0pSUfRuUmsKhPM/4A/CQMSq
         /xLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a6vu4NXc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758110487; x=1758715287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7wcxOeAkCDodJQSqqGT1ps2VotHXIwoy4aOOHKF5f+4=;
        b=aY0UPiiNsTSz3XPzxqtKPozAm5LPjGbk59PpjT4yHPF7QFI3NgKhU/1OYUov3rpK1R
         lIsR2V824NzRPYpkQJvxRwLGxY1hJvrOMRLuD3vd6JsOu2F8TrOblif7eyy5fNnWUW7q
         ZL82o6apUziEZKHhudiGWG+GtIW+HgAWgPI4d7YBpQvHNBXbJfeHC/eBB+PGafumQjG5
         7fFYdZONKzBk8h+V07afXPRDV28ZkhDKDcrUwUjRBZElTXI8fzZqXTPM9A7gPBB9dZh+
         bjgGmE8LgNfzEs71bIAlMJFQwaIVOhoncFKep6K3EdDmg9cKjeeeS5vTAh7d9PHM4I9W
         Nmvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758110487; x=1758715287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7wcxOeAkCDodJQSqqGT1ps2VotHXIwoy4aOOHKF5f+4=;
        b=jA8/GDj3LGsFJPhAMZEqauZphx74yf1kLNu0D96vjjUGVsqh1oZHlh4JzVch5/R0LG
         f6WC4jK6ADy3r9QV0HeNeLTvt/+VFYd4g8iMPrDI4KaL7822pLJyr7pz3obdyp65xStE
         lLhERRqOVuTivM+IZkb2NEQVZa3lh5Fa4W5QZQfwy9SW5hnKVIUW0OxnMDyIrrkHKN1a
         LshMytmNHlLfNctuB6hG8/z4euf3QyfaQc3u0/9ShGtH+YUnZxkjtmq6i8xYrefapAVw
         /0S1w0yQtXVoxvz/FUh+nvl2nUfzF7wSpwFJq4AwGFrRbTPkOGcpuTZoHjwpqMXGFnLx
         wLAg==
X-Forwarded-Encrypted: i=2; AJvYcCWJAxulfsWmP+O50HdQrqh8//pkiffF3Ism6gwESyo+B4USEs2wWdrYkExLqhkKwX1wyRuJ3g==@lfdr.de
X-Gm-Message-State: AOJu0YwR9TY28o1kw+VMV1pO35PvAx/QQf/snoB4DcUb3kzjAVxnhqOE
	UJfOYfSMiPYB6U+VsO7n56qxSaN10OqcPKPpX7K86Senniiyh3X9Aj0+
X-Google-Smtp-Source: AGHT+IEZzxKd7NXW7BN8f8Mz1klrFAtGZavysTM7TxgS0eWbBE0GPrrvbHmvNYb23Ar7YQ+AJnfSSg==
X-Received: by 2002:a05:6871:5809:b0:330:dd41:6e12 with SMTP id 586e51a60fabf-335c14a1a46mr901732fac.48.1758110487333;
        Wed, 17 Sep 2025 05:01:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4VVbloA9WptSWvpMGRkqPYAXH93sHT7PHmRNuJWGKloQ==
Received: by 2002:a05:6e02:4507:10b0:423:f3d2:2369 with SMTP id
 e9e14a558f8ab-423f3d229c5ls27956925ab.0.-pod-prod-08-us; Wed, 17 Sep 2025
 05:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZ5LnBoGKIvd11RK4o+/Sg9kMOR89W/7Hr3GW+Wy1CSX4AafGCcnu/wthgAUP9o38PitjPdVBEJqc=@googlegroups.com
X-Received: by 2002:a05:6602:2c05:b0:887:6ad6:da59 with SMTP id ca18e2360f4ac-89d22bb144fmr306290239f.4.1758110446423;
        Wed, 17 Sep 2025 05:00:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758110446; cv=none;
        d=google.com; s=arc-20240605;
        b=C9WUjb06SSgmDgnT6v11/34MfC/QCpCLHBwJ39fwlfdupp0k08jA4fC5rrkmFK9R3n
         JMs7xIzLof6wrfKNpbjrFxB4eZ4zCfl8MMCi9gdWPY/ZkneaGTxlNADb7Rm+pfUEG9wE
         AWrWjGo8grlrCDkCb0Q8I0KdhpGs17rMLXJVt5BYq3GsUilGWotye5YOzeHrpgMm7dZy
         BkDPPPDl02C6XbPHOO8RM7jT/Qbk6+zIGPKIAhp8Q8nY6PXB+DW2QWAn5uWsXizj2/SB
         TEo++X/b3ipsSLuKtxIuDkBiITOgEvAKYQCUs2lFoOI9stikWhs2XHMKnLs9mQsatT6a
         rW9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UACzCyCSXTVYBvNeF7X28zPTXpB3Pxq8jPBy4L814NU=;
        fh=NIE83D36gTWlQGr+hpUuLC1YM/s3XnT8NFoewKN0x8E=;
        b=aEcjE1Q/c6sfESlfWumuewxDkOTrXtzg4zx2lm90FgoqF/tLc9dw5l3QrYRS0YteuB
         Ls5U91oo3I8W/NhmLzgbCa15SUAaMnMMkNKzbUBrGOgGZO+W9zGqPSq0j3k9sjMceyUR
         ZCsdoNu7oOgpttHASHRWfUcSgRDJSlKL6592gYh8h0Yb2KSoQANlymd7dRmr/9KpWKyu
         Jmq+stSToeo0iwfW447UqGwgfRk5e+fqAtAvIJuEIp2mr//0i1xo2FumWv2NQ+RwbSCi
         zIlRSQrmjTXohqFY5S5UQS29TXYBYIiU0oab3iiWrKQgefKeqgNf5mhxSmMTuaTxwP17
         CNzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a6vu4NXc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-511f300906asi701567173.3.2025.09.17.05.00.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Sep 2025 05:00:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id af79cd13be357-8173e8effa1so422201685a.0
        for <kasan-dev@googlegroups.com>; Wed, 17 Sep 2025 05:00:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVkoNrKzh4rgFaSYcf3mg4moPALK5eXenSS0ld+gLITvqqbPGurY7QkYOP7MtSruC+t9crTomW9K7s=@googlegroups.com
X-Gm-Gg: ASbGncvXilRYRlqx149BFEbxlyNFkncOZDJqcFbU4+KrX0yY9AEITgj8xZyjuK+AxxL
	Pi+Eki+QkNG+ivWyD52o95+hoz2VQhLR8kUF5mJh4jaEBJgXH5H2Gdcu4Lhf4f+otfWqVUOPhT9
	jGBzQ8Jxe90sq87Pzg3uabHU407REhZ1jcQaUkznVlbbn0vtWOSoj+l91YsJt1lE/D/hraKlZV1
	gHP81V4HYJDU7L2nAxJ0EQk818BE/dXAjqnJ2mezvxCLNZQpzVAIw==
X-Received: by 2002:a05:620a:471f:b0:811:5849:656e with SMTP id
 af79cd13be357-8310a641767mr177796285a.35.1758110444753; Wed, 17 Sep 2025
 05:00:44 -0700 (PDT)
MIME-Version: 1.0
References: <4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon@kernel.org>
 <20250917112242.GZ1086830@nvidia.com>
In-Reply-To: <20250917112242.GZ1086830@nvidia.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Sep 2025 14:00:06 +0200
X-Gm-Features: AS18NWBOKXsu7wnGTnT6zHPRB3malyIoD_14jKNdkoZmt_gqP0U2UlyOiEpbgCA
Message-ID: <CAG_fn=WWw87a47aqXFBK1YpHAFStzpoU01CJTf=Eut2FgVTkMg@mail.gmail.com>
Subject: Re: [PATCH] kmsan: fix missed kmsan_handle_dma() signature conversion
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Leon Romanovsky <leon@kernel.org>, Marek Szyprowski <m.szyprowski@samsung.com>, 
	Leon Romanovsky <leonro@nvidia.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, kernel test robot <lkp@intel.com>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=a6vu4NXc;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Sep 17, 2025 at 1:22=E2=80=AFPM Jason Gunthorpe <jgg@nvidia.com> wr=
ote:
>
> On Wed, Sep 17, 2025 at 09:37:36AM +0300, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> >
> > kmsan_handle_dma_sg() has call to kmsan_handle_dma() function which was
> > missed during conversion to physical addresses. Update that caller too
> > and fix the following compilation error:
> >
> > mm/kmsan/hooks.c:372:6: error: too many arguments to function call, exp=
ected 3, have 4
> >   371 |                 kmsan_handle_dma(sg_page(item), item->offset, i=
tem->length,
> >       |                 ~~~~~~~~~~~~~~~~
> >   372 |                                  dir);
> >       |                                  ^~~
> > mm/kmsan/hooks.c:362:19: note: 'kmsan_handle_dma' declared here
> >   362 | EXPORT_SYMBOL_GPL(kmsan_handle_dma);
> >
> > Fixes: 6eb1e769b2c1 ("kmsan: convert kmsan_handle_dma to use physical a=
ddresses")
> > Reported-by: kernel test robot <lkp@intel.com>
> > Closes: https://lore.kernel.org/oe-kbuild-all/202509170638.AMGNCMEE-lkp=
@intel.com/
> > Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> > ---
> >  mm/kmsan/hooks.c | 3 +--
> >  1 file changed, 1 insertion(+), 2 deletions(-)
>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWWw87a47aqXFBK1YpHAFStzpoU01CJTf%3DEut2FgVTkMg%40mail.gmail.com.
