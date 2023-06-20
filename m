Return-Path: <kasan-dev+bncBDW2JDUY5AORBFV7Y6SAMGQEYBZ42DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 97E6D73729D
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 19:19:19 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5559caee9d3sf3210233eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 10:19:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687281558; cv=pass;
        d=google.com; s=arc-20160816;
        b=cCInB5Hxk6U91PhZ/XnQktxjPpCV+3isfx54BOKg2CPwo76bzsYEy/UtlUYtGI7HCD
         z6lNBOjuqFTqhCXGaZkM58vAm4zt2dBaDQ7BR4evg3SnvtQCcMwPQRu7BLq+hiryM5nF
         z5Dc9vIVCCAqiH1qL2t9vbp94SrNbnrUn593IiPFJBbfqnST5eoJIG0a3JX1usZ7fWGx
         lI9/C/4y4hvltXKmbeVN+WNNzauO4eCLbdI6liTKPoE+yNaOrgOJb1SU8iFkKbm/60zh
         x6mqQbx+qre43dIX3ZxMYMBJQEI2NTqO+XTiPBUApo59aiXZCGIXhZHFYhrzOYeJAeNF
         ZjFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=EbiNzB3KqeqKa7s2HI1hrONL6zSoA2JnJpUEEp2AAmM=;
        b=c2/6QWSvNvuL4y5rXCIq9bEJAnSMejRHn3OnWYfMxNfmU/OvdmS7y0+KYHyqgWMTY3
         03T5DMos1+DRPygecCGP/sIPRucjeGJwgAvr62/Xof1+p+lVbaK72keOeGkG+0OlhHeJ
         4ot3AKGEYzefbrKX3PAOF2hZ3C+qixKvVxVjNMbsWb/Vo8PRXzhWTLFLfoOKbMvWK+56
         nz66k1k5c7bdu1vyJyFhGSKw//rDULThfqgsm9DzwjRC9ugDtWZ/9Bkto8M6/QsrmqDU
         IxANj8PWpTvsvzQn/Qk7fb2vV2R5FsPZRDhnU274ej5lXanDsO44mK6CW46yX72iTjnC
         tUWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=b9lHqrba;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687281558; x=1689873558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EbiNzB3KqeqKa7s2HI1hrONL6zSoA2JnJpUEEp2AAmM=;
        b=crjhpfO4z4wTVCzzkaAU4WRvicPTzHb+OGNKRJVAzYNqqMYG/ql6uioXBZDoSqRRas
         dXHd6DwbyAB7jgQOdKSw6h4gQerApjv5SEhd/MmzHFGvH90+roS4WRjeAluwEFEnlnnJ
         loXUgzyv6iBPF3zLgYo5sm7nQrRPaKNoGZZ6r4M7Si5a/neVXi2QgI3354ooRJaC01N1
         Ss2xyZevkVFzaoPE81jfm8wREGlZ+98ACkydB278Mqmezxz7SaKkXRgI26aq3g3nk4P6
         ZPpM5X1jLmMOgj6gA0REjPpeDsVzTiNxdVceiEKPc7iRuHBik47S2Xh6prvAZ1SAIL6t
         iqUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687281558; x=1689873558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EbiNzB3KqeqKa7s2HI1hrONL6zSoA2JnJpUEEp2AAmM=;
        b=MYnaMF2sbFPyjFQSfWhSw5rTzCKpDdHpUn2P16QvAG+KirKjkclABKJw4OGsH1Lwu9
         TrwECJ809iUolKRZEE9IrzdNT56qBre8pe0vPLMgvnYsIjpw424I/lXD0JlF0KyW5mJN
         gyMh1qWW+jxHiyHuplJItnGDIQVEfCkK6azkLNKoWMJmbEySyTz9WpZb0iWbztwW0BK7
         VTfgs4bnM6d8C21+ZY2dWgnrKQCpRF8vNucwtVucbxeBOTDvWtzj+AmkFTt0DxUebRK/
         69j9B/kvvitTQ2DA2JxcRD7Kbi50V/xoVTct3GBGrmbZZs4MWcTx7A5+ephOQ6vjaYpa
         X7yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687281558; x=1689873558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EbiNzB3KqeqKa7s2HI1hrONL6zSoA2JnJpUEEp2AAmM=;
        b=JdYCs6UyBzWcbbCeHI7S+gMvvL73aHubnFgfpm/Fjp/4JQOUzqJPi2ZF6rDLyNMrg7
         tJ7Ks1FXaD3HF93v1Gss9O6clVoLYA724WOdibQF3JURlURIhvtU/qJ/J0oozEEhHbjm
         1Rk6C5WiGod8MCnrpQ6urzs8cHUNnqonONTuMOLkEPjPV7d/2pnnH62mskd2ud3WihaS
         DCoPardcbUY5vaFxthjQ4ym4PLjXf4cNn7ZdHEtVEaobIT7Fvx8EmJBT6vSJsevNvnv8
         LDT1U37IvpdrTWgeFXNL4H8qo4NRZwNOQ5fAIj4K1nkn3R/BlCKukUj0H2OlA/Km9Ix4
         AcsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwClrBkR2ktEgyJ2WY405LCpRV7VgmamomGMLOtLh9vFzXLLN1M
	FDkmwOp9OTSkKZABr0tLs/k=
X-Google-Smtp-Source: ACHHUZ6kZWbKB4OTIOT50Ibdee85bMkkBAoDwmyuFRAZkfBHOCsYt8k+oYMtEqPL4HjT5EztcOhW7A==
X-Received: by 2002:a4a:e509:0:b0:558:a4cd:8813 with SMTP id r9-20020a4ae509000000b00558a4cd8813mr8860862oot.9.1687281558253;
        Tue, 20 Jun 2023 10:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:942:0:b0:550:2178:5bf1 with SMTP id 63-20020a4a0942000000b0055021785bf1ls284267ooa.1.-pod-prod-02-us;
 Tue, 20 Jun 2023 10:19:17 -0700 (PDT)
X-Received: by 2002:a4a:b283:0:b0:560:7bb7:d2fb with SMTP id k3-20020a4ab283000000b005607bb7d2fbmr3544303ooo.6.1687281557793;
        Tue, 20 Jun 2023 10:19:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687281557; cv=none;
        d=google.com; s=arc-20160816;
        b=kxnG9slqqyTm3lAhIGw1i/A421pVd2CS2ovEl+jiaYiEIFsq5pbCDr+5QFBAz6YFK3
         FPAmHOlPW5CQLXtibLq7hCNSltRtzcnt2S2ZF98R8BFpQZdgyVRvq2OFmBc2W7LA1/Hh
         xy2t1FQbwGdclVfIkef+JEP+drY8eb3k39r8iNDWa/2nsftOr8bDNNL85O4QJnrX86Qy
         EPVEqQPEPykWbJTWMB9rJhpVgR8Qu+pLw6sSrMbGvzFclHpi3g4MGxrFEUP9ouC2uSsW
         oBgjeWx6wYJjG1m6P2KhH39pgbhcUvPRJDEFqW9CbCGD6zEToeA6A14fkUDDgNtJJTg0
         3a9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WmCprH+idanaTAuo2dvFzhcGXyTLAiyj5xkHxuQVXTU=;
        b=PGPb2yn395aIDQIIvBgCFbqEXTtFWf5//VtYCath8LmfT/SaNNw9ToQSXjmg40ctfi
         aB2Z9SYuUwdYgDC1AlCoJeYcT6AZ975d1x3xG9mDedH/CNLuVPr7g1OCL3S5fW/kgtsM
         3GFVS9ztM37dsqfJzgqQDqG9LALE8D2CCMzrxiKjBzVgvWxd6kjfAPYi7NFXJ3Dngqn9
         v5sPSQpjX6dtKOixTdVOlS5YEoUkzOoPLqlAG5g6hBFgURYP+uDtPDYDKGSzzpdK7miQ
         iwmiLZ6SmEljdj54A4VTeniTtExuaXkajwYWo+EUivOTkywDweiLab6LHfg2Kfq119q/
         H5NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=b9lHqrba;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id bx1-20020a4ae901000000b00558b743ef2asi228975oob.0.2023.06.20.10.19.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 10:19:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id 5614622812f47-3942c6584f0so3250972b6e.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 10:19:17 -0700 (PDT)
X-Received: by 2002:a05:6808:1b0f:b0:39a:aafd:dda7 with SMTP id
 bx15-20020a0568081b0f00b0039aaafddda7mr15864716oib.35.1687281557150; Tue, 20
 Jun 2023 10:19:17 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com> <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
 <ZJGSqdDQPs0sRQTb@elver.google.com> <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
 <ZJG8WiamZvEJJKUc@elver.google.com> <CA+fCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA@mail.gmail.com>
 <ZJHfL6vavKUZ3Yd8@elver.google.com>
In-Reply-To: <ZJHfL6vavKUZ3Yd8@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jun 2023 19:19:06 +0200
Message-ID: <CA+fCnZe4cetv53bGM0cOxLGB+ZDiNU7eeSb2LKNkO2j4xCPkYQ@mail.gmail.com>
Subject: Re: [PATCH] kasan, doc: note kasan.fault=panic_on_write behaviour for
 async modes
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Taras Madan <tarasmadan@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=b9lHqrba;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::231
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 20, 2023 at 7:17=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> Note the behaviour of kasan.fault=3Dpanic_on_write for async modes, since
> all asynchronous faults will result in panic (even if they are reads).
>
> Fixes: 452c03fdbed0 ("kasan: add support for kasan.fault=3Dpanic_on_write=
")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 7f37a46af574..f4acf9c2e90f 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -110,7 +110,9 @@ parameter can be used to control panic and reporting =
behaviour:
>  - ``kasan.fault=3Dreport``, ``=3Dpanic``, or ``=3Dpanic_on_write`` contr=
ols whether
>    to only print a KASAN report, panic the kernel, or panic the kernel on
>    invalid writes only (default: ``report``). The panic happens even if
> -  ``kasan_multi_shot`` is enabled.
> +  ``kasan_multi_shot`` is enabled. Note that when using asynchronous mod=
e of
> +  Hardware Tag-Based KASAN, ``kasan.fault=3Dpanic_on_write`` always pani=
cs on
> +  asynchronously checked accesses (including reads).
>
>  Software and Hardware Tag-Based KASAN modes (see the section about vario=
us
>  modes below) support altering stack trace collection behavior:
> --
> 2.41.0.185.g7c58973941-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe4cetv53bGM0cOxLGB%2BZDiNU7eeSb2LKNkO2j4xCPkYQ%40mail.gm=
ail.com.
