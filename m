Return-Path: <kasan-dev+bncBDW2JDUY5AORB34USKUAMGQEK5RUENQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA80C7A23D9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 18:46:40 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3aa142796a5sf4013988b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 09:46:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694796399; cv=pass;
        d=google.com; s=arc-20160816;
        b=ABrAQmxD7imwZN6ag9+KXIWK57PJE7qAp4yMxifsprJn+I0Eq/uOs+zZX4ix4YwBsn
         6VdxYMHSUN1dgj0Jsd5GR5tsxk8CUOgxWXFLt8rReUGtSOOlb1O3d5HCaNowvcPuUaHD
         Hf3DmMXR9V1Gnf9NCOjgibXKr6prR/HyCVSKCKy7gUacXtaRv0LqKJ2vRflnZ6iCgayT
         7PFl7EH82ZEuzS+7OGnA/pyQYexzMxg3RwhLPjyw/8IIdr93JM5ANO1e7he85cShCzmp
         pdnwJFI3nGDjg5MLv/irQOCeQtFZJGctSvc2516jUQ7artS/prv5JXJdSQas+q0wjWpu
         ef3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=1EdWmaD+IWmtkwikzS9Yh2UiPAanto8onU049SNTeaQ=;
        fh=eLBvtPgIPGXrKWkSllAgQrmoJJNmy3KaT4bQ94uM2hU=;
        b=q5IXiHMOtRmjEytZXHj8spJIiNo6jGOgrdoDJli8Q9rALJOllG+iALlunNL/f2IxYR
         II/abE3mULuYZb98mRH69LJcmUsR4aipS5KDVgCdR9CBVYFGvyVlmJglCL6a1KsBtqPj
         H2xvNehIUUcWb1S5ZaBi/lFDdhCEx4coWjFqBL649nT8ExET1y/vNbn5DjkI++/j/zOw
         QmLdiI+bvA94PBVTZD0AxOyAUBz/gNFwJpFWQCe/y4rijONHWx2Vaqp8IVapfXuTDQi0
         Kp+s1QeD8oJcpAAWksq4/ihubVaVusc6KCXDhDq6rHrnqmzdqRNeXAZtjXCGxY2bkMFP
         oSrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lr+sF+3p;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694796399; x=1695401199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1EdWmaD+IWmtkwikzS9Yh2UiPAanto8onU049SNTeaQ=;
        b=WdfFSzN9cXIKZxbouBdv1uIvW01ibH1thE1I49Tudh3Ak8PtFX+lF8DwwePa8Amqdy
         ov223Ze21w3cXjP6yy6TGYp7pQ5AiNoK9vZYqBKTAcbQierES4LjrNznqR+5/34Dc7cd
         utyTlUPdzmSrq2MO2fzzndnAVSdcIq1D/uIqgJoRn0zdbdx4Xq4v8inA3r9C3XpHFLj2
         pvR9PqBV/aXTXek7+TtMFDIH6UdEQ/nICtN7XgZGz9X1JunRMPObSzS99hxADalswPEW
         SqenWJ2KKAzjTKxZusnbItMY6DBAUcjpFR0ptMJiLqq2MvaKfxkkonX8PJiBAL2GE3hB
         60Cg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694796399; x=1695401199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1EdWmaD+IWmtkwikzS9Yh2UiPAanto8onU049SNTeaQ=;
        b=D1RnxAVukic0uBGlrJWK4CvQJko2xVd8OqJUgTubNXkiX5zV3clZy8DpSWcv4B/qlL
         r9q770gjqAncO4Vc6mog4zUs1UoezpzneYXOTznHPu8b9JjmfyvcKSyyc3XpMRlQ/mhQ
         FhLAqK5lick4AmzY7QMQjY472rbSi6ULsq+7DNeUuS7psxf4qNq6Hsmnqvs1gB5C0Qe1
         U1HRh3juazx1UShpNa1WVAmSoFn7X6ZR4s8lVjgD2+FdKrZuYxcCGtY3WCSJ1de2S1YI
         rByj/TLLOpwB4UW5L8fNwA8SslU1YmFa1rEcwzyAr/0J/2e/W8cbvfo+Nl5Bs3Mk/CFH
         d8gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694796399; x=1695401199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1EdWmaD+IWmtkwikzS9Yh2UiPAanto8onU049SNTeaQ=;
        b=N2fz0xlqc4JZw+87mvG8hewACkIbHFQ0HigUW59TCBQRzmZYWi6Jq6PywCQ/mLFZ2m
         a3a5ssz2gcv2HoN3CTj/2Q36CY8c3Xpmh9NyS9vOy4RBaHDtJp+GGvLsJGXyhHWBWABf
         wx+yyIUAg9ZjbNFp8m+rUex5uCRm2xtXdvHPVz6YqeT8RiDeaGJLQ4VgLanpMtCDdGaM
         mYQXFxaH1Mq553Up3K4m0EnI2pbwXQ8s0f6r1riMO/UIzEaI9kzSiOpvK8yyvfDjZXgp
         rjL20XukKg+K8HdRTN2kuZZtccFR+ckQPpRU3geH7A4o/+40Tp63w+BnfxhAFBEsLLiY
         qFSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz3dJWyTplRftoL58I8vzl/AdnxgW536E9aFRhZket3ywysZ56K
	3heaFYPirThJmvulFS+7hfY=
X-Google-Smtp-Source: AGHT+IFTDqwZsMDYgYOYznZnEjDAw6y0929Ij1h1vOlqmG8NUXJYcBq0ChmH2TCNwJAB4AvdKLqUlg==
X-Received: by 2002:aca:1c08:0:b0:39c:93ba:cb92 with SMTP id c8-20020aca1c08000000b0039c93bacb92mr2441768oic.8.1694796399460;
        Fri, 15 Sep 2023 09:46:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:758d:0:b0:410:8d47:1ebf with SMTP id s13-20020ac8758d000000b004108d471ebfls1378738qtq.1.-pod-prod-04-us;
 Fri, 15 Sep 2023 09:46:38 -0700 (PDT)
X-Received: by 2002:a1f:c683:0:b0:495:cac2:2532 with SMTP id w125-20020a1fc683000000b00495cac22532mr2440225vkf.8.1694796398772;
        Fri, 15 Sep 2023 09:46:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694796398; cv=none;
        d=google.com; s=arc-20160816;
        b=0piEV9NWF7mv74qPYNEcXZMWiQXFX4mbbd+nw/wNnY2qacXsr/voUqLswUqjsgwn6o
         zDXakrizNZb4upyXIzLLlFAS40JF8VXqvpN/Nzd7NCMcBYJPV28efhzNL5dI0FKMiyrd
         qsZpgw+GN7lwkCBNKg6DS6fpTjpF1eLUmP928zZgAnbZW89RZQwrHAcwQqh6E+k974gW
         bQikv/mb3PIVM5f8kL2OVNKNd2LfhnINyvj0YAbWKNkXw5U4+ZzFr2Bccn5kyGXZXIu5
         6azXAvs0VNbQHeGVErZUx3MuVLzkiGX7kINTzFMcE3d/wvb4q3O7IQEGa18KrD3PfGpK
         w63g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YSRPmYTgQYAS8/W7DnTR2CfDhO5J0xkkJUsesS4GK9E=;
        fh=eLBvtPgIPGXrKWkSllAgQrmoJJNmy3KaT4bQ94uM2hU=;
        b=gv6KoLfYywxdL1U32pU9o60mfg0MabjgDDwBQBfCIjiSPOuA0KjypHQGQhtkNFQ0XO
         lcgMIt6xbvbqNITHHgSH2f1K8CaA2hnf4m5+hBYtXfoc12q+oZ05NLFWJLrG8RYIs5UA
         fsYQFNUiuR8SErjurUmFXrSe1Yxm2MAwDfrcrlOwqSE4ZSlePNQDfQO8Ak6DHFHYt/HJ
         DdOaVd6UQ1BaN9HDC/utOH9/KzVESAYg1vv6Fp+WUh6yxATsDpxxHBEqUJh6DMypqJgf
         LVfbDPe3aZLGExSaJPBnZF57RJzpBNUmMT25qJCP+UFZ3wkAAL3lmy7XuTPmASbBr+4w
         My6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lr+sF+3p;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 139-20020a1f1791000000b0048d29aa0861si864779vkx.1.2023.09.15.09.46.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 09:46:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-273ca7ab3f5so2046775a91.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 09:46:38 -0700 (PDT)
X-Received: by 2002:a17:90a:300e:b0:274:922d:4b35 with SMTP id
 g14-20020a17090a300e00b00274922d4b35mr2051394pjb.1.1694796397759; Fri, 15 Sep
 2023 09:46:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <658f5f34d4f94721844ad8ba41452d54b4f8ace5.1694625260.git.andreyknvl@google.com>
 <CANpmjNP8O-GLQ9m06riX+kjbPSD9sBo+XGtTE2xW=pq9uJFGAg@mail.gmail.com>
In-Reply-To: <CANpmjNP8O-GLQ9m06riX+kjbPSD9sBo+XGtTE2xW=pq9uJFGAg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Sep 2023 18:46:26 +0200
Message-ID: <CA+fCnZdS1LobT9Wg3zxtq1Lec9hbgM8gRSmy=A=UyQzAr-BCtQ@mail.gmail.com>
Subject: Re: [PATCH v2 05/19] lib/stackdepot: use fixed-sized slots for stack records
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lr+sF+3p;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
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

On Fri, Sep 15, 2023 at 10:56=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
> > --- a/lib/Kconfig
> > +++ b/lib/Kconfig
> > @@ -708,13 +708,19 @@ config ARCH_STACKWALK
> >         bool
> >
> >  config STACKDEPOT
> > -       bool
> > +       bool "Stack depot: stack trace storage that avoids duplication"
> >         select STACKTRACE
> >
> >  config STACKDEPOT_ALWAYS_INIT
> > -       bool
> > +       bool "Always initialize stack depot during early boot"
> >         select STACKDEPOT
>
> This makes both STACKDEPOT and STACKDEPOT_ALWAYS_INIT configurable by
> users: https://www.kernel.org/doc/html/next/kbuild/kconfig-language.html#=
menu-attributes
>
> Usually the way to add documentation for non-user-configurable options
> is to add text in the "help" section of the config.
>
> I think the change here is not what was intended.

Ah, didn't know about that. Will fix in v3. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdS1LobT9Wg3zxtq1Lec9hbgM8gRSmy%3DA%3DUyQzAr-BCtQ%40mail.=
gmail.com.
