Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTMB2KVAMGQEG65H5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C27B17EBE8E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 09:26:54 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-58a3be29c95sf3430295eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 00:26:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700036813; cv=pass;
        d=google.com; s=arc-20160816;
        b=aOv3srQExNE/Xvrsn+9kuYD0iDLNidy0dbr7ropjyFEDIMDhtCSKiczFTPWeq3LsmJ
         I78aG5ScPk7iMhOW+LqacqC1eghYovJHc5jQbZS7STkgGrJkFKatMSsxwqXSUJGuUpkY
         ZrNtssE9dH82UtXNUnHdAOz75wC6EYHVDYgkJZPbkeNRdIJT6eFqi2NJYqstdjQ2eV/4
         GKBPZsc8ZTES0Xo3E+jno63nPXsEPoStO+wU+OzRUXYbOX9xYDolDeDG8IrmYQ0te9vK
         uTkbb2L46EOt7mJlXapnMRlnXiOy4S05OsegtXxlJuZhirfAu8pO2b2NMBPEjGsAAn/H
         HmtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bgPJOoJEbPyoAmsOhOwBGmq6U3rCm6+dpEUP4De7KFo=;
        fh=3zgOJ2tUfuDYDoy2bOrC8JZlqlKVsd7ahyADgzQhFCI=;
        b=L6eHtzUV+NxJVU9aE+b1Bono/X/Gti+Op/EWOq/vHCfBgKN0R56bgfRExt34fc1/uZ
         E26gjkIPKamTUvnqkFvKYTDjHfXsOR0ZTxeXlMZH4OSklf8xdGVA1CrfBpFDPy0SqHuf
         XKATwmD8p7LR+ns1f6vUe9NgsZIla/ywJXS8cbK4SOIGbCs/MmBNwwis3a6T/u+XhtZU
         Cn2f+/sM1K7Sxztv+/JuJlha+mNkj5gCb63yi2+s2tQmmq/fL6cFX6D1rrlMgX+IHH6C
         /zC5NCRKvGDmQn7xwYq2xvwvLFRe0USGH4DntnY0vWB8PSdmnwfHtpdbUCQ5igmN//bC
         EHRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=txxpUQST;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700036813; x=1700641613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bgPJOoJEbPyoAmsOhOwBGmq6U3rCm6+dpEUP4De7KFo=;
        b=oSRq60JDViB5ReYFJOftWAamV1uG6SmzmC0hXbcIDChKwWu+0wIv8DAUa3e1l/N5zZ
         8UvBjWqpAbXBrykUiASC0/pGAJ1tfMYqP+KEECHR8j6Y020LQOKAzSkbED36BdJu+oAn
         BNHhB79y95JdIh8uKCFQI5BQH8iVuK+rpHCuM/dnW29esxXzgzN0NnnRV35DM2a45jrI
         SSPzYB1Ywc/efWYzPhjfLN1QyTe4JtnVmgeIlgqdbun54up42L2AT0C91OBgyMTID9tU
         MrLdWd3EmkcXwcPpdKLLhbOOffdT+pTFEyVyw3Z67jANDMwVoG75pUk8whfDZ3WzrV7g
         5Dvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700036813; x=1700641613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bgPJOoJEbPyoAmsOhOwBGmq6U3rCm6+dpEUP4De7KFo=;
        b=BcrvF6tfjrRZmqhshHwgG9qT7ejmAoBFPn3jXyV0SpLYCk9mgimel6a0De8dX/D0Qi
         CXU6Cac5jTG00bPTGZjxVFqZ/MD4JmB92PlI9SSVUVQTA7LBqc7iSqx8mPra4q729s2i
         aKCH9Ggjj57z5AvIz6b9OnAQvMnNtsQAGjQsC1NhDS11Fk2gMbsVx8uV9AY7mSsuyWqi
         pD2IShArllgECsbPJzfCiGeLAOHBabbz2TnfBsjgeuygiCEQT1Idcz+1wGdnWhurEYfd
         BcFtvJ6aP+PnfY07WZdchRihwsTDckwQvbnGaCHOF0h8MoKXqQu4QqSYE9SNZ1uPgeuY
         Pugg==
X-Gm-Message-State: AOJu0YzGzq41qTuyhJ5Gk5sMRybU1v0pici71Yy1CQGY7dR9qAy3ElF4
	0DcCaYTw4xC9AzRbwepImzY=
X-Google-Smtp-Source: AGHT+IHr+0ZD6XIAhOgY/UlybTXkE/hM0a1yBJByZ0FHR4iiDKZcf3mmCLrezKGAPTRQpBPdfOyx1A==
X-Received: by 2002:a4a:3412:0:b0:581:ec87:edc0 with SMTP id b18-20020a4a3412000000b00581ec87edc0mr11973624ooa.9.1700036813510;
        Wed, 15 Nov 2023 00:26:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:584a:0:b0:576:64f2:fd89 with SMTP id f71-20020a4a584a000000b0057664f2fd89ls4373365oob.1.-pod-prod-09-us;
 Wed, 15 Nov 2023 00:26:52 -0800 (PST)
X-Received: by 2002:a05:6830:90b:b0:6b9:b1b0:fcd1 with SMTP id v11-20020a056830090b00b006b9b1b0fcd1mr6128992ott.31.1700036812119;
        Wed, 15 Nov 2023 00:26:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700036812; cv=none;
        d=google.com; s=arc-20160816;
        b=tbf2yg3iTIlq4I5/vhjnIqmAAqpYPH7GKo5PTkQEmexIDKpL9tzmJlalGPXjytpbPf
         P7vS2djQH/35Zr+LgxUAC0KDhr2+iZIz8Q51GRl90IZcjylJvekVrkKwNCbElptsfYmh
         3TvyBUYKp6VtA4pn4TUME4nMDjP/hrWzxKiH/nZjxi4WppHmPKDq0ElCbc6LlUA630o8
         EHDnzertKB2hXr43MFATh3YvZkHAtTCX9HfGDF2SHDchBQH3jxxfHx5AA/fR9tcdcaa4
         PXYCNkU5lJ6CAJf+Z3fr6efgVBcfaknhcXsd2X6g4bpjWvxtAgZaqB2s7e7CM8vxiYnu
         UytQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9jKwR1gpSfQdTlAXjlEEGIRRbRHY5oxkajkqLsICLD8=;
        fh=3zgOJ2tUfuDYDoy2bOrC8JZlqlKVsd7ahyADgzQhFCI=;
        b=y9vOJ/EZzklqRn2mduwefs4CzKI8GUade+VBYgmP4Ld9NLbQs2ipyY/sBfIk0v/op3
         B5ksPa/E6lvpN3B9QyIDhoU0jrNs70pGCwqTJS5v2LNgQoE9j0901epTlsUZBUoZgfZ0
         6g/q19DYQJ+Vqk3cYs+Iku44dbI815miLDGpQcYudZJlUxW7WxdgMPfzIvtT1WvsTV9c
         r5FMTgdz0MuxhB9qYV25Q3w6jO+MfbvkP5XAxPuyPRL1VpaZxKbNNUufX9LKVFqpSZW0
         uUHFmM39mXs5WS3LtpUxgL9a9pc4JVT/wbCzYjQ1+CViQBAtZodwENj2fFgikQhAMeSm
         o5Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=txxpUQST;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe36.google.com (mail-vs1-xe36.google.com. [2607:f8b0:4864:20::e36])
        by gmr-mx.google.com with ESMTPS id d5-20020a0568301b6500b006c6510a80d7si540648ote.1.2023.11.15.00.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Nov 2023 00:26:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) client-ip=2607:f8b0:4864:20::e36;
Received: by mail-vs1-xe36.google.com with SMTP id ada2fe7eead31-45fa1536e16so2463260137.0
        for <kasan-dev@googlegroups.com>; Wed, 15 Nov 2023 00:26:52 -0800 (PST)
X-Received: by 2002:a67:ab0d:0:b0:45d:920b:f111 with SMTP id
 u13-20020a67ab0d000000b0045d920bf111mr12202204vse.5.1700036811448; Wed, 15
 Nov 2023 00:26:51 -0800 (PST)
MIME-Version: 1.0
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
 <CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
 <CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
 <20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org> <918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
In-Reply-To: <918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Nov 2023 09:26:15 +0100
Message-ID: <CANpmjNP+UsZS_vcuWaCPSqHpg54ZJZXe6k1p4zC+Bkd9vnoc4w@mail.gmail.com>
Subject: Re: [PATCH] kasan: default to inline instrumentation
To: Joe Perches <joe@perches.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	=?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=txxpUQST;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 15 Nov 2023 at 06:38, Joe Perches <joe@perches.com> wrote:
>
> On Tue, 2023-11-14 at 15:11 -0800, Andrew Morton wrote:
> > On Tue, 14 Nov 2023 12:00:49 +0100 Marco Elver <elver@google.com> wrote:
> >
> > > +Cc Andrew (get_maintainers.pl doesn't add Andrew automatically for
> > > KASAN sources in lib/)
> >
> > Did I do this right?

If the signal to noise ratio is acceptable, something like that could
be helpful. New contributors like Paul in this case may have an easier
time, if none of the reviewers spot the missing Cc.

However, folks familiar with subsystems that also have bits in lib/
(or elsewhere) know to Cc you. It worked in this case.

Thanks,
-- Marco

> > From: Andrew Morton <akpm@linux-foundation.org>
> > Subject: MAINTAINERS: add Andrew Morton for lib/*
> > Date: Tue Nov 14 03:02:04 PM PST 2023
> >
> > Add myself as the fallthough maintainer for material under lib/
> >
> > Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >
> >  MAINTAINERS |    7 +++++++
> >  1 file changed, 7 insertions(+)
> >
> > --- a/MAINTAINERS~a
> > +++ a/MAINTAINERS
> > @@ -12209,6 +12209,13 @@ F:   include/linux/nd.h
> >  F:   include/uapi/linux/ndctl.h
> >  F:   tools/testing/nvdimm/
> >
> > +LIBRARY CODE
> > +M:   Andrew Morton <akpm@linux-foundation.org>
> > +L:   linux-kernel@vger.kernel.org
> > +S:   Supported
>
> Dunno.
>
> There are a lot of already specifically maintained or
> supported files in lib/
>
> Maybe be a reviewer?
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BUsZS_vcuWaCPSqHpg54ZJZXe6k1p4zC%2BBkd9vnoc4w%40mail.gmail.com.
