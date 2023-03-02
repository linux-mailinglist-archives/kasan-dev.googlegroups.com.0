Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCHFQKQAMGQERS5DRJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id BE4CF6A8421
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 15:28:26 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id m18-20020a17090a7f9200b002375a3cbc9bsf6180939pjl.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 06:28:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677767305; cv=pass;
        d=google.com; s=arc-20160816;
        b=mMDuW/HW1Z2hp8/SqCwBFuNhdwj0sJO28l7evJko64U3WMIj7b0lvZzr9jIS5OBewk
         Dn4MRGjT1YBV8dhYk3LZXOYYXNFTl1tlygG9A0K7eG7nZjn7MXS0DyKQd+4S24ydNrAO
         oSNNz71z0c5TyuftSo78Ng76yI5WozQA4u//bfWJUpmEMg17SkFEv98NYv0ph13btEn7
         W9AQe98pM3yIRVsR/ywvH9lqYnV/alQfrjrLfNaRRnm1Uv1GSQiTWoKaCGnC1H2jWTlK
         kGrFzsZ/VOKAXn9lJYvwHuxFTvE75ytowtYieEw666KXbKzzgthASOQlUnpap6JOU/05
         9IOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jtiHmZCt5ptUbXkCsak/2T69nti9DQf0oeDlDFM9iaQ=;
        b=ARD6vuk+JdDYrgyIe276j0WTrec2fRtnrdH/rw3oII4cc+4i6fBtwu9LOfxrx90D/4
         7R9pJecI9tjs6x+FjMoJD0iGIzYCvDdEAdkw+Su6tmWCN8RK4aZLTr2cJDhcCYmt1Oh8
         uE6vH1/x94meeO0LupkMdiG2t3mJegrxC55NXtyW+VJEGr45l+pPCeyHcm2MOSXG6xX8
         eNhiZeCInwlcL96+rBpCwXm3U7VMJ4fA2FQ3135u1UZpVO3MD/K1cr/VIpMP/2ofwPhL
         ExWNvpsUwkb+wTLJUFwkZcGicGM0BvkuhvId96yUUJf/m47Lzi+Nfb14MBRBeYiasqXj
         Q1cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jOnksMU1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jtiHmZCt5ptUbXkCsak/2T69nti9DQf0oeDlDFM9iaQ=;
        b=Gzr9SNUX+0CXyO0ni3xC33UTVoqkGBlKFOSzXVdJ0uU6u3mbeWMldSAcbyaJqK9HMY
         gwg/e5McpMmAMBY0BVPYmwzyDHFOioR06+pH/FoSSQh4pNgNXdtrwWxcEHB4DAIbgdLJ
         IgmHfmIRRkhQVHsZg3wOKaa7vhKTjIl/IkD2JW83L6f7l3llD9gIG6v0NUq7PcbZqyIL
         2sebx3a5nASJjd5r4LqnHPsR2AMpnKeLXQWC5VyX9xA4OzllvavM1h2/BeGScI9lzYDl
         FJqwcL+mpP9z9TGOg/3BV+bTuDGFM/Oq63HCwGXKgg/644991vj3NVzmErxdhkF6zZYZ
         AOYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jtiHmZCt5ptUbXkCsak/2T69nti9DQf0oeDlDFM9iaQ=;
        b=YJX8X/0bHPj1qSPH6orgholG9erSSbXCD5oHBJOItkwHlDgvmnDK5kGuQEtOf7U2tb
         w7GU868YGC4PyIorAAYEEsk2JPWENUEVjF4Mty6tpmwY4EnkI3V3Ga6pWg5NA9iNAQ7g
         jtTKrPlzIGnbFDdVGgEMKI7NpWKV9PQtgvYoofn9xIWjnodrFAcCICrYdYTCe/3byKG2
         AxS436KZypJM/+ZSK7OKlVciU6kU6HrUm+0m4qYC4ERo3f3+F1bkixeX8cbVmLoRBcVU
         F5mw182ZPgr9SYe+wyQ6FhcjPVUcwn31XS8lEIv6aOZc0+A15FIDCzJg7vvILaTzzRQ1
         7kzw==
X-Gm-Message-State: AO0yUKWsMQqxy5+12mtq5PLP1PDLJdQEPIML03f0rx3rde/WC5GfopO3
	HUGYsQyGxiKkmayyohgwQA4=
X-Google-Smtp-Source: AK7set9JEC6lTepHmhjrH2oloVBSa2nIPzZEDMI3tmDbIkiz2/hldQiBQzJXeNzicM370yfSPvML9g==
X-Received: by 2002:a17:90a:4b82:b0:230:8d09:962b with SMTP id i2-20020a17090a4b8200b002308d09962bmr4092611pjh.7.1677767304938;
        Thu, 02 Mar 2023 06:28:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b390:b0:237:18be:2595 with SMTP id
 e16-20020a17090ab39000b0023718be2595ls3303238pjr.3.-pod-control-gmail; Thu,
 02 Mar 2023 06:28:24 -0800 (PST)
X-Received: by 2002:a17:90b:38c7:b0:237:4a3b:cfff with SMTP id nn7-20020a17090b38c700b002374a3bcfffmr11580007pjb.20.1677767304210;
        Thu, 02 Mar 2023 06:28:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677767304; cv=none;
        d=google.com; s=arc-20160816;
        b=H/GE4Hb7If2+lUlO62MMDH+UQ6r7/Ruqxq5Gwjx2pNBD2osg69Dv9i0P8PQA+UfYs3
         gGlDSEzF00rjo47rzN1XayFFpd3OQhmjFHUFoPHV8JcC2v5MPB9qsJM1+1Mtbm7UdFVa
         KY7C+J+aJdVVtSoZkNOAo9F4yMwkQAomDj/3jlZcp72NrOEBH3O2hffLf1tf9EooAJXh
         lLbNBydNM6O3dbfPztmLBt2W6LVO/5h1yLj68tkYB6UPDXRZHbW4U4cmI0zHxZuoWV6+
         HvvxK5i5cFGSqhXoH4lB0a4FOGiZjj70uNsrjvvKLDG+ZzOXdsf94ITJffCK1sqDo24e
         D75A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7xMPcWX9J82fx546/2/UxZ96PyLg7wpVPFiDqKOfZ5I=;
        b=dxpJOSAk98nJwhP5ArDN7mKUHm/2mZSfkW4deM4g0l+Ds4h2NfJX1hygY+x93Mwlku
         ndYt7Z1jkSi7fmPQoR595kTdQmlfYYV6cpMOuvnBd4NnrFE17o8LazaQrmyilareVXqp
         xJnvTQZGUC8hZW0jsit5L/cPZ6eKxOrnSMR1IEg2Bg340vAabKZRzt3JnHS9OiaV1bze
         Bph+JZhh5R6UpglaOogPO7AP781cWnXrQH3KgzZ/vb/g7QIBow5eNAWw8h3WojhGLUaT
         TNFry4ldOLue3+xVlS4l3uXWf74o6/k9asYkD3trGFH6keFMXGN9G0msWErV+Uz+If9m
         MWCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jOnksMU1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id dw18-20020a17090b095200b002373b032314si276459pjb.0.2023.03.02.06.28.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 06:28:24 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id f14so6801672iow.5
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 06:28:24 -0800 (PST)
X-Received: by 2002:a6b:7c09:0:b0:745:6788:149f with SMTP id
 m9-20020a6b7c09000000b007456788149fmr4528404iok.0.1677767303478; Thu, 02 Mar
 2023 06:28:23 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <CANpmjNMR5ExTdo+EiLs=_b0M=SpN_gKAZTbSZmyfWFpBh4kN-w@mail.gmail.com>
In-Reply-To: <CANpmjNMR5ExTdo+EiLs=_b0M=SpN_gKAZTbSZmyfWFpBh4kN-w@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 15:27:47 +0100
Message-ID: <CAG_fn=U9H2bmUxkJA6vyD15j+=GJTkSgKuMRbd=CWVZsRwR7TQ@mail.gmail.com>
Subject: Re: [PATCH 1/4] x86: kmsan: Don't rename memintrinsics in
 uninstrumented files
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jOnksMU1;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Mar 2, 2023 at 12:14=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 1 Mar 2023 at 15:39, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > KMSAN should be overriding calls to memset/memcpy/memmove and their
>
> You mean that the compiler will override calls?
> All supported compilers that have fsanitize=3Dkernel-memory replace
> memintrinsics with __msan_mem*() calls, right?

Right. Changed to:

KMSAN already replaces calls to to memset/memcpy/memmove and their
__builtin_ versions with __msan_memset/__msan_memcpy/__msan_memmove in
instrumented files, so there is no need to override them.


>
> > __builtin_ versions in instrumented files, so there is no need to
> > override them. In non-instrumented versions we are now required to
> > leave memset() and friends intact, so we cannot replace them with
> > __msan_XXX() functions.
> >
> > Cc: Kees Cook <keescook@chromium.org>
> > Suggested-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Other than that,
>
> Reviewed-by: Marco Elver <elver@google.com>
Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU9H2bmUxkJA6vyD15j%2B%3DGJTkSgKuMRbd%3DCWVZsRwR7TQ%40mai=
l.gmail.com.
