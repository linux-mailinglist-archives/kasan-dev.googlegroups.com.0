Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLP2QKQAMGQEQG5PHGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C11736A84FA
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 16:13:50 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id d6-20020a92d786000000b00316f1737173sf10266457iln.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 07:13:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677770029; cv=pass;
        d=google.com; s=arc-20160816;
        b=fjCE9VULNTShlNPt7b3z/JZsgC9UsWp6W1/hVBxYESpVCqMjOUgu2EgzSmPNZd9lFc
         uBYWHyl+zF6+blRAEWUrbEEIIA3GQHdvXhM59N8coiVx9EYpR7YFFeO1DFc0nKGNnzXH
         hn9qsx+Rg3cijK40rJWcIe53mJGy+wdzK41eImn0Ek5Zz+NuYbIk0GLGb4qPsiCTAbX0
         zwQO+h14vULp8rnSrtrDUzzxDsmL9Vkbc3W5WIj7uhlRH0KJvXGhmIGeH5jPBO8xWj0Q
         nCu4woXb/wrM4QWFVaaVJO1vtaRg6dgIozNpqD7imd5I6rmaRec9Kt7aG1cXEiVDq90m
         N5VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g6GRhNql2lbsU/GGKBhB0pPW3MVH5ZkAJxgi9s/Hbzo=;
        b=vbeBV6OMLpmw9N90DQ/A7MerUrSFNeF7F/c45AyX2M8jsC6BB4zdndFwTCiAYsY2wk
         +r/4F40RJGKlYdWgNsexGYHBms/hR9BlksPKZjGcFQKSZMoVt3/lP8WwhA8V8gzoe0nl
         xUiJz7dL8nXjrp5mp+YJtpfswyWj/ENVBoTkwoy2N5OtXT5c+aE1brrF+hS0Z0sP8b8V
         Tn7NK5b4Nc8v1dYhv8Snm0c8zXHr0OWwUCz7e3sb8I2ueVMzWmyWBByCBL+HnjjFbmSt
         ddzuqPESyDawAc+7S+rf2P3AoTQShWa7zpWFyahAnHiEMlmkxH71/u+MMsZzKHt2MvZX
         yE0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ikUsdVcN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g6GRhNql2lbsU/GGKBhB0pPW3MVH5ZkAJxgi9s/Hbzo=;
        b=No6OhQnldd8Ke8WPHd/zFh59V1xAV3RasrhlY1fofsUTXfKhijJkSj5tvRUpQUxvua
         I0Db26eOFjGcrBPKEYpwxn9C11TvtNq0m/yDlsAK9W2DlOzz7/fVX66TEbpmc/kmuP2I
         zBtpm8NOVmgEnT9c+GHyZxxG6Ak1YAmJI/Us9HZxB7GiakH1ohnMvusJRWhMImaj3s0H
         67Q2sH1f0g/Iu9UlaZDsX5deJayyc0WpsLWemHZM3SUP+VD0EtqYk8kL4cCtyjrrxNCb
         wJ4my63QJb+nmg+a7hwGVUFija9RDzC6GDwI9nGykaUwwUcuYnFk44px500Ow2sETS0B
         Iimw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g6GRhNql2lbsU/GGKBhB0pPW3MVH5ZkAJxgi9s/Hbzo=;
        b=hxREJTb/0IXmWbC22RhSfQX2Ja970fJXq4wP0pMwmOMESxdw+2i3MZlwlhZhm7YWm5
         i0+F7s/T5tUniJhhfj8aTu6f07+HadhsamM1B0jZ7MQAqGtIJ3bOBBRFcgKoyfIZOe3s
         IGG1tqFZacRpU1OzR4U7+0CRbkZlycRG3tLoP6/+oPaRpaDJaOd0AUxAvXgwvrCZp8pu
         pLfBcd0ToaHvvSlgxmEBLOyVJqoYsMZpZ8H4qoxrZVwNKC79nCruNKK8mupURwztzGO2
         95BlZHyUK6H2RGs1DM6+IeVquBI4gSDHkLOJi0mYUVchehL5gyQt7yjG1ECHHR5QSlGB
         paVw==
X-Gm-Message-State: AO0yUKU7v8Wj0hHf1rRrx/RztF5MYnBDRBxcMSOln1J2X2BoDqGu+v1A
	0W90ftTyY+MPd4i83jNZMJ8=
X-Google-Smtp-Source: AK7set8l8cUD0djGMQtNr/ZliijqUQQV4cHCYkJamB409cU9IabNgLDWRyLcxrpgbUGJ6Yd2YejaEg==
X-Received: by 2002:a02:b013:0:b0:3c8:c0dc:2d65 with SMTP id p19-20020a02b013000000b003c8c0dc2d65mr4866572jah.5.1677770029619;
        Thu, 02 Mar 2023 07:13:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b492:0:b0:74d:364:dfd7 with SMTP id d140-20020a6bb492000000b0074d0364dfd7ls2432172iof.10.-pod-prod-gmail;
 Thu, 02 Mar 2023 07:13:49 -0800 (PST)
X-Received: by 2002:a6b:3b0f:0:b0:74c:9907:e5b4 with SMTP id i15-20020a6b3b0f000000b0074c9907e5b4mr1783047ioa.6.1677770028990;
        Thu, 02 Mar 2023 07:13:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677770028; cv=none;
        d=google.com; s=arc-20160816;
        b=F9HdUBXmpkXQdqkE+EbahRre97FnI9Gubatt2GY+eFpoGHlYu3fShkFeWKtFWbu6Ab
         3gR1vXk4rh7aPIf02hXKHXQ0+IyZcNyHTNz8p/eBbPH6Fn0QdZSSMz1PNlYi3AMnZ42V
         gr9qpc3aeXI+qsCIemcH5U4UVtf5dSLPqe1NOX0oJSZitzYSTqnTRZhHSpdLY+/o1+dV
         49iXLeR7QapbDt9rMIFGNYR7LifTB1uKGzVkWhVj29Li1rKacGRAANO+KZ8NEUrXN7cm
         GJ7VCUsClZxzA33jZVpBlCrOmq3qc9xV4i8mujMU1N8JhdaQiF9Z2mA1cFRlGKjNZU65
         d6tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=H2cHLqdllPliHQfcCj7lym6e5ewTgURvCIfBNx7SCko=;
        b=iEaf6qTyTzkkzAo74NhR/+DJ4jg13j2KTQPCSpHi9H2q3gyyV4t746e9d1XAN0AR3x
         Bx/9WtUsz8yfPvvHP/gUa+rm2Z2OUXMu++sbYCwp8I2HH4aXj9gNYgieqdcLgryHV4Pl
         Hr7OomNwNqeBx+T6S9X4L86Emz0CTsDrCiM8tvLsA4QhQMGJYUHxFIn1go6F37wQPxkz
         CHJAv6oC1pA3tjeWhNBzmV718IrdIYUbFUL2to+VU8MiHybXxMikDd6+V1OnN9onyS2K
         IvXX3FyAZIlMr67hlZyYeY2NsZuH2XtJ6vv16xDwg8wzCdF/GHJdUxQtOaxw8xClygXG
         pi0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ikUsdVcN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92a.google.com (mail-ua1-x92a.google.com. [2607:f8b0:4864:20::92a])
        by gmr-mx.google.com with ESMTPS id s22-20020a056638219600b003e7efb1d848si1407495jaj.3.2023.03.02.07.13.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 07:13:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) client-ip=2607:f8b0:4864:20::92a;
Received: by mail-ua1-x92a.google.com with SMTP id v48so6394444uad.6
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 07:13:48 -0800 (PST)
X-Received: by 2002:ab0:5b59:0:b0:68b:9eed:1c7d with SMTP id
 v25-20020ab05b59000000b0068b9eed1c7dmr6233732uae.0.1677770028306; Thu, 02 Mar
 2023 07:13:48 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <CANpmjNMR5ExTdo+EiLs=_b0M=SpN_gKAZTbSZmyfWFpBh4kN-w@mail.gmail.com>
 <CAG_fn=U9H2bmUxkJA6vyD15j+=GJTkSgKuMRbd=CWVZsRwR7TQ@mail.gmail.com>
In-Reply-To: <CAG_fn=U9H2bmUxkJA6vyD15j+=GJTkSgKuMRbd=CWVZsRwR7TQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 16:13:12 +0100
Message-ID: <CANpmjNMtXudXbVy4cZDAUUVjHX+hQ0P+FY6La3bsp2zp4t-pZw@mail.gmail.com>
Subject: Re: [PATCH 1/4] x86: kmsan: Don't rename memintrinsics in
 uninstrumented files
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ikUsdVcN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as
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

On Thu, 2 Mar 2023 at 15:28, Alexander Potapenko <glider@google.com> wrote:
>
> On Thu, Mar 2, 2023 at 12:14=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > On Wed, 1 Mar 2023 at 15:39, Alexander Potapenko <glider@google.com> wr=
ote:
> > >
> > > KMSAN should be overriding calls to memset/memcpy/memmove and their
> >
> > You mean that the compiler will override calls?
> > All supported compilers that have fsanitize=3Dkernel-memory replace
> > memintrinsics with __msan_mem*() calls, right?
>
> Right. Changed to:
>
> KMSAN already replaces calls to to memset/memcpy/memmove and their
> __builtin_ versions with __msan_memset/__msan_memcpy/__msan_memmove in
> instrumented files, so there is no need to override them.

But it's not KMSAN - KMSAN is the combined end result of runtime and
compiler - in this case we need to be specific and point out it's the
compiler that's doing it. There is no code in the Linux kernel that
does this replacement.

>
> >
> > > __builtin_ versions in instrumented files, so there is no need to
> > > override them. In non-instrumented versions we are now required to
> > > leave memset() and friends intact, so we cannot replace them with
> > > __msan_XXX() functions.
> > >
> > > Cc: Kees Cook <keescook@chromium.org>
> > > Suggested-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> >
> > Other than that,
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMtXudXbVy4cZDAUUVjHX%2BhQ0P%2BFY6La3bsp2zp4t-pZw%40mail.gm=
ail.com.
