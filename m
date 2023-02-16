Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ5WXGPQMGQEZGFSYYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 51529699A30
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 17:35:16 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id o42-20020a05600c512a00b003dc5341afbasf1380392wms.7
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 08:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676565316; cv=pass;
        d=google.com; s=arc-20160816;
        b=x3rFkjA3fz4NTwxqs4Wb6hSKZGN9mxTXCvt+M2WPIXr9M3yDmGhmNCXPQHfaNQh5oQ
         w5w9YtdElkhBSgWN5A4QDJ5g7R5P0ub75lR4qkNr3drvx0xUp0iFgGNZD/Gqzkhdz7VK
         sm7UtWjoKeR6tI+FS7JyPEBdYb6S1pQSgZ+o+lIRjFdDaXx3VGvvO21idchvFVD8qZve
         M7urBe0qD2Pif1sehSMxercIjXjGcLWXrUNfupc2wh3fE7C8hcRBciekMhgJRMKenCKR
         S0QtxoI5IYBITCvPfizztVUrmXIb3hjkjkatPpeF3sQpmrUHnMeCsr1+EjFa1X1q5VtH
         VU1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4x0i2DAOSebsbyjNTWMq1/KkqkFM9OSNiXGAGiWUuPk=;
        b=ihtN37xs+i8e9cqZzw5ovLGpnkS7MBTTE4gqYYs+KCzr5+0PDgaB+hTMS2XONHiQMb
         6CQ0bI0acUpVAtfgQkwkDCgL6RO97wPOQjog6RHZQ7LLNJI2lSYpz2HyOchtZd002doD
         0b5zKA7pO43T0nP0YMdMHCC8wxzKbvjr6RFSL56G6vIIU7OVXF0xiS1GsBQQrnmsZJhN
         tI058SIVxXMpv/Lc76Hru8KTWVWmbGY846ABEOfuIjUiGn4BKaD7bC2uDno+dnOk7oV6
         1dyldDBVf3yVFTm+WcfmSeFR6ewHK/obztAMb8GsHBID+GSAvV+YDQsV9jBl4ZG14Z+0
         7n/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZoTA6ZJX;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4x0i2DAOSebsbyjNTWMq1/KkqkFM9OSNiXGAGiWUuPk=;
        b=QqcHAKYTieCqRIBRu78lMXCBQdij1OV7JY/mBq8GgsDM6AaUlEfFdl1CYhazWp6YTS
         mN+pE6eTefXy5foY/0PzKNght/R/uWSEAU4OiOO6R6s4IzeIArjrM+ZlQG/e7sDVaJyS
         taLfgHxKgSxCtegBztllqJKVKNIB8l9rw21n0N++3fZTTZmnFirlF+lqNw39fLZUSPMs
         8QIqTLIH7GR2Bi1HRUyCcByQCNQ7nwBRVCPTo4RTX1XiWJ4VT3hU/VPXW+VfelS4DC8c
         lJxf3GiDwTQq/RuPGkHq0iARcxcU9oZtSbC1htZh5C8vq04Rh76qADNun5PTQ1/y+sPI
         ho8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4x0i2DAOSebsbyjNTWMq1/KkqkFM9OSNiXGAGiWUuPk=;
        b=v+m1w13x3fbFlLHwM3wdHV4qTDz+Ddhx0YNOFi3SIZc7P2SF0F4akU3AmRlGrI2pq/
         eFU15H2HMgid5cGl4K4eBFUzhugqoulAWTxp1E99Z9/bafe8Fyppnu5PsQr4VvhC5Y3k
         C5eQsAmEAyAFMqnopx+d3rEBAHvk1f2U88JYFb0MrD9BX7PWzrrP2j0MeK1BIC5BQzI0
         PggmTLKuoNl496f1wCCUEQddJcLY7iCUCKjFPzEw91NV1bMliW6VpgnMj8M3MN8mIL9L
         elT3A/ik6gO1HimVZGJ9krjXkFDp8NyyJaNrembPxCOqLJN7a7bXCxejQK/dDKwF6HxZ
         LziA==
X-Gm-Message-State: AO0yUKWbIb9hx/Vau3FgCVDGil5uYPqnQUydWaBfoBtO1aiA06ZtRYnX
	XhaQvdCOGqN7Ig9+ccH5MZI=
X-Google-Smtp-Source: AK7set98oXHgJ1ao7P9ucGRXGPA5KBayAXmuavF17I4N301GctXZkPWJPgjauzWSsX+FHMThWUei4g==
X-Received: by 2002:a05:600c:c83:b0:3d1:fe1b:df82 with SMTP id fj3-20020a05600c0c8300b003d1fe1bdf82mr234487wmb.79.1676565315763;
        Thu, 16 Feb 2023 08:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3084:b0:3e2:1c34:a7c8 with SMTP id
 g4-20020a05600c308400b003e21c34a7c8ls386130wmn.1.-pod-canary-gmail; Thu, 16
 Feb 2023 08:35:14 -0800 (PST)
X-Received: by 2002:a05:600c:80a:b0:3db:2e06:4091 with SMTP id k10-20020a05600c080a00b003db2e064091mr6244516wmp.37.1676565314483;
        Thu, 16 Feb 2023 08:35:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676565314; cv=none;
        d=google.com; s=arc-20160816;
        b=U3y455Q5IIB4dOkqbZzYQG/8TV7ZxJDxG1KsfdBnOxKYCybqNPgJ/f//vmy+v5STRW
         /jDcjMjrMs6Z/M6hKwPH4sDaP3bmMkGm/iw1XwlFHgwnea4pdlrmQVdQ6mM6sjfgFL88
         8hvgDUhuGRD8/hWLMoVOrW49KdfmJD1i4VoIV6LOvpj5cTTRjODGZbug0cAgHU7t+rya
         ymIPjYDI3s17IOKlytyd6L56CQHwAznQg6fZ1gUYnUe0+t4Iz1z+OH4k+SMSJC23EvwW
         kT5SCljZ+qG21F1DeTkyO13vDQUprFNuJRoPWbm4C1rA7+98EGMyl+VBGg0gwXk4apaM
         tBpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YvjzzplOyYWEsKigVOczYa0vP8bscsvw+TTYRzm8kTA=;
        b=xymnyP3+9jLQ5bI4YNkbHrWjh69IrU9CBIHoFng5MerkMfEnzr/d6M8sIDoC3a2CLp
         Z3ExHQR2uElDgN16kpOlqw3w3EbpIsKIR7izuDIOrVyjcRgaYaXRuHsah7SCvD1o8eDs
         P1i0yIhNRdkarqoAHza3js2rmcEeq6InIkCvR9nS2HNw1pTLsspay8aYT4OdWgUG208C
         LR3Tb1n8o6lc4mxDUJqpBv+Fdia4JcMf5UwW6BmjbBRd7vSpUWCr+hfGu6JF8htRnb1w
         cEqJ9rlhu6EpkSwiVhgencZKh3AzWDKEi/s0XpTOEcldekHGEzhIwkrp6YNjhGhaY8U2
         uMig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZoTA6ZJX;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id p25-20020a05600c1d9900b003e2066b4ce7si93959wms.0.2023.02.16.08.35.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 08:35:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id z13so2007691wmp.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 08:35:14 -0800 (PST)
X-Received: by 2002:a05:600c:46d0:b0:3dd:67c6:8c58 with SMTP id
 q16-20020a05600c46d000b003dd67c68c58mr353816wmo.51.1676565313986; Thu, 16 Feb
 2023 08:35:13 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
In-Reply-To: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Feb 2023 17:34:33 +0100
Message-ID: <CAG_fn=V3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf+fRw@mail.gmail.com>
Subject: Re: next: x86_64: kunit test crashed and kernel panic
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev, Marco Elver <elver@google.com>, 
	Anders Roxell <anders.roxell@linaro.org>, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZoTA6ZJX;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as
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

On Thu, Feb 16, 2023 at 1:13 PM Naresh Kamboju
<naresh.kamboju@linaro.org> wrote:
>
> Following kernel panic noticed while running KUNIT testing on qemu-x86_64
> with KASAN enabled kernel.
>
> CONFIG_KASAN=y
> CONFIG_KUNIT=y
> CONFIG_KUNIT_ALL_TESTS=y
>

This is reproducible for me locally, taking a look...


> <4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
> <4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10

Most certainly kmalloc_memmove_negative_size() is related.
Looks like we fail to intercept the call to memmove() in this test,
passing -2 to the actual __memmove().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf%2BfRw%40mail.gmail.com.
