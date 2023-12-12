Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XJ4KVQMGQENXNHEBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EE79C80F6B1
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 20:30:59 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-67ec47a7cccsf2932446d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 11:30:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702409459; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZlXKlritS1feS6QqLt5SRv1vunudYv1jaytAF/Sji8mCKEl8AQqpI0WxqgBrkjn1E
         pc87y/OU/CuZ0dNh2ENtg4EOXtS9h880lNW66dKVdHG1Xbk7NYkAmtbY7jshGkZxYq8Q
         nAqtwPMvphAHpLJk+a02NHv0Kh0uwqV3h7seXIxjckc2hT67fziCwdOGTh2VTnPzd3FB
         LXYLbQHgM+v+aRKp0zUA+Zt9bKkTSHcDG7BJKNq8qTGnhyX9h7btCozhc/47UU+t8laC
         5Q6gzrQ4DBx7+5YnyHv0bIplYIMzncwbtYE1oax39bUUnrGw4AORr6VJRxeyOf9/6J1l
         3QyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NwfQN1ZelwNRLWJyhBqMWJVmNGPkEGLNSgk1TzD4llw=;
        fh=U+LkbmzWWCZxhGJEzEnoma1O4OhNrWGKYws0tLC4nok=;
        b=rh4fe3NHkTJtN3OulzcvSNF1sSlrS+miDN9WZM8IGV6SAuinHCA+k0ojRasJkkqRct
         4ZgK+wYARXMJbfp8BYZ+AvXRBVeMBYdh4aCcvM28EmVEoCAPafpLcENw/ZkUDpsGDfiY
         BVxD3I1l6V0p6vMy8DmPYo8E6PoSio0ZVVvFhBi5Qr5/x+kVBKAHOE+WRhBp8Xxmdc63
         7L3ENjsH7iFayEhiM/ac5+rVSafrGOnGCTlbmmWJsLl4MhizWW931iMPpdKJMU8+9rTX
         0odii82l3RiNSGOwFy0f8S/9wwRAHYwVybksTYQV8T0m5dhsUUG2wyM2ZDRCKsFGDiAf
         1Oyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GySnI+RO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702409459; x=1703014259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NwfQN1ZelwNRLWJyhBqMWJVmNGPkEGLNSgk1TzD4llw=;
        b=lVhC7GYZMw4eQE11n/3o34J+b2o72ssPA82rKIZEfEziRUwP5wMe9KP+uZ6eX/f3WY
         N4kEquiRbaPJKGy8i9eYfyosaYUK+UvUrwFO3Dz777o4Ois1zD8KAHQwVlH8pWYb98Zq
         qxVxg20MpAv2V5jNbpHHO+95gXU9yNTiiTEJh27YG8JN5ZgwcOx6TIRI7iMTv5vfreMX
         qPuSHV/uTPVh7wk2nnop+Sz/rtc2jHwcKaTuCvvuQ6H4D+CqEMokcNoKMT99ewRMeSg3
         m6q8F+HH2iDZto0Sfg77vZFH58Sps0nmy/wPDPZnEnr5PNUlmELOMw77pYC2AvS0VcwA
         weLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702409459; x=1703014259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NwfQN1ZelwNRLWJyhBqMWJVmNGPkEGLNSgk1TzD4llw=;
        b=YQegH+BOYtyb56NjgZH5cQ1xJ1CoGeYcghOkn1C1zvBOKWdKkuU4w3rjflt3IBXdyI
         kE160Bxvv1UsreKZqKD5tcznCUCwAB/BYyiYN6IdeQiYZZ+pkx73R27GTCSh8cnWmuCu
         SGT7zrPRf90sZchAFR5Gv/fKolDj3RyoqNfLSIEQZ42dTTkcGgoGHmlPolcj/oUVehtZ
         H0pfPW1u9O2QJT2zEZ4qaDNOTD20ycvX0NE1+pJBrhm+AByuNkeRK9rn+c+y+Yc4rY/B
         GEYWFpqDaTaE58/PgYM6qbyMGib8YrV1SpN0grLLNwhVaGRz782LAPZZiUEokW7uqgrw
         yo8w==
X-Gm-Message-State: AOJu0Yy4TJt0KzfaLBpyQ9TNop88kCKJiXPKV8c1dIAkNd3CXE/Kuu6U
	YDQJbdlTCiCeOLSu8Uq67gU=
X-Google-Smtp-Source: AGHT+IHFBn1VuZfe2pdviQJw+IU5HN4siKO5ZsdosAg+P1qXaLJTcGf1t1m1HTUMvU0xdii4JvbjBg==
X-Received: by 2002:a05:6214:154a:b0:67e:eada:a328 with SMTP id t10-20020a056214154a00b0067eeadaa328mr2331702qvw.6.1702409458903;
        Tue, 12 Dec 2023 11:30:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:330:b0:67a:9b35:cc14 with SMTP id
 j16-20020a056214033000b0067a9b35cc14ls854357qvu.2.-pod-prod-00-us; Tue, 12
 Dec 2023 11:30:58 -0800 (PST)
X-Received: by 2002:a05:6122:50d:b0:4b2:956e:f64e with SMTP id x13-20020a056122050d00b004b2956ef64emr5717652vko.7.1702409458045;
        Tue, 12 Dec 2023 11:30:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702409458; cv=none;
        d=google.com; s=arc-20160816;
        b=yx9+6mnJEDtYRId3My3HW2MOjRjMxYxI647LvX6xHZtxheAT9gEfafuNmv/J8YU7dk
         uJTPIJkuFs8QdAZAxbvxuJiyAGvZtUI1kSFLnghaSXZzQALaHnldyOLPcq7MBRaOFpcL
         XVuzDMY1VGHTexD7u0IScZrbAHN4DUlNtYEE92JP6qYx7vVmxrrdxX1oHPZh2JE4goUi
         yMXHgAQsJZ98qkpf83ZBl3aC+S9VY3Jk4gIr8st3Ie3wwTnBJUav4WTA2rKn09bz7SDG
         z1pRH74lya2gE3gXIIy3W43YJNdUzmr6gh9OtsrVwzRggpDDzREbXAdM2Qacuc4UQ9Cs
         BgJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JMbpC3BtNOe8bELQw2u1EoYqYVQ1htSh7I5QpYrW3xA=;
        fh=U+LkbmzWWCZxhGJEzEnoma1O4OhNrWGKYws0tLC4nok=;
        b=UmO+rcEp+kCyCyqUhLUf6FzLoagfQXMZtbp25CRoq8rFw375hP5hnWNmaRGII+MHGo
         Ln69NIHJHiRGKcWz9rh+0OtpEfeK3GlAlI9/s04Qxwpnh5dxNBIrcXgdY5+1bHjWS+Dc
         TKf3W6ge1iamCzQwuEJiBeGKGUigg2Ld7xdHC/aUxSg3pMnXuzY9AQEmKMxIeZzNPuvs
         gTR620KjnSzd4ugSOX4vs8mzmA5d74P9JiSaENbP5XLtZ0sKIJ+Sna7cLgm8RhlAz1yY
         DNRWjNmQK2Z/n8b4Y6rYIOqMxcKqtdtt1MJ4GmkJNVgwwhu2E4UEiHa2vp/Q4aVVUTLB
         mmEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GySnI+RO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2d.google.com (mail-vk1-xa2d.google.com. [2607:f8b0:4864:20::a2d])
        by gmr-mx.google.com with ESMTPS id 10-20020a05612208ca00b004b2e6e4330asi195937vkg.1.2023.12.12.11.30.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 11:30:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) client-ip=2607:f8b0:4864:20::a2d;
Received: by mail-vk1-xa2d.google.com with SMTP id 71dfb90a1353d-4b2d64a368aso3335263e0c.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 11:30:58 -0800 (PST)
X-Received: by 2002:a05:6122:c9f:b0:4b2:c554:cd04 with SMTP id
 ba31-20020a0561220c9f00b004b2c554cd04mr5816814vkb.16.1702409457619; Tue, 12
 Dec 2023 11:30:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <c8bf7352aca695ea9752792412af9ee66dc2ca17.1702339432.git.andreyknvl@google.com>
In-Reply-To: <c8bf7352aca695ea9752792412af9ee66dc2ca17.1702339432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Dec 2023 20:30:21 +0100
Message-ID: <CANpmjNOkMM4BLEsNWAwduCFCbUFrnW8eOb1gA-j9RLNO+eh4Fw@mail.gmail.com>
Subject: Re: [PATCH mm 4/4] lib/stackdepot: fix comment in include/linux/stackdepot.h
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GySnI+RO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as
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

On Tue, 12 Dec 2023 at 01:14, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> As stack traces can now be evicted from the stack depot, remove the
> comment saying that they are never removed.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> Can be squashed into "lib/stackdepot: allow users to evict stack traces"
> or left standalone.
> ---
>  include/linux/stackdepot.h | 2 --
>  1 file changed, 2 deletions(-)
>
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index a6796f178913..adcbb8f23600 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -11,8 +11,6 @@
>   * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
>   * stack traces often repeat, using stack depot allows to save about 100x space.
>   *
> - * Stack traces are never removed from the stack depot.
> - *
>   * Author: Alexander Potapenko <glider@google.com>
>   * Copyright (C) 2016 Google, Inc.
>   *
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOkMM4BLEsNWAwduCFCbUFrnW8eOb1gA-j9RLNO%2Beh4Fw%40mail.gmail.com.
