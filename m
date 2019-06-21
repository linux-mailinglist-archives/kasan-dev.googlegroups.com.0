Return-Path: <kasan-dev+bncBDEKVJM7XAHRB4GNWLUAKGQEKC2UINI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 642AB4E469
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 11:44:18 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id a200sf1977296vsd.8
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 02:44:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561110257; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMl1lYnR8krDbO2BJUjTJ5LOHB8fAHtqS9L2kc+gZF5WDGfDzo82KjLB/Wq3Foxm2c
         mWhssCjZ+sA4Te1mrN9k5g9lsmjGXzonU6te8+Y2sVMa/paSMFULQphDAp8dmm/iBAHo
         tQuXbCZ7F43Wt6CABB7+BtOiHT1L1UDfBWxK7SjEFkuUskRM1Z3BHGc+0iIEJUl0CVG+
         wIJj01MswaSFtmaraGGMrUJ0afprUB3Tp4eA8StTiBVfJsgGW5Ov9iDckNEBljJ3Bye+
         vU7TPHjS7p993o13IRPYK5gNxcIE0+w4T/OMUFzqF9GFlH4qV+s4W1L3ZmQjQuSw0IQM
         rr0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=9MZEktPOO/mgCo6tJ2FCpcJuoKuq+Vn43XKb1rGdBBM=;
        b=w3YHKY9O1DmodPbZPME99oFQFA4ukzWjCl4ltyAd9KQN32d0/tKNV3BIO+8ZK1eyxG
         cT5KLGMoMSBmQDb9Q5rlRBdfo+P+ykdzwkJYMcvaqTf2N8r/I2SXjp1glUpGT/gwobWr
         5H9WufXLAA8tPrSYYJl39SiQzCSXfi8rzp8sulF9H1vno8E3yPyN3SsHfWlF8rhaFe7k
         IbsFgcT+hGbmCVBCv69L932vfwoM4QtBrHdI3pgoYflXfKHjcb52TH3eUt15JKnrlR2W
         piHEZEW7VWKdCyafDwVSjROj72IIlPOtrZUWjYd0HQ+uptTWiT/tYyH4gC5e5pj+WgZJ
         MSsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.196 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MZEktPOO/mgCo6tJ2FCpcJuoKuq+Vn43XKb1rGdBBM=;
        b=KEYn5CYQwl8WZmDJEjNm+7Rv7CpjLQPXJiNEgJwwy1pUDDRevh1EIT4jCd7S76EEJr
         oBTPZtJ0a2nX77VGTEN856Z0TVyWVXgQX+xRxF0mShXZ/+STBqns5eM+Vdub1tb5J463
         hknIesOgyWWJ7pzUzcXSSzm8MzOjPXemWtxv84FTVXw2TAZkP6pT2XMHaqtx37B20UrS
         W540qNbnu6FvekwNG5fFVo3HCXcczu6MRq24q7iX8MZARJHs/3vs0PfWvrOS74FGGitO
         oKJN2WSlkpZcVW/JSLBZcvV7kKH00pwKCwV3OMp0VWkp3gIwQ5+abQnvR9ZqBH6By/0t
         KjOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MZEktPOO/mgCo6tJ2FCpcJuoKuq+Vn43XKb1rGdBBM=;
        b=qPxQD0Uri3CWjuzP2gENwWqZsLyEn/3nUM3pnXmX+jhf77i34cMP6+c+HodUK2iEe4
         9xQU2FCHBcmIJceElfwtAGLD3LN89Kuy2rID3ZTTvoiC65ZGaLp4Npf4Dr36fFetO/5U
         XipJrCjO+rUV187P69Xtc7Iyfzr7jqJxlq9Wzg7UyGAJF0wBkslFKykoIMa24Knv+H5e
         iN4X6HSdZh3i0Ggd2fAhq6ZutvA6vpw9/aUjscQB2NIJjtcEuze1Tu9mS2MqrUezgF7o
         lNa/9/lHsOayg43Cwol0y+bMQp3vpghFQRGqBJl/zW1bbZMvsDiSx35sh9zTBX1pqARC
         WaeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVY67+49d2fm+4HHLp4tiltNtUUjMdtPyy1v5/8dZOesXfzJfHt
	v4AmkqwaRDjjPHby+PemqIk=
X-Google-Smtp-Source: APXvYqzFuK+rYmqd7Ayx+oW4eDdZ/y+i3LLNNl8onuld404Euld+cobcs2dDJSRL4sq1kc2UV8epmg==
X-Received: by 2002:ab0:30f5:: with SMTP id d21mr8149334uam.67.1561110257124;
        Fri, 21 Jun 2019 02:44:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:28d4:: with SMTP id g20ls525899uaq.16.gmail; Fri, 21 Jun
 2019 02:44:16 -0700 (PDT)
X-Received: by 2002:ab0:2bc6:: with SMTP id s6mr8711343uar.86.1561110256747;
        Fri, 21 Jun 2019 02:44:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561110256; cv=none;
        d=google.com; s=arc-20160816;
        b=NFxfFthwof71EJjq0r6a7utlCHxTupQZXXqF7NZckVOQiAQzM4am8028nw6G0tga1A
         qMnKywLHsTCX0f1ItuIFbBLmrxhblwzy0cjhrcXVUTctMSwZwVtZw/ftNajk93/Gu5OP
         kK31zNVktaraJftBMrG5r2moBIs6DLIaTjy8/vo1BluZ+FMMPn/PsX0lC+8ZjjFbJZRY
         /PjSCHzefxZXDD/O3/BfIEVzOr5QQGlORXqpEAQQ8uRLjOWYtLxtKRrd+nJkv+H5mD3h
         gEoTbg/HeyZ3cYaeEdpRb7sDVApP38tpRpaOzKpi1SlF7YEIVOFczoVz53fgSe5Hg4/n
         Oy8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=UY8gc9yYdcrJaXj0oq+rSDKkKaI9rAlIB6YxZFfkWXQ=;
        b=NoBlQyT55t6ZTCUiHI5ZdlA1xVwk/aK1Voht6gANdMqZD0VRy2PInxAmBUSWHe6Z15
         SPIGhZNZJpuoaCuGeoeoxguGLolutK8v5ne1cd+WL61RB4W8iXmeydalgXvoVwLlMfPg
         0owtxScqttKAluC1q6HXcCNhifz4+a1q0lwW8Du4eKHgpw8LDZmppGF2F5Y+5BoZ4Mru
         GXyUbfWE/qSS1ND3iX0Qy52cyYhZAgvpVd+Jsg4hlw2y9dmPr7SrZhYkxkBanQJvIbSf
         H45P1PT6b9GJnhoNPYxpM+7ewiwDK3ckedp6LKo98KtAiR+ZBLBaRoqmIKUUOq4hypNf
         +v7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.196 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
Received: from mail-qt1-f196.google.com (mail-qt1-f196.google.com. [209.85.160.196])
        by gmr-mx.google.com with ESMTPS id g25si109918vsq.0.2019.06.21.02.44.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2019 02:44:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.196 as permitted sender) client-ip=209.85.160.196;
Received: by mail-qt1-f196.google.com with SMTP id x2so6304097qtr.0
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2019 02:44:16 -0700 (PDT)
X-Received: by 2002:a0c:87ab:: with SMTP id 40mr42484713qvj.93.1561110256287;
 Fri, 21 Jun 2019 02:44:16 -0700 (PDT)
MIME-Version: 1.0
References: <20190618094731.3677294-1-arnd@arndb.de> <201906201034.9E44D8A2A8@keescook>
In-Reply-To: <201906201034.9E44D8A2A8@keescook>
From: Arnd Bergmann <arnd@arndb.de>
Date: Fri, 21 Jun 2019 11:43:58 +0200
Message-ID: <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com>
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with KASAN_STACK
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Popov <alex.popov@linux.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, 
	LSM List <linux-security-module@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of arndbergmann@gmail.com designates 209.85.160.196 as
 permitted sender) smtp.mailfrom=arndbergmann@gmail.com
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

On Thu, Jun 20, 2019 at 7:36 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Tue, Jun 18, 2019 at 11:47:13AM +0200, Arnd Bergmann wrote:
> > The combination of KASAN_STACK and GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
> > leads to much larger kernel stack usage, as seen from the warnings
> > about functions that now exceed the 2048 byte limit:
>
> Is the preference that this go into v5.2 (there's not much time left),
> or should this be v5.3? (You didn't mark it as Cc: stable?)

Having it in 5.2 would be great. I had not done much build testing in the last
months, so I didn't actually realize that your patch was merged a while ago
rather than only in linux-next.

BTW, I have now run into a small number of files that are still affected
by a stack overflow warning from STRUCTLEAK_BYREF_ALL. I'm trying
to come up with patches for those as well, we can probably do it in a way
that also improves the affected drivers. I'll put you on Cc when I
find another one.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U%3Dz2UdBSL5U0Lw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
