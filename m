Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3MDYGZQMGQEGLYMG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 478BC90B0BE
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 16:02:23 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-43fd537e6a6sf9719991cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 07:02:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718632942; cv=pass;
        d=google.com; s=arc-20160816;
        b=B742kzWoofEOA1TnDEExZWc6hMqFybpkpM5woG08mYpukM/0rqCuapz0qTMREMiFGI
         KdlxW67zgF6nfLz6DAs9m/MamkOu4hb0Bhdaft76j4HBrl7hZEgGZuELx1HH3JuOtZ9U
         5tVaZNZEnfD4wkDfPTck16rdwnelZbweUdsiwdT7XXaD70tK2rRCC7RhT2XbVIOAKHe9
         0xxbkpnT/ae1hHUMQ3xCGilhrUSfZSu8nctfXxZVfLce+GReGXHIqHsaMqPvXuxGi5Xe
         RbQ1VEv1BDmBiKQwAgdyA+xnducdeRbzURImE8teAj0eAmc9Lh7IXwznuORMWlwRZHcc
         4nDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3mbtFFnmMq0yGWFaQ3kbTydiDnLZMKLsMv3JLFoG2sY=;
        fh=nc7JQZ/jsLm8IRY6mm8MziSb7wAT+FZts0ysuc/Ku+k=;
        b=kx85voOxaB5JT+FbFeM9C/TG6QSxsC1KtFJIM2k4p+KILJrwlzJbatI2lnu6ci25Rt
         WI4zRDgvF4Yz/WyO7Iqo0iDTVyVF69omQR2ozSAFMnICksYqBZd9oHrNCtLtII6O1WxT
         TCS7G1qwun2OV74+4uUjuywTFiGu/xWrmIbiVccLRD6jNLFvKKcFej5pzxYoNNEffNVN
         LlJ21nm2Tgh8hv8Tghjut14R79pd0QPe5RgyGyEmjwmKbu0eNp20FTHxfxAiuGI6XlAz
         nf9gt6zPG7UL+Bu+mjNP9ri4hw6VxZev0dWLRF+HSAaAF7sT7U9pGVysowWI6VhzTwvM
         gqmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k3op3nck;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718632942; x=1719237742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3mbtFFnmMq0yGWFaQ3kbTydiDnLZMKLsMv3JLFoG2sY=;
        b=Y4oE2QqUUpTMcu5QnfPN3NNyCUCqO90kguDVFI9UMd5PGhq2uAqAf9HsfQicnDS+Nb
         BbsPR583KgRBUEmKnUgpnCif+DdRyiQILnGFhyBhxq07L5mQxKA9BgDKH3OGQDF6awCz
         B4324p54M/IpQ62JWTn31b9rYkbJVl4HKOAeP0idqH+610NIPdfM05KhwS//MNQJ3K7s
         lXgb/UW318Wa1icqeU2JSpSp22JARZhvzeWUAerrcv7AnxTI4ORFxncWHRU7rerw2GWn
         CCe56OjAcR7Ot322x1KSs6E++9NMCTYfXC2FJ7RmXEeOmsEeUXG/Zxaq04trrYZqo4bZ
         51YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718632942; x=1719237742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3mbtFFnmMq0yGWFaQ3kbTydiDnLZMKLsMv3JLFoG2sY=;
        b=g31b0sPIjAMxedBotMpZXZV1S14KMmW0hAM7B5psEig1HhcUorawKdN5ds9bVxmZMM
         pxtNyJrPMQgi6bXV/J3ZcQ5Wp/KTqOMyL5K+tOhKa1OIF6RdNAWh21nrUkicqJe17xFC
         ywA9iofZJZbw34iF5qzs5aY/Nw4M3sC1Vo9SdYsOMc6m01ERz9V/lKnLrVzi7Ar4oLUv
         DF/8laewYIG9a1TJ0ybDvuSZO671Tvv/0CgBV0LcfyV4oXSxqkD9HOY9Czyj7NRisV6N
         hdnBdM1QVE4yjKkuHG1FCkW6hb3iec8QCQCTyScOnjlpP2vf1TKcSuQB6UmXPBZ2dOCh
         yLgg==
X-Forwarded-Encrypted: i=2; AJvYcCVSZ2KakTFAvNcTqhBvix69wv/CHm1+Heo0/8koE3NVBFggYmOdHDJRa4nu4RDkxORZguquB3jZEZFiviNvaJv/tANYumfNGQ==
X-Gm-Message-State: AOJu0YzM16KLeWj1Q4Ayb3YUPiPz2E5/uU/gNlEHQ8xAZtMv3GT38X6k
	Sbm6cycdBSUjw53jUlXAXGG26voRPyIRFLwAVbB/9XbbUirJ7Ie0
X-Google-Smtp-Source: AGHT+IE2QutNyCZX6xE0/lSiyVCImaTRmikiJEhDQgbuS1tonlGhIipBQt1exG3hAGIiATc915cZbw==
X-Received: by 2002:ac8:7e92:0:b0:441:45bf:971b with SMTP id d75a77b69052e-442165bc041mr128521221cf.0.1718632941231;
        Mon, 17 Jun 2024 07:02:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1287:0:b0:440:3c7a:5e7f with SMTP id d75a77b69052e-44178dcc214ls50487821cf.0.-pod-prod-09-us;
 Mon, 17 Jun 2024 07:02:20 -0700 (PDT)
X-Received: by 2002:a05:622a:103:b0:43e:717:38cc with SMTP id d75a77b69052e-44216b0346amr112273531cf.53.1718632940015;
        Mon, 17 Jun 2024 07:02:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718632939; cv=none;
        d=google.com; s=arc-20160816;
        b=IkyhEcB+/4zBafrl5/k+rABp5hwqEOatnadAxK3/U7wDYMwDg88CsJDmdLCJJmM8MT
         9EvPxpXUzJvEKFQbtTTViZphogHDrKhky9G7W8nJ5kc5abPSW3vg9upAIakIerojMU88
         EVJXDfgZKQD4EdwYQbrooE8R5DcQZkfYvT6PwlHPDzHwNW6ikQj3r4PQJKmpNXaaIPuv
         RpfqRq6BJ83bXnvpxpDrOGbd6pOo4GTSNnHv8zYhW80dR0GZlXRvwyAoHof/VL0dU+4a
         k9zoEPbjvcovguX62RK8h8hmRLOoOGfVpPBp8Xbl5VBtt/PQKtqjELSbclj5o04h5QuE
         fvrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fe88b6+4oYZDKjwdX1I+zJbo2bqdKGX2bZyz8pztxCk=;
        fh=7DXMdIN8+wqT7KPx/9s0a8CjAHRCBl+kRzfQzjH6sbA=;
        b=zfTc1F07sJb7anqAHuI0V3adY8lQeJyeMlfLxJ7/iiwIDshNcEwBZgWLirQOa757/K
         rjy4jdLZ9i2llZ/z6rqmix8k3vt5T+XEIGqWqYM0VIc9lwxGSx96/A7d04a2fkQSgmRq
         i8NTgXwpqE7IOlF8HbU1T5pN9sophZR5OESUXk3U6TnL1/6zq8Cb8ojDtBmIc2KIbhf8
         kPvwdEg4rwnDofKoiv0VwQKxh2l1D6sletXlh/SqOayBLI2TN1lem8K163/RWUhddSia
         npdq9TVF3H8TPz7zDsoKY+i5vVd6S6giMvJlO/q3HIcMThU1wja8itrXuDZttt5uRBJ7
         j95Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k3op3nck;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-44360afc199si1251631cf.0.2024.06.17.07.02.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jun 2024 07:02:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id 5614622812f47-3c9c36db8eeso2413102b6e.0
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2024 07:02:19 -0700 (PDT)
X-Received: by 2002:a05:6808:2184:b0:3d2:4fe3:5100 with SMTP id
 5614622812f47-3d24fe354f7mr11828382b6e.17.1718632939158; Mon, 17 Jun 2024
 07:02:19 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNM-0ALzHqVaEO2u-OGncYQa-KWKtsTCfioSjG4c+YnRbA@mail.gmail.com>
In-Reply-To: <CANpmjNM-0ALzHqVaEO2u-OGncYQa-KWKtsTCfioSjG4c+YnRbA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Jun 2024 16:01:43 +0200
Message-ID: <CANpmjNPvZWO-ywo4BXPZVJ1FH9XguztyCCwCMY29XokTD35Piw@mail.gmail.com>
Subject: Re: BoF at LPC 2024 on Sanitizers and Syzkaller
To: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Kees Cook <keescook@chromium.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=k3op3nck;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Tue, 11 Jun 2024 at 10:25, Marco Elver <elver@google.com> wrote:
>
> Hi all,
>
> [Cc'ing K*SAN and syzkaller mailing lists, in case any collaborators
> have particular topics they'd like to discuss.]
>
> Paul has reminded me that it might be helpful to do a BoF (or also
> talk) on the topic of kernel sanitizers at Linux Plumbers Conference
> 2024.
>
> Last year Aleksandr did a BoF on syzkaller and syzbot and said it was
> helpful with plenty of topics discussed.
>
> My question to fellow K*SAN and syzkaller maintainers and collaborators:
>
>   1. Would you be interested in joining a BoF on Kernel Sanitizers?
> Since 2019 (the last in-person LPC I have attended), the kernel has
> grown several new sanitizers: KCSAN, KFENCE, KMSAN. I suspect that if
> we include the whole range of sanitizers (KASAN, KCSAN, KMSAN, UBSAN,
> KFENCE) there will be plenty to talk about, but may also be not enough
> time to do any particular topic justice. One way to solve this is by
> driving the discussion and allocating an equal amount of time to each
> sanitizer (and if there is nothing to talk, move on to the next).

I will go ahead and submit something.

>   2. Are we interested in another BoF on syzkaller?

( @ Aleksandr, Dmitry, Taras to decide )

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPvZWO-ywo4BXPZVJ1FH9XguztyCCwCMY29XokTD35Piw%40mail.gmail.com.
