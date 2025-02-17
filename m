Return-Path: <kasan-dev+bncBDW2JDUY5AORBB6IZW6QMGQE2UXDYYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 043D5A38922
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 17:30:01 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-38f2cefb154sf2331258f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:30:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739809800; cv=pass;
        d=google.com; s=arc-20240605;
        b=EurZOxaGUEnYSmNu+uYEx1JWfGJ1yhLrr0gQj10gSJh2YKp+r6Cd+uyOnbhYr6tTHk
         Zg+90xbfdzJNLgqKF49tIlQ9oU1cE0CW44oayQh9dPAk4ATTRBQlCGotw5LgddG9n+za
         qhG2486B9fENBqD+ktKCNaVK5yrAIcVEHNBe65ozdWOuXtiAFuU1e/la4yPIooDZh2KM
         Cqg2aGk3lGY2Jy2YNoJPZUEAq5nR7xU/phdeWiPuV1pf+jS8eShCRrUY3ohC2AuOqZaC
         Kqpcd21hRyDfixD55Mvj9mpikrdCoRqyBiMbxiXVAgAUaoBikn6vQZTPWX7LqW4r7AGI
         Gd/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=SIOfShu/rrbtBKe8ErA5QIvpGKpIFkdv2M7zNUZv6o0=;
        fh=JIuRrN/n8jgk8dmnRSQy8k9SL/98WRl+mrRDAAgQdW4=;
        b=TYUyW5EMDUBb4qIgwlpwH0QfmNZ1vR3k8BbQ01bu/knA/boJRRTexOrnYnggqI6Yjb
         E77LCPeK/sBfV+AECp1uSUp2kdOgQ/gvQyQSPI3G1ash357313EytYrVELF1MLLGmGoD
         LdcZCE797z79njas1lPkxKTuzzALVGDQNKaTLx0lq/kMGqBdR2CKRpJKe+CgFRfxBmuo
         o6y9obvqVy+Y3iwSD6HnmN0faM7EjVkdlwQJVr7861bUrDtobkj4aCkF0sayCicOYRFf
         +PfQorsMIop+l7h++P9G/CHlTzZiaX8MNWds4WtSBfzREjbtH6u7I+i6PU0z6bGG1rhv
         7vug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WLWM1YFn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739809800; x=1740414600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SIOfShu/rrbtBKe8ErA5QIvpGKpIFkdv2M7zNUZv6o0=;
        b=w9bWXB7PaeYW6Y2hbKsdDb3/JNXXIF7a2jPVurEFLjHYNQ3uWHOzG+OmFyb7rRhs7C
         WSmePZEADkURSbB0elbboTgQ0NfvON1nfMkhu7drfRBqkP7391foQY3p9iNu7GTQGr51
         MC5FJ8wmex8BRmvwJp7BKrXIPA9cwtBwHFlBgZDVil9F/iPPjbQv08iDBvgt3TT+0aXQ
         wVJ49gs9lFTU0RNUmuvrrsBXZmW98BsuiYyC1BAgDvFmwE9Rj71X5fzJgZQHNEFC1YMM
         Sx/iJlb2RqiZR3sEWSJfLCvSw3U4oS0sUoKfnqicwDs/g0TMpJiT0ouYuxJ+JqYvm05X
         1F9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739809800; x=1740414600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SIOfShu/rrbtBKe8ErA5QIvpGKpIFkdv2M7zNUZv6o0=;
        b=Gb9vSswF1ufh+OleIrvtgw8Bi7K75kU+gPfrpc0fiN9u+M1DDbUQ7DZ2EuBnTI1w/9
         GNG3v0dzBZAY01iYEXzMPmteYMhjk3pVSR3HoiiQ5v0/lUoq+L/lxJabtwO8Ib6cv2Dm
         3OvWzwsF3BbQY8z2nm1qvEGtYgZZROkaIedqQqAhWQHjmEyx7GyQWBXlmDuGrbhRK/Wh
         Yk7ul/8JB/zJLQuecgEOAYL8Wko2MfC1GRskTJHKXgLHetwAGccZiUDg2gP6mXjn5zc5
         3Sy33VONGPfUnRkNuvImuJFab7l++EpC3MNdQtnnB80mGsheC+TtZO72yBPvwtaWZ4MZ
         RfnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739809800; x=1740414600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SIOfShu/rrbtBKe8ErA5QIvpGKpIFkdv2M7zNUZv6o0=;
        b=pq0rTShfYbEsahHk7mINkTfUh/jjYK8tw+t5jHloU6rx2RELArdfTlh0tSZKgZbJwn
         elEwV2oBLtccfG/ZaH6i1yAk3nTDX9WrLxLWNelim6pztGhN1MHjT6aSmBar36nzd7Em
         j4Yc4K6iGaInInA6YTFwKN21KWJqOf10sw3laEuuQ07oZcLLs8X8NQGYcKIRH/q7darg
         xUme8vGoyp3X4VEBFkL4warAhTblpnZPruH9KRreE+D8edVNFEKgHyBUCBZ14kWS4tGe
         esgOqMI0xCz7ZIDVRx6/TLlZWYmMBcDy8BRW9liGGNeLSHi82S7D6MZe+cs3rWpElilV
         ypBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWc9IYJUWBhkxebBHnGonGLczR4w7wapBJrHiP7tkRlfPFdxOomReZKvXKMpor5NRoCtuKzRw==@lfdr.de
X-Gm-Message-State: AOJu0YysHAKv8fMoDfdWVqRjUYPXPNlIwfdR8KZ5oHnOxEK8Y9u1JttF
	1fGh3H93/HCp40MqaD7ViHu5XGYl5p1GrQmlvPr3HX/CiUxh30mj
X-Google-Smtp-Source: AGHT+IEg9fRJwAu3Ofj/AFfSIZuqrrqmPV3JmVE84MP8ILADYYBdMdJ5AP4qFAJYVszpOpNgrAkzkQ==
X-Received: by 2002:adf:ec05:0:b0:38f:2a82:4427 with SMTP id ffacd0b85a97d-38f33f28bf6mr6931201f8f.20.1739809799870;
        Mon, 17 Feb 2025 08:29:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHtfoVAr6xEOZmXq6WHNYJ6PQhCTR+cbLtRQ8r4+qEv4A==
Received: by 2002:a05:6000:178b:b0:38f:2133:2c23 with SMTP id
 ffacd0b85a97d-38f245e17d3ls1793409f8f.0.-pod-prod-09-eu; Mon, 17 Feb 2025
 08:29:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJ5b/sA0YNnb+K7ts6ESoWnMp2iAL8yHvOKs5rgzoH/Ox1367iIiRUNwyoYf2YEGlmRMUuXWEmpR8=@googlegroups.com
X-Received: by 2002:a5d:498b:0:b0:38d:e411:7dcc with SMTP id ffacd0b85a97d-38f33f44cd8mr6491023f8f.37.1739809797449;
        Mon, 17 Feb 2025 08:29:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739809797; cv=none;
        d=google.com; s=arc-20240605;
        b=N/2V5PlYZ2f/iEVezf5/zXnigVm7RVa0nniA7LpVLummJlz7prGMU1Xkb5awhnpYCc
         clxvE/r//OSRsC6ABnc0jBVyBScCUorqz3GNw3AO52LqDYuHnl+LZcVmWl+OEBtkEtqT
         kDPYj1YtulCOLoXi0nwNzh2F885ZplsNEP+AUPIObZl14A8kK+F9eXkA34SeypREpZ5E
         c+AxoiaxBYCdbAqrbkLUmR/QIkR9TlkM6akXZ7BZzmCVBgIQes9l+K0DVPissrFu57dO
         zgq5Hci+TtgXxOczx61DFX+vE47tdkSA4gpsDYQX4tFLLI8qUcrKTZgtp6GjloF4vRkv
         Ji1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pZQb2m4LI3eZ0whbBX38Hfb+TR1d3xUyfma8FbMenc8=;
        fh=HgZXLBjdwXdQTTJG5tLJ6F2tX9/YoTPfsz88ag3fFRA=;
        b=fZ41Jz3Jpt9cIN4RhzG6O9N66Qp8UHeHx2csN+J4us+F2q4Zb7Kre3v3rjtZoQMlTR
         y0ky2lPTJ0aApSYDGP/PySm3x7CMvO3IDfMJDy3g+CutrCvO1frxjOeN9rwqAiQruMX1
         gtlMEys74uyXecRRdAyzKAMkMFFqrf52P7yOfKO3tbkknwxsfOVpPFEp6WJuuNNozwUb
         pnSx4PE0yxipMSVo8eYkECBdFBXvONFpNV/pn9LaWpmJfnAjva2ZwW2NHi0APi8rVQzF
         LRXQVCmtDv8K0SPEnOBPZcazWMFI4xnDxgkLIqb5gKvXYG7waR4zWASO0gyVXUKrCQO7
         R+0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WLWM1YFn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4396b83ce91si5580575e9.0.2025.02.17.08.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 08:29:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4397dff185fso13260575e9.2
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 08:29:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUfdrrSZjx7eV7IsLHycec/AFtv8uwBiJ9hoKwX0xnm8pTC64aY0Q14HApfWLh4TdLwEX1I9RzrQTU=@googlegroups.com
X-Gm-Gg: ASbGncsla9TAHDTQsqT4BCvYxwBXSIfsj8J8fUQYLV5WS02KoQNmziKpUs7/bTISHz0
	ZQgq0pRMLKL8/J+/Y2V4PadRTx9gIjmwfWmyssMewznGMZ7C9SttpdiCLxYyWsuAtJCxevomf2H
	k=
X-Received: by 2002:a05:6000:1fa4:b0:38f:3d10:6ab7 with SMTP id
 ffacd0b85a97d-38f3d1072b9mr4816691f8f.23.1739809796774; Mon, 17 Feb 2025
 08:29:56 -0800 (PST)
MIME-Version: 1.0
References: <20250217042108.185932-1-longman@redhat.com> <20250217154309.C2CMqCjE@linutronix.de>
In-Reply-To: <20250217154309.C2CMqCjE@linutronix.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 17:29:45 +0100
X-Gm-Features: AWEUYZlZbQRUYlLo8ZMq5M3z45K6gh8vpPysxswkL9MmuffmUF5lc2K91cMG2qk
Message-ID: <CA+fCnZekjO6ajX5YDE2VgL3pzyawdVNkJ0g6-w0Xq15zdDdLog@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: Don't call find_vm_area() in RT kernel
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Waiman Long <longman@redhat.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WLWM1YFn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Feb 17, 2025 at 4:43=E2=80=AFPM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -370,6 +370,34 @@ static inline bool init_task_stack_addr(const void=
 *addr)
> >                       sizeof(init_thread_union.stack));
> >  }
> >
> > +/*
> > + * RT kernel cannot call find_vm_area() in atomic context. For !RT ker=
nel,
> > + * prevent spinlock_t inside raw_spinlock_t warning by raising wait-ty=
pe
> > + * to WAIT_SLEEP.
> > + */
>
> Do we need this comment? I lacks context of why it is atomic. And we
> have it in the commit description.

I would prefer to have this in the comment, but with a full
explanation of why this needs to be done.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZekjO6ajX5YDE2VgL3pzyawdVNkJ0g6-w0Xq15zdDdLog%40mail.gmail.com.
