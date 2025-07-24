Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIP5RDCAMGQELAOO5ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 876DDB10CBA
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 16:09:39 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2e92a214e2esf603724fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 07:09:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753366178; cv=pass;
        d=google.com; s=arc-20240605;
        b=PG4yQj89X5jlW43twNF0ed72hklj73o0xBBi0isqOa28WOfHUMaeizvd36gPKFFhKU
         BDXIANZncviktswL4oVcaPLMg9+vqVFJvfOUTjqSQrmnkKlOr3EccQWDJj9KzqTCEQXW
         OyFCT2Jd+xKzaMsIw8NRqeKgfbfET+qpfBYuSya6D/Yzzh+MAYoWFFOUU9HF0v3MlSr8
         R8wAokuVhtGsL6Qq/62lK3DSt+TbVcbYIBKI64EIs7wvY5+QsYAnRWXqZZqi///o6yrW
         +4M18E4BD9OjYBDXpIHnZ5aO+ESwdQ9Ten9cyh7sQp6InUxb/7pMakYrkSFCGgq2X0lV
         F5jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tOTdi+/eZKsKnpslMy6l4mYL5+wXjsXPvcGsqFZfo4Q=;
        fh=GW9lsdiE///QZn27Z5a3oVB9DWOSTknZywntewjCAeY=;
        b=eiwgGjDqK9REQNJAP1Iy7W6gpoewhMmkDE6IGnHwd09aW3NeD/kbEtFue7ag1HuTOm
         FrHc/cmlbsTmcsKOUtsUwupMg4EvkHIS7sTmf6kPWCd9AJ24IVXLd/HgRqWgbmamK3xt
         oUE/iIVrCbKVbL60E/Fibk6BkZpcsIY0QerTFXpRUYG4R/g+7Cq0NVoaBv+zE2v2So1y
         NZEzddBL4KNYQH9kcjPvpdhu5z5iF6Q0gk89haF9g07Z+jlyKEHlwH8816CDaQ5y/C+w
         OvCpxDn+JgYPns1PiM5vU2KjxTGMLT+VGcBS4ObmwioLK9sFFV4xmeu8E2LfzflnXS/5
         wWLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yJgBvnLV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753366178; x=1753970978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tOTdi+/eZKsKnpslMy6l4mYL5+wXjsXPvcGsqFZfo4Q=;
        b=R7Dwg1Afgppw9EIfjR7gomcTXr8ws/rP7P8C1dC6QAVR1q0ysP7mLwAiGBkyPPmkNG
         NYP2jNJheAwIRkQOmrCIxwHgU/FgTLiorgDiNJl5mWE/DvCXdT2SwsCnkaHzj41QYIVL
         rflggVuWYmqhgjLIAgKRYffnw73VFBT4WOKaE4YOKkcNLM8Ol47WtQbwlTIFJhpP7d+P
         5pkFLdLYA7WZOCRpKtbmnTi85CA4Bbtluw5g9TFvDl/PbreKVX4WqPHaGnifzfV94iH2
         yRtPkg6HqcI4osobdsYMvLTMypLT+m2aC4QFD/LFym0HzN5L7QNFsnsjgpsl+u2kWEtA
         w8uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753366178; x=1753970978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tOTdi+/eZKsKnpslMy6l4mYL5+wXjsXPvcGsqFZfo4Q=;
        b=FNXH6xs+4ptjn6fNwMPTDfqEg2ypKnDEpdKEyHiSP08K26wkPHWX0Z6Qv6kDuX9qOr
         zmKj43NOttWrqv/5g3Ac2qp9/66cK31o+wiX+RTyYkT0dIzMRW1THXDDrKpkUq9jkYbA
         UvLOktSa7foCivt5zX2OOS7bm+pRazwJtzH6JafrbbkRs46FESHzQCjwOMSOB18DzOdd
         eJt9uTW6bcx5slQFskN8Q50jJxEL71/pFQ9E06IvprcA6GuR+L0PX7t5C1WyzpQCb4XJ
         tmnT8ldtfK7mrFg6VXPcE4/cxs0nPSBC5q7ImBB7s0DS7rrPkiLu8fSRBuJ1n4SdYpsE
         FtfQ==
X-Forwarded-Encrypted: i=2; AJvYcCX/QCxs02+P0NkdFMJJoHWFLaWF5mfOYNc2cQbhiRs+H5MPlNueBKqmIQ5Ets/mWJd2uRFiPA==@lfdr.de
X-Gm-Message-State: AOJu0YzBTopXUXD47TTR7R58TyZ97iiIA2rjjL1hKtOzOzD400QRKo13
	larwNJ8jFxn86K+BWjtkkrmhbgsGnOs9FHnedTfjFiMxmMucfprKsBC3
X-Google-Smtp-Source: AGHT+IGdus2Ghj3TfI+MbKJNIRPG8waUeit6reuLn0jzldk1bjVehFTeW+Lz3e4q638m+7VFJ+fR3g==
X-Received: by 2002:a05:6870:1d2:b0:2d9:8578:9478 with SMTP id 586e51a60fabf-306c6ef7b24mr4937909fac.4.1753366178095;
        Thu, 24 Jul 2025 07:09:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKxy9MZo8CfTltg8R+G/QVnd7HZdaJsg3Q5EqhmJkIcA==
Received: by 2002:a05:6871:89e:b0:2ef:3864:284c with SMTP id
 586e51a60fabf-306ddbfc7bdls433451fac.1.-pod-prod-04-us; Thu, 24 Jul 2025
 07:09:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzwW/IIVatkX9fj0BFkmpLanNvAGcC7/VwYwtRFyrVusvXwSz4K9boVxxLfrWgVO5xIIYIhkn4+zY=@googlegroups.com
X-Received: by 2002:a05:6808:159f:b0:41c:4f7:1929 with SMTP id 5614622812f47-426c642ef21mr4930399b6e.21.1753366177224;
        Thu, 24 Jul 2025 07:09:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753366177; cv=none;
        d=google.com; s=arc-20240605;
        b=asVNZ9Z9GFLxqD1LFkMFnMEh4q8JMoA0vcG/Ofcctbte+ASvih3WG5m86sjljzFEtV
         J6y0Litt0GE6N7GDQ/swkYMVgo89Fu7uq8AOTR4iWWaz285kEyoMdmK/puy3mIjti8iQ
         Kik/kW8bB+xSILqJ5lDecoe0QaSHaRLSICXJrjtwK4amlf3jl019oEkGLUXldMQ6qCFp
         AKzTO0ut57rgFbKJQeK8F3nbOvToAkAG9zTqYC2rvsL9dkKLUoM/jsFUqradek4j/XL0
         Jk/ltuksq/ZtynUsnBPxgLv8X3OqF0B6mp2+5pt/g6rqJtYaXBJu/NoqDphNipjd24gi
         e+Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kI2DQQXCIIwX47gBWMT7lpZ+yA28bBKAj+N03xB3U1A=;
        fh=itisjhPtUSRvjf7FeqcnYYc61986KtIe1Qz9ygZPfN4=;
        b=GXIO22beHrGBxGhjTq5l5yapfjASPQgKvnet4Wz+KSgItC4xkqVa5oGQ+sh0VgzfMi
         /vlhX/Z700g7/GQmMxOia5wOqh4g1OBLaYojeoYOG8h0cbALaC0X2ugr0vDjz9JccOmp
         CY5MFq70vhOpkCrUikqKi065MES9rAE4HTcL1QY9d2w7Ds6xX/UVzRBYmpy8i4T4eIX0
         Zp4UHaVbHMQNbjqKXrA1sYBgjBAAkR13j6hLeWsHIPkNIVXd+dNOInkUbfRrjKQbUFsd
         9PKACfDvLRJxJ3rx4dCbk3wLCpQpGgzfmmM8YQovzlhAnsgm3jxZt8vnbJrVm2epawyB
         qi4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yJgBvnLV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-42a31735ea2si14331b6e.3.2025.07.24.07.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 07:09:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-701046cfeefso16899416d6.2
        for <kasan-dev@googlegroups.com>; Thu, 24 Jul 2025 07:09:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAaL4eyoLjryHVj4Rl10WA1LpIRrOcEAq1BQfG6LXMjwkWsUxPoVJ7dz5AXhe7k7ZO/0qgBT56nmg=@googlegroups.com
X-Gm-Gg: ASbGncuM0B8PkhMoRWhU/hkrW258kY9eRbv5YNqc1xuDgNJtgi4q1NDFw4oL2jMs0H0
	KXgyDSqgmzji5YxT2XGUjS37WYMa5+IP7qWfOL/g99Cb1ObePAdnoz3uG24JMffbVUob5vz5lhA
	HOY+MuXyBFPxL3Y/L3dPBkDt9JYaiZFMzHOvzU1aWiOf6eDXNUtskykl1R+VLf9Jnz//+u03mzp
	hQQW33LhQNyvHPECFiEIUK0mPor2g43IqRyTg==
X-Received: by 2002:a05:6214:c22:b0:706:ea6d:e161 with SMTP id
 6a1803df08f44-707007167e0mr87858626d6.32.1753366175902; Thu, 24 Jul 2025
 07:09:35 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-5-glider@google.com>
 <CACT4Y+aqcDyxkBE5JaFFNGP_UjBfwwx-Wj3EONnHdhadTGYdDw@mail.gmail.com>
In-Reply-To: <CACT4Y+aqcDyxkBE5JaFFNGP_UjBfwwx-Wj3EONnHdhadTGYdDw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Jul 2025 16:08:58 +0200
X-Gm-Features: Ac12FXwxdn9n_fsgy-sBaQApTVNHpsQuZ09bYLlik0nb09t323N91TFtaqoJ4HA
Message-ID: <CAG_fn=VBdzEAUHDSOfV4rTKrw6+fdtrAz-mxQwpYxdicUzGoVQ@mail.gmail.com>
Subject: Re: [PATCH v2 04/11] kcov: factor out struct kcov_state
To: Dmitry Vyukov <dvyukov@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yJgBvnLV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> > -       /* Buffer for coverage collection: */
> > -       void                            *kcov_area;
> > +       /* kcov buffer state for this task. */
>
> For consistency: s/kcov/KCOV/
Ack


> >         if (data->saved_kcov) {
> > -               kcov_start(t, data->saved_kcov, data->saved_size,
> > -                          data->saved_area, data->saved_mode,
> > -                          data->saved_sequence);
> > -               data->saved_mode = 0;
> > -               data->saved_size = 0;
> > -               data->saved_area = NULL;
> > -               data->saved_sequence = 0;
> > +               kcov_start(t, data->saved_kcov, t->kcov_mode,
>
> We used to pass data->saved_mode, now we pass t->kcov_mode.
> Are they the same here? This makes me a bit nervous.

Thanks for noticing! I'll fix this one in v3.



> > -       kcov_start(t, kcov, size, area, mode, sequence);
> > +       kcov_start(t, kcov, t->kcov_mode, &state);
>
> We used to pass kcov->mode here, now it's t->kcov_mode.
> Are they the same here? I would prefer to restore the current version,
> if there is no specific reason to change it.

Ditto.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVBdzEAUHDSOfV4rTKrw6%2BfdtrAz-mxQwpYxdicUzGoVQ%40mail.gmail.com.
