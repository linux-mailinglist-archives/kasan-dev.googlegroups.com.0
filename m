Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD6XUPAAMGQEVCD4EDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id A37FAA98B0F
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 15:30:57 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-601e231e8d2sf4304818eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 06:30:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745415056; cv=pass;
        d=google.com; s=arc-20240605;
        b=koOSpl2wb+ftHAMUQJUngiQj6O6aFrHv7b6yJwCr2wI6GWcstpPd5jdjohM41mG9YK
         69XceAwvhv2NlXVMbSWbXlnFP4uoIYxsqJ5nT3G6a8mvyGIfKsNIFdn2rYAWyLyIIYpk
         U+5aYKPHt/i6j2AsdJVmHlHhMhaSj0fAP8jG44RWwHOV27psn2NWsJizAhQOLANdT2Dz
         0msIYScTVH7q3iA9+MRa0EC7l2k7YwWnFuP1JBITaOePRw+umhfLnWcnJLBHUQDx7NTP
         xSTSlnDzG7qXg/ptlDRXH1wOaXmVwrOOvLuCOTq2D6XHp1eQFMSOWqM6tZjwHtyrjbGW
         vJBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Eq7RvwqCv8P425pj6Pk72gu4DDdyvAUa/vx5ilKHtvE=;
        fh=oBQylCXh0xxBs/FadGYRzo/dnrNMKENF9+oK9vLVyHY=;
        b=BE8B/FJK1yOZqhZtF3b6XE8ly4kqsHtHxqZDVeDGUlj4R80Rwmaut5UVjDc+LmAuq6
         wgVBun1XztzVZ0SMAtAhf0OvILoH+6P+9/KfMqqxajUoE+j7zcIOG3Sv9u/7bAVF6G9C
         QpqntAHaFOF0Ux7+M2XXt0sds8gohizS6W/xP2/1f8C6uChucVOZXhORT0+ScvUaHGb2
         OUWJq2z2a8GpreKBpHQGoOnu/RKNZY5l0VFoCfAliEv+LOItv0VYPXCCjihFq5q2DoGJ
         3maw+51Hwbo5jd1ZXzNedELh+bqolfFPvkuvHfNVcICjhJjp7aqKQSnsVxrVwC0ByZzj
         YFXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DygAaOYv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745415056; x=1746019856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Eq7RvwqCv8P425pj6Pk72gu4DDdyvAUa/vx5ilKHtvE=;
        b=gIK533aHmo9xJApNNwjwRHjVb/dR6CRzOpotvihbOl3PYwjJWPy7CBMQaqIIk92H7K
         QazcNQCvfUTYoT9DmYOsh5uXf9IkNWJswxZNWLZQ3uucp3n85nkGRkrnnJ0NaDobz0ED
         cO8isSirjJSdcqqHU9UGTnp60Uu3l96bPU1CkhCJP5Z5EW6FoC5LG2VclTJ2jYpyfNpW
         /iX3hi6lBIZlvw4NxTp1lzFXoXYgAg53xFLy+GjY3hefal1fGJRenLyGKmX+ywFlljQa
         drVeWQVmc0AsW17OXsRxsjINOAjjaqwpzn4cLxH3L8gu0AWZ4TR1s+Jezf3k6H54KjMM
         uLmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745415056; x=1746019856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Eq7RvwqCv8P425pj6Pk72gu4DDdyvAUa/vx5ilKHtvE=;
        b=L4/8CulddZX/sgQ2D/rhOs53H93iPZKfYipL3/c52lfoMLYV63WaQ9dzVGFX39MPbe
         CsZ8fbp9ZlzDIHY72jl1+zUmiIZ3jlY3HBYYyozrNoD5JW01UfkCr5s2b5W7WH2Vwg/t
         GiMHaH96malFU2tv9x7jvPuOcFFBL21QgS8wPIIt/TBnJUZUkOLXdyWCvOnWDXs6GAQC
         T0g33ZhjgGQDOPBIpsZ6xMDsEsBjQPQ/kGs4LTYQTWyz5pQzZ2vkcx4IGk2ckRFK2ygg
         5/rNp4P+uTt+Ke3A7IN97iXh6SSTXFDF2xV3BHX3XeOOp/B0yoba2rzWsogVRJUjFcGE
         B7Cw==
X-Forwarded-Encrypted: i=2; AJvYcCWD800lwne/OOLCCVyrIfnEwQSSqwM1gQ97HqZzneax1spSBPmbh2Ne7deTwHXld1+Km0/bSg==@lfdr.de
X-Gm-Message-State: AOJu0Yz15E1J08RoS5VDfVwOGfLuUrBFmfxJyNePXdy8CQgzB904DjQd
	fHdzxhpMGP7G8JNujbZSMQqYxPngvphgJTeVKcX8jXu6dDdarpJW
X-Google-Smtp-Source: AGHT+IEyBmmUZzgiSngl2Gjwas2v/eva11FWWR9gPuit56EaZAl4ESk5tQJ1Bhv8I4TaZq9YL9Nv8w==
X-Received: by 2002:a05:6820:2903:b0:603:f29b:85b4 with SMTP id 006d021491bc7-606003ef78bmr9433393eaf.0.1745415056000;
        Wed, 23 Apr 2025 06:30:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAItRJSxue3X/L3BXTerMrgL4TxZNLzsZ6481Zqd04jE3A==
Received: by 2002:a05:6820:4b07:b0:601:894e:8954 with SMTP id
 006d021491bc7-604c468ab5fls2383022eaf.0.-pod-prod-07-us; Wed, 23 Apr 2025
 06:30:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfq5nMmbj4V/qhI7b7hhqcSxmTorixyOS09m+Uvcfrn2g25PYPB+ucCjC2DgO2KfpYNEOhYWXdTcM=@googlegroups.com
X-Received: by 2002:a05:6820:22a0:b0:602:5856:255c with SMTP id 006d021491bc7-606005e0517mr9929495eaf.8.1745415055048;
        Wed, 23 Apr 2025 06:30:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745415055; cv=none;
        d=google.com; s=arc-20240605;
        b=HjbVi2sUR90w7E8IOrhCTmFRv6Dp8RaOV8hFRa6ao2URCZ9SUR4jOU8/ohK1qOBBCb
         i0sU9r8HrTwzhjUkHLDsAe0MZvvQaYpQNhq7OTHPQPRoIbySW6cGgDgeozOHytVkLkX/
         dJmN4NaCUaJtSs9dWaFi4rP33BO+vJcofkbjys6QOUdY8ebCPckXbs9DomqmoTL87nuZ
         SH98Cbr+kpT0IzLHLO5MwSuRAq0jc5lwahoIzBoyRlHpWz3//0QgsdoEtfqxfTmhTAFw
         iV9OhMGxWYZ6LhtFGwSGpQ+tCtXqXhiJesn1Zx530M5TRZyeQlzKxMXX9iLYaehtUOXA
         y9zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4L5TNO4YtE2jxiFN/yCn5WrVeYAQNfukr6iFB6Lfgxc=;
        fh=7SaPLC8vkX/0d4XegZ1ciM3skdWAOKjBj+ePvA3RIIY=;
        b=lpAxGi5a4cTB9J3sbcvesZ8NUH0Duiqg6DsCrCE7nIZAxaQtu+aN1sw7awyMy0eZjD
         RgXcgIBRGKskmPZ+jF1QCcVI/ioVKaIF6c9jUudwTKkuSotqlx4GcjoeeoQXpFGCRgVe
         IN3XiycmxsLW+RcaAjdMO9mQIo0Nlz6tsCTJnS3HEU5xg34OGCknmJwLcdfSa9Zsw/bj
         tLCCsGmxVB4uJ4igG9RBuLcXoyL9e/1/77XahQ+VTVpPCc41nKxS9JskqYDyZ3OCv2jw
         yVa9GgqHeXUQ2jh5FcWvbCqC6mPAE/Hl1k4uFhsRriCmaICRonumIX4h7cYh55yFKrfN
         RtKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DygAaOYv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-605ff4f153esi485236eaf.0.2025.04.23.06.30.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Apr 2025 06:30:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id 5614622812f47-4003b22c2f4so4108323b6e.0
        for <kasan-dev@googlegroups.com>; Wed, 23 Apr 2025 06:30:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSMspQe/RQDFmD9/sS3B1djLh38+dIgnKyj1fOUD4khp9p1YjTBxwb1wZgmO4eaE7Sb1XKL6ijIKU=@googlegroups.com
X-Gm-Gg: ASbGncvMVgKrX06SazK+L1X+w0aq2buN6/wkX7meWJjckukbMZAMf595ILNVFuG4P3S
	lp42ITDRe/GG1O+rHkb6vtUxyijHr90Z2Ovm1DqqRkvy293bDS0QrXiUDFqVAe1fXllNExdF4zG
	0F1FaaUGKFETl98Q6c4VDHL3L/DnA8o/Lm2ZMorudVQh0YI9NbXo0=
X-Received: by 2002:a05:6808:3389:b0:401:e949:6374 with SMTP id
 5614622812f47-401e94965eamr224040b6e.16.1745415054538; Wed, 23 Apr 2025
 06:30:54 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-6-glider@google.com>
In-Reply-To: <20250416085446.480069-6-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Apr 2025 15:30:18 +0200
X-Gm-Features: ATxdqUEd4B89CtgCh-IpkJ7kUq5K69XFf4rQc1EYsavp22XzPfItwK0vxopKh40
Message-ID: <CAG_fn=VfLhCNdU7Yu5D_nWuaxF7nU=YVirK2aTPM6h9o2wsy5A@mail.gmail.com>
Subject: Re: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DygAaOYv;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::230 as
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

>  void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
>  {
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> -               return;
> +       u32 pc_index;
> +       enum kcov_mode mode = get_kcov_mode(current);
>
> -       sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> -                                      current->kcov_state.s.trace_size,
> -                                      canonicalize_ip(_RET_IP_));
> +       switch (mode) {
> +       case KCOV_MODE_TRACE_UNIQUE_PC:
> +               pc_index = READ_ONCE(*guard);
> +               if (unlikely(!pc_index))
> +                       pc_index = init_pc_guard(guard);
> +
> +               /*
> +                * Use the bitmap for coverage deduplication. We assume both
> +                * s.bitmap and s.trace are non-NULL.
> +                */
> +               if (likely(pc_index < current->kcov_state.s.bitmap_size))
> +                       if (test_and_set_bit(pc_index,

A promising improvement would be removing the LOCK prefix here by
changing test_and_set_bit() to __test_and_set_bit().

> +                                            current->kcov_state.s.bitmap))
> +                               return;
> +               /* If the PC is new, write it to the trace. */
> +               fallthrough;
> +       case KCOV_MODE_TRACE_PC:
> +               sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> +                                              current->kcov_state.s.trace_size,
> +                                              canonicalize_ip(_RET_IP_));
> +               break;
> +       default:
> +               return;
> +       }
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVfLhCNdU7Yu5D_nWuaxF7nU%3DYVirK2aTPM6h9o2wsy5A%40mail.gmail.com.
