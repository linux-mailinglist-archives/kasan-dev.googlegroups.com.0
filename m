Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLEHVHAAMGQESPDKFDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B920A9AFF2
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Apr 2025 15:59:10 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-b1415cba951sf661422a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Apr 2025 06:59:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745503148; cv=pass;
        d=google.com; s=arc-20240605;
        b=THARnGc32Yc9ELVKZ1OMi3k5wpCXPI34KHOwbM19VUy6ZdkeqTecPJjc4qHGkeds4X
         mf+kqEbaowcVHbs4SZQNg77b1Or4ih5+Xw00r5gWQy1o01UWgQDLO+d7MjHJ0n/RzKbR
         mQZn3my6YAaDu3zRodjOaCWu7hYRnXPDjHUCcaksFKWoDSJzhMIr4wqDsZKmB4Ncbv1t
         419CzlKxJxJIhrfmlj323fIdjTj9V7XMbIynktpIhC52NsKhcYmT8gTp7KXs3FHhbLa0
         2XiYhL5nMcLHvo7cT6w1K6kzT1IZVu/1TIGHVNvzSdOP/hTvZuRF1ogWt5gxPcI5WP4F
         QbNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9FuAstH1Nr4XPTaMsdRykMDxkDPb0ks9jPCNyMhgzzI=;
        fh=QUuHSJoocHlEpbtk0BH3F95uwFx29724wnUt9u/kCgg=;
        b=VBmDLZhH6qsKMbv0Wvtglz3NKy8AgRfBkff5ii8BFsJMWRQb7zBok58OcPrRkM5Thg
         JOcAInzW9oSPgCIBG0Zv5/nxQlCkezqfqbQd0i+CL5HbXCdoznul0PCvpiCMxdxuUJDx
         aHl7+SY4p3hqS/hpEn+KW5qvP+HoCDWtIohVUxdR1qBX3gAhmd3ydBPJF5OiY2suadfy
         xupogR5kNfqCDNNhtMpprMkjEWZ3SloAPVvuodSDn3G5ikBHlTuBW0RqQXsMyoqqJeW8
         jkAocDHQRPf0ujVqGiZB6RA9xiVsFANNXu5TNbYnRurovQXE/GoyDC6evzCL21fcqemA
         oNpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AE3mXtds;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745503148; x=1746107948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9FuAstH1Nr4XPTaMsdRykMDxkDPb0ks9jPCNyMhgzzI=;
        b=cQTR4f+XgNWxfNWFZtOcUaXTN0/yuo8UT3X0O94pxIweDxXOF+HvqRyP8Rw38tyU3Y
         rUGjDNBKvD1Ws7Ibf3okzuLNnA5xV/fuyZn4q4d6OSBGesFWibbQtAGX+EpfKEjHapp2
         QWQUNmxLXaqdaQjzbOL4ooHKCXkwdpWUN96rAuazD1kj/x9ptl8wboEhVp+wUi2zDz7s
         JFRjkIWVOgz7pWnSZEta3rhkOn86wJPcpv47c9bMvcjb2ioHAoJ7pCqWKibgVYN/5FBD
         vQF9La8wxTLSPJR4dCvDpcDy725090hASfqVfAWBwsHzFfBSpzcp2fKwr/bky4F28T2/
         1N4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745503148; x=1746107948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9FuAstH1Nr4XPTaMsdRykMDxkDPb0ks9jPCNyMhgzzI=;
        b=wokO7V1OqqzlxFUc8dBSAaVfv0O0WfxxTYmDYcDLjz++s1/3uAjM9KFH8/UgTbfHYt
         FEi2xckBL3o6g8eCet4bOvKATnNSzTqfCHXJXE/REFTYa+WjfMrfPpuSUEEs8D/oPGfK
         zfCTh79pi60XXm+s1eUdYn70dH/5Wq4Q+G5uaIClN8/LrjnK3zqi4yUupG1UYUCkKGdi
         mjCs6GnpSkOtLmpaG2XCmOzpisR9Av3NGpWEJ68ot1NPnSiC1yCJO93/ZGGBXG7m4eFD
         8+JtDdk98FuCAxH5dVZyVi4mEqQTCbpx4HmQoquTjEDMatxM6lI+DOiYwh9y5sM+B46x
         Ab8w==
X-Forwarded-Encrypted: i=2; AJvYcCWS+CvuQ7s9iCD4ICQroiS1pZcpShDgF3sUjoeSgxZ40HZumJ+yeJ2mPEblaWYGQDJdnmigUw==@lfdr.de
X-Gm-Message-State: AOJu0YzRlvKRuJuL3elkk9YHawhAbbQ1jJsgP/Cz8xgL5L4awMpvu74a
	UcynMHERvx6N4Wdc5L8zXv+rQQ9RHkb//g8hC5Mc+zhh6DcYXSR/
X-Google-Smtp-Source: AGHT+IExsxZCwJX0LifvvlJ5TX4NCtizM5z4tqJU8x8DE/fClWxkn4jDjNk7Bg3XJH9lIJyFjvApCQ==
X-Received: by 2002:a17:90a:d007:b0:2ea:a9ac:eee1 with SMTP id 98e67ed59e1d1-309ed27c0edmr4629200a91.10.1745503148429;
        Thu, 24 Apr 2025 06:59:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALjHDYZVSwtZZHG4wJtBTazoEIrmBpE73hwDCN4ETKBMQ==
Received: by 2002:a17:90b:280e:b0:2ef:9dbc:38e5 with SMTP id
 98e67ed59e1d1-309ebd20984ls749616a91.0.-pod-prod-02-us; Thu, 24 Apr 2025
 06:59:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7vFLf+kVps4a/jS4wIsuG5Lu9g0ZK3w8ntqS7HhyeCEMpJD4ElbqU6SIiERKZzXLjhnz3aFMhKH0=@googlegroups.com
X-Received: by 2002:a17:90b:4ec7:b0:2fe:99cf:f566 with SMTP id 98e67ed59e1d1-309ed27c15fmr4142188a91.13.1745503146903;
        Thu, 24 Apr 2025 06:59:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745503146; cv=none;
        d=google.com; s=arc-20240605;
        b=ZDAIUJNbI4kQW/YclRBQbp5u6rEVQIjcG7B+7sKI30ira3lQaLqucEm0vX+dP9LrO/
         KSzlMonk/f+ffotYVImTrkOcfZnQa6lUTFmJVsO0onJ/kNHy1f8VLt3IBQrpyeIk3FbQ
         Qn01VAtdy+Ao+LIPTM98hGvV3jgfiSo0CPH3WHaLTPIfrFrDJxPn2QunNqrdyYbnXT/s
         xI8SEEvB9kIeTSrD8/uqPvErmYly51p6sljh5eLS3eTnFu618JBDLHmpAtGU4MnAh3OP
         9PY7attym8BPMU2391P18FAw2ywhHbJtTNKPWffmA49Ec6OEgM/511ykZPsUJz+A9MPB
         Hd9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pto+LbylSLjB1C6LlqbFL+yEYLFcjU7iIt4pqlTAkNc=;
        fh=x+IWH5dkzcyrzZTAGczkRgj/ewbikLXOWoICueii+cg=;
        b=XBJn2A9+Vz7CCvxM7qNWA7tCU8wApqj1y6jK25wDZta/votJaaWn6Mh4sEd+8zbSm3
         4tGpT7Z2jSQmJ3zD/1gSnJdwHwlpA59mstcyMsfbUWw3uWccteVfkW5peTXBsM7UR+u/
         v6wRWqc44lJhCicB/5t5fDwgnH6mTCYNiElQCGrRfj5Jznoe+sdJ4d0pNN1PqYpmW/Qi
         3Qw6HPENQY57I8uIzfqCF8hoemrhvqwVUai+ka+NL6hKfBh0uGRvgB6QvA6+E/wPI5wM
         YGjWP9A1UzfTrr3Jhiv6uaZxXZ2aGOz2mcdYq6DQ31YNZrMGoX7uWW3orhSstXh3Izwz
         BhAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AE3mXtds;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d3bd5db9si458294a91.1.2025.04.24.06.59.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Apr 2025 06:59:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-6eaf1b6ce9aso12877756d6.2
        for <kasan-dev@googlegroups.com>; Thu, 24 Apr 2025 06:59:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXd7893utx3270D7bcAcGgP/BNe8MZYkl0UFlYtNDFJ/gUCtEqL9xLgb2vcmFnDcVdpJQasCa7ItA0=@googlegroups.com
X-Gm-Gg: ASbGnctiGYU6VylS5heKBNkrC82cdjC1eF26rY2AsL9EWf4xnbFzlgPifnYKBBcFZ46
	vTJIBPH5VgV6Nnkbwk7JTZwURvEzoPTn3RlkP6zfQj/gzTkXlrtw3uKdRJvQ3rH5dgfds3dsd5S
	TJFFZpPErmU70649EpQED9u9k4hJoUnOJVzLgndVUzMAOM+16p7r3S
X-Received: by 2002:a05:6214:2a45:b0:6f4:b265:261 with SMTP id
 6a1803df08f44-6f4bfbbbb5emr48222186d6.8.1745503146206; Thu, 24 Apr 2025
 06:59:06 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-4-glider@google.com>
 <CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ@mail.gmail.com>
In-Reply-To: <CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Apr 2025 15:58:28 +0200
X-Gm-Features: ATxdqUEAntNIADHuPo_njoWHouU5ml7tSeW27VNL67TCm3kup8bcUf3veAU30Yo
Message-ID: <CAG_fn=UBVzq3V4EHQ94zOUwdFLd_awwkQUPLb5XjnMmgBoXpgg@mail.gmail.com>
Subject: Re: [PATCH 3/7] kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
To: Marco Elver <elver@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AE3mXtds;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
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

> > --- a/arch/x86/kernel/vmlinux.lds.S
> > +++ b/arch/x86/kernel/vmlinux.lds.S
> > @@ -390,6 +390,7 @@ SECTIONS
> >                 . = ALIGN(PAGE_SIZE);
> >                 __bss_stop = .;
> >         }
> > +       SANCOV_GUARDS_BSS
>
> Right now this will be broken on other architectures, right?

Right. I'm going to make it depend on X86_64 for now.


> > - * Entry point from instrumented code.
> > - * This is called once per basic-block/edge.
> > - */
> > -void notrace __sanitizer_cov_trace_pc(void)
> > +static void sanitizer_cov_write_subsequent(unsigned long *area, int size,
>
> notrace is missing.
Ack.
> Can we give this a more descriptive name? E.g. "kcov_append" ?
I'll rename it to kcov_append_to_buffer().


> > +
> > +/*
> > + * Entry point from instrumented code.
> > + * This is called once per basic-block/edge.
> > + */
> > +#ifndef CONFIG_KCOV_ENABLE_GUARDS
>
> Negation makes it harder to read - just #ifdef, and swap the branches below.

I thought I'd better keep the default hook above, but maybe you are right.
Will do in v2.


> >
> > +config KCOV_ENABLE_GUARDS
>
> The "ENABLE" here seems redundant.
> Just KCOV_GUARDS should be clear enough.

I am already renaming this config to KCOV_UNIQUE per Dmitry's request :)

>
> > +       depends on KCOV
> > +       depends on CC_HAS_SANCOV_TRACE_PC_GUARD
> > +       bool "Use fsanitize-coverage=trace-pc-guard for kcov"
>
> The compiler option is an implementation detail - it might be more
> helpful to have this say "Use coverage guards for kcov".

Ack.

> > --- a/scripts/Makefile.kcov
> > +++ b/scripts/Makefile.kcov
> > @@ -1,5 +1,9 @@
> >  # SPDX-License-Identifier: GPL-2.0-only
> > +ifeq ($(CONFIG_KCOV_ENABLE_GUARDS),y)
> > +kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD) += -fsanitize-coverage=trace-pc-guard
>
> This can just be kcov-flags-y, because CONFIG_KCOV_ENABLE_GUARDS
> implies CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD.
>

Agreed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUBVzq3V4EHQ94zOUwdFLd_awwkQUPLb5XjnMmgBoXpgg%40mail.gmail.com.
