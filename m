Return-Path: <kasan-dev+bncBCMIZB7QWENRBRWE7W2AMGQERBI3S6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D305D939C09
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2024 09:56:55 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2ef62acc9ffsf14267541fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2024 00:56:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721721415; cv=pass;
        d=google.com; s=arc-20160816;
        b=fw3azpqVp9P4DxjBlhlIbqlX/GU58bXmgHUl0QbjWKHE42ry/WxqT7ThVExrr/OBuR
         XFunonfFTxoN7IBrrV0SYM5POyJ5DoYnN7un/Hz4TxmjlKuMWdRl8+M09bp7w+OPDGkD
         F+y3S3spF7CKMscMCC5iiUmrvhpX1C2nj1H06REWTCPTMGfkm+uzRNJYajvleRFHkI2c
         nrTmW3FdSjlZxZpwWAxFfTUuz0DTRdAYSAhhNOJe61Q5+kzmI8oaoktErEklRnQK7WXV
         QAMAdoB4WFCbyBpaJ3diKO4MxpoUu6gWbma/2UmngMdlr1orHFNsYkW3zr1q+3PWi/KV
         Wc9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wyhMmb+6UfLk1jZm7NFNY4yOWrJNXJo2wxVd19koeoo=;
        fh=5yqsAE5pg+oKC6jsh/RBxMcplQbWFPQy7a4PmhaUg18=;
        b=OhKzzeXAM/CbGYXlZaRfFc4isiw9VEIIVzw7h5YCA0RxDVygKfl1gHvVZEhNWGKpNp
         7M8BNJ128Afzihaoa35S4mblO/uVGql+/aYBc6ZgNvC5nTwN4CcZam+UVFDgyzsZumnv
         I9/2qc3PX9mrDz/RkJu/eJNAU3TqMqLNtjVXmNCvilCRcGD9uni8B9odMVLuxq48FXtS
         xPBM3qvUfh6K6zTYQo8yQohtP7BP5TJ27YUphRYvBn184NV9G69DSycJ3UEBayqdldN9
         7hGQMBJAkZlg3A9MK95vFP57u/K+VdFlniU7Zbm0uK3QDNmi5wn+4vtjng8qiSajjzUW
         xxFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1SBrkfFT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721721415; x=1722326215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wyhMmb+6UfLk1jZm7NFNY4yOWrJNXJo2wxVd19koeoo=;
        b=R9M4MKBTWOOQD99dxcL7sEed95KrrJF5t0DaU7Y4MmH0WG1k27FkG63O0cILh4hyxC
         dPjid/ciR2nanTaZIosylUtHzyKXhoNtPFjN6bYIJvm3jrw2+e9RaqkPEVlXgaFV2xLi
         L+OQ+xGLkIzSh+9TOqM63ersRoBFDXMeqG5xJl2Yfu8tTZ3tEgax1pg4jMrcoyMfdf8j
         n9twAstOm4G0iJhliCg9dsbG9txUW8ZMu9qbet1ShZ1yPVYoNTOHqQoD0lAYzlpPdo09
         YHLF3S83z13xQPxJTBPUF6ytMIn8RZFX46TN4JTMdWsBWLAt2NJ3Ah7VUOy1UUXi6O4n
         421Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721721415; x=1722326215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wyhMmb+6UfLk1jZm7NFNY4yOWrJNXJo2wxVd19koeoo=;
        b=bdJaTv+JKlr/pb6kIXJmX8Ajgd/euS09zjA+jr5sW85RTcg0SNw7TuHscHmeUeOVJW
         f/JPNv4XjHv2mSIqehooySDZEpt2knTrTpjUCkJ/bT8vImbdSmjFCwfyQjMZRPMROU9Z
         t+5tn7vePRlcqopNZAqw0h+dVr25eJyt6zphlgxopNrx5nXyqlwGnrYBrJz09nz/KwtR
         0E1mdJblpStFFDscr288y0yEd9RP0xiMLJdTJoLHxxDGMk9Q27A+iCADwX/LfK+Ousdm
         Pj80rbQtOZWwKEjf6NIU+bh0IDIErKjgUkdlPQge81MBb0MZgUhRMvnnxNOHSC9vGwD9
         5M7w==
X-Forwarded-Encrypted: i=2; AJvYcCWBWd1BP24li65fDaXH1VyR9/c7Lt7o0JJY8zXMqQ0IJmQqTjDOPq5pBY1TfysJ31UgJ0AVqRxbWJ1MoJdr9zDld6S2DVHW2g==
X-Gm-Message-State: AOJu0YybDvRBYuPQO5bhl92vbGiiNva7n7B+JJXmfYjNt1sT4IiiBLKm
	AIixkWV7AQuSWFNRlZS8WK7ZCoXxKsmiEy8qA9YxiWwQPAnyudXB
X-Google-Smtp-Source: AGHT+IGGJ9Lo+2X1tW2o0CBm2YnIMrjptJwbuRjBWQ3qH02GEy0zMVZZcIEJRe3EHeLTOnPcVw/k4w==
X-Received: by 2002:a2e:8053:0:b0:2ee:df26:9d4d with SMTP id 38308e7fff4ca-2f01ead522fmr14114851fa.47.1721721414631;
        Tue, 23 Jul 2024 00:56:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc09:0:b0:2ef:2eec:5052 with SMTP id 38308e7fff4ca-2ef2eec52f8ls7901231fa.1.-pod-prod-03-eu;
 Tue, 23 Jul 2024 00:56:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdIrvwj3aZfhbC5+cBrp5RccNagwSZIHwxPV1X+kKYgwtiDPvyp6y20kOYFmAZXIOlWzAPgMHm2IGQw/NCTBK2dhTqXMKdEpeZPg==
X-Received: by 2002:a2e:9959:0:b0:2ef:2c0f:284a with SMTP id 38308e7fff4ca-2f01ead523amr14369091fa.44.1721721412571;
        Tue, 23 Jul 2024 00:56:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721721412; cv=none;
        d=google.com; s=arc-20160816;
        b=VzeLozXzYv0tzmFXPJLghKX9Bs45zXQ/InEQKNxHjYOSb02+r6pPoWGKJ99u8tIc8f
         KdcOSjOqDa2Mx+y1o6WR861eLt9S3EokTSt5hwwxirCr8k1m1bOSfH/Wep0Lbu9UL3RT
         TJ5alolfRzWcxpNmOsyUKZDKo7LzXQxe8ZytqXVEVEjeWZQwChJ//4zufSnzHJPmRdBI
         l7pQzHXYPnRGzuag+nR5592tHauf7Wm839J9RDeeFXAsGKm2drIBrFWvIPQhD4b34n98
         A7z8WPvHqjszUHYzkcKAB4yEhWdmVs80ECsywrJQya0tGVeiG1Kpqr/ULvwNaxeI3YY1
         /ICg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1GR/uOEg6eBIIHTSjN+mU57G2H8hU3EN0wvpjh4VCBE=;
        fh=ZSU+E2vHUpLeeZ3X6tMjQNOyx6VvJUy2grU76XiuQAQ=;
        b=u3UngFzPkrBXxWldbfE7t9byu1QUeFJyyE8wRoBE/4je3AdWSA2ZBSor42+okFIKik
         bB7Ur3tutaGNF9o1qKTaIqJUaJDQtdorNamVw2YEfalIwdy74sCks34mFojCL9X5XMBh
         dyq8VhEs486m8dHCLug2Iwl/vh+tVPz6brgMqGByfdujtt5W13uj2VLx4t8tLbpp2GMc
         ozup6iI3WnehXD1j94u7VFPvM4t+XHtbUjS6VROK9jDEnlYKc8QdEfDRtb0Q1iulOwv0
         WpmS6jotIBFC6ue01h5r99UBBp1fVyIR26g6LwmktFDv+agapk47ZUY6QRNRR05ZxsXc
         BfiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1SBrkfFT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f01d458265si451481fa.8.2024.07.23.00.56.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jul 2024 00:56:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-52efce25f36so1262e87.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Jul 2024 00:56:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVTvlbAA9XkGbhkAcKBpdktx65f8qnHmpUvSYiPoRf7aXVvIfQKBE7eR4imWrptCoEhaIzs0esH8FBle+zb5wM4Cg4kbbTnAjDuGQ==
X-Received: by 2002:a05:6512:6c7:b0:52c:ea5c:fb8c with SMTP id
 2adb3069b0e04-52efa181580mr249357e87.2.1721721411790; Tue, 23 Jul 2024
 00:56:51 -0700 (PDT)
MIME-Version: 1.0
References: <20240722223726.194658-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240722223726.194658-1-andrey.konovalov@linux.dev>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jul 2024 09:56:39 +0200
Message-ID: <CACT4Y+bA9mMmU1ZvNB2OgoDZ0jDBvFH38FQmxCKee7L_TNpvXQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't instrument lib/find_bit.c
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Yury Norov <yury.norov@gmail.com>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1SBrkfFT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 23 Jul 2024 at 00:37, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> This file produces large amounts of flaky coverage not useful for the
> KCOV's intended use case (guiding the fuzzing process).
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>
> I noticed this while running one of the syzkaller's programs.
>
> In one run of the program, the number of KCOV entries amounts to ~300k,
> with the top ones:
>
>  117285 /home/user/src/lib/find_bit.c:137 (discriminator 10)
>  116752 /home/user/src/lib/find_bit.c:137 (discriminator 3)
>    2455 /home/user/src/lib/vsprintf.c:2559
>    2033 /home/user/src/fs/kernfs/dir.c:317
>    1662 /home/user/src/fs/kernfs/kernfs-internal.h:72
>    ...
>
> In another run (that triggers exactly the same behavior in the kernel),
> the amount of entries drops to ~110k:
>
>    7141 /home/user/src/lib/find_bit.c:137 (discriminator 10)
>    7110 /home/user/src/lib/find_bit.c:137 (discriminator 3)
>    2455 /home/user/src/lib/vsprintf.c:2559
>    2033 /home/user/src/fs/kernfs/dir.c:317
>    1662 /home/user/src/fs/kernfs/kernfs-internal.h:72
>     ...
>
> With this patch applied, the amount of KCOV entries for the same program
> remains somewhat stable at ~100k.
> ---
>  lib/Makefile | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/lib/Makefile b/lib/Makefile
> index 322bb127b4dc..0fde1c360f32 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -14,6 +14,7 @@ KCOV_INSTRUMENT_list_debug.o := n
>  KCOV_INSTRUMENT_debugobjects.o := n
>  KCOV_INSTRUMENT_dynamic_debug.o := n
>  KCOV_INSTRUMENT_fault-inject.o := n
> +KCOV_INSTRUMENT_find_bit.o := n
>
>  # string.o implements standard library functions like memset/memcpy etc.
>  # Use -ffreestanding to ensure that the compiler does not try to "optimize"
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240722223726.194658-1-andrey.konovalov%40linux.dev.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbA9mMmU1ZvNB2OgoDZ0jDBvFH38FQmxCKee7L_TNpvXQ%40mail.gmail.com.
