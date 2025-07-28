Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFV5T7CAMGQER4VPYSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FC1FB14338
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 22:33:28 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-31eec1709e7sf2232102a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 13:33:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753734807; cv=pass;
        d=google.com; s=arc-20240605;
        b=HfyOCzpxxTVFAbVYVhz6rsXPUWs5cNF4Cw+c63UsPPatltFHNomHVvQOM6Bym4LK8A
         7TjEY8Sb6z7mSgWIYBQjviNmNa43OYV4+2KrlkvVydoCKPsqSZFcQ8NcCWx0Xf8RGoyV
         aoGTEK4MGY2O9x6qw7juO8W7fW91YrS7yz7Ke8m8b5qzn6iKYTg3GMmIqIt3rKbl0VHl
         tp28SYVc9ikPXVme+asEdNxe8F9b8g1tLU2BtApvMJCLtWeUBMoHOwiSCOTRBC5GSCAA
         Ns/tJxf+RDLPrHcqWGPIXLzzHK71PRJ7eGdJsUB/uWGa6WoB/BJvy9jv0k4Blmf9+EET
         Y7tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RhBg/uW5CSqin++CQLSvAoHdjt6YfclVExyKv39KOmc=;
        fh=hmDhZdp9dlmh5ZcWf2YGe/eKTDmWKcmqU81FzOevQIY=;
        b=AQYJE9gWXXPX1fSUyyzgxlH1Gr6eYWMvZxXMMISuetzpNvD3XR1AWijtYQlfizngSc
         mU0oKOhJQacv82uzKNnvIdZwibXvQB4RdhulXpQY2sVcZFWSPC3m4zW5jo71C2ha46Jz
         YaIB4L3LPxLH9NiRC3unO+AkCCjt7bO3AKlLatWM/4uNCp3YvMyoOChk3hN0CO6RtixP
         UMJ9bnZbW3YQVJMt2noJuZm2Cu5BMPM00PSgGDaegu3QwFSkjBEzAd5e5tt88+78VhhX
         LwlfVHGO04QiWwkYjFWGndcdAOrN6NX6j86hmWStmkh9a/WzIWhioJVK2RfkW/5iLAQa
         VLRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h9EXv1Sd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753734807; x=1754339607; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RhBg/uW5CSqin++CQLSvAoHdjt6YfclVExyKv39KOmc=;
        b=Riydz9zLCXxK9dHsmhEu25+AMizP4QOEByu+dy1FTQsEmyB2gYTlS1Nf8xnLpKFRvW
         UK34wCaKpRlc3gZpaODSSxtk9fmf+jtJjxZarSDqHCmFmBCI9epzHFrCL1oi/RKLOsOR
         1Y3I/Ej4yWZ1y0hr7hqTfMUc2Whrn8nFrdqntQX4lfmRYvSSnAddcvloVtNVEfRezY08
         zg3bHEpsaxtaJ8q14ReRERnBS+7gm6jYi88r+JLc3/AQMbULZ/NHsXOnDwIzkRbAdlrG
         PlIY6t1V+DDXgyqViVCo4tEAwuQag98S2Go3yq0RPjPFuuVFWfuGtYZqDi4p4pElCUev
         lOwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753734807; x=1754339607;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RhBg/uW5CSqin++CQLSvAoHdjt6YfclVExyKv39KOmc=;
        b=WOlKfqPcl3mJU9dbzOoIUFHfgi8yHVROJ5rfWVp4g4uNfrzo4MvwtT3YqQi5yR82Fk
         chFl71jdW5EEL5YQBdjjMARtCUfbmuQ2vgS4+m4cHrR6ZIg0vYST4V9ppBjcJWMOI7Fr
         I9D2qbCXoFkiDyUXdVo2eIm+MfaW+6qD26Ir1Tl2UsNsk+3HmIjW/FnJxlJkP0bunHt6
         N1Q5/j+WqMwRBjJLIXOHv7Z2OsBCAXBhxX4LcL1HPtr3uqgqM+XCtHPLOXRVP2+TiCu+
         OZ91uxrAtwY6INtBnwYaNNZnU3jPIlUdVpwCim0jPlgfRlJCgfXk6WwEGRPy3C+wvK2H
         3A2g==
X-Forwarded-Encrypted: i=2; AJvYcCUl8XQUoadEXxYHV+/y/KrY9eTJiGZbtSQSj7Yl7ICjJ0ZWdxDNVoEoJrD0bo1IHl7C4ou7mg==@lfdr.de
X-Gm-Message-State: AOJu0Yy1IZJlCHXQeDScqGiUnMdeSRdhHvXKMtUl9myTGJbzl2fyahJU
	JzEiqJ2Qeh9HJXIIJpCyfaoYeVKNS69cKjjWO9p40QzkBR3b5qjsC7Jq
X-Google-Smtp-Source: AGHT+IG0KVT+3tJygyJQlEIoa2yB0psFZJ9JhDLTRCkM08ibaezzy3NO4UtYp7cKVbf6CEk3buvhtQ==
X-Received: by 2002:a17:90b:268b:b0:31f:eae:a7e8 with SMTP id 98e67ed59e1d1-31f0eaeb3b8mr4674956a91.11.1753734806743;
        Mon, 28 Jul 2025 13:33:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfsOki58RkTYDy+SiGnSmdwa0828AjBggq7jLYC1AJfdQ==
Received: by 2002:a17:90a:1543:b0:31e:d9ef:bdc5 with SMTP id
 98e67ed59e1d1-31ed9efc675ls1116529a91.2.-pod-prod-08-us; Mon, 28 Jul 2025
 13:33:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUyo8EN6Kp67IXBD7IChWalMpxZtriSF1O3QawmVA7gAJBX1wEYXNXMpcrPmLm7nfdKyfFOZ3KwUAg=@googlegroups.com
X-Received: by 2002:a17:90b:3ec6:b0:31c:3669:3bd8 with SMTP id 98e67ed59e1d1-31e77adba28mr20907944a91.21.1753734805259;
        Mon, 28 Jul 2025 13:33:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753734805; cv=none;
        d=google.com; s=arc-20240605;
        b=ES7mIztFJX+VqubEM6H3XKfGEMMsYORnwrC5AKrViwdZQ6EKcIkw9OZmx3unnFG7Cr
         BYP3tgEboL7eQwh0PmKqqsdFVqcArmTseqleeupqRrLvCpDr2WHRKaDRci5Xz+/6U/HB
         SfuWPX9Q85YLP3I2ruSdFlqAh+LFHt/jF6khIaKpb7fD8OMODiXrBxCahcg3Rc/TIhnD
         kGORLL4g3ZCh8TdB31p6e3sOSuVUXL6AuWEibBqtFpYrb5sqEtz/JhsBrIC3GVZuMwc3
         RcnFpj1Br7tMHhTsqqjARE/hf0piwGq32LudLlEP/4wxo/G4P7cTApAqDW9DnqIsPnPC
         dH/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OUBXSlb6O3h9wA9dBxb9GAArtBxswFFmvqz7tVHohcQ=;
        fh=iezfgFsWWkGBMT+0v5qEeIOGJV8IBRjZvaiASHu50iM=;
        b=Sx4a9qrRdjx3Rg1/KA48ESnExEp+HPlp70I1CDZz17BHG7nrdLyN6l25OUH+VyHMgA
         IL/sX9/gH19JAlFUlv7nsALfiSoPorOHRu49hdzasbebKVE6EXMNJRSxoD2sYcc6NS+5
         SxJ8VlLsZOjOhbIToyYUy3SkIlYcat4TDn2DIx71TVrXjg92xZ6Q3uQT9j1V2rMDwHZ1
         3Omo+uiSPcRHPoe1KKJoMdQwXr0nVmaidrIrdWEnd08KGBZdRehBJ56FaR7W7JWUTXIo
         EgDiAF0GNoxG8W7BGraUCd0jcB7br4BIuDk2feK5TLNgnj/7U5bYt80GrMn+HypkEgcU
         AhcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h9EXv1Sd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31f175c4de3si70051a91.1.2025.07.28.13.33.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 13:33:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-31e3d29b0ffso4459758a91.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 13:33:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUXfFJRqITEaaozs9fAVIoWweTtUSbPyZFP/O2ddzH2RE3BQo/T4wbLZrG0YcRTyp3+JVrA6DXay0E=@googlegroups.com
X-Gm-Gg: ASbGncu26fon0vRrejFvizauN5b4Z3zNXhIEI/2L3WKGz/gIDZ8c7QL6rgHcIUX0gl3
	e/+7SCgsqaWNEWQ+TuR0YIMbCuswmh/7gjFep2w5SoMDOscuTKl80kquy3WoJCs5y8pGY12Camq
	BxxZViPYxvLfSxAg00K8a2btHbnyY++AhyrVRiSL3qls1/TEFDgIZHbhLzdpETb6/auv0LUHYBP
	9DU0bV8zNeNhA9LyZEDpsbFLHkz47W/eVLBvLM=
X-Received: by 2002:a17:90b:4c:b0:31f:1db2:69b1 with SMTP id
 98e67ed59e1d1-31f1db27000mr3287346a91.18.1753734804686; Mon, 28 Jul 2025
 13:33:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250728184318.1839137-1-soham.bagchi@utah.edu> <20250728184318.1839137-2-soham.bagchi@utah.edu>
In-Reply-To: <20250728184318.1839137-2-soham.bagchi@utah.edu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jul 2025 22:32:48 +0200
X-Gm-Features: Ac12FXxrA0KuBzkm3AL3l8gRNoz9nEwCgGw777gfr_Ks9ZDLjrKOw5hgi17LW5w
Message-ID: <CANpmjNPWzJZrAFT3-013GJhksK0jkB6n0HmF+h0hdoQUwGuxfA@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcov: load acquire coverage count in user-space code
To: Soham Bagchi <soham.bagchi@utah.edu>
Cc: dvyukov@google.com, andreyknvl@gmail.com, akpm@linux-foundation.org, 
	tglx@linutronix.de, glider@google.com, sohambagchi@outlook.com, arnd@arndb.de, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, corbet@lwn.net, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=h9EXv1Sd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 28 Jul 2025 at 20:43, Soham Bagchi <soham.bagchi@utah.edu> wrote:
>
> Updating the KCOV documentation to use a load-acquire
> operation for the first element of the shared memory
> buffer between kernel-space and user-space.
>
> The load-acquire pairs with the write memory barrier
> used in kcov_move_area()
>
> Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>
> ---
>  Documentation/dev-tools/kcov.rst | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 6611434e2dd..46450fb46fe 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -287,6 +287,11 @@ handle instance id.
>  The following program demonstrates using KCOV to collect coverage from both
>  local tasks spawned by the process and the global task that handles USB bus #1:
>
> +The user-space code for KCOV should also use an acquire to fetch the count
> +of coverage entries in the shared buffer. This acquire pairs with the
> +corresponding write memory barrier (smp_wmb()) on the kernel-side in
> +kcov_move_area().
> +

This new paragraph is misplaced.
You've added it after the "... handles USB bus #1:" part which clearly
should be right before the code (note the colon).

Why not add what you wrote here as a block-comment (similar in style
to comment above the sleep()) right above the __atomic_load_n below? I
think those details probably don't quite belong into the high level
text, but the detailed code example.

>  .. code-block:: c
>
>      /* Same includes and defines as above. */
> @@ -361,7 +366,7 @@ local tasks spawned by the process and the global task that handles USB bus #1:
>          */
>         sleep(2);
>
> -       n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> +       n = __atomic_load_n(&cover[0], __ATOMIC_ACQUIRE);
>         for (i = 0; i < n; i++)
>                 printf("0x%lx\n", cover[i + 1]);
>         if (ioctl(fd, KCOV_DISABLE, 0))
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPWzJZrAFT3-013GJhksK0jkB6n0HmF%2Bh0hdoQUwGuxfA%40mail.gmail.com.
