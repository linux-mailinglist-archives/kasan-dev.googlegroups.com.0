Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4URVCGQMGQEM42374Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D5DD467718
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 13:09:22 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id bg20-20020a05600c3c9400b0033a9300b44bsf1288116wmb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 04:09:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638533362; cv=pass;
        d=google.com; s=arc-20160816;
        b=HvFRZI2xvWAq0TfdT19/jcy8hHkPftXNFt2ZebRLbyFYWXTzg8crXps9I2Xm6KCUeq
         Xjhkydj8n87zSIIKn613Ya3b8Sb4KDT+GoFxE+hINd65gEUrG9Fw14Npnivy0ZH2aR4m
         PzdxQD1VYLp763QVCHGI3r3iHBjBZ6Dq7bNjwICUxUqgCW3C8HsIdDmr9bKtGYJfKx/D
         DgL/IT/6DA92OTozOxgG7JUSdwbQGuw2zh8f9KEVP6X7P/OcKWwSFiJcfWfBWuBTWIHL
         HDyhlRIV48myO1Uv/7f+dcwQqQUU/8XAKyD5vGJLVDadMf5aM/ug8FkiXj8tcAkVyI4j
         dYjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hd3h9fLr9dgRudF58tinl2K1f2F9rh6pj2F9g1VJzL0=;
        b=V7N7uy8/7oVOSsxRW2WpUxuWKg5HwFtMu8hhC8py90N4rLhzI5Uy6rAxX3kRQzQLKe
         Blwy/JyD9x9YdBd3fHlt2vflSHxLslcBVgShEuO9dqpOZ5agdIvQ74UTtsIX5mct3twV
         SrKV4ZXoL9Xb+4svgMeK8eMhlI1QQuJesDtsXoM0Xiq9Ee949sNfOOQ29Fmkfp8EmFF3
         A2H1zPhwqznOoY6fE4VP2C8tvAxYo5/4Y2DmMeWkjcby2A7aBSCupuipL1EU7dQj2KkJ
         NgZi816bIjIy9Xe5fcZP07/4Btb3dGBCFTdTaHQbJdujzZtyql+q8a46ZfCkbB+2OZoF
         Qa7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=acfUr0YA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hd3h9fLr9dgRudF58tinl2K1f2F9rh6pj2F9g1VJzL0=;
        b=rD17wirYyxEI0umm1DQnoxApYKQRIQvKnT8qxKbsOgdo9x9//nFFIz9Mcp0XWdl40V
         atuT5lK+czj/2IMdRpKb0fUJg/I/rLZXbBOfYOtJqJvkbx0Pdv1lFKvMnoYtSZ4YFYBS
         5XXDmKrLZLmVdQHhZnc6jj8Prkdb3oKlFkcNmLOm0fwzf6MAe1G9oEDRQaTSu+Ir9XYx
         yOZ9hb3fsdcmnXNzyKZ4pS/pS/GtH0WN6TGfpm2XtP2skTcAZCOi2ugjuXmAXLkCXU1O
         KSEJFsrIPxyy49QVCP604jJj5Ofx4JhbbPeIDFtVMOfZFgGXh0U8yZEx+skLFc56k97m
         YTBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hd3h9fLr9dgRudF58tinl2K1f2F9rh6pj2F9g1VJzL0=;
        b=Fg8HzPMSMUDvMSYxhAUDDJ93DRMVlIB0aucB62162yyx7XgVMPK6WJ6KZCFvrzpCpF
         Mg7Zo8bHG9+vdnQy3kgxNPlfw65LUAFpI0pOfrJ50qgxZTIEu+vKrp7oWwBHyRYCxmjx
         SVne00EIHopmTiNuuM2CEQjuuuuHY56FIK8D8WCBZusYpKV6gd/soMxkLifRTIawMIv+
         ra3iZJRZtRKn9KOVzasJ1v7vbeco4WFl2R4Mf4BAZVUiw+nQ5t2tLNDJyzlPHkanj1Be
         gK0WXzOJIxn5P3c/M3m8Tkzbp8dxsWhZkpzM8i6sc9UJWcVlNrluPf20acxVWG2rhK4P
         ckCA==
X-Gm-Message-State: AOAM532dBWA7TITEzl8i8SwkcK8iXAufyptjDbls3pVs26JDE9nPyBKf
	OaMsrIXvj5lHygXArt0jn6k=
X-Google-Smtp-Source: ABdhPJy9l1RjT5oP6t4/w3WaXl3mq6NupjPTfPncejwPtll5JGFkoSR2g/F6I918ZzaENcUx+dgTKw==
X-Received: by 2002:a05:6000:1788:: with SMTP id e8mr22671073wrg.45.1638533362293;
        Fri, 03 Dec 2021 04:09:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls345426wrr.0.gmail; Fri, 03 Dec
 2021 04:09:21 -0800 (PST)
X-Received: by 2002:adf:fb0c:: with SMTP id c12mr22871444wrr.614.1638533361329;
        Fri, 03 Dec 2021 04:09:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638533361; cv=none;
        d=google.com; s=arc-20160816;
        b=CrUl2e7p0Jhg2yg6bDI8R4urMNjOhz4aaIOyYJCMziOlrftqG7NqIwVeeUcXBhikCC
         QwEBMwOaO/mNsUvRLQaPUVmOHYFHMu9Wnup3NUAP8iqrWGFQjTyVSFlRXfOFGpa0IVJd
         +nGNw3lKJL/3PLrpSs+l7zbl15HnDMnJ6v/xmOoDpNr5aJmBAJYpcEyI6K91eXCyxBGY
         2wVNkYGICtB4JUQSQydIHMYfDYHlZDwWOsNmYIhRey1kf1QZhMoV414IEYX6EHaigypF
         6iefnknjyrMVZZg4TBpjg7mV2EpFr00qax/3T3yk9zs0p5OIASH4CTRVma545xpEfb/M
         8l+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zGjZvzsKy1y8icyn9C690f6JNNVuD1rBRqAJbaQP+Us=;
        b=Xgs+39iseFCZstoMVGUO3/bVoW0cAtHqPMC9NFI+dLdrUrqoCJwe0Fz9hhEWRx8zdE
         9Ub1dF6f1T7w5KJdcbLF9fhfOBjvm4inz9P6iceKX4zUTzj1ytCvnPQXrZoF9D8X6XkT
         /GceTT5mJZA8ASglKIwPOuJC/ICy+TPVluIIJXabKu6oDCYv4MlOtZRs7X00RxP5C+Dx
         cpYLaHBjxzaC1MX9Q2DlPQqs99ExttKKdfKvbJXF+RVnapi3Q0Vsxwcl4MuwwJLWB3ij
         84HxONlhcCtTF7XGQkwVE/yDtFqgLbSRihGnFDjnY6LqlSGaQuPoqPNWTMnUHGjNcuv0
         tZsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=acfUr0YA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id c2si785696wmq.2.2021.12.03.04.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 04:09:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id d72-20020a1c1d4b000000b00331140f3dc8so2050338wmd.1
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 04:09:21 -0800 (PST)
X-Received: by 2002:a1c:4d15:: with SMTP id o21mr14191061wmh.171.1638533360735;
        Fri, 03 Dec 2021 04:09:20 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:cb5f:d3e:205e:c7c4])
        by smtp.gmail.com with ESMTPSA id p12sm2699606wro.33.2021.12.03.04.09.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Dec 2021 04:09:20 -0800 (PST)
Date: Fri, 3 Dec 2021 13:09:14 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 28/31] kasan: add kasan.vmalloc command line flag
Message-ID: <YaoI6qgQEmzNU/In@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <b82fe56af4aa45a0895eb31f8e611f24512cf85b.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b82fe56af4aa45a0895eb31f8e611f24512cf85b.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=acfUr0YA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
[...]
>  enum kasan_arg_stacktrace {
>  	KASAN_ARG_STACKTRACE_DEFAULT,
>  	KASAN_ARG_STACKTRACE_OFF,
> @@ -40,6 +46,7 @@ enum kasan_arg_stacktrace {
>  
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> +static enum kasan_arg_vmalloc kasan_arg_vmalloc __ro_after_init;
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;

It just occurred to me that all of these (except kasan_arg_mode) are
only used by __init functions, so they could actually be marked
__initdata instead of __ro_after_init to free up some bytes after init.

Not sure if you think it's worth it, I leave it to you.

[...] 
> +	switch (kasan_arg_vmalloc) {
> +	case KASAN_ARG_VMALLOC_DEFAULT:
> +		/* Default to enabling vmalloc tagging. */
> +		static_branch_enable(&kasan_flag_vmalloc);
> +		break;
> +	case KASAN_ARG_VMALLOC_OFF:
> +		/* Do nothing, kasan_flag_vmalloc keeps its default value. */
> +		break;
> +	case KASAN_ARG_VMALLOC_ON:
> +		static_branch_enable(&kasan_flag_vmalloc);
> +		break;
> +	}

The KASAN_ARG_STACKTRACE_DEFAULT and KASAN_ARG_VMALLOC_ON cases can be
combined.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaoI6qgQEmzNU/In%40elver.google.com.
