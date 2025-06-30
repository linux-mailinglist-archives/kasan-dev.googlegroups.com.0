Return-Path: <kasan-dev+bncBDBK55H2UQKRBPEGRHBQMGQEH3SATCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 82215AED644
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 09:56:45 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3a50816ccc6sf1175547f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 00:56:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751270205; cv=pass;
        d=google.com; s=arc-20240605;
        b=jpOPuBuJgWmwhG8qt68/gfQL0OG9VujMy1FQmRsmPAnlB1emE+gD9rF+cb8vSyDsLi
         aUrgjcTFwcKi/gzgZf8hbyCvxtwdiInkC9b9XAB1HpHTfEXaOGDrEpd+rzTt6mnbCZoB
         tbhjfvGvRgH6HaemaXHUr0mRcl0H0ZUeDK1KtCpXtyhKS1ALDYH37mr3X1dppz84tPvp
         8iN4UYmarkEqjkEYywivGOfLijTSdt0nG0GVPCwDUN8ZduLV+82xVhCC06lz0tpKXwcI
         /X24O3GTNg4B7zl6I5K+30JdiImd5DTsdhyDvq63A3T/Egt8ZT0TsRFn5e+6K6NU/ePv
         3I0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HJ4lFpcPPDp0jln2LVyk4yOKAAaiq9aQaeAfwbOm53I=;
        fh=BlbswFilVvOZWptKhSKvaj2Jpyzl2VEL89GQRjbNHAI=;
        b=X3ZxIFkY/sD9QWkz9Q2nsXZEVytX/APN8wJZ9TLPimvI3MalFF6oOyTWDvGdJJi2G4
         8snjj7w0a06XGzcFGdMQH0pldS9b/pYEZIeeHRZbkPubQMCxoTuX8ldAWS9quPcmrn9f
         oV5GhxTwWeGAX+Sklcin2et8DQ7LOq3Cibwj6IyqOTJDAVVc8nwL3TfuHofiWypHR+mQ
         6baD2IORDlqU5whYLa47fW5ly1FEFovwpUPii6OKrZWpPigtvKsFlq/zOm9p1ViD98FR
         uUzNliSQhcUimHiUHTtN014kdeiiVPjmAU7c6P+vpFs/ugwPeqJ6bxbbd0Y8Xe2hTAHT
         7DJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=H3StGTsu;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751270205; x=1751875005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HJ4lFpcPPDp0jln2LVyk4yOKAAaiq9aQaeAfwbOm53I=;
        b=hwZQoslSwD+FMBZhjnZEC110jZDuFWg9uMAlP96KXof03ouReyGrzQ1jlv3BjpIgmT
         uCGBetd7aqB12g8pTwFG6e1faGGLWqTPUWqecWUgQ48F8Bx/MXvhTyaP+9rwuBXUCFP2
         O9k2WWylz1ZiSKLS2bsh4iucuBDBki2gDrIoNPTTMX7fA5hbIaiZomnjNjh8Ddms2zD9
         3kOTwdUuXDVuUdDnM2Xt6+tp0EU3iiQHZ9rBmRO3BrKrEyzVHI5rJ18eJzSHcGcUcEPu
         TQWchEMyzUSndkdbb6l9YZ6tSE4PN3PkOjpobtOmCX2fCz232yPlbsyTXb9tD8+5VuJV
         mseA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751270205; x=1751875005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HJ4lFpcPPDp0jln2LVyk4yOKAAaiq9aQaeAfwbOm53I=;
        b=F0Ru4OuJwox8/6jh7DdGAiMotsaFJq1yASYUeSZvm8F6A2HOm6Dy/Xc4ihvo9IwSHf
         Yh5E/GMQkB0znRPTLqE/+zXd9JaBDVIxeEc1puYwAy4/FHvo6D2NXHQErPRJUlPKf9Mm
         ZTT87zih6zcHxCuYHiJmslLcc7Z1Ub3pkLcPm3V7gvJez9nOW9/2U+Y/VDace8W2tSm0
         r57oSw9cEny2r3gSahYkm8E/Cude5eODJKr4ukGm4pR27GIKBURjLhOVmgEBvg5W9t7b
         FxOsNRybZdqJ9qvnwusUnQl9TjbSmoGFLMGPqCkMSUh6cRGti4B6BLy3hA4UP/LEQ8Au
         s7gQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgREzcHAfW5g4MCXpxPwL0c59bhud86RUumFvTpriswLUj7eBjbdKz+jRysh+/LpXolAfOng==@lfdr.de
X-Gm-Message-State: AOJu0YxbsKLESVMamYaMDyPDvLsqM6iOWhr4WSfoP8nMxo5gk0unx4d8
	B/U84i1/eHgIuo1ALwFjb/7k1EVvGoH7hpWKJh8jJdFbyr3wDdPQprLK
X-Google-Smtp-Source: AGHT+IHdQvzS7vmOrzS0ryGLUlHpLoZPargvb4QE8ja0Jg/ORdpcD2+DfjQu7V0yzhTzHwHW9BSq+Q==
X-Received: by 2002:a05:6000:2d07:b0:3a5:2cb5:63fd with SMTP id ffacd0b85a97d-3a8f435e569mr8042565f8f.10.1751270204592;
        Mon, 30 Jun 2025 00:56:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe0mMZs04HQnjGRbhtPUBhK2aCfj/ed6Y1Zc9QkJVR35w==
Received: by 2002:a05:6000:4010:b0:3a4:eed9:752b with SMTP id
 ffacd0b85a97d-3a6f329e493ls1882866f8f.2.-pod-prod-09-eu; Mon, 30 Jun 2025
 00:56:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlp3wgUFMh/RXvVCRI0few7hJUtmtfUd0PF45FDcuyh0a5suItoMuPzUQyc76VX5yrOwTzxutVFMI=@googlegroups.com
X-Received: by 2002:a05:6000:2810:b0:3a6:e1bb:a083 with SMTP id ffacd0b85a97d-3a8f4ee111emr7275944f8f.25.1751270201344;
        Mon, 30 Jun 2025 00:56:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751270201; cv=none;
        d=google.com; s=arc-20240605;
        b=knknM0UZnYmWJUKTWmIt18QHU0LMRmH3QMCvLc8B/ZQhrn/HS9+QdAP20FOREUXRpI
         y6f9miUnPszupLlLlaIeRqXch00QhLNpDSDQ1ISETlDg6KFULv8IpBtbLIcxPVFEF3Yq
         R6vcLJLqVYTjBY+8ZpccPsViobCTkQpp560tGYr35Bc1SkDNua79Ub6S9g4JFpRZ0nNH
         Pzw/huQJzUuwOpqfy452kOBukvOH+j/li1WT6l9VbA/IAey8yb5DECb7r+n7WIlULnoF
         Y7QcSQEMjdt2Jjsf8tI4sgR0moRFbsUmOw6p/6w8wlUt4ll0DIg1o440mL9xEcKHZgy4
         LRbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=clXotmQK2fBKk6NffSDoLpVZjlb7gWYryEPzX0KmYXw=;
        fh=RPPJJnE8BHlvVfJC/VoJ1AA/H2qLCDX57PIIfNZsptU=;
        b=SGp+IaggAJrwRt4jYFHkkaQem9aNEhmOG6i1vZkcMZkWi28mtvxdytGCXCe3mK5Hny
         gpz+Pdx6BhjtgjIC5iWZA7b3ahn+O28nbYBMXbjPgzkloMgk3pSDR4j9hcsYk/CV11yU
         d5UxpLWsm5wVyGvKUGCl7KF/L/+OfF5D9mnUll1e7dQuLhaDa3n0nUErGEzRLkEfljzR
         YT4D5s2u4hz+IBg2qu51I7kdNPFt/rMjnAnaMkG+o4b/3bTB9Zb9zPWWhQ4BnkL06zsc
         qqUxehYWxDYMDDKDa0kam3wPihCqlBD0K/C5PXhYYP/XgGKHZBwGdATRWAqs/V+XysOQ
         vByg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=H3StGTsu;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a87e96a387si568620f8f.0.2025.06.30.00.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jun 2025 00:56:41 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uW9NX-00000006k9z-26hv;
	Mon, 30 Jun 2025 07:56:40 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 14413300125; Mon, 30 Jun 2025 09:56:39 +0200 (CEST)
Date: Mon, 30 Jun 2025 09:56:38 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: Miguel Ojeda <ojeda@kernel.org>, quic_jiangenj@quicinc.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
Message-ID: <20250630075638.GJ1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-3-glider@google.com>
 <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=H3StGTsu;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 27, 2025 at 02:50:18PM +0200, Alexander Potapenko wrote:

> Setting AlignConsecutiveDeclarations: AcrossEmptyLinesAndComments will
> replace the above with the following diff:
> 
>  struct kcov_percpu_data {
> -       void                    *irq_area;
> -       local_lock_t            lock;
> -
> -       unsigned int            saved_mode;
> -       unsigned int            saved_size;
> -       void                    *saved_area;
> -       struct kcov             *saved_kcov;
> -       int                     saved_sequence;
> +       void        *irq_area;
> +       local_lock_t lock;
> +
> +       unsigned int saved_mode;
> +       unsigned int saved_size;
> +       void        *saved_area;
> +       struct kcov *saved_kcov;
> +       int          saved_sequence;
>  };
> 
> (a bit denser, plus it aligns the variable names, not the pointer signs)
> Does this look better?

Better yes, but still not really nice.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250630075638.GJ1613200%40noisy.programming.kicks-ass.net.
