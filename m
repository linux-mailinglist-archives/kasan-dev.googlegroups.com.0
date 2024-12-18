Return-Path: <kasan-dev+bncBCA3DTHS4QLRBFMVRK5QMGQEW33RTJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id EFD8C9F6050
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2024 09:40:55 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-216728b170csf58250585ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2024 00:40:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734511254; cv=pass;
        d=google.com; s=arc-20240605;
        b=G5MF6pAsEVTf4M3xz22+vXcRo21ilSPZRpzVyNqTKrvhR9A9vEQsS6+MNg8yumV1NL
         qjvCvUZb4yKxphpLm9PvKQmfO+I0TOiPOeeYb94TcCDwH9ukxXot2SIoyGEucSdaDLqP
         h71BuLUQgMfUld2ud7vRWgHbQLwsqdly6pdn8vsZRaENFR08Uuv3AO5VgfrrZ4H6vG42
         B9akrhGPu2NSq6lWVaGWJNHoMgQjyMEaA5UkNPL0xMxSRXqpTJz7Zxcl5TjBk0s8Mwlq
         byZeYSz7inDvWC9kqSIjBxGKxxNw+pIT/G78kK2t2VuEvWoxJjkHFP+NohJnbW9Q4iwF
         Exjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0YqEnYCqYVob65TMmKvHOv2Lol8hiMgDJ85VpGTQy2I=;
        fh=savc218rvTF8+abd8fA0IohrTxQSBDEsZsWmTx6BMwM=;
        b=dEdoAzlVrl5ihwFSoGhbaLiCs/v6h3IUgcEBpV6h6aQ7hG3srdlSiLPgSHydnZyQ/b
         +6UyrI55FwinAA8T3vyZC1r59y4VLY4SggQSO3evwShGXMXm/FCnLaEB2Et4ms1KgwXF
         MtjvRv9HmkCelbHUS+PJrAnU0OyCbBdzWPKaxWKefDerhIoIKamgaWq6gjmewDRB41/f
         0eVNq7VJ6Rot2aatYdEejr7xkN5hz1lqZRltdg1++cDmLWsdLuCOcJmBzMmfE+89p6bF
         BwV5Yds+yuVFrdrfulRz7vgCB8BIpJ8GYMRAyOS5oSmCkIfOk4a/oLVbRtHNyyt9mIXH
         8LfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mxfWZwnk;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734511254; x=1735116054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=0YqEnYCqYVob65TMmKvHOv2Lol8hiMgDJ85VpGTQy2I=;
        b=IgI4GP51yhsArwZ8bU4CkBh6LHoDydmsb3Hdiz4tR1zUKCCqqr5Wn+3ja2p8YGJ9dN
         tyuBP8NBwcdFF8kNGxqr3CtJ6Z7BZ2NgpFjOnf9/3aTHJOv6KnrTERT+OqmjgTYe1a1o
         /4ucE45JurB3tW/nxToUXUAsCzhqnOhZvJF7SlpvHwRPux9zHBfufzY7pPWqRrlhGGvX
         o3GYRP41T373GlmFvoJUbQecFMj5bfQ0KhjTt/luP0n2XhzmtYwjSiNIp/rNrxxKjx96
         TYvrw32tQOxc0sUTexkPi/jLu1ZLg8llw/rYd2ZBP6AJFiAX9KKvjD3upoqIyJiq4vzn
         3kKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734511254; x=1735116054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0YqEnYCqYVob65TMmKvHOv2Lol8hiMgDJ85VpGTQy2I=;
        b=ruESdf2P6OU5xoL6JOmbU9FkRNBz+TsumFN2i/piNYNzwi7246NK8oU3pfGF7fOylT
         SqRe9qKGv2IQ8HUHCryEd7GHP6GGrL6SYmkqaJhHXP3uboz+MXbcQvpmmUpc2XBzEHui
         4rCR3uoGC4cHjh86FCORTh1bUQo14b1hxo3aZlGONe5voBK2HAUed6+I2Pbk6F/DfvnX
         KRJrbW/A3aNpOXRfsJNGrAPFy6wH7Wbrpetb7YTl4xRaP8E31Vu+yC+0oZkG6Fs17F0/
         Y8HHYf3Ne5vWYYQZgUcYriB7AizKo58FuNuNsV0ZCb3na9JVwaC0PisbecMyznlhg+Gi
         zw6g==
X-Forwarded-Encrypted: i=2; AJvYcCXh9f9+IlCtu8rUPqny+yEjjGbykdyNf8gPUxvJ2R/LfEpCMMWnVE9jxFzfgw2P7rV8dXyBFQ==@lfdr.de
X-Gm-Message-State: AOJu0YzUhMtrghEYMlGmMGVHGh/HabTTayvy6swbX5VkfkbGsLrqAy8O
	WSa8W+09wqOpaeEdEBaDxT4eBXOUcItP1kr/RVaGKI1Qj7Bzmldf
X-Google-Smtp-Source: AGHT+IGtH+hH11cpB6XWqxfg+qBKkmtQ+upf4mtXSduZDJttGNYmyE7FdsXBA4Dh1xhjWQWGQNSRPw==
X-Received: by 2002:a17:902:ced1:b0:216:501e:e321 with SMTP id d9443c01a7336-218d728cd2amr24794575ad.56.1734511253889;
        Wed, 18 Dec 2024 00:40:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fd84:b0:2ee:864d:21a3 with SMTP id
 98e67ed59e1d1-2f291b14d10ls3983593a91.1.-pod-prod-07-us; Wed, 18 Dec 2024
 00:40:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV1ltDPZz8gEZTg2jYqTZmvRfLRnuG1rSKP+Vu+nb3MIpenVoQaayBJ71PVW6ieUr7wruUueWAt0PA=@googlegroups.com
X-Received: by 2002:a17:90b:51c4:b0:2ee:5bc9:75b5 with SMTP id 98e67ed59e1d1-2f2e91c2df0mr2965779a91.4.1734511252532;
        Wed, 18 Dec 2024 00:40:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734511252; cv=none;
        d=google.com; s=arc-20240605;
        b=SQ03RNIP6SuedVv3mrtNMTbMsHF4krNffnpeoc/AqaAtsNRDb4BryyLV77O1Hmqo28
         HKM5pCIboAZ6IsCjp4Q9eFFQz2syXOa3S9JkuZD34608gLD/rMnmVtSeAbnpgdIHqFAA
         E/9JxRJ7UBXMk4twHNeuIZmVFrp4z9kRXsp2NhkbHX1xlBZKSU/7a/f0YRkmK6ynHY8t
         KuKoTvWW7MpSxY9mUYQit8BsxKrYlV3V6snoUWo/ngrmiFvyxF121rtoc7OTY0T/tJZ5
         6jhMrSp1M0FUl2cz9zFquLUvYX53i9nvXcfIubY3GrzzFkMyola/UWfHlNPelAmX/4Mh
         8lgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5O2FAk4XZv7JO1esOr4zfC9nqiqVOmwbGQwMg6lWHdU=;
        fh=BK/OGZg2zETSvY7fkXc57YnYsrYJzXznyXZ4C8ZhGvA=;
        b=H/aPdAyAXrfmclnsaRZdv7YssiC4I8X5Q+cMC3bLn8TUcKWhfgudCssgwmjqfqVatX
         dlBFBYVkGTV0mLo7d8gZdcXvKGMsvmjwG8KnHsANabqlvKq722yyVietdazoNVr+z8bf
         VWqklM+X4XKR5Ylyk0cP6OC6OlWpJmOPkjUH3wYbj+KnEiG/Phw8qZVEAfln0G+lufsC
         lURg0wOPfu+NPuFkmKbwWpFlWV5oPNNKJGgglWsRxZe8SNwwhBpM9QwNRN+48xQyon0N
         rJ4lEGHTUEfJqj0MmpjdaWRF1yld+NQlTx8t+CXtcLxsZBDCiV5WXZXE6WKTtCh8eaIM
         AdfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mxfWZwnk;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f2ed0d882esi28054a91.0.2024.12.18.00.40.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2024 00:40:52 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 010EDA4085A;
	Wed, 18 Dec 2024 08:39:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0B933C4CECE;
	Wed, 18 Dec 2024 08:40:51 +0000 (UTC)
Date: Wed, 18 Dec 2024 00:40:49 -0800
From: "'Josh Poimboeuf' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcov: mark in_softirq_really() as __always_inline
Message-ID: <20241218084049.npa3zhkagbqp2khc@jpoimboe>
References: <20241217071814.2261620-1-arnd@kernel.org>
 <CANpmjNOjY-XaJqGzQW7=EDWPuEfOSyGCSLUKLj++WAKRS2EmAQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOjY-XaJqGzQW7=EDWPuEfOSyGCSLUKLj++WAKRS2EmAQ@mail.gmail.com>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mxfWZwnk;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Josh Poimboeuf <jpoimboe@kernel.org>
Reply-To: Josh Poimboeuf <jpoimboe@kernel.org>
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

On Tue, Dec 17, 2024 at 09:30:24AM +0100, Marco Elver wrote:
> On Tue, 17 Dec 2024 at 08:18, Arnd Bergmann <arnd@kernel.org> wrote:
> >
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > If gcc decides not to inline in_softirq_really(), objtool warns about
> > a function call with UACCESS enabled:
> >
> > kernel/kcov.o: warning: objtool: __sanitizer_cov_trace_pc+0x1e: call to in_softirq_really() with UACCESS enabled
> > kernel/kcov.o: warning: objtool: check_kcov_mode+0x11: call to in_softirq_really() with UACCESS enabled
> >
> > Mark this as __always_inline to avoid the problem.
> >
> > Fixes: 7d4df2dad312 ("kcov: properly check for softirq context")
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> 
> __always_inline is the usual approach for code that can be
> instrumented - but I thought we explicitly never instrument
> kernel/kcov.c with anything. So I'm rather puzzled why gcc would not
> inline this function. In any case "inline" guarantees nothing, so:

I'm guessing CONFIG_DEBUG_SECTION_MISMATCH was enabled, which enables
-fno-inline-functions-called-once which ends up being the cause of a lot
of these __always_inline patches.

I had a patch to get rid of that at some point, guess it got lost...

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241218084049.npa3zhkagbqp2khc%40jpoimboe.
