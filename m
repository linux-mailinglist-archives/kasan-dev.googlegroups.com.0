Return-Path: <kasan-dev+bncBCF5XGNWYQBRB4V2YT7AKGQEQ45FOPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E902D4983
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:54:43 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id p32sf1281324ooi.19
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:54:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607540082; cv=pass;
        d=google.com; s=arc-20160816;
        b=AgxtXglBynoPgSGvLS7Vl34yUDlfRoGyD/6N83Wlb+gHy0r3Hju2C4R7vfo27TLgTV
         51JguZARWAkxDJKOxcSnvgV+tuiSLeSkzgTWZMyPRZw+7l2l04EAd2iMFF6ivZgsiPrt
         x0w99Ej2urririmz6cuGZMUYuJLQ/4S0Eg3hnwbgmlzSm4THz04KoshCEzM3UVnSCTqP
         0dhJ1QJGcxtjFLCfgf24Qb2DWuW0lpunVEvSfnOAggQFIJu/NjidyCv0BIl7QiSflmEm
         pAMQSw9n/CVkJIYXHqBccUH18WA1doDT4SFZajzml2ImpuqqTh1C0jKlc/3Sc3F0gV2Z
         pgcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mQUGGmQDHN4mAoQr9Kb2z2gbV4NebhJVaZ0xIta9M8o=;
        b=cK0vgwlb6lcTLFZvg0zLGwxB+U41NUPLZttlmdR/mj8rX2erIiKzOxfeTXnmvazp1G
         nXcmFwf8XdSkyshDYQEL7P8DLqA2Ycylpgzs0A/by52IBCk0dHzxDmKplvrgaDIwGNkN
         lrvHMU+SSpG8VyyNbcCJNuLeOpniK0ENyCIXV3nAI7VY9CzmohXRmHTP7up6r0NPQ3kg
         DywU4mGa2fDgB5uNOeFIUfhBgXcb2sN3Z13Vb9uk0n3wERA6Pi6i02ZPdfap83mS9+Qq
         O73YIxrT5lWGGn3J1QzwrFcn0JEmoDqNq2KNEYhQNiIDCS3+02VlbhZO3dAJyHtDuuRb
         OgSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=amGZUB2Q;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mQUGGmQDHN4mAoQr9Kb2z2gbV4NebhJVaZ0xIta9M8o=;
        b=rY4TE5hvC5crz6StX0rY4eApNvjnCX802YOyEM8uOlvXnTDSdC8LUTytTG0wEn9G8f
         VyrsNQ2eV5goTliU43D/KD+RXSwpa+XmvEbYbWqDQCd6W7zxNIvRBhlCnBFArScs+9X/
         faIH0iKDt1mZk/18dKRxkSE06GXNZ54HYABl85ju8+RR8KmV78d2FBq019RsCHdclkh6
         Jnt8TE216clEaGEFkrwzTdw9KRTbw7lW6yMI5aoqOrpUdl7d+eAtHASxkc44ry34Jg0N
         3FDZ6y3U/g4iRbiGwpTpW9IVs4cV5sC2mMaH/CKXnUPz78htqf/4xpj5Y2hPkEGDb+ok
         fVLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mQUGGmQDHN4mAoQr9Kb2z2gbV4NebhJVaZ0xIta9M8o=;
        b=byrG6P+C9bv0xWDM7yUH6Syy7cIuqSh6gzIM46wJk5OfkX3MktxjR74/TLlaiJU5o9
         BbFeCg8nt9VqIzYYERYgliVCVlwuMaWzdJjJMvZeydVczCSYbobYSXQVohpYvcP/W8vp
         TF2meqGL0n9e+118sykW5fFyADMTXdV3F2uu2/hI03NnM52sozGWk/vWAPU9KLuHPw1B
         Qv2vOiPykGHhWe9j4ARM06zJ4ouhgDTaMtlDyx6IwV69whyCzCNHf3Iz+7WwsA+CoGbW
         4z5EAnOu3qqyvhCHtB8+yJbewrVhnlC8mUDj9LdMwDCzSF8sW6zbQ12emZ1EXwa0YFnT
         QoeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XPHPZrLPC7D0vqXas+buTE2f1gh3QjUlQ/7L6+FzCbrne7tc3
	QCc7vb1TeFPrCnSolyj/CnM=
X-Google-Smtp-Source: ABdhPJyRaVcqc7s2/jxBQw1RXSntbfCEBcOguotro4NYrN7u0FVT0G1WNHl92rsAJgzWTJmPKZjReA==
X-Received: by 2002:aca:d9d7:: with SMTP id q206mr2829042oig.63.1607540082307;
        Wed, 09 Dec 2020 10:54:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c413:: with SMTP id u19ls675230oif.11.gmail; Wed, 09 Dec
 2020 10:54:41 -0800 (PST)
X-Received: by 2002:aca:568f:: with SMTP id k137mr2819625oib.138.1607540081727;
        Wed, 09 Dec 2020 10:54:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607540081; cv=none;
        d=google.com; s=arc-20160816;
        b=aTXLEAmgMqocuEUDnPJ5RZnluOs/+Zz52SQ6783MNCq5ohmJGUDZMC2NEr3S2WT13u
         0eexJ5o18XHZahKZEnXErrmojSp04AyWyaK+975UwLW+cfnBoLEjnkXi+BSHpPmXn93T
         KYfJNnZd78i3qKnOwSRGu71GvPt2qBTD0b8WywBlGnM9OIh5LIYGIJvQWEXDlnnIqsRz
         +H/le4vGU+HGt0y9ks9lDiI3tNzy596aa+wyAKxGFnQdOhKP2jgOT7LoG7VcLL3P8VsJ
         Icg4UMT5AbIJiWDDV5B85XnYWu7AjJ+aPTHzh9wrQKQOKgZU90jZGnKNAquYWckv2iaE
         XuSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6rcG5E2ND0M3zVFvR91c2KDlufplbmx+6aVT4b7pfH4=;
        b=Tz3bPav8lGfBnjOhm5AjtED3e/3yHUiSuB1roZpAwNfmZnoKwlAjMAPOue/W8b8VsM
         GNE3IFmhLSRWPur6TKdNm6r8M4wMIOtpU3LZ4NpQeLlu4dZAipFT0Q9EZS0MAJ980YGk
         U5nTV7C8d8VJx3ZmipZduKdvL+8VtHFMFMv0Wcb812cNmrR52HId3uBA8HafgZa5q88G
         HKShO/DED0sQtlJQXWsoVmJTrMQ/xh0kM3TMDflqAF26AiYbvmH/v80q2YPRMPzPXKGr
         FiJplfdMnKvDhxoE39m8bMJwPSIwrQjjVWLUuGhKX1wSyl2fQQANBE2R86pInvnk5aft
         3Rxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=amGZUB2Q;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id 7si155100otq.5.2020.12.09.10.54.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:54:41 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id p6so1428667plo.6
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:54:41 -0800 (PST)
X-Received: by 2002:a17:902:ee11:b029:db:c0d6:581a with SMTP id z17-20020a170902ee11b02900dbc0d6581amr3244470plb.54.1607540081165;
        Wed, 09 Dec 2020 10:54:41 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id v8sm2900365pjk.39.2020.12.09.10.54.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Dec 2020 10:54:40 -0800 (PST)
Date: Wed, 9 Dec 2020 10:54:39 -0800
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: akpm@linux-foundation.org, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Stephen Rothwell <sfr@canb.auug.org.au>,
	Marco Elver <elver@google.com>
Subject: Re: [PATCH] kcov: don't instrument with UBSAN
Message-ID: <202012091054.08D70D4F@keescook>
References: <20201209100152.2492072-1-dvyukov@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201209100152.2492072-1-dvyukov@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=amGZUB2Q;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Dec 09, 2020 at 11:01:52AM +0100, Dmitry Vyukov wrote:
> Both KCOV and UBSAN use compiler instrumentation. If UBSAN detects a bug
> in KCOV, it may cause infinite recursion via printk and other common
> functions. We already don't instrument KCOV with KASAN/KCSAN for this
> reason, don't instrument it with UBSAN as well.
> 
> As a side effect this also resolves the following gcc warning:
> 
> conflicting types for built-in function '__sanitizer_cov_trace_switch';
> expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
> 
> It's only reported when kcov.c is compiled with any of the sanitizers
> enabled. Size of the arguments is correct, it's just that gcc uses 'long'
> on 64-bit arches and 'long long' on 32-bit arches, while kernel type is
> always 'long long'.
> 
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

Thanks for chasing this down!

Andrew, can you add this to the stack of ubsan patches you're carrying,
please?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202012091054.08D70D4F%40keescook.
