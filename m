Return-Path: <kasan-dev+bncBDYJPJO25UGBB4NH4DZAKGQEWLIAKDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C7A6C172856
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:09:38 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id p26sf345596iop.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:09:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582830577; cv=pass;
        d=google.com; s=arc-20160816;
        b=n1ZpfkGp27zEFCL7VT6mxIozcchOIoCp5O584r8QImW7CYSvFLcTV045D0WRWIE7Nq
         Q7Cj3LzQ1m/Nlg8QeoyKj15YjJmMMe2Z7XsoUcVPqgQOEEie4RNVO4W+BM1YZK36DJGD
         vM8tlq6zxbQ1m7V2KoNHNJCtdVXezBGbjnKugnWxcuqpBBjPCJR2hc0htZ9gsMRM9+ua
         rPq815R0hl/UtI25XmToWpGjG7I7DbQh/kTLDlBudMzm9DQhAxx95KrombNh+A5qUr5n
         InTG4I3bOxS7MGF38P6OMCv3cVqqjtRO2B9sD4vwdgdEQnQDqNN7NjxdPLPOKC8aTSd/
         3+3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=56wrUZx9SzlBaZ1qMrsTNLGJn0ULwipH9NbiCVpfNZU=;
        b=Uh5ZKgWiENL9ZdMajOtkkyFzMgjRvCUIZZvVdxVoOd6zNoFUZiiOLavwUxm7guISfb
         kUAMz/nytDh++sFZnFxOmj79r78Gv3uF0is4r9qajX31LdQEaBse7kjDHZp9jUlRhFAp
         wokEKbBwiozZ+R0LAnWKJR3lPUsTKadwl/FZt3yc7tkIgGTOaYVnCowNLHR4e2FvHkaC
         tjy+pmaWvLuCWu6UJDR7wxv36U1VkDbFxgy+VzQVTRiuM6Pu5t11ukOsYs8PrNkTmgtI
         JI5GgKXEe04qqWK2t8VYRbDUxrJncMGpPmSwIvwAdL2D1b1UWYCEwFJ37FG6yd4E/3Bg
         qfbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kamb1Svg;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56wrUZx9SzlBaZ1qMrsTNLGJn0ULwipH9NbiCVpfNZU=;
        b=XkIfMp7QooufRxvYqZViHDlCMzcv1jypV7LxNvqRw0rXAaPe4iqeYQoDxl307BlcZR
         MRitBpyICqReLXTEijEiYMUVaM4qYGGs23rXj2vfe3jucFJZ3rdItGrFD1hpDK0Gsdpp
         wR4l7CJM0JTxYfDbL3osGyb6Iu9Gq0DMioiUA93M/0VEBKzgI0YNSmfKszBa0nQTIB19
         C228UDdfRPE3sfhScBVCuujC73ygU2UFu7F+DehSU342vEAGNRd+FHJ8+wwvurQvnnof
         w24X6uglv4txYA+pLrpVy1mu0u5YqlHQ5vBlIVkEgFaO7QnHVzY8xRCeIJoKIF5yQEGW
         3piA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56wrUZx9SzlBaZ1qMrsTNLGJn0ULwipH9NbiCVpfNZU=;
        b=nM5G3q+tX55Gs9RCLPbodyVEgNdZoO94IWiJZs5taUmHEyysqBKyLN/Mqs1q8ugB/T
         eAkIoVQXCGeEJeu7sgjPX7Tr/sStLTt8eyXjGutPuj82k+vDw13+e8hr4jv0q0c+WlfL
         N/E2v1KvEDsneKV5/PuwMZDI+F7odXSSlBCeEUJU7Z2+zbJzKl75z0P68QGz60iorBtP
         ha0gvoey+J3wpuuolWLD16yCFXIORFgFGyV0wxqYJNHjA2PLRjM1HHNJvbe1othn09Em
         MZOqg8dyEB6L2T9JPGPpb8011ZUW3rxrhGfU+IcEO8lmadBm0GuxQFheqmJF+elfLTda
         JUPQ==
X-Gm-Message-State: APjAAAUJ8z0edvOVCe2MmLE3Or3hmv/lyKuz7sApmWQv6y3hltLadjpy
	OFpAeFr4AsvfJX4A60Gb1Ws=
X-Google-Smtp-Source: APXvYqzpyS3103n7Cwxspjk0nNEPHzjPis5jS4YHgoE3MiAH/JgiR1UJN2wIx3fGIXxyDPPcYQSsrw==
X-Received: by 2002:a02:a694:: with SMTP id j20mr270273jam.69.1582830577575;
        Thu, 27 Feb 2020 11:09:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db04:: with SMTP id b4ls32089iln.5.gmail; Thu, 27 Feb
 2020 11:09:37 -0800 (PST)
X-Received: by 2002:a92:da01:: with SMTP id z1mr862573ilm.108.1582830577256;
        Thu, 27 Feb 2020 11:09:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582830577; cv=none;
        d=google.com; s=arc-20160816;
        b=RAwHx9xvrzJFH5RADZuJTgbD2rSKEsPM3p/cV9H0k2Rn5VjC7kYbmaTD/RTZ5IlMoS
         Aol/MBC85Y6qn6hdGsXsIUdd4tEUTXh+k8Ja7O/2q1ng8VfiLSY6ll/oi96MwMNWhKQ/
         3LXBTnnq8sxqG1YC2+RGBqtq5MejPDsPv9S1BK1c9N6cp08ZgwNTSBljhFXtMd/MYKGu
         X0+Re94MBu87sEcs3k9kOBtiC3nMPE8uB0dAa706/iM9f+f87ljZeceZgcaMu9yg3q5N
         zR/I6KTeOl+n85Supubmb/ERtos5fD16raBdJiHrCZi9lW/7s524jc8tWXFK7sKGVchh
         b+6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IIUUVcQLz6sKgnI4FMJ5K8CICSDgtCiRkSBsjamGD9Y=;
        b=irL3XarQ1V//1hSga0oNsuT8GsosRL27t8iNwXsgO/+xBVM+NmHuNLOkTYL+8kGrPw
         9DzV+KTafrLDlwjNdy2X/ykDi5n2WjI7Qy9e7ksGHw2YyWxbfhdqf7L0oGKKGemQ8HAv
         mDS611p90Te6gULdDLz+HJMCweBgY2cnGobITYW+F/LRA1K0TRy/6LBINYv9m+SJWJEE
         EPz9uAWa+JEbZm7UjQT4T3nhIrKSCFRTuvkG4KLBmLLvDbgPeCaSG6soCR7MYXU6XzPS
         Dm1D5bHvdfBIa1mpMB1iLl170tIzBZw7JgPnLExgxLv0Q8NQUbYO0oOHz/AruEtnOJ6d
         hkTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kamb1Svg;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id u22si13121ioc.3.2020.02.27.11.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:09:37 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id j9so307579pfa.8
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:09:37 -0800 (PST)
X-Received: by 2002:a63:4453:: with SMTP id t19mr724146pgk.381.1582830576299;
 Thu, 27 Feb 2020 11:09:36 -0800 (PST)
MIME-Version: 1.0
References: <1582822342-26871-1-git-send-email-hqjagain@gmail.com>
In-Reply-To: <1582822342-26871-1-git-send-email-hqjagain@gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Feb 2020 11:09:25 -0800
Message-ID: <CAKwvOdm_6cBtRexkmbkj-NF3WTTDc+UzcZkQXfa05BaYvaLX=A@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Fix a typo in a comment
To: Qiujun Huang <hqjagain@gmail.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kamb1Svg;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, Feb 27, 2020 at 8:52 AM Qiujun Huang <hqjagain@gmail.com> wrote:
>

Thanks for the patch.
s/slots slots/slots/
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>

>
> Signed-off-by: Qiujun Huang <hqjagain@gmail.com>
> ---
>  kernel/kcsan/core.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 065615d..4b8b846 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -45,7 +45,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
>  };
>
>  /*
> - * Helper macros to index into adjacent slots slots, starting from address slot
> + * Helper macros to index into adjacent slots, starting from address slot
>   * itself, followed by the right and left slots.
>   *
>   * The purpose is 2-fold:
> --

-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdm_6cBtRexkmbkj-NF3WTTDc%2BUzcZkQXfa05BaYvaLX%3DA%40mail.gmail.com.
