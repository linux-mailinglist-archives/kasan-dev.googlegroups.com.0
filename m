Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNYYT7AKGQEJXPAF4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 276C22D4971
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:49:50 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id l3sf1763502qvr.10
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:49:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607539789; cv=pass;
        d=google.com; s=arc-20160816;
        b=eGkE6T9/IvFmkPLkGV852Pvigap1nnQp3hO2tIhaOHhZYLbNWRQfNy9vVsfDjXbEKt
         6YXN0TdDSUnacT7vzM7uLgsXpkSSYbpZYSsRiQDoDYlwcE/l0pgD3i6vh/cWEuIbAwUF
         z30teC24CO4HVyrdxBVu+MRWU+IqyL4PWtCdxZDF3lEqFGiNCIgKK9M/iVG+4F/oLcU4
         8ruomJ+39mP+CWnDH86Q8V5loGZY0ywuCJlhQS6AWMmSFHM56yDxNQCHTjvCddY0C7Oa
         N/dh5rguSZiMQUiPmtccC7djK0mfYqdZXh0PR4uF4r2j7xNPSE2QSxV2BUOVKoyKD8YJ
         Ei4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8Q9lrf51FSJtRiwAcMF6M3TMNWn/s2EzoV9q1TahsI0=;
        b=QDUcPAXkZIoqtdWZJcVRNbPiw/HVUq3YctxyESUR2xTo9f/Vyjy7tKelYuTAAfqpIC
         6IkqbxM0QWbTnMGi77DNtDVnbKitV2TKn/JxaZXqEyhr3BIu73OlJKw8a3OXU484nhc7
         FgyJFpttT5kgClqC6jSO0SZYZ3ztpYT06x33anicrs+kh1ppJTLqt9+05uNB+NBXfUai
         aPBDKRC1sNx+ntcEp6fuCZaOYpE9U5+yrj/3K6eMa3/qlfPumrzqeHcuqRC3Zf/e2JS3
         zUGeECWhO6aYpAuurnq9ikrFIguQJKePMBs9X5a5qbbCUQRsNriqhdPgGaO517QhmJbg
         +K6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l9z1W9O3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Q9lrf51FSJtRiwAcMF6M3TMNWn/s2EzoV9q1TahsI0=;
        b=WkeS1NXRFS4rhzWWVkRPKIP5kkAtIIrdU0XluzRssWeWTCeorpMtgSoK3IcnzBDBvq
         Iz5tfeTPAyIIZ0a7l6KWJQ53D/2s+HiJcGCB2UW+yI3atSJyF+NuycKCUmEjtJmEQS2H
         l8VUkcPKxoxEReglYFahIgFqARfYlfK/hmKyzH/VnQzn3FPNONLBalD8GEbVngm3boZZ
         2o/aforAm/Gj6N6KneXUZI1BxV/J1eMgrYHiOVAW66QNFPKs+KeaIuUDJ4KKFcBttSD2
         p8BWKfytQXIfNXxF0ISCVH7GnwDGP6sW72euyRGPGtnz1hZaA65fYpVz3A7bh2ll+djD
         RJHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Q9lrf51FSJtRiwAcMF6M3TMNWn/s2EzoV9q1TahsI0=;
        b=Uq/RXDfzBQbYfl/SROp+NPNfwEIN9kk8TVeZkX392NX64Y8iwUXx5aSQ6lYFJnAsLH
         XCJuidxzsXjpfJoG+amJiGWvCTWqoNfUmoRdjtAsM4NsniJpGeAcTXxXhksYKQA9dhHP
         HxnZ1rq7mmJ9nwK6K8e3U5/7a3Z5syIvTdIc8nZWxwO0p4r1ifX7EZdJoOGC5k/MxT4H
         A7sHv2FMlMlpSeC1g0YqGVB1KiHijZSf+Q2RSFZo02jbYq6IBn8USsLrjZgHm+aWrWfx
         KJkuXvCh+X5MtjzFLMdf0ihKEebaU/5OnZWRurzfsYBVmhomJtlu/obiw3wGNvVuYqNw
         0+kg==
X-Gm-Message-State: AOAM531cFH3nB1vOOmwC+9DwCHmPXwbl+aQsF8dZOZHUuvy6eZEEAtpf
	7b2oKy7oHqcljGVvUu60uwQ=
X-Google-Smtp-Source: ABdhPJx+YErpOd3ngCtg0CUiSvcOTP4CSTe0+v/XlV3l5xhwvkjo8I9zbCUv9YjOenTKSbArMivrVA==
X-Received: by 2002:ac8:70c2:: with SMTP id g2mr4376561qtp.49.1607539789284;
        Wed, 09 Dec 2020 10:49:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:15f5:: with SMTP id p21ls1237421qkm.6.gmail; Wed,
 09 Dec 2020 10:49:48 -0800 (PST)
X-Received: by 2002:a05:620a:983:: with SMTP id x3mr4788769qkx.231.1607539788796;
        Wed, 09 Dec 2020 10:49:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607539788; cv=none;
        d=google.com; s=arc-20160816;
        b=xA2t1oej6dcfm63Xm8qr375fDGKsi3tUSYAfMn9gmzxlIXPGHmpSRPZrViJvThQYbr
         HWiKQO6zzRqFZkic+wbvVRXB4AN1yTXNShQP6hOUOsIck6UFG3raPPtpevzwMvdlreFG
         d4iXBu8tGHSzh8VwsyQUmgWWsrjivZQc+nlfsBa59UFRDlS2P7C0RKNCvePvJB441icz
         6ykX7/JI8TGuDUPl4jKtpBVgEI9RtBYuu2dq4Ytq7HOu+bT0MJrvWQM407Mq1zBZxLRm
         LzGdQKIb9lGUskMeWrA/6XXWNvZPepEZGMWLdKhz9SEw58vOv+/0q3cKHAyPilRVcHoI
         wyrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nQgmlgyLspfkVp2FCuJol7fCS4Xdf4wtNQYwX+VG7Nw=;
        b=Vlb+CtZavHRhdUe3vOJ7e7Tr4tIAiHedn2VoPqgzntGtg495LXSaZd2r07Ms0Qg2H4
         M79yry3NhuRjodD2udDHCQPaCeWFNzfRFqKuql5oV6duJyN4neFcIhlHf6Nsct608f3B
         bRrD+kl4VfTHWaFLPT01xskxMBU2KfN1nYDm9pK0Mw5fET1ccXS0zicJKI3yvvNh2t1v
         cMn0ow6hm7tEsfS9g31tAzT3tdWpUbvmpKHQvGdyM7HCeR8jqe68vpWuTaaOq2/C6oOg
         LXMiqybN28l6Xv0B79vg6Nf8no0JCXeXhu0/dNGA+/EsW9y9X3Mx1fEXx5sxZpny9c8I
         exWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l9z1W9O3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y56si130175qtb.4.2020.12.09.10.49.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:49:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id a109so2408931otc.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:49:48 -0800 (PST)
X-Received: by 2002:a9d:6317:: with SMTP id q23mr3014950otk.251.1607539788150;
 Wed, 09 Dec 2020 10:49:48 -0800 (PST)
MIME-Version: 1.0
References: <cover.1607537948.git.andreyknvl@google.com> <f2ded589eba1597f7360a972226083de9afd86e2.1607537948.git.andreyknvl@google.com>
In-Reply-To: <f2ded589eba1597f7360a972226083de9afd86e2.1607537948.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 19:49:36 +0100
Message-ID: <CANpmjNMf1tOYTFojUQrHoscFxPPEed_vkBufgxVLduQ6dBvCUA@mail.gmail.com>
Subject: Re: [PATCH mm 1/2] kasan: don't use read-only static keys
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l9z1W9O3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 9 Dec 2020 at 19:24, Andrey Konovalov <andreyknvl@google.com> wrote:
> __ro_after_init static keys are incompatible with usage in loadable kernel
> modules and cause crashes. Don't use those, use normal static keys.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> This fix can be squashed into
> "kasan: add and integrate kasan boot parameters".
>
> ---
>  mm/kasan/hw_tags.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index c91f2c06ecb5..55bd6f09c70f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -43,11 +43,11 @@ static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>
>  /* Whether KASAN is enabled at all. */
> -DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);

Side-node: This appears to be just a bad interface; I think the macro
DEFINE_STATIC_KEY_FALSE_RO() is error-prone, if it can't be guaranteed
that this is always safe, since the presence of the macro encourages
its use and we'll inevitably run into this problem again.

>  EXPORT_SYMBOL(kasan_flag_enabled);

DEFINE_STATIC_KEY_FALSE_RO() + EXPORT_SYMBOL() is an immediate bug.
Given its use has not increased substantially since its introduction,
it may be safer to consider its removal.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMf1tOYTFojUQrHoscFxPPEed_vkBufgxVLduQ6dBvCUA%40mail.gmail.com.
