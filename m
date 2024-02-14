Return-Path: <kasan-dev+bncBDW2JDUY5AORBMHYWSXAMGQEIOTSU6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF1C8555A2
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 23:18:26 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-51147e9d9a2sf207767e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 14:18:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707949105; cv=pass;
        d=google.com; s=arc-20160816;
        b=WHOM4al9/MQ2jwagv0YsJqBvNLI9CB9Nhs0ginzjZkoRi1/CoQbOKvVn64PBrwsW0r
         sO2Jko9H777E8k5KHQ8qBISfZTAz7w9quvM+S4nqOO86m7kvE1bi+nVC3RIEC+MwxfTf
         VsnTyYHP/d6I9Zy3bBgE+OJucYpNgpOuqIzd8a2yJ9kJUuLOPh2bogBBrXoZ2zFHqGna
         hzUXyBysMBnp/Xvp+a1JVQPu65aukYcj2L4SNKbKRzfaUWlH+2lenu+bbdj0F3kZjyE3
         pepl+0hW9FhYIxD4kgPi4SthWr3x3TI4t/qxns5Ta8OLnlH2O+Hx1hg+4nAPSRvFiG1S
         orNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=niwEBKrKqFG3jqTvZAbSTcgE+RBhCQz3BeRtHmaXduc=;
        fh=iuaNYZU1K6j7jzdUZzH1VbifufFf/qJpYm3r/v2cSe8=;
        b=H66OOhBRSAw0b0WQj90oYrBADtl2dgpvbfqdB1y8dp7sxcsKbIlMtZDl9qJfdD9IDy
         Lt+47IhA5/bBMxv8XULulGbdEosRIeWy0mHovziu7sNb+iuNZMPinlYhBjoWCQPuL9bb
         9V1IbY67Q3U1AmRfaDi01UTukm0yd93NTUuUT2bQ/KsQ11+DgAWnlJDtqPQ/K+hOdHrn
         LDbv6lKwgzDkzoQMREPeuie3aGAO71cBK9rsB9TQvDJTgUP3XPkP4C6gMl/5YSIsVyuV
         rUHDc4WI2Y/ZYgwbZNSnYX0IyzCybltOHIIZQBYWrQJPj/ULccalT5AmcLUkdO9JnAR2
         0v8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BcejXY2Z;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707949105; x=1708553905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=niwEBKrKqFG3jqTvZAbSTcgE+RBhCQz3BeRtHmaXduc=;
        b=X1yu5oLq6uyVJSz2PyWlUoFxYCOu5yC0GSLG8q1DrWv5o0FIm0zM2aTp3TwSHwdjp5
         ndLVqYGl5W1AsniiU8KVNqE/d176WlMVou6V/43xSs/tAaKzCRJHcTzY73dlVyU6Og3n
         gs5djC0pvzI+R2MsaHnjrNcSvcC0eNka1R3vsD3ehLesr5L14rczrO3vldAqE+kfh0iL
         2QbiV+xKeJtEqNTrYvHyBhOHM68sgfPQny+Ht1sgq3aw9Zfxe1bj27WShOIrw/CVF6+V
         PvQ1Y9VBNxOXythIIFyllV3FblzQLSoxpQ9lVXjeIY+m21yowuFnckSxJg0KT7L9n7OO
         hJvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707949105; x=1708553905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=niwEBKrKqFG3jqTvZAbSTcgE+RBhCQz3BeRtHmaXduc=;
        b=kZErk722aw4NroSWvrlABwzBfMnchR9CcG9ORS/hKjNrsSDjkIyF/nFMO6ASs2QLVW
         2eybYu7l8ukwrSFrWTkD3L6Dld/MmqTF3FMOERQQTL14OftjIUSn3+r+RErivzyD3h3m
         Hl/orNWDuD7I2SgftV6ZqlC16KpnWFw91YvrC++607hm8qffzt52E0YO2SKe+TXbPt2Q
         mGb1Em5rQ46XcgdkcJQQ2pds5cF4EyDXVxod2Q9Lw99fx6kvc1ZUTku9bmnpRF24bEN7
         9jtS5h1smOEXLSmW9pwljX4HjufhFn+RhyksHEX07DVXaAss9DpuNYmxG0SPoPBg687V
         kQvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707949105; x=1708553905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=niwEBKrKqFG3jqTvZAbSTcgE+RBhCQz3BeRtHmaXduc=;
        b=hvhcL2aqlrTsfp+IexLJ5Gas2afmMFAqXkp6sZ2qMvX31f7QAF/Bh32QApDVg7/qiu
         lyr6wQfZpdc5nZxVtQzlhmz6Ww7XG+P7ypmP3TFlmjWVbblmbASByDZqeuihfVWudmSS
         zyHAolvQhHGeOU7QACzOkOVV9H466BmdP6cCGLEV2IlhfZbAS3QtYnwLRUu3Gp3btWeh
         TJXDGTz4IUK29Z+TD6A01JdKjdcwLuAbG0SrttFXcGGzxhGx7+j8dNjQPIlWl1StiPBT
         06yfLJo42otU+MBOomozwfx3/POBfS28MrAsUGtJyRQ3PVQypmELAsJiTf7Ew2A9eawW
         qNTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXb4JFBHJyUb0X2U7vam40JOvsRMoDXbHlUMzzPYrqMDJ4ALmZOwUmm5zy7GUeibAlm7atpcY7ZxcCC87XkQpGHhwdXDCLXEg==
X-Gm-Message-State: AOJu0Yzr6Dlh1yLKlwz8uCXTImHpUUbHr9FzYpJzeENbegkoT1RpMNEo
	+BCH/tlXO/j5qL0q/bQ3rJFxpRnGdNz9CUVe6xF3xhk6pCEz2g9A
X-Google-Smtp-Source: AGHT+IFNhbx/TAp/qJqpdHhBVKXQzikaMIkDTpLGFQHRtkVsmK9idTwQHkeEPSgYtzHvxkPSK0fmHw==
X-Received: by 2002:a05:6512:3e16:b0:511:79ac:2d78 with SMTP id i22-20020a0565123e1600b0051179ac2d78mr102880lfv.39.1707949104837;
        Wed, 14 Feb 2024 14:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c81:b0:511:60d8:ef2f with SMTP id
 h1-20020a0565123c8100b0051160d8ef2fls442638lfv.1.-pod-prod-07-eu; Wed, 14 Feb
 2024 14:18:23 -0800 (PST)
X-Received: by 2002:ac2:5964:0:b0:511:8659:73e4 with SMTP id h4-20020ac25964000000b00511865973e4mr94167lfp.8.1707949102993;
        Wed, 14 Feb 2024 14:18:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707949102; cv=none;
        d=google.com; s=arc-20160816;
        b=zDd/y3Hxm5wPRyzym79sCIUZvGNTtZ+PY605aygB3S5T8iH3k5FtQHbLkr4DL9SfXk
         y+7Qp47/KLUDZtrKk8b7iYNeG7ZN/j9R/gZOovKpd6cDx1sbZeFoYYiUB5fj+hg1MvmT
         jqlF/6A3Fd4zfNyde+qu2Z4QkJ3ANGHZu0wClKQnUogLcGBq4nI07konePV8wDqBgJeb
         V/P7nRor9S+87nyFlODDTnLhlN9+yCIv1iZP2qKEw1DY+m+P73Jz6+9KCXjNst3fg0Dp
         XxKh7D27ANuc6GJ1jUlXFwS2xoc9ejaCte5C0zplEQSXJa6ysVk9PFDkCR1bEgY1PENB
         gk+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=b89wrtq0WG5HUy7Xs4940xVOlE3ZB98xRJ+p4Pz65kk=;
        fh=KNQQtRPUSE0ZCvkFQkawHZoC0tgd0KS8JBs4Z5NZ73Y=;
        b=w/GyYclxHEzjdy25Fq9xabfN8HHsUGuMJmjquLYXTLCk+dbgXcwkJOoCMvB2hsv2Au
         1rYPQj7YQT+0fH98RlTpES4VezHFKfdEKMemTo/5MNrnmvvkExVSRzk5Q5fFuA8OnOxY
         juKaNINjCvrNQGRXIg3zGqKaRXuzTPfU+UjcKClNTxjpseDDKD1d/VqYbqRChcKNjWDw
         FiWhz9ZKo4ExILnUmJ6WV7XaCwDceN614Qw8Ia1qLm5ywTBfjpXHtQzENzCnswDWAqhg
         1T0IcxMF1txIKSmBonZmUmWPqZ5wFIbGYR+4EIVYsr8Gd5p73D1FPEa5Ygp6qAvPEiz5
         6LuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BcejXY2Z;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id i33-20020a0565123e2100b005116bbbbd07si685236lfv.12.2024.02.14.14.18.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 14:18:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-33cf46a5f10so68276f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 14:18:22 -0800 (PST)
X-Received: by 2002:a05:6000:1247:b0:33b:4d13:a1b2 with SMTP id
 j7-20020a056000124700b0033b4d13a1b2mr2634603wrx.30.1707949102194; Wed, 14 Feb
 2024 14:18:22 -0800 (PST)
MIME-Version: 1.0
References: <20240213033958.139383-1-bgray@linux.ibm.com>
In-Reply-To: <20240213033958.139383-1-bgray@linux.ibm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Feb 2024 23:18:11 +0100
Message-ID: <CA+fCnZe2Ma6Xj5kp6NK9MekF+REbazTFwukdxkgnE9QAwyY=NA@mail.gmail.com>
Subject: Re: [PATCH] kasan: guard release_free_meta() shadow access with kasan_arch_is_ready()
To: Benjamin Gray <bgray@linux.ibm.com>
Cc: kasan-dev@googlegroups.com, mpe@ellerman.id.au, ryabinin.a.a@gmail.com, 
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BcejXY2Z;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Feb 13, 2024 at 4:40=E2=80=AFAM Benjamin Gray <bgray@linux.ibm.com>=
 wrote:
>
> release_free_meta() accesses the shadow directly through the path
>
>   kasan_slab_free
>     __kasan_slab_free
>       kasan_release_object_meta
>         release_free_meta
>           kasan_mem_to_shadow
>
> There are no kasan_arch_is_ready() guards here, allowing an oops when
> the shadow is not initialized. The oops can be seen on a Power8 KVM
> guest.
>
> This patch adds the guard to release_free_meta(), as it's the first
> level that specifically requires the shadow.
>
> It is safe to put the guard at the start of this function, before the
> stack put: only kasan_save_free_info() can initialize the saved stack,
> which itself is guarded with kasan_arch_is_ready() by its caller
> poison_slab_object(). If the arch becomes ready before
> release_free_meta() then we will not observe KASAN_SLAB_FREE_META in the
> object's shadow, so we will not put an uninitialized stack either.
>
> Signed-off-by: Benjamin Gray <bgray@linux.ibm.com>
>
> ---
>
> I am interested in removing the need for kasan_arch_is_ready() entirely,
> as it mostly acts like a separate check of kasan_enabled().

Dropping kasan_arch_is_ready() calls from KASAN internals and instead
relying on kasan_enabled() checks in include/linux/kasan.h would be
great!

I filed a bug about this a while ago:
https://bugzilla.kernel.org/show_bug.cgi?id=3D217049

> Currently
> both are necessary, but I think adding a kasan_enabled() guard to
> check_region_inline() makes kasan_enabled() a superset of
> kasan_arch_is_ready().

Sounds good to me. I would also go through the list of other exported
KASAN functions to check whether any of them also need a
kasan_enabled() check. At least kasan_unpoison_task_stack() seems to
be one of them.

> Allowing an arch to override kasan_enabled() can then let us replace it
> with a static branch that we enable somewhere in boot (for PowerPC,
> after we use a bunch of generic code to parse the device tree to
> determine how we want to configure the MMU). This should generally work
> OK I think, as HW tags already does this,

We can also add something like CONFIG_ARCH_HAS_KASAN_FLAG_ENABLE and
only use a static branch only on those architectures where it's
required.

> but I did have to add another
> patch for an uninitialised data access it introduces.

What was this data access? Is this something we need to fix in the mainline=
?

> On the other hand, KASAN does more than shadow based sanitisation, so
> we'd be disabling that in early boot too.

I think the things that we need to handle before KASAN is enabled is
kasan_cache_create() and kasan_metadata_size() (if these can even
called before KASAN is enabled). Otherwise, KASAN just collects
metadata, which is useless without shadow memory-based reporting
anyway.

> ---
>  mm/kasan/generic.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..032bf3e98c24 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -522,6 +522,9 @@ static void release_alloc_meta(struct kasan_alloc_met=
a *meta)
>
>  static void release_free_meta(const void *object, struct kasan_free_meta=
 *meta)
>  {
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         /* Check if free meta is valid. */
>         if (*(u8 *)kasan_mem_to_shadow(object) !=3D KASAN_SLAB_FREE_META)
>                 return;
> --
> 2.43.0
>

For the patch itself as a fix:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe2Ma6Xj5kp6NK9MekF%2BREbazTFwukdxkgnE9QAwyY%3DNA%40mail.=
gmail.com.
