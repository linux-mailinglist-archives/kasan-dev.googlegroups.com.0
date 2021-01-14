Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4ODQKAAMGQE6WELZQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BED6D2F6B92
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:56:34 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id k192sf2757468vkk.9
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:56:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610654193; cv=pass;
        d=google.com; s=arc-20160816;
        b=jnOMLRoSaQzhyC2T9FM11eho3WazhWeVXEFAOOd+V0GYbmJv2E7sLnXz0ZPY5wHvgS
         iLgCzPytEd0+Nuhn4XqSTQExLlJ6EJTqnmWFMvt4dUx8BjnmfTFPZy16AIjrZhFkyafR
         jqHyqKc5ycudjCfmSS//9zbqp8H6QH0rW5/3WT20MXpO3CvUJXRXyBKNRO8q+ZWHdIGw
         m7fjvm9u4F8c9RTMNNlSYkVlaz9jjZUUWlg5kqGO8EinW+Bh7hXvQkA7CaVMte+uKBur
         WajgVluASrKIRWWrE4t05Tb+LOGmax9pDIkiRxzvtUfhZczzDHPkb30bkkVFP5PeHJOV
         KB8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=H+4I0XXqsMzww7pM8dSRoGHpLJPZczhGvKZB6goBq3g=;
        b=wlveorXgttqmMUZNsfCnAx9Qutt8DY+sThuJbWYK4APIwA+Z1Z75FPRtIjclOyKQSX
         BVFjOfros245DSwCDPuDUeZm4QXCZ43w5LQsosd24L2DRgivU8yZtog7iRZqPmBDlS9K
         vf2FuF4I+oiG8rQUz5UFLixD0BzGZpkk8KfJsWv03/NYVuQ6pvXSdrTWn3cFtrGv/4fE
         eAJlJIIFfF9878N3TgvFNR+cpaLSYd4KZX7cXIlmM2UH7VHGqRwBPJzTDbSbz2IkUaDH
         XLRM0edzTzJ5+vg9Nfex48fn0pAfZyc1pUqoRQPtcsrNti3nF9jEViHiDIN9uOyn2WNB
         E20Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vmXs67op;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H+4I0XXqsMzww7pM8dSRoGHpLJPZczhGvKZB6goBq3g=;
        b=VA128yr09dkEeLyBPQmhqTz7ovY3o/qkWSGzTZeugctcYrD/CD2OiD3bxGIxyxvLmg
         jsqXFJbZvuixf4fUeRjwTddvewESpriDcsrREzDU/93BGXFH6QhVqz6VSyyjfFhFJQIB
         TUA6UkXxOrIhFRCwsbV4WyDsgyLbxxiM+7+Joz+XbWGRZ0P/paIl1tJMXQZ9gAC3w6BL
         n04O8kcsfVcTI2HXx3H7dPpi733ofY5qMK3mg/Yfv7k6RZ+GrclQkE5Kxpg/cQjDLidl
         9zD7+fu0uD6Aqi6DPAeymvBPYqa+JSn5zkVt15RK5bFJbSGksgU9l6nkCkqfVedSdZi6
         HVaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H+4I0XXqsMzww7pM8dSRoGHpLJPZczhGvKZB6goBq3g=;
        b=Zuqy//zH3wMIwwwOiLc54v3VVYPmCOhkK2HwLsE06xOZdafCknMtRDUwyD1gMZhNSb
         Kw9WOobU9oslFWQDW9xi59B1gIeWTRxpKsp0AZUL+HIRrf7a7SEW5QijfgmYaxyFHh14
         HIQeLewN2q4qTBkYVzk2363G4ihkQ2XAV6LkQbfdHJYd6xqLi9NNdtM16gfoxicdhAhf
         G1ICoHZxdEaATqqnnbQrYE96yETX10ea/WOC32FblDgIwnwd6370N7XXelrfbEdgmjIW
         VNhTfltyR72agqQsCDYNdQHyPSpVoSvRbBpvVJI3f7lpnU+NXfnCKarHr2x31Dm5lbZK
         Hb8w==
X-Gm-Message-State: AOAM5319/lf8RkG5FBoD1UCKCnkE3gCH5mKA2vR9Whc34d5N+AKZkwSi
	M+1FJywvPrkGv7tx4q90LA8=
X-Google-Smtp-Source: ABdhPJwLdnBIAV8HYId5xH9Yla82g8MvbuF2xCro0PmCxg/iv5ADqpxOevyejlqTLcbS8ntkaWCsQA==
X-Received: by 2002:ab0:6b:: with SMTP id 98mr7195287uai.86.1610654193871;
        Thu, 14 Jan 2021 11:56:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e287:: with SMTP id g7ls884388vsf.5.gmail; Thu, 14 Jan
 2021 11:56:33 -0800 (PST)
X-Received: by 2002:a67:e155:: with SMTP id o21mr8600800vsl.47.1610654193411;
        Thu, 14 Jan 2021 11:56:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610654193; cv=none;
        d=google.com; s=arc-20160816;
        b=QZuVG+e6NIoB3/xlrkJwEf6tprH/pWXcKJt2PQwiktORvlwcqZPZ8T5Pcpr7Rdla9B
         ZQX51WeufOG2HqzIdIAvKYnS3a58TRVIBCaQJb0i0DSsWVqXvKDWTnSbZjXaEfqb5uVf
         eGmR8xJnbO2XXi0KgEO2aqfgLS77L2KGKhcrrZJqar6eYw93NvOnlPl1P/ksEl6Q5M9K
         diqiWZiAhL22vWWDHwi0irGBUlYsQ9Uwp8AJiU75+Jed1h7y4yfgA3ts8hy/Rna9c1A0
         N7Bp+Vj0njYJ2H09WcB5hlMP64cxsudHbYp+PUaiMHrpj4cxQZtiQwyrZMc1mWdgl0BQ
         Ff/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZAcc3zNp7VGprtlxhdh/3qjDl2q8+DBIOh9GzZOOC9c=;
        b=pcezWNBrSkAtkwqAzuuR9Xie1JFXXJcR/GyjvDYzwjhHgSmod3ImXildhFVgPo84vs
         REGlYTJ9+HlLu+gqW61CBgUBfL99nUyj1WhMr3nwbDmIdpwKUJyN/Tza8JKcLxDjqiPV
         JfxtsV9RFBwZMJZrdliWxwZd2MfffdLRKXoZ163VSkZ5ckKwpWI7U/NzKBHQYGSL8VV0
         nK20bjTsYg8kKZnDZC9mTwbFeW1Y5x55E7SGAAti2p743dJsfovIqhKYOnZa0XIejfr0
         gZVUxTEGQm7OwkAd9DL3Y0S61uIg/XPLxOplruQyCgWDtlWBIxjvDcrBUBYGltnDOgRT
         Fo4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vmXs67op;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc31.google.com (mail-oo1-xc31.google.com. [2607:f8b0:4864:20::c31])
        by gmr-mx.google.com with ESMTPS id v23si420700uap.1.2021.01.14.11.56.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:56:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as permitted sender) client-ip=2607:f8b0:4864:20::c31;
Received: by mail-oo1-xc31.google.com with SMTP id k9so1656405oop.6
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:56:33 -0800 (PST)
X-Received: by 2002:a4a:e1c1:: with SMTP id n1mr5779219oot.36.1610654192707;
 Thu, 14 Jan 2021 11:56:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <77015767eb7cfe1cc112a564d31e749d68615a0f.1610554432.git.andreyknvl@google.com>
 <CANpmjNPX9yn5izxtYMq14Aas2y4NA1ijkcS9KN4QQ-7Hv8qZEQ@mail.gmail.com> <CAAeHK+zD17_esgDvsUd3Yku4cCKDdADo82_u3c47tMWtHL63oQ@mail.gmail.com>
In-Reply-To: <CAAeHK+zD17_esgDvsUd3Yku4cCKDdADo82_u3c47tMWtHL63oQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jan 2021 20:56:21 +0100
Message-ID: <CANpmjNNGBCrTwcm=3wrXfdy5A5=3Vd-MVdLd8BBzHRseykFX6Q@mail.gmail.com>
Subject: Re: [PATCH v2 11/14] kasan: fix bug detection via ksize for HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vmXs67op;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c31 as
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

On Thu, 14 Jan 2021 at 19:01, 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Wed, Jan 13, 2021 at 5:54 PM Marco Elver <elver@google.com> wrote:
> >
> > > +/*
> > > + * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
> > > + * the hardware tag-based mode that doesn't rely on compiler instrumentation.
> > > + */
> > > +bool __kasan_check_byte(const void *addr, unsigned long ip);
> > > +static __always_inline bool kasan_check_byte(const void *addr, unsigned long ip)
> > > +{
> > > +       if (kasan_enabled())
> > > +               return __kasan_check_byte(addr, ip);
> > > +       return true;
> > > +}
> >
> > Why was this not added to kasan-checks.h? I'd assume including all of
> > kasan.h is also undesirable for tag-based modes if we just want to do
> > a kasan_check_byte().
>
> It requires kasan_enabled() definition. I can move both to
> kasan-checks.h if you prefer. However, the only place where
> kasan_check_byte() is currently used includes kasan.h anyway.

Hmm, if it makes too much of a mess, let's just leave as-is.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNGBCrTwcm%3D3wrXfdy5A5%3D3Vd-MVdLd8BBzHRseykFX6Q%40mail.gmail.com.
