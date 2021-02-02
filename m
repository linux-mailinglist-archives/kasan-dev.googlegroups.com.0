Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXER42AAMGQE5YVFCPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id A345F30C72B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 18:16:13 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 76sf9101942oty.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 09:16:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612286172; cv=pass;
        d=google.com; s=arc-20160816;
        b=AM+hiQYrMIVfEBYAcn5y0GYS9PgAZ+ixjTzT6Gm8zSAIep6j4ed51eglhhXokhGczh
         V2miJfZ+XR4q18eRnNb10q086nOGpi8eF5M6PDUnZwLZzU/EflsQHUVDiLpNXHjTCotD
         aue0KNWayrf8EiiKVr+ev0IT0e6OIBuH8/8HqbaGilM7yApJ9aLTgYBSLkdJflFujmFI
         Tis9hczrwKid1WWTN99ReScK+Iv5WgKYSIii3QCTAE+gDCqzPBstpTw8IQ/F0NDYwI95
         pQImCPJw/Gi8OGHievNf6uNGn2WM2ypzGFxxfKUg06Gvb5v08v8MWBPPcHtcWRg2rkXy
         18Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iB+l+sgIF/jlxvyTsVtShJYothXmKUlCJYDZeKZV0o0=;
        b=a5w1PozH+RviSzDkDJ6qXL/WZXcpnN19cw+MSJgzde1AN5iwvmhcJf480UqCOpnCXX
         shZUMr9ecFspTbq9/f4OvEvuOb4oNsiJunkkCNs0yYbkhLeNbbTdGUmeZIJ9con08mwi
         hZL+tsOk3V9YsYVlKzntOBqSyVa/d1RZ3EmRCbjAsmEbYHqdJhJVIaTuqTL/QKDf8OLK
         FekOjkpgG8TRONmRhJGYpZTb2VKPq1DoWkcMJQb7juPcj2qy/p44SE0QXS5JQ/DiN7Tz
         6oH7cL1DzqViXYIiyb6nhaNQcQvuO2YL7TfMjZ1EH5lZbtTFwq4O4M1HUuZkATCjrOT1
         xA+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bBR97nkE;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iB+l+sgIF/jlxvyTsVtShJYothXmKUlCJYDZeKZV0o0=;
        b=lkweyKYQPD/K7SsM80hpsYHNf9VqNCXAMV60xqm9hTpzvJVm7N1cYNbF3rj6cMnA6N
         fYTXjyzru2vZYpFZIlwx10pt1A/77RYPCAgbeXb0JmsUJnrNzqLG+y0vD5xNKrAbvslq
         cL+vE+ZsPiFu/spiofLz9kDp/IGay31NZ5H8UBCLFCyD45e5FvuJZbkMzHBawpko0SS6
         IMOGvPEblieKTgmocI4j6wYjrcQBrod/S4rlZq3U815A9KN73IoKoezdqXMsV8Puao2r
         aMhfGtCjgsljhytdVvrbcJIaFf8b0VJPeVtdi3g83E1J3ISrem7nIlwMYFjLMdLVQntv
         Q4mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iB+l+sgIF/jlxvyTsVtShJYothXmKUlCJYDZeKZV0o0=;
        b=SOI73YhpxVmh2cNX5C6hpgoPo3zw6hxIv636yCF+Ruy2vFN9Hbny8B+5Xsbhm0JHaF
         UvYy/qSlKfYWlgyw7sETcCOe0TIe5Uo8o7EBsHuyKKG2PRGDKaFsL0p+EP+L3Jmh+WRQ
         E1Mm7wofZy0b46zpQLvVY4l69eh0lmlCNFfncNejEJwlDMo5k7N1btd8QRpyonF+TR4n
         hV7ibLbUT1lUrJW38pNK8iuzgMVuG5RwfcF3n6PcbTQYXWev4/ZbYJuoKYNOIkpKwyhx
         yFq42lgqwAHP0IUSc/NcCzX2w7VNJwp1nC4kI9szqfY6noHg4VPq8xxj/AOangnVU0oO
         dkow==
X-Gm-Message-State: AOAM532w7+qZV30HU+XzU/Q9PkEVAAl1dExKMqIwz+i9bI13Mv4XMRZ1
	MPZqhHV2nGl1rVdXg8xc+1k=
X-Google-Smtp-Source: ABdhPJzqbH5uwByX1pfhz6FiyZCNUt/AU0rzGc+X4K3ppj1rJDoAc3HYr3kvNvIjzZYyeGQDEnlMtw==
X-Received: by 2002:aca:5285:: with SMTP id g127mr3536538oib.74.1612286172647;
        Tue, 02 Feb 2021 09:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fd82:: with SMTP id b124ls5083741oii.3.gmail; Tue, 02
 Feb 2021 09:16:12 -0800 (PST)
X-Received: by 2002:aca:dd08:: with SMTP id u8mr3618297oig.55.1612286170557;
        Tue, 02 Feb 2021 09:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612286170; cv=none;
        d=google.com; s=arc-20160816;
        b=lgAQ4jQRJDpfDVbkUakNmAs6Lk1PMexQdSn+TvG7WFKxQRgRspBdDOMQ6YNLGL3L/g
         T+T39wvFRrFuWKiUveuKbu9RyQ/MuS7SXHZbbh3ndySUBSaWZTdqq501Z6sNOPJJgH06
         9HG4CTPJrTKlJLFfl3c78X1JRj1yHeITuoe8Zf47DVBnN2OtzUOnZvmrM1g4LzQt5DC4
         A813eMCyAHegzGOWzcaXq+rwWn/s97R+UJn9MCfKiPSpzGHJcCFNCKhs+mHt0c6yfzRD
         0vnFdgNoQJrJhKYREuV4sOarJz+EPwWhgnarsrIBs0LShpyr9ANz6lNHIQgBJvkyt6Xf
         nthg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qn4pclhdqmAAoIxBnEwAj7m8g+jtHb7YgGNlKFxvSYU=;
        b=e5f6PugwTAN75wfn1VZDclJIEi55J97r7lsrpxBDQ5L/mhsEQ5kzLIAM34LsFBZ9DD
         HqGXY2nDMhiDeVgO/jeC5s7+kyN+mhPseao8ifN5dIzltXaEZ/C5RZyWmVKpYl0BCsPG
         8JjL4C4QeOv20QEvJ8yXemkagTPbnYwBwG+8WTl7tulM5M4M63CvBVDwBwpFZ16BbWBV
         lwNIVNmm1p7808803vwW4s54ZYghXmrpddD6yGyDj92O0mHULRaRcqPZIeZXe8xwqjQY
         Jf0Lu0NdGtj4mxz/0qqsRX1kgiNhcA7Uazc3t1E1qpiOaaIfPVg5KTOr8ZH74/zqROg5
         0p5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bBR97nkE;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id t22si1347237otr.0.2021.02.02.09.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 09:16:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id o63so15290432pgo.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 09:16:10 -0800 (PST)
X-Received: by 2002:a62:18d6:0:b029:1bf:1c5f:bfa4 with SMTP id
 205-20020a6218d60000b02901bf1c5fbfa4mr22215803pfy.24.1612286170018; Tue, 02
 Feb 2021 09:16:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com> <b3a02f4f7cda00c87af170c1bf555996a9c6788c.1612208222.git.andreyknvl@google.com>
 <YBl9C+q84BqiFd4F@elver.google.com>
In-Reply-To: <YBl9C+q84BqiFd4F@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 18:15:58 +0100
Message-ID: <CAAeHK+xzBpdzO7BmdVZe3_g5Di+-AGyYAO5zBVvOpEUtXD8koA@mail.gmail.com>
Subject: Re: [PATCH 02/12] kasan, mm: optimize kmalloc poisoning
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bBR97nkE;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Feb 2, 2021 at 5:25 PM Marco Elver <elver@google.com> wrote:
>
> > +#ifdef CONFIG_KASAN_GENERIC
> > +
> > +/**
> > + * kasan_poison_last_granule - mark the last granule of the memory range as
> > + * unaccessible
> > + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> > + * @size - range size
> > + *
> > + * This function is only available for the generic mode, as it's the only mode
> > + * that has partially poisoned memory granules.
> > + */
> > +void kasan_poison_last_granule(const void *address, size_t size);
> > +
> > +#else /* CONFIG_KASAN_GENERIC */
> > +
> > +static inline void kasan_poison_last_granule(const void *address, size_t size) { }

^

> > +
> > +#endif /* CONFIG_KASAN_GENERIC */
> > +
> >  /*
> >   * Exported functions for interfaces called from assembly or from generated
> >   * code. Declarations here to avoid warning about missing declarations.

> > @@ -96,6 +92,16 @@ void kasan_poison(const void *address, size_t size, u8 value)
> >  }
> >  EXPORT_SYMBOL(kasan_poison);
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +void kasan_poison_last_granule(const void *address, size_t size)
> > +{
> > +     if (size & KASAN_GRANULE_MASK) {
> > +             u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> > +             *shadow = size & KASAN_GRANULE_MASK;
> > +     }
> > +}
> > +#endif
>
> The function declaration still needs to exist in the dead branch if
> !IS_ENABLED(CONFIG_KASAN_GENERIC). It appears in that case it's declared
> (in kasan.h), but not defined.  We shouldn't get linker errors because
> the optimizer should remove the dead branch. Nevertheless, is this code
> generally acceptable?

The function is defined as empty when !CONFIG_KASAN_GENERIC, see above.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxzBpdzO7BmdVZe3_g5Di%2B-AGyYAO5zBVvOpEUtXD8koA%40mail.gmail.com.
