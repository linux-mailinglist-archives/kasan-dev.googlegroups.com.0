Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP6R7D7QKGQEYZZQUUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B68092F3C7A
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 23:54:56 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id l191sf85264ooc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:54:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610492095; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDvAnAg96K+D4qhmlCvLr+g+0h9KCRq6vJM52pwACTcthIDGCGQyO2GFPUY8Kd8ktk
         P0HWYzct7CDmleEN/I/Yjq+ALtbZmUmsE9aUKTgzAFWd9AxNlHE+ObHOaru4th21A/4x
         ob1z2t9achWZ/01gnV2S/Cntznq+KGBJQS1nMU7zoJm8AVoZ+swBrAkziCH4Cp5aBWTd
         1IXOHZkpTkkgQV3y8nkDsy7T9lbR+9JIdYkFNWvBYx9UApaKG39i7zPKBc/4LYiw97ga
         d1etjoRnzUDcFDoH073qBC1F1xfqZE/9TBRvhCaaatHyLkyg4cok1NcWTul8/1DZFdGL
         Vs5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5tx9MLL+nQza+wPWHmBi+ybpyxZ8P6xxI3P+60OMSiM=;
        b=MXeHiLAUB130f8d1+I0fkfYbb5QR9ckzBIf6Y/LNAlEn/5ZIhaqrKKtf/YMEPS7Wug
         pkQPjMyCtyblTgryoSrfTNJF0jQGJKRCmto2G5E3nhx0wWHm4UsIhTsWLYPOyZMgHIUn
         6EJPe364X0xrTTdrNaOSfM8W9YJeLz8iaAHE5IANKzRZzOqoxVbWdGN8wFErTM28fcOR
         aMjS7M/te5NEzuTQkfAmPViyEQQebz667reEbj//Y5G2VyO07xJ2GdyhKyMOtgOsx0ZW
         kdDJFBwrwca7rbbrafb/HxCFPBKhk6yXkty/KJctDegm8QcEwZTRaLCTZlnpHPKkWn0B
         xnKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ww3KXfMq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5tx9MLL+nQza+wPWHmBi+ybpyxZ8P6xxI3P+60OMSiM=;
        b=qzRdV/e8UfAHsT+Ni3VABAIDS39ETapX96p8NCe6okNWojYvD52dtp/lcMVQAtR8Hc
         +R5WktIeJF2I9K4d/WRhAD33X0VxPykYhXCPGlpEthaUmDIp7mw14yeNyVbf6hGbdVIT
         O9qY6mxB+7IvSe9AI4Z6GPMk0+KlLe/P7ulGDBLLbGMWG3CeBjlDcXt6qz5CpTA1S8T4
         nA+TPBr07AJQFR8vtY0hArV9XyDQ97wEap0tp5+1NXtcN07DwbD+xXHRN4gxpUEOasck
         ksxp+bprXdXgnAnTSQmr5NOBIWBw2feLRvFow5ejLBXXmInYpLTIpQKUamBMKfcBYSHZ
         hkcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5tx9MLL+nQza+wPWHmBi+ybpyxZ8P6xxI3P+60OMSiM=;
        b=nkHAD3Bsy7GfltwoUI+yiVuK8+rGQVXmVHKioIfPpJap0uTofVtIOeBNp+kEURT6Ir
         BuAZuu/jfFCZ3hIH0eEEOjGqjC/stlxx6OnXWbuCOTX1R62O6b7/tbC7u0AGEXqn+Qa3
         U+/KmnATmnf4sDYZj6NjFwgn1/UrbXG2xO5JhYahE/ubNWFi6bQHakIkfepVY2HvLomN
         iYb69YEk1mA+VMG5fICtgkmpwNI0fKbcYciOOb8uMK746YJwgsABZ+6XtkH+vVm+wUCs
         ig8d2W/87lMqaOlsQMgFNygsjBidwSZytgcdzGR+vwU++23w4Kork/hry5r3/hjaqjk+
         mUtA==
X-Gm-Message-State: AOAM533JknDB1AdoxXP2HpCCw7EoC6JWwc/eGEikN96KanFdPYFSxDgZ
	XQosRK6IlOqAdVu3NRKqO5g=
X-Google-Smtp-Source: ABdhPJxAMwnDl6OSlgHCCWSE66KhJKFIa+k9T8ePRNOre4QS0oqybkawvl9KVV2ZnLKZGydEc3yGoA==
X-Received: by 2002:a05:6830:107:: with SMTP id i7mr1077182otp.247.1610492095555;
        Tue, 12 Jan 2021 14:54:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d15:: with SMTP id o21ls40078otp.2.gmail; Tue, 12 Jan
 2021 14:54:55 -0800 (PST)
X-Received: by 2002:a05:6830:cf:: with SMTP id x15mr1122320oto.55.1610492095185;
        Tue, 12 Jan 2021 14:54:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610492095; cv=none;
        d=google.com; s=arc-20160816;
        b=0nuhb26P/+STBncbCaZzrrniuJHiJTxAmVJeucYs1UAnr33q7RkcYjJAE/YDuTznch
         SJh3ZadjCQ0UjZdklCHvFQB0w8OByN0xuJW45WvijxCl2k3ajeo8j8gTIaAt+T3Cov7d
         uPTKBYep4H7JeXPRcFSLb8FA0nVkPza0uDmpv0aQ/rmgmFXEjp5VfZIVSRqCWRGZ7Ygp
         JCrxCQr3KOL1Z+uh7daRS28gbT7WT/tNfNTxJCkTpe+dpNYtVz24FqyIWoXWhNV3Bouw
         AU4ANWzkkN6fL5qP9YjFhedAZBXh+gWwSUB2A17dHaVXEpvSj55CGEp4XsgIvNS3k0vG
         k4zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/vYKtRUvIW2ynJjXb8EKOHINwCaI0vhIQWTSSZNFGWc=;
        b=bEpUBPf4x6QJYZ6ofQ9Pk+DbHPXj0+xrSmndWyeJFUVPimZqVSuRPsSLXq030EOZfz
         T0UAtPcmLuSPAgmC5KdM1Fo4brnxKbH+J3NS0nEm26GiLEfvXAoGQpLzbeiSnSZVeJ3f
         3XBqkTKAVy1qpPgiUU7QqQ5LOaHL+0y2d63fN8LAVIH1cp1XEL7dDhLmPLT8t2SshEd6
         b19nlT7qG4FrrPkRBVu4q7Ul2WPKKRgs4wcDiwzqcvhGSi6mqd5BwXcU4WuFRZaYZwl4
         GzoY0Ut8/2fWK8d9FtTFVX1iCXV0ODvglfsgAi2EZeRfDL9NE05tf/rDQG/PHV2qPlV3
         dhrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ww3KXfMq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id v23si8217otn.0.2021.01.12.14.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 14:54:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id j12so90556ota.7
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 14:54:55 -0800 (PST)
X-Received: by 2002:a05:6830:19ca:: with SMTP id p10mr1108587otp.233.1610492094692;
 Tue, 12 Jan 2021 14:54:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <a83aa371e2ef96e79cbdefceebaa960a34957a79.1609871239.git.andreyknvl@google.com>
 <X/2zBibnd/zCBFa/@elver.google.com> <CAAeHK+y0nmeDEWG8ZMX9KmE3-MhWCtrssDJi5oHG2PFNtrDK_g@mail.gmail.com>
In-Reply-To: <CAAeHK+y0nmeDEWG8ZMX9KmE3-MhWCtrssDJi5oHG2PFNtrDK_g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 23:54:43 +0100
Message-ID: <CANpmjNNfLG-iCJY9=ogiozYGmEat0U=huMpTO4RrC0LebOdmkQ@mail.gmail.com>
Subject: Re: [PATCH 10/11] kasan: fix bug detection via ksize for HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ww3KXfMq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Tue, 12 Jan 2021 at 22:16, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Tue, Jan 12, 2021 at 3:32 PM Marco Elver <elver@google.com> wrote:
> >
> > > +/*
> > > + * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
> > > + * the hardware tag-based mode that doesn't rely on compiler instrumentation.
> > > + */
> >
> > We have too many check-functions, and the name needs to be more precise.
> > Intuitively, I would have thought this should have access-type, i.e.
> > read or write, effectively mirroring a normal access.
> >
> > Would kasan_check_byte_read() be better (and just not have a 'write'
> > variant because we do not need it)? This would restore ksize() closest
> > to what it was before (assuming reporting behaviour is fixed, too).
>
> > >  void kasan_poison(const void *address, size_t size, u8 value);
> > >  void kasan_unpoison(const void *address, size_t size);
> > > -bool kasan_check_invalid_free(void *addr);
> > > +bool kasan_check(const void *addr);
> >
> > Definitely prefer shorted names, but we're in the unfortunate situation
> > of having numerous kasan_check-functions, so we probably need to be more
> > precise.
> >
> > kasan_check() makes me think this also does reporting, but it does not
> > (it seems to only check the metadata for validity).
> >
> > The internal function could therefore be kasan_check_allocated() (it's
> > now the inverse of kasan_check_invalid_free()).
>
> Re: kasan_check_byte():
>
> I think the _read suffix is only making the name longer. ksize() isn't
> checking that the memory is readable (or writable), it's checking that
> it's addressable. At least that's the intention of the annotation, so
> it makes sense to name it correspondingly despite the implementation.
>
> Having all kasan_check_*() functions both checking and reporting makes
> sense, so let's keep the kasan_check_ prefix.
>
> What isn't obvious from the name is that this function is present for
> every kasan mode. Maybe kasan_check_byte_always()? Although it also
> seems too long.
>
> But I'm OK with keeping kasan_check_byte().

This is fine.

> Re kasan_check():
>
> Here we can use Andrew's suggestion about the name being related to
> what the function returns. And also drop the kasan_check_ prefix as
> this function only does the checking.
>
> Let's use kasan_byte_accessible() instead of kasan_check().

Sounds reasonable to me.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNfLG-iCJY9%3DogiozYGmEat0U%3DhuMpTO4RrC0LebOdmkQ%40mail.gmail.com.
