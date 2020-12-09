Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP55YT7AKGQEXK4GDAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F9292D49A9
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 20:00:17 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id c72sf2228901ila.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 11:00:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607540415; cv=pass;
        d=google.com; s=arc-20160816;
        b=vUDofd9fysqru9Ojfe9T+C2zyhc13/tBOWcChRd7oaN2KHl52NBdYehze0HBtL+nj1
         49Nrd8sJbq3mYp37cRjMzMQ4lr9EYsIox7KW2/o35MvzOxSTnJ2x5XN88uR655QRILBr
         DSFGiwTxJxz8ExEDxFzGhFvB9Q+NaKomMXSJ4bKFkutqdxIrvADS3KXXyIua/hBkMBg2
         XukCJvcJCyhj2oXA479HnjMH75jzGKAb/Z/7zyCFKKuJyJXlAnv/fthXhTfdl4HjrfcZ
         bi56BPPbdYL3YzXQtCzNhIkfpukTkQWPgMLvzCFrgl2lLs1bVGIXsTnN9t2792HaRH6I
         QBYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WOH8N8f9nb781aiPZUSBpxjAxLSy05CIOyklqg/Bbhw=;
        b=AOujgv3X+0c1dxlBEga9SWlGItoDN1uCKpk+kK76Ol6BXnnQnae30kzq+Sr+CMnlB+
         8sEDLNjHOKucFLNMHnZzijCyDASRGpV3FGjBJGB7BDV0bUkHGBLKrnEUy2Z/Sy06SL3W
         SMIjINzqtDSl0IzuDqCMX58zVht1qkfmNpWbdSuPE7XbIrHUoV29y+Wh2x3N46MktU3E
         6B33qcoKVIBViQtbOzEyMDiyKpR+ab37RPMbaoryVPvoFuu0y5uET+OCiPb7UpoGicu+
         6t+1a4JHw4nLVZ7riyuXXhSZeO7Ab8tiZMyhctKHZwXXJScL7h/btbjyIPuCjygzf79w
         MLhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qVYCs76S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WOH8N8f9nb781aiPZUSBpxjAxLSy05CIOyklqg/Bbhw=;
        b=OGGCJ+W4xDKhllJPmLRWwFLyffVAlW5JqNncDM0buj7W8D7zqG6YciEBwz+6kzHt6G
         iB9Ejj84ytoWfE7/z/cbM70GKVeKPUHIB3YsPbprM9cvFdq5b7tG9RPDcS0P+Hrad6Ed
         dDgJFsWde/nk79DgFsml1TBiEVtWPKBfkaQNe/nHZekpUSVMxHKcLDrOsP8CPPkBoDw9
         LHc5uu5yQRqDbQBwAW0bnErhUylodoQsbWS+tRuLPj4jObshJdLUHIvji0LlrC8ODFox
         MEPNHUvnZZEfzmO1NZlR1do3I5gKoHdkwEWq3ZxL24Mg95ILdylFED9KQaIswmZb/xcP
         IPuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WOH8N8f9nb781aiPZUSBpxjAxLSy05CIOyklqg/Bbhw=;
        b=YN7M3LUkYDV9UnukYwdoZh3d/opPqDT7od9wztYj3c/6o3btJzy9k0VkdHd0xm0toB
         k/JlfHaS2JFGQVV5gGzDMmFPLOxBnI5/3I+6bCy0ddfXYGagZqgLOZCoaya9nuw28/oV
         nagQys5xbz7KAUWAoT4WBEhffUxwDHsHtyeJroxXjJfMc6PCEaDBWLfh9ThkA6kWf0FZ
         Im2cHBDaG3Acb7wSWAvh2cbOA7PcjaGVRioEWPxQy1/k3vVtmqexxbuCdmDtz1uCUN3k
         UR1txy89bBp9GS6Bo13c8QahRapxmlRZY6Bz6eRAfplnM1Dz26AhFnLI5fN5tPMXPbR8
         vQMA==
X-Gm-Message-State: AOAM530iUyhM14uvAtRUMGPrdukKenIeCbXc49/M5eDg7IlTkTMXaiXZ
	LOVMlZb/ywMPYbdUpknflzw=
X-Google-Smtp-Source: ABdhPJwRXT2yjhorW/P0ffjZdAC9zhye9+/7YmNLLYY1N1/OsJj5pTFw3f4SkvxFQgSzANF1AyMjcg==
X-Received: by 2002:a92:d44e:: with SMTP id r14mr4750222ilm.83.1607540415797;
        Wed, 09 Dec 2020 11:00:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f48:: with SMTP id y8ls707165ilj.7.gmail; Wed, 09
 Dec 2020 11:00:15 -0800 (PST)
X-Received: by 2002:a92:9816:: with SMTP id l22mr5063985ili.243.1607540415339;
        Wed, 09 Dec 2020 11:00:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607540415; cv=none;
        d=google.com; s=arc-20160816;
        b=K/RmktP8u5aQnatEaVWX7LsOgYoHaVji16LFHMDNhOi0CVT1uFvCEEJh8ZUCqQOejX
         g3fTp7p7REFJmoWPQltBN87lG0lKwHgkTMwN2iUAwVLwd9mFphpVO7zsFCby6PTw1Bd2
         dFo7E1x2iOhM/CwvHX/aOAB8lfdnj9c/xn06tgWAGpRwK8b1ANA9HkaGJfcChWrkSlb/
         sGSUhRiPfdeOu0AATGSpVUW5rC30ZLP/PG8IrRJ/VZs0sCS06cdj0q04Bge2hy+fwpME
         1OUWSAuD0vEpx+Ms656zdrSQNNyfI1QpLQLoLZHO4STgvZ95Uor5t9NaBiKSwhO79fKn
         qB+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pG0gcuo9xEY2L/FAHV4bggSQ0KrdHynw2Uo10jca5Xk=;
        b=wtfRzyrr3J37TMUZTDh0jb06bu4M+nXY69fOtKuxer5ZsmFv9k+hJFlUBfj9Dt1xLl
         ot8BatsTomw2CbDwTCWYhvuMZQgaAjMCxGSwjkrmcnhwZ/MxT6lbmTb2HS42jEWxxTG2
         Hz0bdpAyykqbZTa+HDtEAG7xBE9yp4TgmylewhvA6h3Ohywf+U/NY6vRsHEX2OVTiKlX
         tbeXm8UlH7cDnikUcwEVO8NTQI1X517dtQPEb0i3bHo9S/uGdCnCHDZ0YvqT0C6brh4K
         nuKPi1WS7lMi+EfJ6IUagAiw/UnOujVnNdiY2+jSltkwjk6E/Fcve+E+vk7FTuR2cpoF
         v/Jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qVYCs76S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id a18si197259iow.4.2020.12.09.11.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 11:00:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 11so2421465oty.9
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 11:00:15 -0800 (PST)
X-Received: by 2002:a9d:6317:: with SMTP id q23mr3046880otk.251.1607540414777;
 Wed, 09 Dec 2020 11:00:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1607537948.git.andreyknvl@google.com> <f2ded589eba1597f7360a972226083de9afd86e2.1607537948.git.andreyknvl@google.com>
 <CANpmjNMf1tOYTFojUQrHoscFxPPEed_vkBufgxVLduQ6dBvCUA@mail.gmail.com> <202012091057.50DEDCC@keescook>
In-Reply-To: <202012091057.50DEDCC@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 20:00:03 +0100
Message-ID: <CANpmjNPwmmvFzQW1Cv2kmphwPc7fC2MKdFLRgD+Ht5-ivzxp2Q@mail.gmail.com>
Subject: Re: [PATCH mm 1/2] kasan: don't use read-only static keys
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qVYCs76S;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Wed, 9 Dec 2020 at 19:57, Kees Cook <keescook@chromium.org> wrote:
>
> On Wed, Dec 09, 2020 at 07:49:36PM +0100, Marco Elver wrote:
> > On Wed, 9 Dec 2020 at 19:24, Andrey Konovalov <andreyknvl@google.com> wrote:
> > > __ro_after_init static keys are incompatible with usage in loadable kernel
> > > modules and cause crashes. Don't use those, use normal static keys.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > > ---
> > >
> > > This fix can be squashed into
> > > "kasan: add and integrate kasan boot parameters".
> > >
> > > ---
> > >  mm/kasan/hw_tags.c | 4 ++--
> > >  1 file changed, 2 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > > index c91f2c06ecb5..55bd6f09c70f 100644
> > > --- a/mm/kasan/hw_tags.c
> > > +++ b/mm/kasan/hw_tags.c
> > > @@ -43,11 +43,11 @@ static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
> > >  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> > >
> > >  /* Whether KASAN is enabled at all. */
> > > -DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
> > > +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > Side-node: This appears to be just a bad interface; I think the macro
> > DEFINE_STATIC_KEY_FALSE_RO() is error-prone, if it can't be guaranteed
> > that this is always safe, since the presence of the macro encourages
> > its use and we'll inevitably run into this problem again.
> >
> > >  EXPORT_SYMBOL(kasan_flag_enabled);
> >
> > DEFINE_STATIC_KEY_FALSE_RO() + EXPORT_SYMBOL() is an immediate bug.
> > Given its use has not increased substantially since its introduction,
> > it may be safer to consider its removal.
>
> Right -- it seems the export is the problem, not the RO-ness. What is
> actually trying to change the flag after __init?

It seems to want to add it to a list on module loads:
https://lore.kernel.org/lkml/20201208125129.GY2414@hirez.programming.kicks-ass.net/

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPwmmvFzQW1Cv2kmphwPc7fC2MKdFLRgD%2BHt5-ivzxp2Q%40mail.gmail.com.
