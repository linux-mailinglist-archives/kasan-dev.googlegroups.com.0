Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6VEW36QKGQEZF67ZNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 761792B0E80
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 20:52:27 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id x19sf4224649plm.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:52:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605210746; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nnxe4+rGR9r6WFH0XTpbQlEnky9pFsQqirATMbGthiFJyQagoNmiCFEx8ZXRdIrZhT
         AA/wecoiTH/FgR1VCEDVwL6yMlP+5jxX03ZTfD6+CRUmaM3dQ7Lg4poL/tjsOBHL0B+L
         IjdUKMgBG99kpEHGCfE9Zig6ZOVHHUwbJij0jRsDDFBzxOA4ZhRH45C47/ySi4M/tLJp
         1sdMRCbunc3FCMhRVmGWdn2b/13nadRKYWk5F5PBBhskqfj/jcRCbqbAeWFn52LBAwdv
         Qq8sCG4j+y4Gw90IQMR1yAdgj318oObBbVQGZAkcmj93DjPs+nwg4yQwDo8rRUX79yWv
         K8PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rqxL7bExLxz2pyT31WhGSBzVht9Er/4v7cPsbKpvbSI=;
        b=wLiOOWUzVfK9F3D2f4wQ3DcOrZQPDUFDJzJdW/dZQE/cSEVq82zwFfrWsviGEHxeg8
         aH5qnyT5w+go2Kd20ifvPLc9lj+2A7o9MrUA4aliWRb1JugkuKhX6y72ejkifTycwGfW
         2ysuBr3IEHXvbmvap6t12oUwYbEmzVZeYnJe4BWNMfxv2CRer5uUypkeVloHjdTISYqO
         t9I7GSNbwFvEWsGZ8fmbWPK8Aase8dQZuifP6TnXD76KdS3tA0a/1jjwvhwXi9Jj6F1D
         HleMf5TAC3yIhRGelrzxcQtlwCu/mo6woT1DHBzPAewUgCduB2IRfNxKS/zgCkd4MAyt
         ib4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LyRcRhjy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rqxL7bExLxz2pyT31WhGSBzVht9Er/4v7cPsbKpvbSI=;
        b=caPsKVjXofxdO11NLYADj5DzFZiU6j4YGdVUmsJNMmRW+oHu8tWoyFcHNulBjon5OO
         n87icTvw4KjH/DCAiFeYyI2ga9PSjcFLlf/D8SyVZn/phH/gQL5n/1EZX/ROrfsvyykO
         FmBZMdgS1eYg+dnNONvq8HXg+JMbla8y+2oNBSIPjw/qaPoiooJXokDDpHxiqdGyxMSq
         wQG59FOR5wVlSCtLEtLoZwp5ExmKvh/AWmfeyO7ir4sxF3wlnAqgUhLJVI5ThG8Oq+7U
         xygvtenprOOqYe5bZ40rA0fb1OUD3NJ6HRmkOJjxkzUMpe70uCWMEozwEqe6CSzaWZ/C
         OaYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rqxL7bExLxz2pyT31WhGSBzVht9Er/4v7cPsbKpvbSI=;
        b=d58i8XGevwGtekqTwuP4Tg0C9KoAj0yldiMylp2rj29hFMcTaJw3ipnctb+DRceSqy
         FpOvZwSDDCYvYkkhnlVAYTvOrE5aCLojI5OroXQWWnx3enj/ch5Stcup5+m0/7d9aCTb
         5R62keWBUhL5C4CFdOopT9JyM4tzovyrLCaDtuwbZq8NfxqksUufhlnmeU1Sv+KYrNFt
         4OI+30l9ZsSnkhzc2XRuV4+8st6xjCAgnOfAuUgSQyCcKCkuGIjafmuYQxvUhLnTmFzz
         rGASZIl8057NgCkOXv46vzfJF6LZNiGD3XEUt6hywlI8PVndzF9/y3rlN4lRoVnFwlQK
         63MQ==
X-Gm-Message-State: AOAM531P/35LMVHpmpUrcg99oYRacnrAKmlLCrqWCByFY+Alz6J8Yno8
	artepjyUOD6Prdbkb3WyuKc=
X-Google-Smtp-Source: ABdhPJxcraxdTwNqrDhbqmTiNK2nXUx+kf3n8/XVNY62fWCdtHRwrNpxCO23BhPcepJri4QQwIzWmA==
X-Received: by 2002:a17:90b:3508:: with SMTP id ls8mr845860pjb.61.1605210746191;
        Thu, 12 Nov 2020 11:52:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a0e:: with SMTP id o14ls2211418pjo.1.canary-gmail;
 Thu, 12 Nov 2020 11:52:25 -0800 (PST)
X-Received: by 2002:a17:90a:fed:: with SMTP id 100mr872462pjz.65.1605210745543;
        Thu, 12 Nov 2020 11:52:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605210745; cv=none;
        d=google.com; s=arc-20160816;
        b=UBj3ZYZUcB8NyLInZqHJk1wYYp0tvMRyDHnO13DjAKzz90OeQ144UBYjOhOj6zvcjC
         WP85DmbplF4UHTxcj80hlLjeH4GA9Oa4w9T0fKgOtwk9wmcXUv+7T1dlbspgOGuKTSC8
         85IgnerFMBAZl5el88p4rSkjfCRIJ7J59SdqFydsR8GryKeM9G3FkuDD10rkFNcY5iQT
         8RHe7EM0fagYzWb1y+tWVFVt9bk5cC9cJrYxatK/U83mhuJEPG4CA9H34hLGxxA6fado
         sK8KzXlLiuMTcu6iaFz7eSzmSpKmyzTQNb1U91Jkx3NIvSZ24LeZMq0sLg/ca9f35FgM
         slrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ku38Ht+p6L/Qff47Jz/ZEW3Rmq7V+uR73aOdxjfDMS0=;
        b=dLy+y81WF/MZbFoPzEEuDwewByActy9GjLLynEtjQvZpZmaWkHzFujJZsK/hCbvAIP
         aEJA/iM2kPCLKup5q/YezmnPn3FLh0wsjDtIffxmI/LBqtaGzky0HLgQXJ8Zr/m++Fg+
         1WY6crdFqQP+2CT3TJp2bjySe1anhoD3peD7FBycWVKBKMGRQnImPA/Dqjjjg5KaqIbc
         135vkydq5dQZV+VaBLJupsVztHRLHXBrn3dVAnXs9iFS5J1W1ULts3TbL0PG4oJAqzAW
         MhUEsMOAMH9ZaPSPOZXVI/4ea/QfAcCijv/r24EGcqPJbBFT/te3aUwwuoPqXrVt16zN
         blqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LyRcRhjy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id e2si432927pjm.2.2020.11.12.11.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 11:52:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id k26so7792982oiw.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 11:52:25 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr943053oie.172.1605210744714;
 Thu, 12 Nov 2020 11:52:24 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
 <20201111174902.GK517454@elver.google.com> <CAAeHK+wvvkYko=tM=NHODkKas13h5Jvsswvg05jhv9LqE0jSjQ@mail.gmail.com>
In-Reply-To: <CAAeHK+wvvkYko=tM=NHODkKas13h5Jvsswvg05jhv9LqE0jSjQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 20:52:12 +0100
Message-ID: <CANpmjNOboPh97HdMGAESSEYdeyd9+9MVy6E3QsvVAYuWVReRew@mail.gmail.com>
Subject: Re: [PATCH v2 10/20] kasan: inline and rename kasan_unpoison_memory
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LyRcRhjy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Thu, 12 Nov 2020 at 20:45, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Wed, Nov 11, 2020 at 6:49 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > > Currently kasan_unpoison_memory() is used as both an external annotation
> > > and as an internal memory poisoning helper. Rename external annotation to
> > > kasan_unpoison_data() and inline the internal helper for hardware
> > > tag-based mode to avoid undeeded function calls.
> >
> > I don't understand why this needs to be renamed again. The users of
> > kasan_unpoison_memory() outweigh those of kasan_unpoison_slab(), of
> > which there seems to be only 1!
>
> The idea is to make kasan_(un)poison_memory() functions inlinable for
> internal use. It doesn't have anything to do with the number of times
> they are used.
>
> Perhaps we can drop the kasan_ prefix for the internal implementations
> though, and keep using kasan_unpoison_memory() externally.

Whatever avoids changing the external interface, because it seems
really pointless. I can see why it's done, but it's a side-effect of
the various wrappers being added.

I'd much rather prefer we do it right from the beginning, and cleaning
up things very much is related to this series vs. just making things
uglier and hoping somebody will clean it up later.

> > So can't we just get rid of kasan_unpoison_slab() and just open-code it
> > in mm/mempool.c:kasan_unpoison_element()? That function is already
> > kasan-prefixed, so we can even place a small comment there (which would
> > also be an improvement over current interface, since
> > kasan_unpoison_slab() is not documented and its existence not quite
> > justified).
>
> We can, but this is a change unrelated to this patch.

Not quite, we're trying to optimize KASAN which is related -- this
patch as-is would obviously change, but replaced by a patch
simplifying things. This change as-is makes 2 changes outside of
KASAN, whereas if we removed it it would only be 1 and we end up with
less cruft.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOboPh97HdMGAESSEYdeyd9%2B9MVy6E3QsvVAYuWVReRew%40mail.gmail.com.
