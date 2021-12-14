Return-Path: <kasan-dev+bncBDW2JDUY5AORB26E4OGQMGQE7OQSCYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A4140474AE3
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 19:29:01 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id b9-20020a17090ae38900b001b101afc766sf391538pjz.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 10:29:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639506540; cv=pass;
        d=google.com; s=arc-20160816;
        b=P9KXz9jYlrk9w8gq7nxyEOLFUk0kj4Equf266Gv05XWvW9gWyXuRPE1NATyLktecvd
         T/6IgyyvjNd2qQFxHlhzNKK57DWhgv9UaP+AqnqOIdss8Ymq5eT+XeMxjSmBHd3pnOgY
         rfm0DtsrLsbM8W7t/sdSVI7kGQVlWFXHPqfoL3GXqk7gSCcPfy+kM54tCeJlA0ERHr/A
         VULKRT6+EFTBDAdX4yHVPSh66nXkbitoru1cDdAdIZKX0WCp+8Cjlb41Gdq048qixbfr
         /gaJG9ynXDBg0EZkT9NwfxuC0rULQZpzi0EyGsoJEk0z+ZCjDg6Qfkf1ojxSKXS+TM1M
         LYGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=RFIWHUedPq4Y0qAT6sjWaOnL5GY4MLEgQTK82yHsp4A=;
        b=gm5QlFjjnJvMNuClzZ+yUd2IuCOsq0HQ05kvSxzNdI8Ge2YgSPdgHN4yjD/0Ar8DP9
         cqEcya4Afo/vUP2zCaWitmegNpp3bSZe+yD1bxiVcJU6Uy57vBOpL1vdRKAmlSIHhPbs
         kQdNUES/l81TuKcNodoQpdmh+B+RsBJuVhGDsqSukRUEdTN3UQpX/9MT7CjFi/dUQZYA
         8XH1W3kSkco5Xx1Ryb8QfEu4bAQ+czdIj11USPRd1z5fyfd2XXfAaqViUB0cg+2NnU7h
         H6DdhRsDbQj1fH5/Rg4h+nkOmcqafxxRhgqs8CcWovSksCA5pA71TbF3jJ6/U8ZAci/y
         fF5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YtmXK3Jn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RFIWHUedPq4Y0qAT6sjWaOnL5GY4MLEgQTK82yHsp4A=;
        b=BcuHvVkwDCaIUIXnTKfLaH+O5u8xsxKbTeDi/qSxvgfhoPohykaFkslxwv0Bncs4pA
         itbwkAR10xvNdTS1sxRpR0iMHq18dI4SRmiqWGWJLOfMSBQBKwnxEoj+L7JgWj+OH3F1
         pJR6p98wEbvyKrejyZ9RZ+3FTLTQZHqzoAG48HDqZEH+WL9uQaQ9zP3RvxCgZlu8DQjh
         mB4yM/xQ2h7ohZtDoEvp5kn6EG/J4h4GY+ydJaQlr1N/ofhfo8h5nuvQhKwVHU79mkkv
         MJ2ej68dqyA7CHB7mGn/bttIGb+MvSukuIMoBt5KbzfbSZIxMph/kjc7lNEkpKYqTr5s
         9cbA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RFIWHUedPq4Y0qAT6sjWaOnL5GY4MLEgQTK82yHsp4A=;
        b=KRAgBePu1M/6JMZ35s0lHt7A0KAZ8UMEcNL18r2e2dXFzCY5mJUR46bz72W+E+zEBi
         jTAnwzJgWyQV6FNR0bV+86v5mJVCr4xKK5bEwSXDYTPX5iSls3Rw7w3rZxU7Q0RoIwrM
         IQIyeI190HX8T9/vVBvrgeV3xdGLvpNh3ZX28Yi1egcdhlQUaeODiyEJ44g6Zier720Z
         /jIH/leLqdhQJrXMKrtdN9CxnPT8dgUmWV9vkl2UAomz0pJdqMKwCVN1V4J3EWD1wxjC
         HVjDSLlnNjbY6Fw9qOTx1SLxyluqbMw09YOf7UlGXrRbanZcsUgpJIn4jlKVeSV7JYVK
         OA9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RFIWHUedPq4Y0qAT6sjWaOnL5GY4MLEgQTK82yHsp4A=;
        b=YZgAvt8WwlbF4WG1Q15f4BD4ETQ1nismDl8Rr43r23HeWYqzje9fhUI1lS3gPlhCoq
         YVDmqL337oamrnJ3kXIXz/+GXEcISyK/fkOd3k76PGw8aaos+GEagjsLg1buseIeNP7M
         qb+8wekWhlxoMoM6S2L243RJpjLFR8+c+o4d2YbXc46gCR6ys7W5HXIIisQQ5LyQVzww
         PfCBkSQOn1JamavGvZRLeMmmQaOMRY9V7Jx4SWVK7rpCTwDg7giEMeSaAivjzZmZ57OW
         ewkeSflzg9h7c+UFINER5E8+HQsaGIxO2Jwxs02m3l4DAo3QPYE/Esox53eDDNXpHsh8
         +Gmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338DwEqFTABjF1MkHU1DxHYuojFMUdjietwFyNPbwCMmY0xFNmf
	LgmGJ5zQCRHWDHQD8C8rtzg=
X-Google-Smtp-Source: ABdhPJyWwglPRYFr6hU/slwydJVA8f+6t9Q3cgXAyFDCXiJL4kO5ywAAYXF/iUh4tmcBC/enQtHnRw==
X-Received: by 2002:a17:90b:390a:: with SMTP id ob10mr7432685pjb.216.1639506539857;
        Tue, 14 Dec 2021 10:28:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f8d:: with SMTP id 13ls1143977pjz.2.gmail; Tue, 14
 Dec 2021 10:28:59 -0800 (PST)
X-Received: by 2002:a17:902:e8d4:b0:143:88c2:e2c9 with SMTP id v20-20020a170902e8d400b0014388c2e2c9mr7143395plg.12.1639506539242;
        Tue, 14 Dec 2021 10:28:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639506539; cv=none;
        d=google.com; s=arc-20160816;
        b=qAiCFkGhLwkTYYk/+KqYgdTKKpzZ6ac0Vs8f/re9ifuOCwwMtoZBqp+TqVGSKo2F8S
         +ERAxLOcNgS65YdAsr3xMev4h+lOtpxDCp3UZJpg3n1d7WZuVMUWfbCyWOzNybQ2SVOf
         VfxsPHeOBUFMi3XXSesH1JLBI6R0PlXqPyHdN+aAxynfL24M2mHZQnDSIIiHFgO/SgSw
         wHP3WvXndf5Ev8UIucaHm84DQM1bDaSkmxpb0tKf62s8Orfp82ECG+p3zciH4WgCtLRd
         iNEsIzqgu8xfDAbCYwyvLtTwMSWQ1kTkwcfkYLautpGNulw+g+dhPhN3mUYzi5kbSHxb
         uGkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/eebjakvP32P8uCIh8l8LVBJtnJ0BrHqeLhOnlTGnSw=;
        b=HeZwXp2pwu0xsHlqTjQI2xK+nF2nTt1Tk93LlNGXwyhQlGltP39BLWwaDgh0l+91Q4
         v5KbvjT2M3cJjEYriz/EAVCDRm0RH2xbYoz7b/3IGwd23TSSawEqu3P46RB81+kYrJRl
         U8393PLTpx+lAAI94cArhBC3JwcZOUhbuDkZ46PZ7KobYXQ99EIPRDoBBYaWSTyiJVML
         J2nOxM7bMVOJTd5NeI7TpPHh5FirpdLttXUbvMWe/2nfXWLyo0KnEotgVpkSzJsBZzXw
         MjQb1xABMtd1AJHVpxpNOHui5HnOWOOSpWPlRDThysZCv1j1MM8/sOzXxVTrRSSMBrjN
         W3+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YtmXK3Jn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id z21si49520pfc.4.2021.12.14.10.28.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 10:28:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id r2so18069835ilb.10
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 10:28:59 -0800 (PST)
X-Received: by 2002:a92:c090:: with SMTP id h16mr4769444ile.235.1639506538741;
 Tue, 14 Dec 2021 10:28:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
 <Ybjbw5iPg2BWsgqF@elver.google.com>
In-Reply-To: <Ybjbw5iPg2BWsgqF@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 14 Dec 2021 19:28:48 +0100
Message-ID: <CA+fCnZfx-if88cgRQ3bZM4aDriCiEx7Bg9RFw_9GMQn2JiwCcQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 28/38] kasan, page_alloc: allow skipping memory init
 for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YtmXK3Jn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a
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

On Tue, Dec 14, 2021 at 7:00 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Dec 13, 2021 at 10:54PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add a new GFP flag __GFP_SKIP_ZERO that allows to skip memory
> > initialization. The flag is only effective with HW_TAGS KASAN.
> [...]
> > - * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
> > + * is being zeroed (either via __GFP_ZERO or via init_on_alloc, provided that
> > + * __GFP_SKIP_ZERO is not set).
> > + *
> > + * %__GFP_SKIP_ZERO makes page_alloc skip zeroing memory.
> > + * Only effective when HW_TAGS KASAN is enabled.
> >   *
> >   * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
> >   * Only effective in HW_TAGS mode.
> > @@ -242,6 +247,7 @@ struct vm_area_struct;
> >  #define __GFP_COMP   ((__force gfp_t)___GFP_COMP)
> >  #define __GFP_ZERO   ((__force gfp_t)___GFP_ZERO)
> >  #define __GFP_ZEROTAGS       ((__force gfp_t)___GFP_ZEROTAGS)
> > +#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
> >  #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
> >  #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
> >
> > @@ -249,7 +255,7 @@ struct vm_area_struct;
> >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> >
> >  /* Room for N __GFP_FOO bits */
> > -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> > +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
>
> You're adding several new flags, I think you should also make a
> corresponding change to include/trace/events/mmflags.h?
>
> At least __GFP_SKIP_KASAN_POISON is currently in there.

Indeed, will fix in v4. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfx-if88cgRQ3bZM4aDriCiEx7Bg9RFw_9GMQn2JiwCcQ%40mail.gmail.com.
