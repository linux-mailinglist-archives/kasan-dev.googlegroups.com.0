Return-Path: <kasan-dev+bncBDW2JDUY5AORB2GE5SIQMGQEZWE4FMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ED3A4E533B
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:36:42 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id g5-20020a0568080dc500b002d73eb5c37fsf951440oic.16
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 06:36:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648042601; cv=pass;
        d=google.com; s=arc-20160816;
        b=EbJsPABLH66SdTbw7zBmuTarixo7xpv/32g3WzlrTLs79YLJbckFWOzczyGIAJbdqY
         KLWR4CEhQ3OYIcF79njww2bBxJeImAnRwqS0toth7hoYxX/HtvVZy7bk4iGtzmR2oP9X
         80XbtYmS2yypCjBl8ADHiCGicevyN1PdktfWWjO6sI3UKDbQg6m6NZy4juIKrUkOz8mJ
         u17O+1QwJ2jpRbxnKellzjgXXwtcNWdo4x624ZM+Z3+Vvyw8dpnkHoQnXJtJvlkNbVJC
         UrxOPM4v8Z7ELu38P7KE3P4mtyr5ZGJENB6Fd3PtojouO08gUBq9YZXseqbknvLSOUkr
         7vRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ooTTN6ejnFiq+2C0gxB6h1myqiSyFhD7SzLQtfcInHk=;
        b=S4MUxSXVVt4wTwpupH2W07ug56xG07yd2XPPLj9YGBuoyDTtVAfZh+U5MfXl8hTld6
         h9U0sZr4WyrqYBQovJQJN3bkfo3q6ZNYCBXODIKhRkIuyR3T9P8dmi6yLGp0TY3HpeQi
         boQuFlvWuf29TfOLtay4gjTnd1NnbdZVnwUuh6SDDSyH/xfzDX6RNRoydpI1Xhh0LGV0
         jHkPKljlQYP0uZQ0jPuBJxWShooZVblKZb4H/miH4K58i04U81SDYvdVadlVcxhO4/hC
         dVYSoY1Ga2fenP67gZSNdzTYHhQrw0QqK8HQTQOCs0+/6RlSPUsu2KvfKNdRmO485zqM
         ggiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="NRryz7C/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ooTTN6ejnFiq+2C0gxB6h1myqiSyFhD7SzLQtfcInHk=;
        b=firQWhVk4JAPulwrUs/NNjfpQjehl0N9CHTi9zLafqSJQcWeeNdZRB6ETbK8dF0eNA
         VIZCOx0cVL+GcySTy19gTeLtVC6Khpm0GzuhlMncTTqmIzp3Dmr9Hv5i4Pz7Pz06KP2F
         hVkb+LeYboLinTDnoowUkHNu6OioOKvbcvBToKbxWm0z2QtSSZMuAxh2W4WsDXHtSQux
         AjGB2XMLU6tfibixKzRxMzpw8J5uhzBZ4R2zhyNFTTdBdupayCItDTCKk6zbvOpSkGiz
         s1SEPV1EPi0qZQPwzwd+MdzymXtK50/E7ALbkZdIUB6Q9tqsBzk8u/TOIMO6qPK+Or6/
         TPmQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ooTTN6ejnFiq+2C0gxB6h1myqiSyFhD7SzLQtfcInHk=;
        b=XcsQ0p0jNNM4TR7EPt4eik/f4CK1STp43ddcVu9NZh0msP55mguxOPBjp2Lw5chQCe
         G1C5lpd9xi0P+9zqkjwQaG+JX+WJZUsU9E0wA7/7SxM+EUtR71oMLoBtItrP9YvdFneY
         m0iYFmkxK8j1SsS5jYiMwVeUiUQHRmaDGp4xhyu8HSBSQqHjONw3+oufMVZ1OLP7jktO
         By09ZoJulo6xme8NQtSibKaAvxqie5yQ87JOEJfUspEt41HMx9BMj783LpMfj47jEG1E
         LI5L417Wop5c2uCyHx8/A4K/ETrxmeTmngXOr8WB7OdpLXeMnBimm8meW/SNFhCgmYEA
         LTsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ooTTN6ejnFiq+2C0gxB6h1myqiSyFhD7SzLQtfcInHk=;
        b=DFOOp563kBdJyBCB2g/qOrJxl1+ZqJkcTqAADxfDqXVGRHRvSCysxQHTGgBJ6+RkIQ
         hIWqgVkNZpdWgiRLJQE4ZrwMkQyOI634oScrPHwmTKpSrv5iJU+vuqec/DpRV1ethUqC
         OZIh/4Nwr12IymUMW2O4WObiSHo7YjOzb69dwCNMJZzDjAsS2/mYtvJmZggBUifbt/gB
         y+WgNZ4CqQDbFi/TeTPBEoYjIC8S/wmrWhVBA+0LS/vTMgA1EFAIyv1SO7FDCHvo1Sfr
         S0gtgro8UqLs5Gv/8Qlgy92tR8zUZ4tA8daXBJAR4Qu/9dFLqQLUWxEYzGJRZQ1aihtt
         g/kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Y54puyA2z2LvPRrBayg+m1Par9ioRziVBSjnSJ2sw1jctqgyO
	XaWzcwRi5nS2E4oOKHn1KXQ=
X-Google-Smtp-Source: ABdhPJyiQdB7fOoGrR9h4FsGy+Le82CikTvVyKVFe7KrJY8yyzq9M3qH5ct9lLW8dyKboDLVvQ0Znw==
X-Received: by 2002:a05:6808:218b:b0:2da:5fd1:a85b with SMTP id be11-20020a056808218b00b002da5fd1a85bmr21901oib.71.1648042600761;
        Wed, 23 Mar 2022 06:36:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4c08:b0:dd:f8d1:2137 with SMTP id
 pk8-20020a0568704c0800b000ddf8d12137ls4312531oab.7.gmail; Wed, 23 Mar 2022
 06:36:40 -0700 (PDT)
X-Received: by 2002:a05:6870:31c5:b0:d7:d5:5df with SMTP id x5-20020a05687031c500b000d700d505dfmr4058989oac.57.1648042600434;
        Wed, 23 Mar 2022 06:36:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648042600; cv=none;
        d=google.com; s=arc-20160816;
        b=kFBXYv8RSAZqOMPFNbOkbu6k+jz4RbaibpaYPJ2Jsi5oSj9Mkl69JRINdScOXBErvd
         +P2uIvkhixl1vYUV6tbRjM6YFvJZPr8YQxnFcu649FKGOiMqvp3+dDboOgnkR5jC/9sm
         P9lUBI1V/9rQRcfxOHdLeVTvqR5q8RmRsz0ZkL7DjKQjQ6UVTCxoSCQw0Lo4tCdtZ5fI
         b/Da934xSmPRa8fgvM08hXqFKU8Puo+Frer8tAPSUTJbN0Hywr/Ap43Drfa7Mbl3RW2e
         qngKmFlKbuEI1Aiw2aD4HyizuTqq+sLgZyE8LNtaUFaNNlvaaLNldNhI2vzPqoAStIQc
         rNag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0FQgYBAsErSA0oer7QMlQ/bPAVMnnC+mA8O5EU9gYhE=;
        b=v8tdOhwgtAET6Pp66EdHxRBDrqsXuQxOzFcNNlqT8zjp2n9hYFe1BqE/4onWDaT5fI
         tw8c4+yDDo/Qg1s0IW6vgkwkIMUyheG5bYCo6Ryg0rkdwCoaMdLF2VsDwl24HB1mVRhA
         8wDK+mGPOuB/U/TDv/pU24U71pgHG0czqNIhk/PtwR0JvZSviolOJsHNqhbyO7Js9y/6
         AHr7XBfjUD1wStGSz0dGuF0ypBkro5qZvwNpUJeFMp1OMEjm4tZPpM4uWJUrPA8rYnl6
         9+fpKb/AhgJjtEzZtlz5TbGHFPgUghdZKht/QKk4ylXuu5SUNUknP70HFNoj4qp2uepd
         lpcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="NRryz7C/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id go5-20020a056870da0500b000de8442710bsi32002oab.4.2022.03.23.06.36.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Mar 2022 06:36:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id 125so1667019iov.10
        for <kasan-dev@googlegroups.com>; Wed, 23 Mar 2022 06:36:40 -0700 (PDT)
X-Received: by 2002:a05:6638:4881:b0:321:6522:2cbd with SMTP id
 ct1-20020a056638488100b0032165222cbdmr3282446jab.9.1648042600126; Wed, 23 Mar
 2022 06:36:40 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1643047180.git.andreyknvl@google.com> <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
 <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz> <YjsaaQo5pqmGdBaY@linutronix.de>
In-Reply-To: <YjsaaQo5pqmGdBaY@linutronix.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 23 Mar 2022 14:36:29 +0100
Message-ID: <CA+fCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g@mail.gmail.com>
Subject: Re: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON
 with HW_TAGS
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Andrew Morton <akpm@linux-foundation.org>, 
	Vlastimil Babka <vbabka@suse.cz>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="NRryz7C/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30
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

On Wed, Mar 23, 2022 at 2:02 PM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> On 2022-03-23 12:48:29 [+0100], Vlastimil Babka wrote:
> > > +#ifdef CONFIG_KASAN_HW_TAGS
> > >  #define ___GFP_SKIP_KASAN_POISON   0x1000000u
> > > +#else
> > > +#define ___GFP_SKIP_KASAN_POISON   0
> > > +#endif
> > >  #ifdef CONFIG_LOCKDEP
> > >  #define ___GFP_NOLOCKDEP   0x2000000u
> > >  #else
> > > @@ -251,7 +255,9 @@ struct vm_area_struct;
> > >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> > >
> > >  /* Room for N __GFP_FOO bits */
> > > -#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
> > > +#define __GFP_BITS_SHIFT (24 +                                     \
> > > +                     IS_ENABLED(CONFIG_KASAN_HW_TAGS) +    \
> > > +                     IS_ENABLED(CONFIG_LOCKDEP))
> >
> > This breaks __GFP_NOLOCKDEP, see:
> > https://lore.kernel.org/all/YjoJ4CzB3yfWSV1F@linutronix.de/
>
> This could work because ___GFP_NOLOCKDEP is still 0x2000000u. In
>         ("kasan, page_alloc: allow skipping memory init for HW_TAGS")
>         https://lore.kernel.org/all/0d53efeff345de7d708e0baa0d8829167772521e.1643047180.git.andreyknvl@google.com/
>
> This is replaced with 0x8000000u which breaks lockdep.
>
> Sebastian

Hi Sebastian,

Indeed, sorry for breaking lockdep. Thank you for the report!

I wonder what's the proper fix for this. Perhaps, don't hide KASAN GFP
bits under CONFIG_KASAN_HW_TAGS? And then do:

#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))

Vlastimil, Andrew do you have any preference?

If my suggestion sounds good, Andrew, could you directly apply the
changes? They are needed for these 3 patches:

kasan, page_alloc: allow skipping memory init for HW_TAGS
kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS

As these depend on each other, I can't send separate patches that can
be folded for all 3.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g%40mail.gmail.com.
