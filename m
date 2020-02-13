Return-Path: <kasan-dev+bncBDK3TPOVRULBB6FUSLZAKGQEM4OZHIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id EC6C615B5F1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:38:16 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id p8sf1592952wrw.5
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:38:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581554296; cv=pass;
        d=google.com; s=arc-20160816;
        b=rO3prnasjgUZD+laeGdgujWoJa4PY/VoVwvxeF7HEi5EQpXc1KB90u1fAl8Jgw3RdZ
         RDUUXF7kC8ujcbHcELpS7DTenHOivX1Y0MW2X6UNPRsYze9kJxNsgGyElKSsnSrxzhec
         KzSi10jEAtZeQuCsBPtmRqbZbVJ6ueso9JZ3s00fmAlEFw/pRHGkn09+kvD+G/lIrHhd
         a3wBZrYbI4zgpmruR2wRynmlXe4KF1aiwGqkNiU8q9DaZyQSBDAIYjA4Qydff8c8yOOM
         vIky2w4a36zsxwr4+xuEvVyCDjPmZZZcxQGMST+pfD0+Bcat7UxCwvwa68Uinw/OlexE
         TE5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jGKNK1vAUSS90c4r88SB+dBwriwoh3hsOwY7ZvnTF/w=;
        b=iUIXfgw96n0wnqmAWUVdB2qaW6fn9RYUfqBda2a4iUPf5l2E4F136TFdWtXMrBeM+1
         7UsvHwX78SNfePrZCAWrPQubm3FQlyU9uk5aug67w6WOd0TMEpyATd9cHHO15oyevRWU
         J7PXN7/pky4Y3E6KlMCtZiT3Nwgg2+ICAnhADKKtVVCkrCG0/++uTLki3rmlWGKgjHeL
         E4zIVdV3301x18N3M0Jj4NnNaSy2FYyGBfbmja8erXintxDN8Odbe7e5yu6eFYOFRe7A
         nEjmS2o3vKbR2i3yO2b2N49sIhql7iZn1r743Vu9iuwUVvbo714QS4kBcLM/Zr5aO1t7
         4+uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C1VSERI1;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jGKNK1vAUSS90c4r88SB+dBwriwoh3hsOwY7ZvnTF/w=;
        b=BocY/bTPzw5VmrDQi72AiH6XzlWUzjbg7Ijg1jPaHdmbqVP3Gsv3VBcI7Fl4OBiqUY
         dX/6I3r41BUTOHhKN9Ap5nq2Sfn40Kds95/vXXGNbtHifvaOtP1Y8ItDkutvMMTG7sKI
         KjxZhsQPWa2exZZ+0yFuFXki+4sJd1bHb/mkBfTHGAFRrzD0J8W8MCq6XuigEvwhCGaV
         ia4vfpIcPTy1/UwiDioGn8ioctIehoUA9vPQFP+6tLcVTj8/3nml12ZmjrbCo968oG/r
         nXKWfTyUjcloxaZ69y/t/dbsFAGuM4/LSBElUNEMFi68xeIT+MoNQ9iIopJQuzgPxh1j
         jDnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jGKNK1vAUSS90c4r88SB+dBwriwoh3hsOwY7ZvnTF/w=;
        b=RTicRIq0ksF71T0A/GMZNAmoqFb6J+vlnrrtqgeHFvGnTT5VXOCDRRDfGovPtd/VvD
         8vi4RRPonYTVsqLNcZVsRjxw6+HiJaX0tVglgenrZRfpGphn3kTTmiiDAmovx22c4taz
         JowcJzoHk6kKc7wfc62NC22a1hKxnnh0otrxgR6PDAJjODWbuFbJNI2LhSm6vj7rjTjz
         Bl/xCPsXjjCQk7XThskD6SZSC9jmF5FsS0L5Wb8nXuzIdyXzwrgpTWTXrX2qx8o69OuH
         egrXhbB6UiOxPcoJzFCbBtnme2J2YYq7YbH7VUICaX0lgbtg/S9zHVEbAu3KYGApr6Nc
         S56Q==
X-Gm-Message-State: APjAAAUMvYhpv5Dff5Nb6asT3nH5CrHIY6mMfw2L3tJr24bBXG3ierc6
	wHs02Es6Q2wWVEJlVB6BeIE=
X-Google-Smtp-Source: APXvYqxggmsXxe4YAfVFRq+SuX6iQBiIpH/7rS/6b4sE5KHlWe0bMeR40m5+wIdOm53qq5y/kQApBQ==
X-Received: by 2002:a5d:534b:: with SMTP id t11mr17693421wrv.120.1581554296646;
        Wed, 12 Feb 2020 16:38:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a8f:: with SMTP id s15ls12163652wru.7.gmail; Wed, 12
 Feb 2020 16:38:11 -0800 (PST)
X-Received: by 2002:a5d:56ca:: with SMTP id m10mr18624944wrw.313.1581554291862;
        Wed, 12 Feb 2020 16:38:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581554291; cv=none;
        d=google.com; s=arc-20160816;
        b=NEXXx5fNWyxKCvizqcJFA5NFQVa4SsdM2zNJ8j3J7WRN/9S23jhRZrF/IDV+CnygDY
         AtcbsR68I050hKed5ifaf8dfdRII5B3A5XYnev3Tep3cYoM5HMX5h0B5EuU3kIqssyl3
         cFSIzPYFMJziaqVnSlOkxEQJ/EQlJUzRyseEZ53J3ojtKQtQqXRpFx5wgxy3z1SUgNiS
         gECmEXqJ/9jKGcSM1N9/I0JbZ2akm57lBiym8FanOL6s0FhhCZAA/d8wHOaobsaPEw86
         deJibzrfNOukHP4sd4CSgYWRbLwH4FH5ycL8swOgFoRryYB0q4sK8ONzsouqSGuvcNkI
         SJPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Uu9p1NHkE2MkYSqLVKem4JSGakNOnN3LkVvsdFKxSS0=;
        b=SaokOmTvrGi0k3D8+LiB8eS52HjA2/pDbiOoXh/Q+1xXXTEa60VR8XfbqtVxumpZbJ
         vO5Vi1TExK/88FpxJIrBsSxySVEInTce41Em8pFOMJkR7Cew5PNItyrqvvph1jWCfj+4
         KgOoRJ44cgAlFI+1hohTZeGqclmcUBI04xsVsWVX4e2UzFjEaJc/WyHM2hbVZZ+k2usZ
         lRrHPdOM/Su0Zd3DCn93cc2TQROjaaEoGt4Yk+Y5+ElR3ftkdcuFEkICOjSknyThfq+8
         5hRnJfLwLEjT1H6JCvbo756pdYvMzsljMHJWiSY/tFNmQWbSQB+whCXp9zgULTOGlmMY
         kNcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C1VSERI1;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id u9si37712wri.3.2020.02.12.16.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:38:11 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id u6so4616509wrt.0
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 16:38:11 -0800 (PST)
X-Received: by 2002:adf:81e3:: with SMTP id 90mr17109059wra.23.1581554291169;
 Wed, 12 Feb 2020 16:38:11 -0800 (PST)
MIME-Version: 1.0
References: <20200210225806.249297-1-trishalfonso@google.com> <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
In-Reply-To: <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2020 16:37:59 -0800
Message-ID: <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C1VSERI1;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Tue, Feb 11, 2020 at 12:21 AM Johannes Berg
<johannes@sipsolutions.net> wrote:
>
> Hi,
>
> Looks very nice! Some questions/comments below:
>
> > Depends on Constructor support in UML and is based off of
> > "[RFC PATCH] um: implement CONFIG_CONSTRUCTORS for modules"
> > (https://patchwork.ozlabs.org/patch/1234551/)
>
> I guess I should resend this as a proper patch then. Did you test
> modules? I can try (later) too.
>
I have not tested modules - you might want to test modules before
sending it at a proper patch. I just know that it works for the
purposes of this KASAN project.

> > The location of the KASAN shadow memory, starting at
> > KASAN_SHADOW_OFFSET, can be configured using the
> > KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
> > space, and KASAN requires 1/8th of this.
>
> That also means if I have say 512MB memory allocated for UML, KASAN will
> use an *additional* 64, unlike on a "real" system, where KASAN will take
> about 1/8th of the available physical memory, right?
>
Currently, the amount of shadow memory allocated is a constant based
on the amount of user space address space in x86_64 since this is the
host architecture I have focused on.

> > +     help
> > +       This is the offset at which the ~2.25TB of shadow memory is
> > +       initialized
>
> Maybe that should say "mapped" instead of "initialized", since there are
> relatively few machines on which it could actually all all be used?
>
Valid point!

> > +// used in kasan_mem_to_shadow to divide by 8
> > +#define KASAN_SHADOW_SCALE_SHIFT 3
>
> nit: use /* */ style comments
>
Will do

> > +#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
> > +#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> > +
> > +#ifdef CONFIG_KASAN
> > +void kasan_init(void);
> > +#else
> > +static inline void kasan_init(void) { }
> > +#endif /* CONFIG_KASAN */
> > +
> > +void kasan_map_memory(void *start, unsigned long len);
> > +void kasan_unpoison_shadow(const void *address, size_t size);
> > +
> > +#endif /* __ASM_UM_KASAN_H */
> > diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> > index 5aa882011e04..875e1827588b 100644
> > --- a/arch/um/kernel/Makefile
> > +++ b/arch/um/kernel/Makefile
> > @@ -8,6 +8,28 @@
> >  # kernel.
> >  KCOV_INSTRUMENT                := n
> >
> > +# The way UMl deals with the stack causes seemingly false positive KASAN
> > +# reports such as:
> > +# BUG: KASAN: stack-out-of-bounds in show_stack+0x15e/0x1fb
> > +# Read of size 8 at addr 000000006184bbb0 by task swapper/1
> > +# ==================================================================
> > +# BUG: KASAN: stack-out-of-bounds in dump_trace+0x141/0x1c5
> > +# Read of size 8 at addr 0000000071057eb8 by task swapper/1
> > +# ==================================================================
> > +# BUG: KASAN: stack-out-of-bounds in get_wchan+0xd7/0x138
> > +# Read of size 8 at addr 0000000070e8fc80 by task systemd/1
> > +#
> > +# With these files removed from instrumentation, those reports are
> > +# eliminated, but KASAN still repeatedly reports a bug on syscall_stub_data:
> > +# ==================================================================
> > +# BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x299/0x2bf
> > +# Read of size 128 at addr 0000000071457c50 by task swapper/1
>
> So that's actually something to fix still? Just trying to understand,
> I'll test it later.
>
Yes, I have not found a fix for these issues yet and even with these
few files excluded from instrumentation, the syscall_stub_data error
occurs(unless CONFIG_STACK is disabled, but CONFIG_STACK is enabled by
default when using gcc to compile). It is unclear whether this is a
bug that KASAN has found in UML or it is a mismatch of KASAN error
detection on UML.

> > -extern int printf(const char *msg, ...);
> > -static void early_print(void)
> > +#ifdef CONFIG_KASAN
> > +void kasan_init(void)
> >  {
> > -     printf("I'm super early, before constructors\n");
> > +     kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
>
> Heh, you *actually* based it on my patch, in git terms, not just in code
> terms. I think you should just pick up the few lines that you need from
> that patch and squash them into this one, I just posted that to
> demonstrate more clearly what I meant :-)
>
I did base this on your patch. I figured it was more likely to get
merged before this patch anyway. To clarify, do you want me to include
your constructors patch with this one as a patchset?

> > +/**
> > + * kasan_map_memory() - maps memory from @start with a size of @len.
>
> I think the () shouldn't be there?
>
Okay!

> > +void kasan_map_memory(void *start, size_t len)
> > +{
> > +     if (mmap(start,
> > +              len,
> > +              PROT_READ|PROT_WRITE,
> > +              MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> > +              -1,
> > +              0) == MAP_FAILED)
> > +             os_info("Couldn't allocate shadow memory %s", strerror(errno));
>
> If that fails, can we even continue?
>
Probably not, but with this executing before main(), what is the best
way to have an error occur? Or maybe there's a way we can just
continue without KASAN enabled and print to the console that KASAN
failed to initialize?

> johannes
>

-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKaixKXbUqvVvjzjkty26GS%2BCkshg2t7-%2BerqiN2LVS-g%40mail.gmail.com.
