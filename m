Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMVAWX6QKGQEVLJRHWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E4C12B0828
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 16:09:40 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id u3sf2912091pfm.22
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 07:09:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605193778; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzHURfzll1qYXE10oBtwwu04HMiZ4kQX8iw2a9H5WFLm+3nzJ/2xosa1Ot1hOD7gEy
         ziqhkXTR43knZs6QzOnAJvtiOiok0sslT6iPsiwZDuy/RWxloTLVo2MRvzAwvCRKdMxH
         NrsB0ogDofJa7pN1HzeYMV3GQ5GtadfpRwUmxPomHktxJpNErcRkUzIGEfZW5luEbOSF
         czyINYKVcJwfvCs7E9vz0V2HsL3vFwCo9iDzz7Wp0N7YJaC6GfpWNiDFMILWp9JEHhLE
         x/yEa370sGvaPipc9N0MYYmgGI61HlAyLWEiPalFPkzDGwbikrIcCYK/FaqNoyjPOORE
         dc2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UiS/8F9v/AMkvFZwMu+SRdwAewOMZrDokbNf+v/X3Hc=;
        b=su/Nfy872CzqEtR/NzvkPFnuo0wSu3lhnoOovt1XXrjQQFQ4mOGYIoc57qh9o1E6CJ
         DTeaGjEdnVzJbwK65h+Y7rKk6r9qLXkDnjxsVKCurmOZFozbTzgAsSLZSKeQEFNHuD0c
         LdCJdzuuIAuiiZgmLPfWsbNGlQZUXFeNUxdSXkQVeYHdB6bj3ZxxEs7S4Y402sxeHFxy
         nlJAMGrpMf/txn96IDoRfsb4eUyhEOoizD3lXQ2u5y8RIJY5ve75pvRTO78kWgHaFa4F
         tOjy7wBmDGEs7E1eE3qmgQzTssQ30MQeShVikOuP89sQHWcsYimDnjmI4wM8gDCI+/uF
         gQng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gnR8Ce66;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UiS/8F9v/AMkvFZwMu+SRdwAewOMZrDokbNf+v/X3Hc=;
        b=m9KS8SLEM2lwRi4msWguAbNk3EY6p9kce0cPOw7kpK0KxEmdDevBJ50KRuR+kzOJAB
         1Mr3FcwMaPI4/o0zgKGyZ+DCGs2Og7F0BDucjdBuNupxzP5ENnN8b1BlxPcTZAefXccT
         9gUJeNeRiwsq2Qucj08RV1CoIvJY9oAJ2BgJqm0sorslAfqWBKhrSIwDJ3EMYpdaaVgT
         f+Bw4bkeRewWofM7k6x5LxnwyhUgg/Cr+Ln2wAHDWEfKb3KFwLzNyspA0fdl/cPJWMEe
         HbBWdZRcWLBAE2AsaiixA8K9cVPgbIW8YjUPaWBMhEk4QZgRtUzLBYDg59Eh9gQMxa8g
         wMpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UiS/8F9v/AMkvFZwMu+SRdwAewOMZrDokbNf+v/X3Hc=;
        b=NO7oMTauMj2Rrc38I72M85v5oufArm4XqkvFOt8cQtE36rWkdITVifrt4rokhh2UWW
         u9wpIYbAL5JwlaKn+TPE6TjYT5VMbt6shpTMGOIcFJWo/IParQvbK0vMR09j5uyXFdWN
         CjhQietR0KFG5Aid4uD0YKhv2+x8KisoONeiu9T9dgidACPVnjWw+mRds2+6AKrwwZa7
         T4ULZa0PRAiJFz277RdwA2XH+UkivrDhHbLzyki3MtuCi0C/ktpDxSEcY1J5FAxETzQI
         ql3Wo6KTZaG4SO1Tc0qqxmNdjQCd1KLCe7oWH7ntEDBPRB1IKi1lz9kb+jtSnHiZH7EG
         OIkQ==
X-Gm-Message-State: AOAM530h+yHp7SwINPsY8mJoAk43GQY09YQKHOrOaYFhka8XcaP3RcXW
	+ynE+5PXXL/fZlMfZftRgzU=
X-Google-Smtp-Source: ABdhPJx23KI31isaNf+lT2UOnEDehHMdfr0p+2dsOyXv6i4DpQVaCYuxf3JG4cJn/iMxDFB3QovNxQ==
X-Received: by 2002:a05:6a00:7d7:b029:18c:5ac1:d6b4 with SMTP id n23-20020a056a0007d7b029018c5ac1d6b4mr11369141pfu.32.1605193778753;
        Thu, 12 Nov 2020 07:09:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d98:: with SMTP id v24ls1585971plo.4.gmail; Thu, 12
 Nov 2020 07:09:38 -0800 (PST)
X-Received: by 2002:a17:90b:3508:: with SMTP id ls8mr10164560pjb.61.1605193778159;
        Thu, 12 Nov 2020 07:09:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605193778; cv=none;
        d=google.com; s=arc-20160816;
        b=TBZeOAkLp3qLXEZhC+gPPJ1123TCwbabKQWlJAZoEtiwdaB958830TN/4WR4zv4gwn
         k50UtK9Fryhh1vLppEBgoKRUuF+YUWUHrt2iMOSZEigeBkq9qbKuSzQ4ZAxsnaCACztx
         +RNlgReP1sYITSDgEDTssuEruqvYccDWlOFAZpQdzjzYHzVSdXov1kcrJYcYvxTXBRJM
         CiHHWrE++4SWKbFrvH3Hg2SFHhGdfeyeVGIkmvtMJ39Q7Z+WwQoRotzO+8HqpQnqjTKt
         bd4TZcPPmWx54u1hpLoenMD/XTDYmV5d21eWhzPNm7dMILiTAcD0WHf5l6msb9NeYjMq
         UpCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CoGYL/qpX4DTdicVvMAnSSNFSp8J2Bcqtm1uW4R8eNw=;
        b=scw7P6w0nb9W8noO5PUe1mE02mhc2XxtZPk9Bp9sIszMAGscYhExYYv/NrVwmVcVoO
         pGnG0tgKdgSgeD/K1n72Hs7qluElGVUHrx/fMAlVwbH2qtWKQVDuxxSDYCK0/U3CwAFA
         PF87k6MT7BzYtHBFI9CjLQkBOEENxXTWtlAtNyvES1LbXPgceSc99Y964dIyoXeJu3CL
         kX89/toAGEGEUWJJnSnhxaMufstBiJcIWxb8Qbisi9v3ZjaKWUpO1qJGiXxsgwOwSxXj
         Kq59I3ZM6eLazkziT/6PWDyongvwCVrMOe624xoTD4tSETHtlopblL/TucNySqZqf/Gp
         6e2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gnR8Ce66;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id l8si427098pjt.1.2020.11.12.07.09.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 07:09:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id l2so5528325qkf.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 07:09:38 -0800 (PST)
X-Received: by 2002:a37:b545:: with SMTP id e66mr183119qkf.392.1605193777579;
 Thu, 12 Nov 2020 07:09:37 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <619cb0edad35d946c4796976c25bddb5b3eb0c56.1605046192.git.andreyknvl@google.com>
 <CAG_fn=UKSp8shtYujRbM=8ndhLg_Ccdpk9eSfOeb=KpwNi7HBg@mail.gmail.com> <CAAeHK+zh6tOh91Dg4n4NrJwdPWRaDEtz_Btitg8viQQk7Zm_JQ@mail.gmail.com>
In-Reply-To: <CAAeHK+zh6tOh91Dg4n4NrJwdPWRaDEtz_Btitg8viQQk7Zm_JQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 16:09:25 +0100
Message-ID: <CAG_fn=Vs35BOdyg1BUmLWEK3SzMT7z9_otMtu_BJbz4dTXVyag@mail.gmail.com>
Subject: Re: [PATCH v9 17/44] kasan, arm64: move initialization message
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gnR8Ce66;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Nov 11, 2020 at 7:50 PM Andrey Konovalov <andreyknvl@google.com> wr=
ote:
>
> On Wed, Nov 11, 2020 at 4:04 PM Alexander Potapenko <glider@google.com> w=
rote:
> >
> > On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.co=
m> wrote:
> > >
> > > Software tag-based KASAN mode is fully initialized with kasan_init_ta=
gs(),
> > > while the generic mode only requires kasan_init(). Move the
> > > initialization message for tag-based mode into kasan_init_tags().
> > >
> > > Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as =
it
> > > doesn't use any printing functions; tag-based mode should use "kasan:=
"
> > > instead of KBUILD_MODNAME (which stands for file name).
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Reviewed-by: Alexander Potapenko <glider@google.com>

> > Cannot we have a single kasan_init() function that will call
> > tool-specific initialization functions and print the message at the
> > end?
>
> Unfortunately no. For different modes we need different functions that
> are called in different places in the kernel. E.g. for generic KASAN
> we only need kasan_init() to setup shadow pages; for SW tags we also
> need kasan_init_sw_tags() which initializes per-cpu state and
> finilizes initialization process.

Ok, got it.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVs35BOdyg1BUmLWEK3SzMT7z9_otMtu_BJbz4dTXVyag%40mail.gmai=
l.com.
