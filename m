Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFXM3X5AKGQETQAVNKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 9325E261128
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 14:16:22 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id b17sf1626675ejb.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 05:16:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599567382; cv=pass;
        d=google.com; s=arc-20160816;
        b=yyhedB66JGP/jC6HWE9pEUg2q3cCTMekAY2nZb0pvLwpWeEqnUOzRVWJFySu2Cw9FP
         /m6EbLn7QiGSF1KjIotzvubH/YwUgVFQf05TtQqOHka8rLLYcy3EY47UMSua3b3dEgp9
         Hoi674z4yl/UDmyo0lu1D9aAW7e2/4b+tOQWH4TuQsy90uDLgbWahJWi7kGO7HVdNKbp
         K3Z8OPhNJ8Sq/UF9i7MyGzCr7qa/L4/8lvTmelEVx8eW/69vTNnBJmpB9lgryFSIZhCv
         yVjiGTNVcK6cduKFUD2OVy/vnqCECP5u4NP3bCddwDeN45KSxYXCWMWH0iD0lkmGYW6A
         mnKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GKlKi7ymv0C53lL/KTkZBp3l7JxaFWfn9lb7eRiP3Rk=;
        b=b/FhTZ0swcWQXz9EsJQ/WgHqOcr3h+hXyPIsaP4jeJKLytgTbqWTfmUU62wyH8DS7b
         P6mYWfK9r/8mLNYtwJuiLp9xGGJ42zrnBip6UoLqfRmoWVjsP53cr89s4VRkRB8zmdHQ
         SKg8EES/tM8Xb+d+j7ks1CVzIuo2AGjWjWpJEJ9y6OAxM103PXxNQ/Dy2lLxhbEGtSod
         QvBc2iV8mRGsKI2/urGF88bQFrcjLm6FbAtScCGFRyipeHAVip7n5ZrsKBtjUivVY9KC
         S/yNg7ewbAPwpmlsLRouUsn8JapaOTypWpZRb0WiOFRsxzUeeaocowJI5hxlvpRWZ+NW
         xyGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QPX3it+b;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GKlKi7ymv0C53lL/KTkZBp3l7JxaFWfn9lb7eRiP3Rk=;
        b=IgQxyLl6fG3Kke163q0r667XAmoZgmowGlPJnGyk6nr5KBI/liUYCfng6xqzFgN/4V
         VPLwYR2OGk8uiOffhk4pRAGwr5cks9bAIanxWCnpkmnRmuEpoT0dTpJKD5hLWgzMOS16
         gtoqb6kjjXhybNay8XRiXA+6VKkvEnrnWlzEp8Psw60ONDgod7bOeleiDieacHVM5mTv
         dfyET+SKpkUKdsvUSlM43RfRTmA4QVhtZlpkiztzqL26NgAZNMq0z3fKOjnDJLX+D3Wl
         IF0veQbVAMz9RxhzeegMLp5yVhiE/OPQC5/mjKYZUM0DH2DoYIA6/XL5Z2TB8GnvUy52
         L7DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GKlKi7ymv0C53lL/KTkZBp3l7JxaFWfn9lb7eRiP3Rk=;
        b=qdZplhmsVjMqRFpqlQnAlIb5CUSfB0qaYaXWn1Th7Wt2bvj16MO98id9RpOxjs0xDM
         1jvZWcQq4F08DFz1ppnLRXgkYFY1IuTAw56yo2Yfu7Z2Jx742Y/ctZdHDaqgoGUKr516
         4J4A+u5VhEPxleKewKOvgY7rl7xHLXoEA05N8JdtrXv6YBbou/QKZwETUUxDU11G6Utp
         9CQkcPoqOKxzSBtJicnMRjyrpq/JF0QAXRrgKwqX3Ir/gPkl6mi9359wgsslQJ0SR8bf
         ssI2CJGAcOJQV6G6EhIDnRMUr3JXWuUKcgduCp0+yMSSkopSlG5d3iK5z8l1IoX+gfcr
         Ll2g==
X-Gm-Message-State: AOAM531LqpHjzCCxtq+f8259qzVCDYHVzZQNhD/gFe9rxHInjqUeDLcF
	8XrdSy8f4ZK+qA51uM79Y1U=
X-Google-Smtp-Source: ABdhPJyz97ErThTKXPFLHSmI2X95dIDlpymfxjH6/auXNAWlyjOejdyViH+ll6ZGPVKZtvgJIi9vAg==
X-Received: by 2002:a17:906:4046:: with SMTP id y6mr20441725ejj.148.1599567382331;
        Tue, 08 Sep 2020 05:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:32d9:: with SMTP id k25ls9913799ejk.0.gmail; Tue, 08
 Sep 2020 05:16:21 -0700 (PDT)
X-Received: by 2002:a17:906:30c5:: with SMTP id b5mr15695049ejb.98.1599567381452;
        Tue, 08 Sep 2020 05:16:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599567381; cv=none;
        d=google.com; s=arc-20160816;
        b=uwBj0sg/CqfvlRzRI1qve7iTefuh4sCijajYBvcZEE0HeQEyxO/ad72yiwsp/rG4g0
         x/LOHSophlqZkf0ByLERHa4KJjWlyRhN3IaL3ZXfp7ETVDoy7RgYZyU1QlQalzTdfb5G
         HxPBGP10Klhmmdd/Z6n6orEiiVsypca9MWZ7OWMrpj5VeSieqBRybsyqr3WrqpD5vj/x
         CpZStZi+ZOCw5yy95/khlhill7K0DdcDwUSutTr10wRoUyNYeKnBFlztFvJLs2rnd0EP
         Y+ozIspx9HfOvAlSHfEt2vRXQH+6nC1t7HOSisfa0r8L8dc5eiG6XgkBXVehAAdJEziQ
         T5dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=25SuQDI0eyCRm9y5WDHzplEK9oGtQL3VKe10BEOjmTA=;
        b=LHOFJJ5xbBmPcKW/VKZGD7NRJ64Owi/2UdUeUMaB6q8C3AcK4K7pFLLOMTL1zEcfCk
         MdIAySuISOkj2lF5rteGps7NAn7WxFWxlZsJbv02ZAqEWyjMep1NA2B/Ul/+90OeKpXM
         kath5WjOZ+CK7Ktt5wdBY7gkUjLW9Gh5z+ZYYObRBrZi/qHv5mHV+Pjx8pFUZdgraOwb
         yjbmkDSwHFRJCyed6rH76iNd+869CKBUtiy/hEI1OwaCfyBQKysEAhA8cDbSiOj+NsNV
         SRaESpXPYOuGpYp8AknRZBN0b/GWgXP4urAw1r11IdPyvksYTKp2gzWePifTiJLM/e59
         Oekw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QPX3it+b;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id k6si532066eds.3.2020.09.08.05.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 05:16:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id w2so17071084wmi.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 05:16:21 -0700 (PDT)
X-Received: by 2002:a1c:105:: with SMTP id 5mr4078883wmb.175.1599567380842;
 Tue, 08 Sep 2020 05:16:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <4dc8852a-120d-0835-1dc4-1a91f8391c8a@suse.cz>
In-Reply-To: <4dc8852a-120d-0835-1dc4-1a91f8391c8a@suse.cz>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 14:16:09 +0200
Message-ID: <CAG_fn=UdnN4EL6OtAV8RY7kuqO+VXqSsf+grx2Le64UQJOUMvQ@mail.gmail.com>
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, paulmck@kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, dave.hansen@linux.intel.com, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arm-kernel@lists.infradead.org, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QPX3it+b;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
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

> Toggling a static branch is AFAIK quite disruptive (PeterZ will probably =
tell
> you better), and with the default 100ms sample interval, I'd think it's n=
ot good
> to toggle it so often? Did you measure what performance would you get, if=
 the
> static key was only for long-term toggling the whole feature on and off (=
boot
> time or even runtime), but the decisions "am I in a sample interval right=
 now?"
> would be normal tests behind this static key? Thanks.

100ms is the default that we use for testing, but for production it
should be fine to pick a longer interval (e.g. 1 second or more).
We haven't noticed any performance impact with neither 100ms nor bigger val=
ues.

Regarding using normal branches, they are quite expensive.
E.g. at some point we used to have a branch in slab_free() to check
whether the freed object belonged to KFENCE pool.
When the pool address was taken from memory, this resulted in some
non-zero performance penalty.

As for enabling the whole feature at runtime, our intention is to let
the users have it enabled by default, otherwise someone will need to
tell every machine in the fleet when the feature is to be enabled.
>
> > We have verified by running synthetic benchmarks (sysbench I/O,
> > hackbench) that a kernel with KFENCE is performance-neutral compared to
> > a non-KFENCE baseline kernel.
> >
> > KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
> > properties. The name "KFENCE" is a homage to the Electric Fence Malloc
> > Debugger [2].
> >
> > For more details, see Documentation/dev-tools/kfence.rst added in the
> > series -- also viewable here:
> >
> >       https://raw.githubusercontent.com/google/kasan/kfence/Documentati=
on/dev-tools/kfence.rst
> >
> > [1] http://llvm.org/docs/GwpAsan.html
> > [2] https://linux.die.net/man/3/efence
> >
> > Alexander Potapenko (6):
> >   mm: add Kernel Electric-Fence infrastructure
> >   x86, kfence: enable KFENCE for x86
> >   mm, kfence: insert KFENCE hooks for SLAB
> >   mm, kfence: insert KFENCE hooks for SLUB
> >   kfence, kasan: make KFENCE compatible with KASAN
> >   kfence, kmemleak: make KFENCE compatible with KMEMLEAK
> >
> > Marco Elver (4):
> >   arm64, kfence: enable KFENCE for ARM64
> >   kfence, lockdep: make KFENCE compatible with lockdep
> >   kfence, Documentation: add KFENCE documentation
> >   kfence: add test suite
> >
> >  Documentation/dev-tools/index.rst  |   1 +
> >  Documentation/dev-tools/kfence.rst | 285 +++++++++++
> >  MAINTAINERS                        |  11 +
> >  arch/arm64/Kconfig                 |   1 +
> >  arch/arm64/include/asm/kfence.h    |  39 ++
> >  arch/arm64/mm/fault.c              |   4 +
> >  arch/x86/Kconfig                   |   2 +
> >  arch/x86/include/asm/kfence.h      |  60 +++
> >  arch/x86/mm/fault.c                |   4 +
> >  include/linux/kfence.h             | 174 +++++++
> >  init/main.c                        |   2 +
> >  kernel/locking/lockdep.c           |   8 +
> >  lib/Kconfig.debug                  |   1 +
> >  lib/Kconfig.kfence                 |  70 +++
> >  mm/Makefile                        |   1 +
> >  mm/kasan/common.c                  |   7 +
> >  mm/kfence/Makefile                 |   6 +
> >  mm/kfence/core.c                   | 730 +++++++++++++++++++++++++++
> >  mm/kfence/kfence-test.c            | 777 +++++++++++++++++++++++++++++
> >  mm/kfence/kfence.h                 | 104 ++++
> >  mm/kfence/report.c                 | 201 ++++++++
> >  mm/kmemleak.c                      |  11 +
> >  mm/slab.c                          |  46 +-
> >  mm/slab_common.c                   |   6 +-
> >  mm/slub.c                          |  72 ++-
> >  25 files changed, 2591 insertions(+), 32 deletions(-)
> >  create mode 100644 Documentation/dev-tools/kfence.rst
> >  create mode 100644 arch/arm64/include/asm/kfence.h
> >  create mode 100644 arch/x86/include/asm/kfence.h
> >  create mode 100644 include/linux/kfence.h
> >  create mode 100644 lib/Kconfig.kfence
> >  create mode 100644 mm/kfence/Makefile
> >  create mode 100644 mm/kfence/core.c
> >  create mode 100644 mm/kfence/kfence-test.c
> >  create mode 100644 mm/kfence/kfence.h
> >  create mode 100644 mm/kfence/report.c
> >
>


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
kasan-dev/CAG_fn%3DUdnN4EL6OtAV8RY7kuqO%2BVXqSsf%2Bgrx2Le64UQJOUMvQ%40mail.=
gmail.com.
