Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFV3XCMAMGQE22SGD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A4E95A6635
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 16:24:24 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id lx1-20020a17090b4b0100b001fd720458c3sf876618pjb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 07:24:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661869462; cv=pass;
        d=google.com; s=arc-20160816;
        b=u6ZrIOVqPf7M9RiMyDmu7+6eoklrSNmrbs15LZaBdVknU2m0U4Tv24Hc3PF+aCvHbw
         waPF8Wh3QbhTZn37K/qOGJaJ3To64KDSo+fM4wKW8nbKLGPmSmq+IUWZw/t0Mmsu35PI
         ZerQVfpWH8hsVLRXx0TLuyVT5u4yHEdE0Gho6hG0ivFU8MGayP9FaM1IapAqshJhw3zB
         MrITsnbgEz/0xMp3dIuwWTUIvBM8HVenEByr9fXgtn+zsObAgWiVd8C/YcCY9xaEEchY
         DpbwwZbiFk5yuNhs9UTmwEcZyU15+vB8Y/sCnj5mhhR3PnT2F8nqw85K8gim9e/pzGs4
         w7CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9tICurTRd9BDlqswJa4j5WCr2aYbMYMwznrnGeTrqwA=;
        b=DNOvWhDErg0PJVAJay3Yi2s9kVLhbAzX362NelM52wEuDmrqPcDyHKAA1Gr4/0MgYP
         T7hWH+Z7m/GO2lxmAv2YY4nj4JIonilEvC+Afdm1XEY3KwrDe+XI2DvcMWVzA4ibR5Xj
         o5XH/JV1FfvwlEUoQeUYogLn/YiIC59CRaflYFicYbC9jul9hcc7Egw0aOEZRdDxzdWZ
         4WpaFBXwUgeLutSrNiSCQoavv2qmKX6RVOuwgS43Fm/j8H4hcCdZvZWVY2vTsOOYy+Uk
         wrRE4zt56skUrzVFI4sZDFnn2/O7To81b/ksWYfVlX8/Lautt8YroJUVtAZeMOIRhzrk
         AaOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NJkAG1gp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=9tICurTRd9BDlqswJa4j5WCr2aYbMYMwznrnGeTrqwA=;
        b=G/7UxFp3gxw/dHu3Yr6nyttPbyDU/pUGeSfFlD5it0zvJ+y32uPXQuRri4yn9PYfZA
         MQEyDFR3kjv/yuQwCTKVMSkBCSqBYCId5rwbTQuMXiRa0KzglpT1aMcNgC+EU244WqWc
         vOT801ocytufMetqIWlCHOBu03ATrCjyUEvEJd5xL5gMcBtOTYilRzymJX+GcHS7bJij
         aTxTKjDyjdTvyX2+uHfdr9q2CRO1vkw7i7IQK0QRjv7WGjlfrWQGztkjfGbJdA0YphfE
         5Ylp8Hp8DgNLD+hDYnq0Y9HxXU9oR8xMt+a5wHsV4kEi6WF3LxY9fip5RE99l/96rhGK
         WKNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=9tICurTRd9BDlqswJa4j5WCr2aYbMYMwznrnGeTrqwA=;
        b=qaL7YGNdOc85UolNVraMxZzUdRXGUuf9xC3wg0FRKsw1RBATyuuYLEX59pcoiy/e4Q
         oGvgntsStfsC4CRzB4IMDrWtdkxYgRAvNTWa+Z1ZrU26BdS+kmSHOI75GzssBviBDWvX
         Ya5VKxTr9kfss+H8BmTE+y6q5id9nr3qiAHPum0xlZBAgSBObciqmM6gaCVkgF1LxHnB
         2RbHMAX8zE5mhJObCKzi0fqrdTkpOIgDHQJ09ftanWdfCw6K+clPpqI1cHEuOqVPX23J
         CfveqJzl0+UlYxZxzrhbDJGo0Wgeeq14bLpR3xAFS+2+2Itt8e26FbXry0XGTrbo7fug
         rTgw==
X-Gm-Message-State: ACgBeo1wLSdH0IKD4ejkUIGMVU1/wkDXEW1ecBboVDJCeyOP/98vbGlM
	zDytNJ5+viXiuMgRZGIlReE=
X-Google-Smtp-Source: AA6agR5qqzkEP/DTxmwknJmzISH0SS8ZZq3FOEYa2P7X6qZDy48JN9PuBd8UgXUv6lyZPjJYpSiFfA==
X-Received: by 2002:a17:90b:3901:b0:1fd:99f6:68c with SMTP id ob1-20020a17090b390100b001fd99f6068cmr16155372pjb.5.1661869462391;
        Tue, 30 Aug 2022 07:24:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5a01:0:b0:536:5777:1f90 with SMTP id o1-20020a625a01000000b0053657771f90ls5652030pfb.2.-pod-prod-gmail;
 Tue, 30 Aug 2022 07:24:21 -0700 (PDT)
X-Received: by 2002:a63:d94a:0:b0:412:6e04:dc26 with SMTP id e10-20020a63d94a000000b004126e04dc26mr18330531pgj.539.1661869461643;
        Tue, 30 Aug 2022 07:24:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661869461; cv=none;
        d=google.com; s=arc-20160816;
        b=GbyGwKBBckAgojVRFutq/w0RlXnYj16PEI0p0FpQeyaGOqU/oNZiRUkVYa2dbAWAcq
         FnAi9501K8VQYS/2Gh3YFXW7/RSXV/qf361t9+/Up52b81+V44klS0WmkIPs4tw5SVs1
         Y1Vdwm1t+zpuIS2uiio/qQ4IeKZT2DxKOP+v+WE9UIn5oZez4XNJpjXSzX60gLk6W0n6
         oX3THEXZOYKcyB3eb23vG3rfDwOFP6esMQHCcfVgQlYZmiDeNyrBjlqQG7je4UaApXPP
         ZTm0ZtgNJxT0mkm9R0zkedH8wdxr64ft2J81qw7OHWo0QIiMFmOuG/NqGg1OsOD+DpHB
         0kGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gt/5eV/ZpK3WodQ+XAEGUey1G3s7WAZiZKt3bPC8X9Y=;
        b=VEvlA8yLXW8oFi10L+qJMKWn+HVeqcqeviMzDqHnIMvXdOOksdVM9koehzTm/4pmay
         s48Cea24SBIENBTJUSABoO3LjaDTW8IBcndfJKn/+02luJcvAza6Yr0QkqKIa5uQNLUW
         VFkqLaA8AlziCF4YR5cZWi45Fae9bRiXOT51cRfdHPLNBTo4mMhxHnnR/a1J5h8oHmAE
         VZykrvIzS6AGt1o5RiRp3Kj5vAo9EpbsXe/hzpUtAb+XMb2jOlUzXLdR+gML3jLZD+Yk
         XSJ6NLO5GDL2GHKScJGqG6R7i4gFm4m0gyM+ly2/6Spm3dptWU+ZxrF8r1T4VuyfvpwC
         eb5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NJkAG1gp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id gz8-20020a17090b0ec800b001fdcfe630c9si66156pjb.2.2022.08.30.07.24.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 07:24:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-334dc616f86so276901497b3.8
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 07:24:21 -0700 (PDT)
X-Received: by 2002:a05:6902:1106:b0:695:c353:2c32 with SMTP id
 o6-20020a056902110600b00695c3532c32mr12729722ybu.398.1661869460597; Tue, 30
 Aug 2022 07:24:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
 <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com> <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
In-Reply-To: <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Aug 2022 16:23:44 +0200
Message-ID: <CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NJkAG1gp;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Aug 29, 2022 at 9:24 PM Andrew Morton <akpm@linux-foundation.org> w=
rote:
>
> On Mon, 29 Aug 2022 16:57:31 +0200 Alexander Potapenko <glider@google.com=
> wrote:
>
> > On Sat, Aug 27, 2022 at 6:17 AM Andrew Morton <akpm@linux-foundation.or=
g> wrote:
> > >
> > > On Fri, 26 Aug 2022 17:07:27 +0200 Alexander Potapenko <glider@google=
.com> wrote:
> > >
> > > > Use hooks from instrumented.h to notify bug detection tools about
> > > > usercopy events in variations of get_user() and put_user().
> > >
> > > And this one blows up x86_64 allmodconfig builds.
> >
> > How do I reproduce this?
> > I tried running `make mrproper; make allmodconfig; make -j64` (or
> > allyesconfig, allnoconfig) on both KMSAN tree
> > (https://github.com/google/kmsan/commit/ac3859c02d7f40f59992737d63afcac=
da0a972ec,
> > which is Linux v6.0-rc2 plus the 44 KMSAN patches) and
> > linux-mm/mm-stable @ec6624452e36158d0813758d837f7a2263a4109d with
> > KMSAN patches applied on top of it.
> > All builds were successful.
> >
> > I then tried to cherry-pick just the first 4 commits to mm-stable and
> > see if allmodconfig works - it resulted in numerous "implicit
> > declaration of function =E2=80=98instrument_get_user=E2=80=99" errors (=
quite silly of
> > me), but nothing looking like the errors you posted.
> > I'll try to build-test every patch in the series after fixing the
> > missing declarations, but so far I don't see other problems.
> >
> > Could you share the mmotm commit id which resulted in the failures?
>
> I just pushed out a tree which exhibits this with gcc-12.1.1 and with
> gcc-11.1.0.  Tag is mm-everything-2022-08-29-19-17.
>
> The problem is introduced by d0d9a44d2210 ("kmsan: add KMSAN runtime core=
")
>
> make mrproper
> make allmodconfig
> make init/do_mounts.o
>
> In file included from ./include/linux/kernel.h:22,
>                  from ./arch/x86/include/asm/percpu.h:27,
>                  from ./arch/x86/include/asm/nospec-branch.h:14,
>                  from ./arch/x86/include/asm/paravirt_types.h:40,
>                  from ./arch/x86/include/asm/ptrace.h:97,
>                  from ./arch/x86/include/asm/math_emu.h:5,
>                  from ./arch/x86/include/asm/processor.h:13,
>                  from ./arch/x86/include/asm/timex.h:5,
>                  from ./include/linux/timex.h:67,
>                  from ./include/linux/time32.h:13,
>                  from ./include/linux/time.h:60,
>                  from ./include/linux/stat.h:19,
>                  from ./include/linux/module.h:13,
>                  from init/do_mounts.c:2:
> ./include/linux/page-flags.h: In function =E2=80=98page_fixed_fake_head=
=E2=80=99:
> ./include/linux/page-flags.h:226:36: error: invalid use of undefined type=
 =E2=80=98const struct page=E2=80=99
>   226 |             test_bit(PG_head, &page->flags)) {
>       |                                    ^~
> ./include/linux/bitops.h:50:44: note: in definition of macro =E2=80=98bit=
op=E2=80=99
>    50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (uintptr_t)=
NULL) && \
>       |                                            ^~~~
> ./include/linux/page-flags.h:226:13: note: in expansion of macro =E2=80=
=98test_bit=E2=80=99
>   226 |             test_bit(PG_head, &page->flags)) {
>       |             ^~~~~~~~
> ...

Gotcha, this is a circular dependency: mm_types.h -> sched.h ->
kmsan.h -> gfp.h -> mmzone.h -> page-flags.h -> mm_types.h, where the
inclusion of sched.h into mm_types.h was only introduced in "mm:
multi-gen LRU: support page table walks" - that's why the problem was
missing in other trees.

In fact sched.h only needs the definitions of `struct
kmsan_context_state` and `struct kmsan_ctx` from kmsan.h, so I am
splitting them off into kmsan_types.h to break this circle.
Doing so also helped catch a couple of missing/incorrect inclusions of
KMSAN headers in subsystems.

I'll fix those and do more testing.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX6eZ6Cdrv5pivcROHi3D8uymdgh%2BEbnFasBap2a%3D0LQQ%40mail.=
gmail.com.
