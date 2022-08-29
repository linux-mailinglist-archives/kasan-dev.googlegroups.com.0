Return-Path: <kasan-dev+bncBCCMH5WKTMGRBANIWOMAMGQEGKC5WSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 05DC45A4FB5
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 16:58:11 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id e24-20020a4a91d8000000b0044894b6503dsf3754187ooh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 07:58:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661785089; cv=pass;
        d=google.com; s=arc-20160816;
        b=ehWMusluLZGEpYg34+Bm96BiDmfZFr1Kp55mI69cQ+ETYwRFbKvYo6y9IU2rCEU5qD
         SCoPT7cZzoTvftIHTzmM0lij7YacKMBxs4us5fxZxw7IcX5WqE9oUAnGyig8zU99S/hP
         cHu9Gi4d8Xp43CP9zV6aqTVlSQhsMbwKUGtNiVMnRQI1j960HgXDjhA1TeYyUb8Ynqfr
         L/8njmroSuxtTTjuu6kUSPgsM1TLFes5RaIilOS+h1KWZiGfHMq1EEqsm9O1Zik/G9V4
         W++7wwmTTvTz7sYL73uPQ0BZ/O2s7483ii7ksSO9/VvpANU0OW+mw9q7ORlZDRPVh5HC
         uOFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OsRJk6iI0B6/MgBKo/MP8E+QLsG2vzgCd4BqUoJNdu4=;
        b=JO36E3OxVs9dxVrzAQtJPTsj6kBQgq60vPDeSlUQU0WeNf9r9jHJozyXpP6O25TRoq
         lLCC9waAi0MSVtpABxh5o8rIzsEOdksx/rubZ586byNgnQh04q9FNcWl2O7S1FqhqSaq
         auWtvXyL8rJClbicgw3SJlF89WEcKmJwm1xn7EeF5bY+grEIWYlqQLVbwOAKu1J8rZ5C
         CBS4bJWxuRodK0hOddHmSDJlcE6aRbxgEJff8uCZMtvAdnHLHMcCt6eHSG0BVt7/cDfH
         +7Cy5Kz4OrzB9Wi9jNfwQ98jQCgM2oSjjkrKcnDzb9lxpix+EGgLan/l7ngjoFbZyT0h
         CMMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nGGmFoI9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=OsRJk6iI0B6/MgBKo/MP8E+QLsG2vzgCd4BqUoJNdu4=;
        b=WspMv8ZQmk5V7PGePxg2uTTkm2p04vnrpLgEVOnw6ONyy3tRG1xxClFNSZ2AUMUecj
         P3qn/3bswOsbSa3D4kf+rlzw5cYRBcMRGerZEWLl3tQtlDbN4ALzgw/jXh30gEp2fKG3
         9OEO8/kyzvef7r/BhI7dKJGq7yI6dVvSuf6EVII/uoqIBmPm1UM8uD6/18URVCCE2A+6
         fVonZV3OFiXFnFVcmXdgAoj2UH8V33EBWfUZpPtkMMzTBjMjYcTK2abB7gK0rD0g4n3m
         BxB8AtjNf30kDz+9uDgSIB68KE7pCqqNxtoiKlqWjacSwK8rGR66HE3Ul8XUjJDu38c/
         Yqgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=OsRJk6iI0B6/MgBKo/MP8E+QLsG2vzgCd4BqUoJNdu4=;
        b=awszSijoWhMiEEg7XXWyxqA1PvIu5qp8S0onl/dpbFR5BxgRt3CBjHlyDQmZXC/ZHS
         gnin9DZYOAIohTYlZFT/GHrst2FsozzO32+C0xBRnbN2fphT/L2HP8KxXXQLynkvzPUL
         EZOnkm482mFgq2ySMbZk5EEinwKvSjRjlg4tT+1KePgem7tBDS04mggZ/eoKGxnQZZeO
         UzrCFRjMITbFj5r6AYjNCaqkK+aHISQLtCPGp63dwVvjJ5gAs8p0AnvkOYC+OS36HcuG
         ONL7FJKkSlRIGiaMYd2ZEDbYf7OMrS9YzLmnOaSjft3SBrtILKRE4ajO557ACX0zys/n
         IrWQ==
X-Gm-Message-State: ACgBeo2UR7w/+jRWw5y3OFdFUoO9XHCqUNUa87lGORqMmpF2s2j4nuf5
	lPA2mrVBLLI+un9BgyZ0xOQ=
X-Google-Smtp-Source: AA6agR79E2GjWPJkclUaH9qfZ/HAro59GWd4jFb5xcAsss8MXvWdiXgetiHwRkGv5Ri0Jghi/uLrJg==
X-Received: by 2002:a05:6808:1b0d:b0:344:ee32:f7f9 with SMTP id bx13-20020a0568081b0d00b00344ee32f7f9mr7566830oib.25.1661785089594;
        Mon, 29 Aug 2022 07:58:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:7c2:0:b0:342:e56b:822c with SMTP id 185-20020aca07c2000000b00342e56b822cls2557038oih.8.-pod-prod-gmail;
 Mon, 29 Aug 2022 07:58:09 -0700 (PDT)
X-Received: by 2002:a54:4e8d:0:b0:32e:aa9e:6c50 with SMTP id c13-20020a544e8d000000b0032eaa9e6c50mr7067319oiy.73.1661785089120;
        Mon, 29 Aug 2022 07:58:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661785089; cv=none;
        d=google.com; s=arc-20160816;
        b=0Oxh6Tpo5858X2smWdDjr+Lcxr1hblH7h2zuHoHZUfwCprB7R7UfdqtRrp6HckrUWf
         JDeJ9Nom0qTy6Gn5WYGGhvMQNtSWkvAIE7tw/r7Xs4UBnnq/LmFYcSrYDWJIlbea4DZj
         zWp8PT7gJd1f2KkfENvVspw3XVF9g1x+1XiGzNFFz5lch3+dQOWbmdylMFjaNHy/aBvS
         8bS0gaB0I6WdranJjHLHcrI3a8j8ZqUVkPznXD7Sv/7bScGbUE9ab2Wj38kvaQmg20Gx
         Q7TQQwXP/twwZbAPpilohdAx1nBrkkP/8IcUgkGOZOqMDkj1Tgq3QAJg/xuzAFy4gJSp
         juGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/oXossRp5gmk91oxr3O2OqpJJYrYzHF/cnO4ugwp7xo=;
        b=pboSwMbygieBz2YLIrRfuv1NFGJrcutICFuxV5Yfk2fnOe/YaQKIb2pcFmXc1FD7bU
         Quy5xwkJBjN0T0heCkHfhlnAQoaS1YzZLKJdW6beM24EAe/Z32d2Uv1jIJvMOacSOyNk
         ALEEZr2GiqZ5znd6WA63qgCnVnOkozDIkWqKpLoY14qLxbk6tnXlWyEjzD6IrI+/lwO1
         HGBuldDbzzlXOoLUjqrDnQM70DOBYMJbXBLLkq80UFzNEk8cwjiKruvzqahk6b832xWf
         Pf9peIgWDW5HJV7CuyzONHoRkz7HXDmtJs5cEJvqsgM+Sk+ffOimaI+P045c9RBBZTs3
         L/qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nGGmFoI9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id u15-20020a0568301f4f00b0063892f97dadsi494150oth.3.2022.08.29.07.58.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 07:58:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-3376851fe13so202268627b3.6
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 07:58:09 -0700 (PDT)
X-Received: by 2002:a25:bc3:0:b0:673:bc78:c095 with SMTP id
 186-20020a250bc3000000b00673bc78c095mr8579874ybl.376.1661785088326; Mon, 29
 Aug 2022 07:58:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
In-Reply-To: <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Aug 2022 16:57:31 +0200
Message-ID: <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
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
 header.i=@google.com header.s=20210112 header.b=nGGmFoI9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
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

On Sat, Aug 27, 2022 at 6:17 AM Andrew Morton <akpm@linux-foundation.org> w=
rote:
>
> On Fri, 26 Aug 2022 17:07:27 +0200 Alexander Potapenko <glider@google.com=
> wrote:
>
> > Use hooks from instrumented.h to notify bug detection tools about
> > usercopy events in variations of get_user() and put_user().
>
> And this one blows up x86_64 allmodconfig builds.

How do I reproduce this?
I tried running `make mrproper; make allmodconfig; make -j64` (or
allyesconfig, allnoconfig) on both KMSAN tree
(https://github.com/google/kmsan/commit/ac3859c02d7f40f59992737d63afcacda0a=
972ec,
which is Linux v6.0-rc2 plus the 44 KMSAN patches) and
linux-mm/mm-stable @ec6624452e36158d0813758d837f7a2263a4109d with
KMSAN patches applied on top of it.
All builds were successful.

I then tried to cherry-pick just the first 4 commits to mm-stable and
see if allmodconfig works - it resulted in numerous "implicit
declaration of function =E2=80=98instrument_get_user=E2=80=99" errors (quit=
e silly of
me), but nothing looking like the errors you posted.
I'll try to build-test every patch in the series after fixing the
missing declarations, but so far I don't see other problems.

Could you share the mmotm commit id which resulted in the failures?


> > --- a/arch/x86/include/asm/uaccess.h
> > +++ b/arch/x86/include/asm/uaccess.h
> > @@ -5,6 +5,7 @@
> >   * User space memory access functions
> >   */
> >  #include <linux/compiler.h>
> > +#include <linux/instrumented.h>
> >  #include <linux/kasan-checks.h>
> >  #include <linux/string.h>
> >  #include <asm/asm.h>
>
> instrumented.h looks like a higher-level thing than uaccess.h, so this
> inclusion is an inappropriate layering.  Or maybe not.
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
> ./include/linux/page-flags.h: In function 'page_fixed_fake_head':
> ./include/linux/page-flags.h:226:36: error: invalid use of undefined type=
 'const struct page'
>   226 |             test_bit(PG_head, &page->flags)) {
>       |                                    ^~
>
> [25000 lines snipped]
>
>
> And kmsan-add-kmsan-runtime-core.patch introduces additional build
> errors with x86_64 allmodconfig.
>
> This is all with CONFIG_KMSAN=3Dn
>
> I'll disable the patch series.  Please do much more compilation testing
> - multiple architectures, allnoconfig, allmodconfig, allyesconfig,
> defconfig, randconfig, etc.  Good luck, it looks ugly :(
>


--
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
kasan-dev/CAG_fn%3DXpva_yx8oG-xi7jqJyM2YLcjNda%2B8ZyQPGBMV411XgMQ%40mail.gm=
ail.com.
