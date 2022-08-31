Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNUUXSMAMGQEOEDQRCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2912E5A7753
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:14:00 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-11ca8511155sf4037162fac.15
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661930038; cv=pass;
        d=google.com; s=arc-20160816;
        b=T4MUxczXmkoyZ0CdvQ2aJkXhoLfcNw5kCpUoaPnf9H/qEqgXQjhhDJ4h9lCPSfOfoV
         X0PzLMqfIHFCW9Ud8DjZ8VcC5yIoPPZ9JNiN5SddewJKFDdev8+Gj/8XhheTFC0Zbc+X
         6Iblmd6aCqrVpF6uCurmJh6dUUBREuEsWOr9PqG1Hi3uYE/a+X6hsqruT1ZW2f+Y07s+
         hyTYLo5BP9mYoXGsWYZd1Iw8cokRowD3I+kEklvfDuTQldo8vVzMuEWGQWI2eMCyQ1tY
         dRwnDnnbmTyvhHACquvDNewAkyO9ajSR8nfeIyAg0hVsfpavpe5ZtgeRKho8ibJt6vbj
         Lsjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SL8Je2RCpYVd3kaD6UQWbkDyGTyZ4IgHOGMOA7asHaY=;
        b=D5EN8HnkT+/cZLnIDHoM02dPgm2uLcqtVrX2rHSA9rbr2H/LdydQC0fqTnHJ8D8hK3
         z2yfJa7HNZB64gPNSp3z+Ea52HENydERe4VXxmWsaT9Z4C6RWi2bQxTr53BW6wDnE/Vb
         a7zlnlzykTKpA1ByZF5Wn+o4MrLdxWvaK1wU6cZrpycU9w4pPdi+uKbbZPHvZLMGf7P7
         ML+ALKR+XZ7QpDqSS8rYMyN82cf/N8PBLyK1hPTBkz67FkBRbUcA7RdEgtLEgs9IPnE9
         VEZ86xUrrD9D4zTxBQFJs7AZrs+EF0ZvEhrthY+mWZmWIeU1Y28QfdytJ8TeF/ZVgOQF
         z7fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BelMdRwx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=SL8Je2RCpYVd3kaD6UQWbkDyGTyZ4IgHOGMOA7asHaY=;
        b=QALkNpZSYup80VCTtiX0sVkmG9j+o7qHeKrfmempIeRlBBK1R2/9gRhRUGH1wVPRch
         PLcFf/CagqGC70SXj7mmMbKHWUmhINISCkCWaCpV5dDHltzjDW2nWBIUwo/1UGrY6xqs
         msYgJuR2VUGpu+eV3T1qsazi2mlS1IhTB31fg7u5oL5X+NWIGqK3uu1+zM+w+n7Oi8tQ
         DkYbHLw0C66PMT3jf9bqNdpCKVZJ/3uOmEzuN+tg3wrgJ5efARdYM8caf6rE1ZEf4Vyr
         3T0Ttbp+xd45oauD9rw3FuH1iQHX9GRElvmzqRhAufVzLMQI/t6aSyW5L6ktY7VZmJOG
         6T7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=SL8Je2RCpYVd3kaD6UQWbkDyGTyZ4IgHOGMOA7asHaY=;
        b=nPvM6m5zHSK3IW1DyjH+nG0J1giY1jE19fbb9oeg465fI+s69qVzTCCcy8DCmvfWTe
         G+F1Oibur+jg9X86CT5y3E9TQ1FT5V0C8EvoFZ7zKayG/s0CyMraIUJt+BM0FpUdBfof
         oDD2rt9YaQyP31cMu0le+nItNai7xOrtr+FPE4chnb9cHw8Zk4Kzb1BvZiZsHFTMFiRj
         FvebzwS7q2ERoJ71v6eqLi57gW7Mkqa2M92LjDwc1acdkPfqIjApqGOrmXVx5iS7DeB2
         rBIzTGZjEsviMurhDBDN/WJAmgRqDmd0fh5wOK8wRJOYQizUq8z2kvd35jAl7xr3cSxR
         ROMw==
X-Gm-Message-State: ACgBeo14oEX+VW0+IEJ+Jtw+nMOJ/+d5yNRFtMKKN8umJb46HKBz/tnD
	0TtVgnFhx1pSviNDQBGw8TE=
X-Google-Smtp-Source: AA6agR7pM6Q210LaV2XiHoKP7OE7Lse3MY13sIR/pLTncg8t4ClHoq0XV80WqTvOthMCMRxYxNnhYg==
X-Received: by 2002:a9d:7507:0:b0:638:e210:c9ff with SMTP id r7-20020a9d7507000000b00638e210c9ffmr9506563otk.192.1661930038427;
        Wed, 31 Aug 2022 00:13:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b7b4:b0:11e:7a1d:b272 with SMTP id
 ed52-20020a056870b7b400b0011e7a1db272ls4155181oab.7.-pod-prod-gmail; Wed, 31
 Aug 2022 00:13:58 -0700 (PDT)
X-Received: by 2002:a05:6870:d20b:b0:11d:44be:40fe with SMTP id g11-20020a056870d20b00b0011d44be40femr768743oac.3.1661930037890;
        Wed, 31 Aug 2022 00:13:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661930037; cv=none;
        d=google.com; s=arc-20160816;
        b=R3RzMkg8/wKj1vvORbOCtYF6nFNjEb4/pJTsDjjszBf5VCLtTpFmyO3i0Rvlrv7SHh
         heUdgPtx6W6nwJXujli4jyfFC5vFWDmbAm/GOckDCIh0vmFKD5AcNvgzyc8Qyj67nNSl
         d1svlwroonGe1Kru8Flb91KI2LPgDNucx3Zj+91eF49SmiXYSwUdR2VZqk5A5OxtRzRP
         pAogVb2/tBczL3R8MXv0vMIIRT/SAFFoq/c7Xlh1AHF66FHSodARnLntiRLFQljKwK31
         JQfK9i4zmKoORpGR+CTSCK885qzhi29Mky/Nq02CuD0FYwtAKDTbj4DNj0TEIsQz3mqm
         nAPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Sfi1gRWe3Pv4hFkp/2mywI4Y2D7k7G63OFzJO6B3Cn8=;
        b=myFyIK1QV0y2xRnMkGzlHkQ01xwpJy2ihrkGxikcRL2Ucb1nJMbKt7Nyf+jf5YKpHR
         GIgXaHQmsHBlJ0wH7JCYTdUR8GsDQ4Qe9xOmOoefkju+Vxa8/a2NjnZaQIDAqYNnbo7Q
         worKVnMHVYaLo8JdYj9pD1UgsLzZcKMcdcpdut700x6d/0wL3+1ePxpkr1v19J5FWsr4
         BRsSfZqCoHDLM8EsKfVo5uApAWvkM5DpYydeBK9oC5zac8i9nbnh9bNY3u8fJY7BqJUO
         FC86lHeHU0e/dC33clDH22kcyaxPjQAbc5U8BIdUIxsM2DVqGJk9Bu1QonLUZwvOq4Vo
         j5vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BelMdRwx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id t9-20020a056870600900b00108c292109esi1200683oaa.2.2022.08.31.00.13.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 00:13:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-3376851fe13so299178757b3.6
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 00:13:57 -0700 (PDT)
X-Received: by 2002:a81:b71c:0:b0:340:bb98:fb38 with SMTP id
 v28-20020a81b71c000000b00340bb98fb38mr15645113ywh.428.1661930037271; Wed, 31
 Aug 2022 00:13:57 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
 <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
 <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
 <CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com>
 <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
 <CAOUHufZrb_gkxaWfCLuFodRtCwGGdYjo2wvFW7kTiTkRbg4XNQ@mail.gmail.com>
 <20220830160035.8baf16a7f40cf09963e8bc55@linux-foundation.org> <CAOUHufZQ5QV4_GaJU_SPYk-hNEWnnTxcE8EdpcPBHK6M3qSm-w@mail.gmail.com>
In-Reply-To: <CAOUHufZQ5QV4_GaJU_SPYk-hNEWnnTxcE8EdpcPBHK6M3qSm-w@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 09:13:20 +0200
Message-ID: <CAG_fn=Vwxmc6VwbJObiHNiPaAt9tAV77RqFco=q7traPG5DxYw@mail.gmail.com>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
To: Yu Zhao <yuzhao@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
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
 header.i=@google.com header.s=20210112 header.b=BelMdRwx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d
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

On Wed, Aug 31, 2022 at 1:07 AM Yu Zhao <yuzhao@google.com> wrote:
>
> On Tue, Aug 30, 2022 at 5:00 PM Andrew Morton <akpm@linux-foundation.org>=
 wrote:
> >
> > On Tue, 30 Aug 2022 16:25:24 -0600 Yu Zhao <yuzhao@google.com> wrote:
> >
> > > On Tue, Aug 30, 2022 at 4:05 PM Andrew Morton <akpm@linux-foundation.=
org> wrote:
> > > >
> > > > On Tue, 30 Aug 2022 16:23:44 +0200 Alexander Potapenko <glider@goog=
le.com> wrote:
> > > >
> > > > > >                  from init/do_mounts.c:2:
> > > > > > ./include/linux/page-flags.h: In function =E2=80=98page_fixed_f=
ake_head=E2=80=99:
> > > > > > ./include/linux/page-flags.h:226:36: error: invalid use of unde=
fined type =E2=80=98const struct page=E2=80=99
> > > > > >   226 |             test_bit(PG_head, &page->flags)) {
> > > > > >       |                                    ^~
> > > > > > ./include/linux/bitops.h:50:44: note: in definition of macro =
=E2=80=98bitop=E2=80=99
> > > > > >    50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (=
uintptr_t)NULL) && \
> > > > > >       |                                            ^~~~
> > > > > > ./include/linux/page-flags.h:226:13: note: in expansion of macr=
o =E2=80=98test_bit=E2=80=99
> > > > > >   226 |             test_bit(PG_head, &page->flags)) {
> > > > > >       |             ^~~~~~~~
> > > > > > ...
> > > > >
> > > > > Gotcha, this is a circular dependency: mm_types.h -> sched.h ->
> > > > > kmsan.h -> gfp.h -> mmzone.h -> page-flags.h -> mm_types.h, where=
 the
> > > > > inclusion of sched.h into mm_types.h was only introduced in "mm:
> > > > > multi-gen LRU: support page table walks" - that's why the problem=
 was
> > > > > missing in other trees.
> > > >
> > > > Ah, thanks for digging that out.
> > > >
> > > > Yu, that inclusion is regrettable.
> > >
> > > Sorry for the trouble -- it's also superfluous because we don't call
> > > lru_gen_use_mm() when switching to the kernel.
> > >
> > > I've queued the following for now.
> >
> > Well, the rest of us want it too.
> >
> > > --- a/include/linux/mm_types.h
> > > +++ b/include/linux/mm_types.h
> > > @@ -3,7 +3,6 @@
> > >  #define _LINUX_MM_TYPES_H
> > >
> > >  #include <linux/mm_types_task.h>
> > > -#include <linux/sched.h>
> > >
> > >  #include <linux/auxvec.h>
> > >  #include <linux/kref.h>
> > > @@ -742,8 +741,7 @@ static inline void lru_gen_init_mm(struct mm_stru=
ct *mm)
> > >
> > >  static inline void lru_gen_use_mm(struct mm_struct *mm)
> > >  {
> > > -       if (!(current->flags & PF_KTHREAD))
> > > -               WRITE_ONCE(mm->lru_gen.bitmap, -1);
> > > +       WRITE_ONCE(mm->lru_gen.bitmap, -1);
> > >  }
> >
> > Doesn't apply.  I did:
> >
> > --- a/include/linux/mm_types.h~mm-multi-gen-lru-support-page-table-walk=
s-fix
> > +++ a/include/linux/mm_types.h
> > @@ -3,7 +3,6 @@
> >  #define _LINUX_MM_TYPES_H
> >
> >  #include <linux/mm_types_task.h>
> > -#include <linux/sched.h>
> >
> >  #include <linux/auxvec.h>
> >  #include <linux/kref.h>
> > @@ -742,11 +741,7 @@ static inline void lru_gen_init_mm(struc
> >
> >  static inline void lru_gen_use_mm(struct mm_struct *mm)
> >  {
> > -       /* unlikely but not a bug when racing with lru_gen_migrate_mm()=
 */
> > -       VM_WARN_ON_ONCE(list_empty(&mm->lru_gen.list));
>
> Yes. I got a report that somebody tripped over this "unlikely"
> condition (and ascertained it's not a bug). So I deleted this part as
> well.
>
> Will refresh the series around rc5. Thanks.

Guess I'd still proceed with splitting up kmsan.h just to be on the safe si=
de.

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
kasan-dev/CAG_fn%3DVwxmc6VwbJObiHNiPaAt9tAV77RqFco%3Dq7traPG5DxYw%40mail.gm=
ail.com.
