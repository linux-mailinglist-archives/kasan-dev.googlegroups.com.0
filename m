Return-Path: <kasan-dev+bncBDYYJOE2SAIRBSVQXKMAMGQEK4HU2HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B7095A7160
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 01:08:01 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id oo7-20020a056214450700b00499144ac01dsf1671136qvb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 16:08:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661900875; cv=pass;
        d=google.com; s=arc-20160816;
        b=lTLpuK6FxAS/ZLD8EZMDD+jJca3cdVnRhLDbML9fZj3rrvbWfcX1cCoRKwVAKcZls/
         3s0vgUCvK6Gglxx2XGjb+YguKeqZRLCI7EandPDa/xxBpdRFwYfKhiEn6OwqBTqawuKV
         e3bkeBmgS9+84/2mobUcqiWHvn/nmNUSiRjf0oEPS4Cya8/D22n9y6WZrDqH0n47l22m
         52ZlvRs0Lgtgp8bkI+dqdq9W9JbdYiLi+2KavAGLUzu2aaRcHoUratisHu8XIC91BQUP
         M6rT/WvQAMwqCI8Cd/1ib4M3SUiZ7yIv0+y16/yCqDwd3tI8fRXyDxtNXBHbTHx0fGcd
         Qk3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8PDMkZGszKD9QgIcOnVmJa6lNfqdW9uyGXwA9kHv1ac=;
        b=uIQQwzuuAq3KpsCFOjiglIKuSdzKKowDnO+0NXzFrCrjVdgRDr4bR5snWVABCq68l8
         HQLSgHZ9WPfJK3K3pXtS3PsOzVQkm3d1CvResKiBFIvqRwqYs0LGvuQm76v/ZESPwtlf
         gCH5iw3x5aWw2GWl73V5SKMvx3GXa9sLlIeEV+HC20R+SCpsW5nQqNESUgS7/z0Fy7vb
         2/R+m+/CKRpXP0R6eJqdNPG04tXGeran2vXLSwmBfAfvbtX1bTmf/HjlE0mQyhaPFFUQ
         EMxBx/R7bYVvD2o1mgVLf+dIWD4HwuLiYHRP1kj195giH3WbuGons3hUKqTbxClnHHk5
         2LvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RkRI1opr;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=8PDMkZGszKD9QgIcOnVmJa6lNfqdW9uyGXwA9kHv1ac=;
        b=CNH1DqqOhkKQXqt5zKbefE+kQTbmE5d/mZP/DDpdcork2Zmxl+7lQeDK0bw30QSnpL
         vZlZij8190o5dToFGEnddJ2qDB3pzxoxRwVNvxLGsueWsi51L0kfxnMVNllRNTF1jhBW
         d/KugyPfszyQy/YN+DqaDUzqnWpqb5C/2ezF1kCxRS5Drwt+cKFwgZdUx1hOCkRoMtZp
         85ICfbw21luA2FA9QzuFVBlMyBBYBF442e6scz8E59Jo4Jb1QrT4DSxWApIUhU4hdlnv
         HKuJz0wgc3T9uOz1HaRhDrw9pRVyCdbDXKutvitZAkiOgIwicly27j4xHiHubmYl9AnQ
         r7kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=8PDMkZGszKD9QgIcOnVmJa6lNfqdW9uyGXwA9kHv1ac=;
        b=HBM9zN+KsaAX6JFLAsOx3UlwqLkQNqpoVOpJS3evU8rr9dlQpGIzs2U+NUkP/SKCTB
         5tPrvJEDnJwsPb1ZRyP05q1PUaAFoH3L27LhtVLASN8qKUoDK2rJGT4Mz5keuh+9TxFr
         ZSyVloJB4E9Gji9lJeintFVeiNMWlTxZThC4hpc/nNNTgfcT9LzKXqebBnp2yB2Vaok0
         GPcCnVIUpwwywQENJhGjBtA6HhUxvoJuS+/+FIrmuuKi1T53ACaZTocPVby++GUzubXu
         J8aR5QMd3tMzsL9MVhX+WKosZdOxaiSCuQOnPojIfF+AsdSYqzGCq31GxPXiJF7AbRwy
         6Ctw==
X-Gm-Message-State: ACgBeo2JD/mNq5Xdy3Zh2o/D3EXOw8T6tSeVu1Darl8m4doklORrF9Cq
	Ck3Q79ja7r6MByKq2QlaE3g=
X-Google-Smtp-Source: AA6agR7A+8TKoG0X54nwz9vZRwCa4La5scgl0VFFiWrX0FCQOqlrJ5mL9kQkSJIvgJjtuziH0VlZqw==
X-Received: by 2002:a05:620a:bc3:b0:6b6:5746:f91f with SMTP id s3-20020a05620a0bc300b006b65746f91fmr13813781qki.391.1661900875070;
        Tue, 30 Aug 2022 16:07:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1e0a:0:b0:33b:7974:adc with SMTP id n10-20020ac81e0a000000b0033b79740adcls7377031qtl.2.-pod-prod-gmail;
 Tue, 30 Aug 2022 16:07:54 -0700 (PDT)
X-Received: by 2002:a05:622a:1102:b0:343:66b0:4a2 with SMTP id e2-20020a05622a110200b0034366b004a2mr17027291qty.495.1661900874592;
        Tue, 30 Aug 2022 16:07:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661900874; cv=none;
        d=google.com; s=arc-20160816;
        b=i8gsm6Yq8jMpQJdpzf8USmi885XtPvexr4JV2RbldzLdrm5U/8uJ9eFW01Ck+OEwF1
         bQ9RApdM3oo08UY4iXUhlAW3JkQwwXOSzia7KFK0UqVjzBOtk/OBVmorONHFn6lW6E/9
         uBtenM+QwtnDcrATnWIslg7QLynkyYQd/IlpTYQZTW+/c6DVswSb99PObzPRv4dZXBAc
         gwT2NM/5/LHUyDrJig2Mvk+Ecm6Pzg0VaD54bUlisjXgU5bJ+6pv0dWUNwMl+84yaqz1
         dW8B7VXtkB+kQKAxGkcPEAHeB/4SyZZmQN40L3dO8f65j3E4QOcNWBuiOJJL7P87PG8A
         qOEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Vynfz887MVYBr6yRDwVUmonMdQzXB6om2UVf81HGico=;
        b=GWzpFS/JNSQnsg1MSg/4GwS3xOv0oMHUVStahkLTT6D9liv5PxiT+BLHpaqOopQgyu
         Dt/6TaflohuZv/85E4Xlu13VvhmhxEn+NUMmMPAP7J0ZP/oz0y/ZqHle8IPXJ0E23FBy
         H1MsAcea1X/GrPcIcsBYEUhogx+3aU4XQsDEgQyIi6lskx2VTivYx9fGMcPa1xWEVacr
         l1jgO+OgZrP+eHQHpERoUsgaaKPOUmzuQlI2BGM3i9bi3hHjK6dE4tZ1PLVEMF3c0cGj
         C6Op8eEMepq/6+AhR7PFPL1oW7Y9jVceew702Onsh88VIDm5RFiQrT+iw+MFtanpmmBr
         V+qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RkRI1opr;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id d21-20020ac84e35000000b00341a027f09fsi600603qtw.4.2022.08.30.16.07.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 16:07:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id b128so9391591vsc.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 16:07:54 -0700 (PDT)
X-Received: by 2002:a05:6102:e93:b0:390:d839:9aa2 with SMTP id
 l19-20020a0561020e9300b00390d8399aa2mr5153556vst.65.1661900873993; Tue, 30
 Aug 2022 16:07:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
 <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
 <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
 <CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com>
 <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
 <CAOUHufZrb_gkxaWfCLuFodRtCwGGdYjo2wvFW7kTiTkRbg4XNQ@mail.gmail.com> <20220830160035.8baf16a7f40cf09963e8bc55@linux-foundation.org>
In-Reply-To: <20220830160035.8baf16a7f40cf09963e8bc55@linux-foundation.org>
From: "'Yu Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Aug 2022 17:07:17 -0600
Message-ID: <CAOUHufZQ5QV4_GaJU_SPYk-hNEWnnTxcE8EdpcPBHK6M3qSm-w@mail.gmail.com>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
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
X-Original-Sender: yuzhao@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RkRI1opr;       spf=pass
 (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e2a as
 permitted sender) smtp.mailfrom=yuzhao@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yu Zhao <yuzhao@google.com>
Reply-To: Yu Zhao <yuzhao@google.com>
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

On Tue, Aug 30, 2022 at 5:00 PM Andrew Morton <akpm@linux-foundation.org> w=
rote:
>
> On Tue, 30 Aug 2022 16:25:24 -0600 Yu Zhao <yuzhao@google.com> wrote:
>
> > On Tue, Aug 30, 2022 at 4:05 PM Andrew Morton <akpm@linux-foundation.or=
g> wrote:
> > >
> > > On Tue, 30 Aug 2022 16:23:44 +0200 Alexander Potapenko <glider@google=
.com> wrote:
> > >
> > > > >                  from init/do_mounts.c:2:
> > > > > ./include/linux/page-flags.h: In function =E2=80=98page_fixed_fak=
e_head=E2=80=99:
> > > > > ./include/linux/page-flags.h:226:36: error: invalid use of undefi=
ned type =E2=80=98const struct page=E2=80=99
> > > > >   226 |             test_bit(PG_head, &page->flags)) {
> > > > >       |                                    ^~
> > > > > ./include/linux/bitops.h:50:44: note: in definition of macro =E2=
=80=98bitop=E2=80=99
> > > > >    50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (ui=
ntptr_t)NULL) && \
> > > > >       |                                            ^~~~
> > > > > ./include/linux/page-flags.h:226:13: note: in expansion of macro =
=E2=80=98test_bit=E2=80=99
> > > > >   226 |             test_bit(PG_head, &page->flags)) {
> > > > >       |             ^~~~~~~~
> > > > > ...
> > > >
> > > > Gotcha, this is a circular dependency: mm_types.h -> sched.h ->
> > > > kmsan.h -> gfp.h -> mmzone.h -> page-flags.h -> mm_types.h, where t=
he
> > > > inclusion of sched.h into mm_types.h was only introduced in "mm:
> > > > multi-gen LRU: support page table walks" - that's why the problem w=
as
> > > > missing in other trees.
> > >
> > > Ah, thanks for digging that out.
> > >
> > > Yu, that inclusion is regrettable.
> >
> > Sorry for the trouble -- it's also superfluous because we don't call
> > lru_gen_use_mm() when switching to the kernel.
> >
> > I've queued the following for now.
>
> Well, the rest of us want it too.
>
> > --- a/include/linux/mm_types.h
> > +++ b/include/linux/mm_types.h
> > @@ -3,7 +3,6 @@
> >  #define _LINUX_MM_TYPES_H
> >
> >  #include <linux/mm_types_task.h>
> > -#include <linux/sched.h>
> >
> >  #include <linux/auxvec.h>
> >  #include <linux/kref.h>
> > @@ -742,8 +741,7 @@ static inline void lru_gen_init_mm(struct mm_struct=
 *mm)
> >
> >  static inline void lru_gen_use_mm(struct mm_struct *mm)
> >  {
> > -       if (!(current->flags & PF_KTHREAD))
> > -               WRITE_ONCE(mm->lru_gen.bitmap, -1);
> > +       WRITE_ONCE(mm->lru_gen.bitmap, -1);
> >  }
>
> Doesn't apply.  I did:
>
> --- a/include/linux/mm_types.h~mm-multi-gen-lru-support-page-table-walks-=
fix
> +++ a/include/linux/mm_types.h
> @@ -3,7 +3,6 @@
>  #define _LINUX_MM_TYPES_H
>
>  #include <linux/mm_types_task.h>
> -#include <linux/sched.h>
>
>  #include <linux/auxvec.h>
>  #include <linux/kref.h>
> @@ -742,11 +741,7 @@ static inline void lru_gen_init_mm(struc
>
>  static inline void lru_gen_use_mm(struct mm_struct *mm)
>  {
> -       /* unlikely but not a bug when racing with lru_gen_migrate_mm() *=
/
> -       VM_WARN_ON_ONCE(list_empty(&mm->lru_gen.list));

Yes. I got a report that somebody tripped over this "unlikely"
condition (and ascertained it's not a bug). So I deleted this part as
well.

Will refresh the series around rc5. Thanks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOUHufZQ5QV4_GaJU_SPYk-hNEWnnTxcE8EdpcPBHK6M3qSm-w%40mail.gmail.=
com.
