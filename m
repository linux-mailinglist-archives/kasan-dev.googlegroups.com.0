Return-Path: <kasan-dev+bncBDYYJOE2SAIRB6M4XKMAMGQEU4HOT5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 042075A70BC
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:26:03 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id c1-20020a0cfb01000000b00495ad218c74sf8147306qvp.20
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 15:26:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661898362; cv=pass;
        d=google.com; s=arc-20160816;
        b=WsEHUlWt/a87MiuyBz7748Tb3kyYHy9nqEJiWJ/HRQT24fEAtT97ysZWmbVkDFnVvs
         12Bop/D9H1TqmiOYtzYUJtRvkFIY558w5ytvcZQuy4g0rLMj0j53ijZmNroj83KYiMCu
         XINTWdRbPFXacfWAykbjYWvonvaJnYV1pmKdf7wY38CHUe5YnwaHK8IYkaoU6IZJZ5EB
         CfXzq7r2mEtuWVArnpZimDbqWLq5QxVTcuEHhBnNYkeHzfmOpx5peDPjaPieEAZbj+3j
         SnfrcBWhbdKb+LmP6o9t/Vz2F9Dg0IH27VRkfma29PKZ0hgN0n0x4SZhygocdIG0Z6wH
         pg5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pCMylABrK7tnaCW0utmzjadxCuV7INj/zaoUzGZaTZk=;
        b=rGUpHLptL/CVOZ5KZp65Gvxw4e5qNnmJ6Gk+vhADCc31RP05KeZxOYQFRI/Ocx1cei
         o9tTucwUzh18VGOLoc7Nc6MKz/aEkvH4vkzN4V5LTvi9TdrTT9AhLLOFwqH/gkiloofS
         W/g3KxKhO5LF+t0kAfKuiKBnB2rOOZxo6kQvueKKH3lLVbMm3Jvybraw78NQbDkaKdN8
         ayu++zDw6Biwd4XXrU3ESwYbOyssjrL25faLaawO6WR+YrVuvPANKsPXiGRR0M0hJYhY
         Y24pKelH0nCyiLBtKGTDERaIjwMwqRpzoZJwmMbv98C1E1c6YsrRBd4Hq+3MrwXjydfZ
         JGDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DZGo2BNv;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=pCMylABrK7tnaCW0utmzjadxCuV7INj/zaoUzGZaTZk=;
        b=ncdOOO0MyIxHrjEEKG5iGu6m1UmqdtOAazGAkcT+SUs2FZscCkPz1UOXxwY287VjpK
         1MHkyD5yte6K0XN55iJc+YL8GxQXpDRqmrvF+zx8BdbvNDIJUzw3ygmp4zYONohqj81E
         tBKoLHa0KJNxVKVx4+HM3vv/ysTht1zDdJctexE7BLB46iF66umPYRGuf8AxzRmhgkoL
         ne7Vy7jTfvest0jynacnq1/KUlNDWButP3gFyQJc6UWU65b9Gaonrhph0VN7FJ5PtGL3
         GgKNBUy9cba5/bIHL2VjAQMUw4CIu/0beiv4qz+ByjSnO8LulIbDJx/CoYMfhwTkfBka
         UAfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=pCMylABrK7tnaCW0utmzjadxCuV7INj/zaoUzGZaTZk=;
        b=YC6l70fJkKSMjr9pi5bRgInUDP+J3uhkU7mOkYOqupS+piXtpW1vXhFcOc6OhTeY2U
         IHclSIome8sfta0v8oHQeZ7U1F3iO2G6MQxYG3nrfUu2qzVySCSVk8tqYWPngQIkNLdR
         bPfAKmBEsXg9J9nEQVoOqP9/bvj3C+EfuOYYCEFVaBxSeywRkVfOl5MQ2n3t/QGjuL7Q
         pbKnFqU42XXNhTg4NbzU9VfjTDIPxCF5iPDuKtCS9l3PwP3IASCRHFEwnV5fBmILgMTV
         kl6hIslcx3fu1LcMadaGLRM+fmHK1rFCdt38J4toUUiIDKVeLdgISKF1C591IJaAQI7q
         9oOQ==
X-Gm-Message-State: ACgBeo1y5FDUTmLoxLCwW4IDPEsWMfNOSsoLUiN25A1J1MtS0pfNjo0e
	YyAW+utcUMum2KVj2Wq5iWY=
X-Google-Smtp-Source: AA6agR4b7I4eDmAWUmX1zkF0UOc5+3pDmnbOC2MCq2X1qUjGTG4iblcw2UxOMHw4ri73fl1UsOMC/g==
X-Received: by 2002:a05:6214:2685:b0:477:1d22:f017 with SMTP id gm5-20020a056214268500b004771d22f017mr18011251qvb.96.1661898361961;
        Tue, 30 Aug 2022 15:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1008:b0:6b9:4aa2:f6 with SMTP id
 z8-20020a05620a100800b006b94aa200f6ls6938836qkj.2.-pod-prod-gmail; Tue, 30
 Aug 2022 15:26:01 -0700 (PDT)
X-Received: by 2002:a37:4d0:0:b0:6ba:f09a:a60a with SMTP id 199-20020a3704d0000000b006baf09aa60amr13807077qke.156.1661898361553;
        Tue, 30 Aug 2022 15:26:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661898361; cv=none;
        d=google.com; s=arc-20160816;
        b=KbCBBdxudsOJcXGeYn+dw2QP1fHBilCTE1gA5Mm3fBqu373PuxNjMEPbppjrMI7CAw
         G7QNNdq1lX5nZt1yVN7LYJb0nxGciE6xUDVIctN/mXgZvVhZYXLTmUWqF8XW5lZXbHqK
         LkjJofgzvZVYArH/X3Q5FVEejH9QUwXcNvWho7ltmo3xXejHp8zO9FL3v54732YUd1jo
         XjNGxjXARSU2+rAA1ibwLlobOtLzNRlsgX8NvJ7p/Rl36U5cX6CR012Don5f2dZ5d8Z4
         p5rxIN9gIosLL/3CTks2stk5LEhU+IgxamtRH+5157XVJLCrqJgO3MFwQD7PYZNfvAJ2
         8Vzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=r2P9ypGVKmAeSRno/tnjXqx+dUVsN5K996xR9WW8XbA=;
        b=xZZph3YIjZtHiElQ3hGqhINNbuUy8rBBZv/wsRaSBQMEjF6HdfOKL3YJBDnZ/s61/J
         L1S9vGY9iHLdHmOfXJHiyJMKcBfP+/1AyOuE4Gsl8i+Vq1D4zrDaemX4Y+fSzByRVcQj
         UX/cHQ2jw5eDsZAtZv9gG3lOqdtsjS9C33CKRyC9/rIKPFqQi9ijvXP8ktkBAqnYThjX
         brWqqkIsq+MadcbJbRekbn+D6OidkgngMJ7tdInOfa7D5CaIy/u4s+nwkzepK1T0h9V9
         vQVLfoDj1q766gZSeMMdJEeTGQZwUX3KR2hirt+k9XFfi7tLtkUgjy9qXdnpCA2bs4mR
         40Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DZGo2BNv;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92f.google.com (mail-ua1-x92f.google.com. [2607:f8b0:4864:20::92f])
        by gmr-mx.google.com with ESMTPS id k27-20020a05620a07fb00b006bad5953a88si314646qkk.2.2022.08.30.15.26.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 15:26:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::92f as permitted sender) client-ip=2607:f8b0:4864:20::92f;
Received: by mail-ua1-x92f.google.com with SMTP id l19so2802146uap.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 15:26:01 -0700 (PDT)
X-Received: by 2002:ab0:1e0d:0:b0:39f:a187:b72e with SMTP id
 m13-20020ab01e0d000000b0039fa187b72emr3174662uak.70.1661898361104; Tue, 30
 Aug 2022 15:26:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
 <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
 <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
 <CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com> <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
In-Reply-To: <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
From: "'Yu Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Aug 2022 16:25:24 -0600
Message-ID: <CAOUHufZrb_gkxaWfCLuFodRtCwGGdYjo2wvFW7kTiTkRbg4XNQ@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=DZGo2BNv;       spf=pass
 (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::92f as
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

On Tue, Aug 30, 2022 at 4:05 PM Andrew Morton <akpm@linux-foundation.org> w=
rote:
>
> On Tue, 30 Aug 2022 16:23:44 +0200 Alexander Potapenko <glider@google.com=
> wrote:
>
> > >                  from init/do_mounts.c:2:
> > > ./include/linux/page-flags.h: In function =E2=80=98page_fixed_fake_he=
ad=E2=80=99:
> > > ./include/linux/page-flags.h:226:36: error: invalid use of undefined =
type =E2=80=98const struct page=E2=80=99
> > >   226 |             test_bit(PG_head, &page->flags)) {
> > >       |                                    ^~
> > > ./include/linux/bitops.h:50:44: note: in definition of macro =E2=80=
=98bitop=E2=80=99
> > >    50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (uintpt=
r_t)NULL) && \
> > >       |                                            ^~~~
> > > ./include/linux/page-flags.h:226:13: note: in expansion of macro =E2=
=80=98test_bit=E2=80=99
> > >   226 |             test_bit(PG_head, &page->flags)) {
> > >       |             ^~~~~~~~
> > > ...
> >
> > Gotcha, this is a circular dependency: mm_types.h -> sched.h ->
> > kmsan.h -> gfp.h -> mmzone.h -> page-flags.h -> mm_types.h, where the
> > inclusion of sched.h into mm_types.h was only introduced in "mm:
> > multi-gen LRU: support page table walks" - that's why the problem was
> > missing in other trees.
>
> Ah, thanks for digging that out.
>
> Yu, that inclusion is regrettable.

Sorry for the trouble -- it's also superfluous because we don't call
lru_gen_use_mm() when switching to the kernel.

I've queued the following for now.

--- a/include/linux/mm_types.h
+++ b/include/linux/mm_types.h
@@ -3,7 +3,6 @@
 #define _LINUX_MM_TYPES_H

 #include <linux/mm_types_task.h>
-#include <linux/sched.h>

 #include <linux/auxvec.h>
 #include <linux/kref.h>
@@ -742,8 +741,7 @@ static inline void lru_gen_init_mm(struct mm_struct *mm=
)

 static inline void lru_gen_use_mm(struct mm_struct *mm)
 {
-       if (!(current->flags & PF_KTHREAD))
-               WRITE_ONCE(mm->lru_gen.bitmap, -1);
+       WRITE_ONCE(mm->lru_gen.bitmap, -1);
 }

 #else /* !CONFIG_LRU_GEN */

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOUHufZrb_gkxaWfCLuFodRtCwGGdYjo2wvFW7kTiTkRbg4XNQ%40mail.gmail.=
com.
