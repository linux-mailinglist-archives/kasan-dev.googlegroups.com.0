Return-Path: <kasan-dev+bncBCCMH5WKTMGRBC5HVGLQMGQE5BZ7PMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 79413588AC7
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 12:53:01 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id j11-20020a170902da8b00b0016f17813479sf628632plx.5
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 03:53:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659523980; cv=pass;
        d=google.com; s=arc-20160816;
        b=mUp75PY9hY9RcTnBCvcGKCqJN1qX5caqVsp8mXGLjDPFGH/yu5M1EXRSIexJsg5DuU
         g0TROiV1DHK5jpzSDCWrp1HWpIV2Kx6j+NKkwGX4IfqnWoBgR3zJfHJQpPV6i9fNKT4u
         G+Y9kgptMgKxGkYGuhWpebsEW7G/Xt0CSbdzu70GFlrSVHmeHQxgSkdv28qPZntDo63s
         7hd+wJrY29tuTtvMNI5jShfpxNqOwzPCtO2frAFHGzgcM5eUr25tgSqwkvtYnSZBeQ1j
         VU7ctB0kWQgectpbGa8eG4qO5dOtPbr81ze8rAQ+C/6Co9O0j0OScWqZ6ctrw6DljGyQ
         e4iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IinCaiXCWNT2qrfJ4/zHwlj3iZSACDuiz+ZDskDH3N8=;
        b=idfiWwMPAzV9diWiwwtIuZ/GOxrO3ptGfoPTBufGImcjls+zKsdMIOY617K1MuLFsJ
         TiPktIVid9g7T9I92Jeg5WdHHkAslgf95V7sBT5y/GluUg5B5HnLKjiyWEGiMHoEdCf4
         H/KEaJh2FcVUJEGBlzjFcUbvv9jwtkmPxqOsk/a9Nz0YoEoDWvkLoEAuOe4ri4NpHDdS
         yQ18kTV4QL09Idw5aKriKzf7maTqBykd/Uyxy1VBqlaw8OOnYWumnBIMUVlsv6bo8r8O
         w+mLpKsQYKjEjSS4hOh+i69b7n9OIPHZSx36kGJDSezavnd4B6JTeFYwyjaYSmhxtAOL
         +mmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YKAJ6QXb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IinCaiXCWNT2qrfJ4/zHwlj3iZSACDuiz+ZDskDH3N8=;
        b=PIUfX4C2hHZvdAAlDx/6I/ZUgPhoxNjsRJfSxLid9ZFDKHq0PuLUxg4OixzjauC/6a
         o0nGaE/GVqnVLZfbuFkPYASt+i4gOSzBFkhKtvskaDeKA6Jk4qAiS4N9MugxJZcWMmJr
         Bqe5lHJtSaZme4Aeqsmkodsi92koL2wXLTjuBP2U1Zplu4IbHETVxZowam4dZ6+Omp0u
         5a/nZdZtb0+qB0QEXiIYji9JaFOHqBEEulwEgNBmZ2LVZBWqC6JOJVjoWc63UPAXtZF0
         Murhcv7OrgWVMJb84rQOkQV8pTdEh6IfA/VIBR3fmDJ9G/smV+c0wBhWG/5YuE6BODaB
         hVVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IinCaiXCWNT2qrfJ4/zHwlj3iZSACDuiz+ZDskDH3N8=;
        b=tOIGxdC6HO7C1jwo1V1GphJIuB0esl8F1PZ6H3GrF0rRsOo2rz+SvErTeh8l3wlXw9
         sLDrlN8UHiwthx6wAS0OG74aglzfZOxHAyxj8f3xc3o5rXch1cVIY/JuPeZY4/UEXN+V
         HD7WRjHLhxWAWQfUzJuWekwVyDdKVpsr3WZ2B72rzn0o5aj5l1IdwtTJ4u+ybpWEXT15
         q7PlhGC13Uy3ZisAXzTr25tYfJ8sc07Gub22YZ1KKMb7ehNpMBwPPolUfRxP/bw8078z
         4OnwRRxl8u9SgbD4XOqU4Yeq+A1OZP0EXuhz+mElwufijaKzhnkxKlJx1Kcj703gJiIm
         olBQ==
X-Gm-Message-State: ACgBeo2F0VtRx/XhXoDLx4WWSFNaOFSaOYVgDWx+Z6RkwzIEV1waxP9j
	LkQLyHKQhP4zuPirw7tEyik=
X-Google-Smtp-Source: AA6agR6KL2ZG+NTlwwpuuuAMAZcHSH43Y8nKo/M4HJiKOsD5dGkwA0+eSnWfDQxOTpVTyMI+es50Hw==
X-Received: by 2002:a17:902:8e84:b0:16e:e0d8:8c1a with SMTP id bg4-20020a1709028e8400b0016ee0d88c1amr16263232plb.132.1659523979810;
        Wed, 03 Aug 2022 03:52:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d144:b0:16b:cfea:9f3c with SMTP id
 t4-20020a170902d14400b0016bcfea9f3cls11161415plt.7.-pod-prod-gmail; Wed, 03
 Aug 2022 03:52:59 -0700 (PDT)
X-Received: by 2002:a17:90b:1bd2:b0:1f5:313a:de64 with SMTP id oa18-20020a17090b1bd200b001f5313ade64mr4378801pjb.116.1659523978978;
        Wed, 03 Aug 2022 03:52:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659523978; cv=none;
        d=google.com; s=arc-20160816;
        b=ILhbIqrOXyQAfF19EsSj3VvTZIc/wdZAc/AKEzv/P/bUfzzakK1/w95dcW+a7R/1j0
         ONMHsxPqKYVl2J2hxXH69X80ES2nPbgVDXGCfbfpeAyCprrabQmXn7pjtr9J6MHFmoZa
         gmqWcaQuETPvn+Q7b36IT8SbXOG7Q2SxLsrURJExaOhN3kAzsdCYVGI7XJms/26OVKR4
         mtpEbn/1HyihrnCU6lBmkKG2LHYRn8IPLz3C52SPaP8eRlSOs8WRnuNGX+Dnv/JlHdHh
         EVXY67/wHEEMX2XXkbn/tnz+dVSCMykrbRtv4I0AOMDC/ntZUJKHO13iGpZjlg88t2+K
         jy6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LqDMaGMw0T+ovR4GLNrEVT1Q3GLoKKe4dcxLcnnMrZA=;
        b=JxbqTOkz3hHYTeNudT+w+yh3lONyrrpXd8u0lqQBSnGf9tSsKHnHCHiLreNLBPHF02
         VLX2wPW+xQalxmd27wDDMbz8AB75bThZJgo7DYt5SV28orP1MCe7DaiJU0SHUcbBBKhp
         s+ekFqqG4hdfPs8lmCBPgN3Q2HIRmRjVs1/ncNSHwnhuDq3UkRiHIY07dzJbjN3cni6U
         95bSm6Ma5YXnPdehRzaR62/bWIB5CLRHx3mRG0IADoxKr2BmaYgABT7Vwu8GBnlt89Zb
         iAeDwn4DA8EMufVxRK0VxB0Mg3/gK2A1BZT8Xx3+ZiM2azfFH0DNYSpH7WAHa4AgKUrc
         kNpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YKAJ6QXb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id d12-20020a170902cecc00b0016d711db666si73398plg.13.2022.08.03.03.52.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 03:52:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-31f445bd486so166997587b3.13
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 03:52:58 -0700 (PDT)
X-Received: by 2002:a0d:c7c3:0:b0:31e:9622:c4f6 with SMTP id
 j186-20020a0dc7c3000000b0031e9622c4f6mr22504287ywd.144.1659523978073; Wed, 03
 Aug 2022 03:52:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-34-glider@google.com>
 <CANpmjNMpCow-pwqQnw8aHRUZKuBcOUU4On=JgEgysT8SBTrz6g@mail.gmail.com>
In-Reply-To: <CANpmjNMpCow-pwqQnw8aHRUZKuBcOUU4On=JgEgysT8SBTrz6g@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 12:52:21 +0200
Message-ID: <CAG_fn=Xf_VTgYPk8Bnk2Kc9JCArnaRUO-kKFREh6rDpqC3t1eg@mail.gmail.com>
Subject: Re: [PATCH v4 33/45] x86: kmsan: disable instrumentation of
 unsupported code
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
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
 header.i=@google.com header.s=20210112 header.b=YKAJ6QXb;       spf=pass
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

On Tue, Jul 12, 2022 at 3:44 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:24, 'Alexander Potapenko' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> [...]
> > ---
> >  arch/x86/boot/Makefile            | 1 +
> >  arch/x86/boot/compressed/Makefile | 1 +
> >  arch/x86/entry/vdso/Makefile      | 3 +++
> >  arch/x86/kernel/Makefile          | 2 ++
> >  arch/x86/kernel/cpu/Makefile      | 1 +
> >  arch/x86/mm/Makefile              | 2 ++
> >  arch/x86/realmode/rm/Makefile     | 1 +
> >  lib/Makefile                      | 2 ++
> [...]
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -272,6 +272,8 @@ obj-$(CONFIG_POLYNOMIAL) +=3D polynomial.o
> >  CFLAGS_stackdepot.o +=3D -fno-builtin
> >  obj-$(CONFIG_STACKDEPOT) +=3D stackdepot.o
> >  KASAN_SANITIZE_stackdepot.o :=3D n
> > +# In particular, instrumenting stackdepot.c with KMSAN will result in =
infinite
> > +# recursion.
> >  KMSAN_SANITIZE_stackdepot.o :=3D n
> >  KCOV_INSTRUMENT_stackdepot.o :=3D n
>
> This is generic code and not x86, should it have been in the earlier patc=
h?
Ack.


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
kasan-dev/CAG_fn%3DXf_VTgYPk8Bnk2Kc9JCArnaRUO-kKFREh6rDpqC3t1eg%40mail.gmai=
l.com.
