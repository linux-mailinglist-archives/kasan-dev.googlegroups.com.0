Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEXPX6LQMGQE6DOVFAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3813458BC07
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Aug 2022 19:34:12 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id m123-20020a253f81000000b0066ff6484995sf5904466yba.22
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 10:34:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659893651; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3dCxXaYDroRwCAqK6plg0/zMujXm0oMty9H9OORaUHp1kBBgaD8ECWGqfKUAfVA9n
         OzFuYXbfPRRlW4mVEJSEJpLDJm+5DAyZma6+IAiVGOG/B/Zd7yG6WA/rX5RvST0xU3xK
         z7G0ekNkCXVjGirS4QPY+pO4EQNt9k2mr7fiFOzTFmjMF6JxFEeLO9dfrp360AZjWuk2
         WM/2J9KM1s4UG2DlvfSzbevVdp2haZqGRReWaBaz3znm6QsyDy5FuPIo3ax6sFw1EtC/
         uUlbOVpEuJAKiH1frU+TCp/j6DSdyIUyNRm69nsKXseHA9PkF2r3j7zM2AuSclbWZLhI
         Cj/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DMyvAeQA+roH6QmvmBTq9U6orvkizk9snH0AehNjYoY=;
        b=Uzp2iNA8rLbePGHdfWK3KU8q6CeTjE/Io/tlsK66w6rRFRpqGDwwPeTaam7RJsBswm
         kOcCW/9DTkex/ss076VU6N4z+3TL6lgjIEdE99tzvo8p1U6WCHh7WNLk2ju2ry1HiYI1
         Yw8gi0Ie4O4jwiekH+Br85+35smnvD1ls0ZF+QuTXlboMS+FSd13UO70CytSc9i76PAk
         2APU+Akny6jttrukOL1tCaR8xo8Wu4R+Iwfs06rMKXtERUzrJbJCo22gi+kZKc8YYZWo
         XILbrfabLT/dj9wBYNS/yjkw528x0u0nemdUryERpeyONercs2Z1WYoWcmendYuroyXV
         VPhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XpLWeHmL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=DMyvAeQA+roH6QmvmBTq9U6orvkizk9snH0AehNjYoY=;
        b=l2Ttxkkuczuy8B0YWL/JPwpJxR1ENyo5JQHQsVoBzLtbAD/PQdJhpnHKBhBrK87jqn
         qLm2tCLtzfDcyKPkkhixku4Wm8Yj/Adasi/zQiEzsNlJKlmEVtDv1gG9kmbjh7wB4UYR
         cYwihjjegwt5Cwifqjc2VkIp+2uWzKl0sSbiNxCHnDYlOpsRgA5xWMeJBK3s+KX/2Kii
         OJ9b5Sv2bJCcrxKu42WuXZlrYLcMnUFHFk0GrAbkSRfF/1pOOKRGgv9F/Vl3S3YNZ2YY
         L2/vPZNH8RPjkgN90JBg7XSs1rMDbQdXVSRtGHFA0xbxDLfKsH5eRfvNRFsxu5rcjH7Y
         Y54w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=DMyvAeQA+roH6QmvmBTq9U6orvkizk9snH0AehNjYoY=;
        b=gT5KwRN4cH4iHkDo/8ROUS3VNMhmwUL7UDAeWkdl65/ZI/tePXdlM1e5oH7NsG9n/N
         qC0efJ7kway5Nmv78A408Bz7Z1HKLqqM9tSWZSjlNAZyIYWJJjyvICqN1c4BQzC6mOrl
         jdEtIBWuBkndALr9nZdoxQDOVSsDo3P2qgug1FOe9HICjt6hmxL/Yd1VuCZrQlHpDYIa
         TvnM1o0JPQvhaJsBnB2SmNaYrCphBZgEKBH3ckS73cdxP5JHW3RK/qb9evXuVbr7aOyZ
         N6ZbohUAzUCGFMdn8bcIQjKIZqZnVPtT6zdK9S6D0QPuu02cRPxJ6M7n+L+4z0bb6f6y
         oFJA==
X-Gm-Message-State: ACgBeo0Mg7NF+egPXUtI6v258rZI0K7RJsaqzPZKlpkDQJWSArHo7HE/
	2V5r30tqpEbz+izRf1WKEIQ=
X-Google-Smtp-Source: AA6agR6pkoovEwJhjKgBZfT6yj3yV5OWSDV5FCEEvwcYLfLGZfL0pWM86b9chNz4sj1p/+EFIgfLWg==
X-Received: by 2002:a25:8b8c:0:b0:67b:5c18:870 with SMTP id j12-20020a258b8c000000b0067b5c180870mr13007394ybl.244.1659893650927;
        Sun, 07 Aug 2022 10:34:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:1297:0:b0:31f:56e8:aa58 with SMTP id 145-20020a811297000000b0031f56e8aa58ls4421422yws.9.-pod-prod-gmail;
 Sun, 07 Aug 2022 10:34:10 -0700 (PDT)
X-Received: by 2002:a81:ae55:0:b0:31f:6630:9736 with SMTP id g21-20020a81ae55000000b0031f66309736mr14989823ywk.346.1659893650426;
        Sun, 07 Aug 2022 10:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659893650; cv=none;
        d=google.com; s=arc-20160816;
        b=bvHvrnnH4G9EI3m0ourc9w3R7eVz7I0D58Mx/B0DKpJvoSDuA80cx/T5ZKMSMffasG
         HuJtTy5bneoI6fqrAke64VJIH30tOFfAUmgpmiNM+Km9Gr+fO31ycFWxyX/H5AAQSv/S
         FDgyu0Ie2BciJdn504SMFU5t8A4jcny80nR53q9LxAX5+v9yef7mvWmYaZnCIjn7Mpix
         h/j9A/3W20CxpTtxNMS35RK38G34yIiwXj+R6oze/eFPanGCxsFhGPSVSUl5cnvKZmZJ
         xyEjCmo2I7gCtF56wlVy3bCmgUfoGlx0Z07ZH/KJJERkuBF566Q/xJP/lUzVjheL5zYi
         x+1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aS6EBaNIN10+OZPUpR/4ogKAkoJ9rFIL98FCoXlnNSA=;
        b=rz7SmMhygj+Wl+OKp8tM1D3Pp3dA8oTWhhMcCJQuHZfjz1kJQqiH5dVGDxmgVHPjfi
         A0ofO0xOEQ/FgHlQ1QPboVRLyM6TQWfttAj6WBHO3e2xCJHihKD5JAsgbygChY2rf15V
         /bpr3isylZ3PpHl05eVMk0s+C87cYq+xbXtHGxnpWyCYHhi0+t4ZPz00HL6eqJgOWZlt
         BiYQwjSJNeR200/SYdwo2lYRwymoAao0hxe+QzEGWtItrupKV+dRCyNxx7pj8WisU4ne
         QAfW1d8vo0ScweTYx5MoMb51LeTH/1uC5WdJSAdtGjbhRn/QWPKDkzArFXHQmwBeMpiS
         iEpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XpLWeHmL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id r198-20020a0de8cf000000b00326d475396csi940360ywe.0.2022.08.07.10.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Aug 2022 10:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-32269d60830so61717927b3.2
        for <kasan-dev@googlegroups.com>; Sun, 07 Aug 2022 10:34:10 -0700 (PDT)
X-Received: by 2002:a0d:c7c3:0:b0:31e:9622:c4f6 with SMTP id
 j186-20020a0dc7c3000000b0031e9622c4f6mr14640035ywd.144.1659893650000; Sun, 07
 Aug 2022 10:34:10 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-5-glider@google.com>
 <CANpmjNN28k3B1-nX=gtdJxZ4MS=bF+CuPG1EFp5fC2TDQUU=4Q@mail.gmail.com>
In-Reply-To: <CANpmjNN28k3B1-nX=gtdJxZ4MS=bF+CuPG1EFp5fC2TDQUU=4Q@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 7 Aug 2022 19:33:33 +0200
Message-ID: <CAG_fn=UQ2g9KjixL4Hsbw04r75VB2bp_X7F3RzE4twDro+Xi_Q@mail.gmail.com>
Subject: Re: [PATCH v4 04/45] x86: asm: instrument usercopy in get_user() and __put_user_size()
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
 header.i=@google.com header.s=20210112 header.b=XpLWeHmL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133
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

On Thu, Jul 7, 2022 at 12:13 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > Use hooks from instrumented.h to notify bug detection tools about
> > usercopy events in get_user() and put_user_size().
> >
> > It's still unclear how to instrument put_user(), which assumes that
> > instrumentation code doesn't clobber RAX.
>
> do_put_user_call() has a comment about KASAN clobbering %ax, doesn't
> this also apply to KMSAN? If not, could we have a <asm/instrumented.h>
> that provides helpers to push registers on the stack and pop them back
> on return?

In fact, yes, it is rather simple to not clobber %ax.
A more important aspect of instrumenting get_user()/put_user() is to
always evaluate `x` and `ptr` only once, because sometimes these
macros get called like `put_user(v, sp++)`.
I might have confused the effects of evaluating sp++ twice with some
register clobbering.

> Also it seems the test robot complained about this patch.
Will fix in v5.
>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1=
859fdf5cc485a2fce
> > ---
> >  arch/x86/include/asm/uaccess.h | 7 +++++++
> >  1 file changed, 7 insertions(+)
> >
> > diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uacc=
ess.h
> > index 913e593a3b45f..1a8b5a234474f 100644
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
> > @@ -99,11 +100,13 @@ extern int __get_user_bad(void);
> >         int __ret_gu;                                                  =
 \
> >         register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);           =
 \
> >         __chk_user_ptr(ptr);                                           =
 \
> > +       instrument_copy_from_user_before((void *)&(x), ptr, sizeof(*(pt=
r))); \
> >         asm volatile("call __" #fn "_%P4"                              =
 \
> >                      : "=3Da" (__ret_gu), "=3Dr" (__val_gu),           =
     \
> >                         ASM_CALL_CONSTRAINT                            =
 \
> >                      : "0" (ptr), "i" (sizeof(*(ptr))));               =
 \
> >         (x) =3D (__force __typeof__(*(ptr))) __val_gu;                 =
   \
> > +       instrument_copy_from_user_after((void *)&(x), ptr, sizeof(*(ptr=
)), 0); \
> >         __builtin_expect(__ret_gu, 0);                                 =
 \
> >  })
> >
> > @@ -248,7 +251,9 @@ extern void __put_user_nocheck_8(void);
> >
> >  #define __put_user_size(x, ptr, size, label)                          =
 \
> >  do {                                                                  =
 \
> > +       __typeof__(*(ptr)) __pus_val =3D x;                            =
   \
> >         __chk_user_ptr(ptr);                                           =
 \
> > +       instrument_copy_to_user(ptr, &(__pus_val), size);              =
 \
> >         switch (size) {                                                =
 \
> >         case 1:                                                        =
 \
> >                 __put_user_goto(x, ptr, "b", "iq", label);             =
 \
> > @@ -286,6 +291,7 @@ do {                                               =
                         \
> >  #define __get_user_size(x, ptr, size, label)                          =
 \
> >  do {                                                                  =
 \
> >         __chk_user_ptr(ptr);                                           =
 \
> > +       instrument_copy_from_user_before((void *)&(x), ptr, size);     =
 \
> >         switch (size) {                                                =
 \
> >         case 1: {                                                      =
 \
> >                 unsigned char x_u8__;                                  =
 \
> > @@ -305,6 +311,7 @@ do {                                               =
                         \
> >         default:                                                       =
 \
> >                 (x) =3D __get_user_bad();                              =
   \
> >         }                                                              =
 \
> > +       instrument_copy_from_user_after((void *)&(x), ptr, size, 0);   =
 \
> >  } while (0)
> >
> >  #define __get_user_asm(x, addr, itype, ltype, label)                  =
 \
> > --
> > 2.37.0.rc0.161.g10f37bed90-goog
> >



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
kasan-dev/CAG_fn%3DUQ2g9KjixL4Hsbw04r75VB2bp_X7F3RzE4twDro%2BXi_Q%40mail.gm=
ail.com.
