Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUM4YCJQMGQENKJ27SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 71CCC517542
	for <lists+kasan-dev@lfdr.de>; Mon,  2 May 2022 19:01:06 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id x10-20020ac8700a000000b002c3ef8fc44csf11372438qtm.8
        for <lists+kasan-dev@lfdr.de>; Mon, 02 May 2022 10:01:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651510865; cv=pass;
        d=google.com; s=arc-20160816;
        b=cCDuWRcTK84N/cAssx/gA5Icf4SdnVFZ2B1qwmbtHkM1K3gc4Tr1Qa5vX3bpwVCujv
         lg7hry/8VUoTMO7tq6qRTNcic93Id7pPd1ltcOHgK+xbuZNAcamo555TPhcMy5i/ca7R
         JyYOB4BPjo+TFVn+Y3YVCDx7t6Z5ppQoSK7bYV2uanG2TpAtbFDkjTeVcsIsVTrOpiwh
         d+1ahJPk55tCT9Y94gJ4aBjcPZZPKv7XitzJ3N40xa7jW6LRy6e4WM0jw/sxr1/wKy/c
         I3rBAZ9nB070VE3733Nv/XYgRuVb6vHu+g0QsZcbBIx7D3D5mcfo4pBt1k+987Eb6g23
         mT2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kw/oT8LRzfVqJue3Mn0A8I5dv4lJMZBPKn0OaVzJQKo=;
        b=v9FMmLKWQ3xX8U7UFdAyHvDmKhiFron3ScNU0QMg+LBoel5A376YfKNvzdN1FjTRfb
         1OJ7l0dv5J5jH50VozOP+iteF62g7vZm9iyuKBwofJJbsxX4TYqaOPMFDU7GKI35NKGO
         +8VtMFE5XHhgCNHJv1Ny4IXXcof+kRQcfmwFkZvqkttU9i0vCjVlj2o74x7jNIBWommb
         pNSEFNx211Zfag2SobC7u4LUM4zsiGbCUFu3jpIXs30A46oaEcQssVv9409hKbYoo/hi
         /P83sErFXi4NZnFhUguWSclg3O2U2mdjQMZEjaj5DGULf57G8PjNQm1SfEIo46BTx92O
         h19g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JgdYu4i8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=kw/oT8LRzfVqJue3Mn0A8I5dv4lJMZBPKn0OaVzJQKo=;
        b=VCAUaOtPJMGrRjQ+PT/wxGhkjExCCpTew70jEwJrJnVIFuvXUzMNniliI4FcKOuBZa
         EDbonaNNllxg/Ms5TGrS728B18zVOsf6gc4XMnNVgzBgjLSmqmn+tO5lmNq6gM2T9uGO
         SKC2akaQOkPVZxBziZsthMD0l9+vGDtz1tHoHhsEBG3PDszIRvUmB8xzke5YC663Dnx1
         4qm2e1EXpZujYYrpxPk+ear6CyeZsBy2VU206z9tqWp/yULMe8klA/Z5rSZBGpw73o4+
         NBv5ThjK9CxPmWDeDtqqlgUGY5kfIEYDpE8AFhxv3Po2vnIr5+ox3ghL3StJRimzwwAx
         Uplg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kw/oT8LRzfVqJue3Mn0A8I5dv4lJMZBPKn0OaVzJQKo=;
        b=lcehPRrAiPoq75GCBGCOHLeXf9cGOthccPAUTEinTZsT8x2cC40TmoDLqHj64vwWiu
         6ZFvMZK1PN0HhEIgNLrcKp3ia8zxUndp+1bWDhcOfAiFWjZGXKId/RndDqr55IkhMIV2
         PtJQbo+7EBGKSxA81/aymjcadAPAvuxSbjJtLJntd1DpInwjFDKOzEPxc1ZBkLc8nUK2
         wjs8ilQYgUPbDyFHo/KckigQ61/gSs5ssuJqSXKvH+6laMWSBXgkRRXLefQ/HUUaXIJp
         fCx618ot/myzSeGOddXtbfOvczC+na43C5mNLDazxsMX/zmskNTRcZFXta9SpQOfClBk
         Oh7A==
X-Gm-Message-State: AOAM532GSjUXUQpdWODBwhpZjuIjeGzaT+SP0GAvfq3nfvwQ/MBtvhyC
	JpxcuL8RPqxZGrlQ5hgVXys=
X-Google-Smtp-Source: ABdhPJzVizzGFSfiFXArLJT2xRuek8dB/1Q76ACbUgz5w3F76rgCWLTMyr59q1mfhlo9d2XN/neeow==
X-Received: by 2002:a05:620a:795:b0:69f:d074:6067 with SMTP id 21-20020a05620a079500b0069fd0746067mr5900892qka.527.1651510865228;
        Mon, 02 May 2022 10:01:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3005:b0:443:e715:9e9f with SMTP id
 ke5-20020a056214300500b00443e7159e9fls4850127qvb.6.gmail; Mon, 02 May 2022
 10:01:04 -0700 (PDT)
X-Received: by 2002:ad4:4f26:0:b0:456:3800:7b76 with SMTP id fc6-20020ad44f26000000b0045638007b76mr10424415qvb.106.1651510864720;
        Mon, 02 May 2022 10:01:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651510864; cv=none;
        d=google.com; s=arc-20160816;
        b=O1upsxa51IPXvc+Yzk7msJ83qdSgFwUHlNND/DU+XkwDAWwasY7DCSGcLcJhJK+u4+
         nSV716PjInk8ogRrgZXhKE/orM37t/nSswm9ziln+I2UV8Ph934mfqfqntktRD6JlFpg
         sSCSblzHm5o8JvveyLI0WmkoZsCWSRV92/zqN/sJvH9FEDJMQnt3Ny457Krs8gvAJbyO
         xpJ5QMTRU/mvmN3NcaC48iNdQPhkuLe/8yRyq3sw1X3pWLvlBe5pcuVS3iSZaw0TuYRZ
         2kiBcgE8WhWmidUKKyEissN7WLFKbhYRb8KgFdzQpDmBRclLiFGFNcUcOjTo01I5Uezu
         KrPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZDNXgBhMz20++Q4yigO612T0eYygF7r9J92FIVtim7Y=;
        b=d2J/XK1qWKniTy9gqdhGZ43nH3uAQWD2fwzG9aZnsTMznYVCGMwkXSq33OaHnVhLgd
         HO3efp3DSgdTT08E3eK1+EAfZAp5wtGkzJCWFO40IqIHsOvGcynjWliyM7yIoLfP0Xm7
         OFUQ8w71+GXCT+oapB/SAbt33uZ1VQ0d/+ziWCkNJTO2vVG7xGWCbeb6/jh/WZvFz6aI
         yA7+aV7hRNVhOmCnEB4lR1qSdi6RWXQ6uXuBtJqFAJ6nYZe0oHxDvoIEwZb3woIl2Exm
         FGV0+0G1KRgVs+c0V7NdRTLtng5zvbn8fYm0xbdlIfirKnfc35uMLqDh9J+hkX0RNeyY
         e2GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JgdYu4i8;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id x6-20020ac86b46000000b002eba0cb25f3si1039664qts.4.2022.05.02.10.01.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 May 2022 10:01:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-2f7d621d1caso154226387b3.11
        for <kasan-dev@googlegroups.com>; Mon, 02 May 2022 10:01:04 -0700 (PDT)
X-Received: by 2002:a81:1f8b:0:b0:2f8:5846:445e with SMTP id
 f133-20020a811f8b000000b002f85846445emr11776773ywf.50.1651510864112; Mon, 02
 May 2022 10:01:04 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx>
In-Reply-To: <87a6c6y7mg.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 May 2022 19:00:28 +0200
Message-ID: <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
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
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JgdYu4i8;       spf=pass
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

On Wed, Apr 27, 2022 at 3:32 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Tue, Apr 26 2022 at 18:42, Alexander Potapenko wrote:
>
> Can you please use 'entry:' as prefix. Slapping kmsan in front of
> everything does not really make sense.
Sure, will do.

> > Replace instrumentation_begin()       with instrumentation_begin_with_r=
egs()
> > to let KMSAN handle the non-instrumented code and unpoison pt_regs
> > passed from the instrumented part.
>
> That should be:
>
>      from the non-instrumented part
> or
>      passed to the instrumented part
>
> right?

That should be "from the non-instrumented part", you are right.

> > --- a/kernel/entry/common.c
> > +++ b/kernel/entry/common.c
> > @@ -23,7 +23,7 @@ static __always_inline void __enter_from_user_mode(st=
ruct pt_regs *regs)
> >       CT_WARN_ON(ct_state() !=3D CONTEXT_USER);
> >       user_exit_irqoff();
> >
> > -     instrumentation_begin();
> > +     instrumentation_begin_with_regs(regs);
>
> I can see what you are trying to do, but this will end up doing the same
> thing over and over. Let's just look at a syscall.
>
> __visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
> {
>         ...
>         nr =3D syscall_enter_from_user_mode(regs, nr)
>
>                 __enter_from_user_mode(regs)
>                         .....
>                         instrumentation_begin_with_regs(regs);
>                         ....
>
>                 instrumentation_begin_with_regs(regs);
>                 ....
>
>         instrumentation_begin_with_regs(regs);
>
>         if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr =
!=3D -1) {
>                 /* Invalid system call, but still a system call. */
>                 regs->ax =3D __x64_sys_ni_syscall(regs);
>         }
>
>         instrumentation_end();
>
>         syscall_exit_to_user_mode(regs);
>                 instrumentation_begin_with_regs(regs);
>                 __syscall_exit_to_user_mode_work(regs);
>         instrumentation_end();
>         __exit_to_user_mode();
>
> That means you memset state four times and unpoison regs four times. I'm
> not sure whether that's desired.

Regarding the regs, you are right. It should be enough to unpoison the
regs at idtentry prologue instead.
I tried that initially, but IIRC it required patching each of the
DEFINE_IDTENTRY_XXX macros, which already use instrumentation_begin().
This decision can probably be revisited.

As for the state, what we are doing here is still not enough, although
it appears to work.

Every time an instrumented function calls another function, it sets up
the metadata for the function arguments in the per-task struct
kmsan_context_state.
Similarly, every instrumented function expects its caller to put the
metadata into that structure.
Now, if a non-instrumented function (e.g. every `noinstr` function)
calls an instrumented one (which happens inside the
instrumentation_begin()/instrumentation_end() region), nobody sets up
the state for that instrumented function, so it may report false
positives when accessing its arguments, if there are leftover poisoned
values in the state.

To overcome this problem, ideally we need to wipe kmsan_context_state
every time a call from the non-instrumented function occurs.
But this cannot be done automatically exactly because we cannot
instrument the named function :)

We therefore apply an approximation, wiping the state at the point of
the first transition between instrumented and non-instrumented code.
Because poison values are generally rare, and instrumented regions
tend to be short, it is unlikely that further calls from the same
non-instrumented function will result in false positives.
Yet it is not completely impossible, so wiping the state for the
second/third etc. time won't hurt.

>
> instrumentation_begin()/end() are not really suitable IMO. They were
> added to allow objtool to validate that nothing escapes into
> instrumentable code unless annotated accordingly.

An alternative to this would be adding some extra code unpoisoning the
state to every non-instrumented function that contains an instrumented
region.
That code would have to precede the first instrumentation_begin()
anyway, so I thought it would be reasonable to piggyback on the
existing annotation.

>
> Thanks,
>
>         tglx



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by
mistake, please don't forward it to anyone else, please erase all
copies and attachments, and please let me know that it has gone to the
wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ%40mail.gmai=
l.com.
