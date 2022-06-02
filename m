Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFN24KKAMGQE2DWMA7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id ED83253B7AE
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jun 2022 13:20:55 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-f2db7440d8sf2881941fac.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jun 2022 04:20:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654168854; cv=pass;
        d=google.com; s=arc-20160816;
        b=W5PWfw5jiRg1nB1DaqkNPqWhKBW/gyQaLG6YM7g4h0zaA4OtBxGSzPspWwWhNZ8mU/
         IpRtZa/CIRD9pMQgIYa/jrNY7UqoQhfQzZZHyHetTJtQzUFqTFoyAHWjXyAXBNgy2nwC
         749z0h5szytKXNOyqrDAo6+QqH50xrveJzY+zIptZo0mCNEe2ggPnQWxjdiKs/l19GqG
         /+Erj/X5Jdl5baUJsGlaVDTMzYKH8yG8GxYAlnWdyOD+UDjauWAb3DstdSanvIJB7lc0
         95NEbtm/MMogb/OZdQd6bqHaPcCXZbhkTh08/z7iToeAGnZzrHpW9eWWO+fxy2pTe0yW
         VdZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aVOyTrcSigFr56vWWVoxbVBEIweZZnc2LAPTODU7ESY=;
        b=LjngCmXl0Qbw9CtuNafO7q8+HUhxSizJXdiNOcdtM4ZEWPjzBXTKNyt8CbEvNoKDgL
         xpkmwp/BQSf2u3SomoSt+Prl8tSCQwjkAy7z756etFWy9nl9fxnprqyABDUtp1HuiODX
         kY442U+clqMYv9Y4e9NF+/l4e2AgKZwd25FVtxSSfvlxWTLne2dYvnokmyMy78VwLbpB
         HQNabrxsxNCxpxAyEcnS4UOK+le+S5OK4j9Tbs7M3u72cDL5aLgrxtUq4a/OlWs8QObC
         yAodpASDG97+QzuD1aMMRZvOsJWUy7a1leO+CzJ9s2cx5N4I5oL02ZSD6DHr3Tngnvv8
         8Fjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=m0OEpK59;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aVOyTrcSigFr56vWWVoxbVBEIweZZnc2LAPTODU7ESY=;
        b=LOoNW8WxugTfMzGW4q8i/WTMp0TDuBqN/mipH2CkPKRmirLTJco5kvW2Qn2fxfc89D
         +2H6kzJi20UKofiEkq8GQ4bl9Rryo5inkNXAMYL9NzuKN3ORYO+GnwsapxXGz9HUUX0V
         +e24egoOCKQnwrU4EuIG7WembPlTZm7lfmp0gcXyt28aXa4fYZIJL+Y7fCNDH1duhZAQ
         6j/VrvzcbUqjnyf8pBkBio8GZfT+hiVmpmvFzrQuO2eZd8P2CpmollvZGJavo6DEwgUc
         aS/PEcftY5uq5nMR9TPW0K5O6BeeTK0VN1wXqzNWEkoykFUx6jvaFcVP6sXeME1By4HD
         WSJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aVOyTrcSigFr56vWWVoxbVBEIweZZnc2LAPTODU7ESY=;
        b=0Ep9j3f0eEA6ZFzzsNJ6cUPPyixQ+HYddTWF9tK6V48HK/nf8pX2AfSWDiZVOoskMR
         808anREMfqPuO/A/tMkNInPdCRCgOO2lBIjACxUe81t33QeB3aTjyqfBAm/2gqUF8UdB
         dlbSs44+RYwvPu1ZJEDPsF5IxGZ8gYQCjVY8QntrZP2lUH0LIHkJk1N6Al53Aq0qt8Cq
         +HnQ969d2oWmpXkDOIHWyzeaOmJioJaWEwgiJcAYIDoijCxbfsjhaDMcPQxlQRdkcUVN
         s3Nzb4jnkFskN7KHSK/otmfPSIERVJ0tDlaD5yHdtvAj09GbmSd5nKL9zqRdDYXT+YCS
         MUtA==
X-Gm-Message-State: AOAM532SV88hFEa3zV0dsuez5D+PZ7TEyeydrthjDu5/vcnEL2iQLjlo
	nRhGsevC8WzYTD8GG9qg6So=
X-Google-Smtp-Source: ABdhPJx0CKzrqIEQXtYc1nt7WSijL7Gno3QXhRBH7paBLqWZ3CC3Py8xSYYBDsn5bkKyZfhp10ZBIQ==
X-Received: by 2002:a05:6808:347:b0:32b:b968:6ff8 with SMTP id j7-20020a056808034700b0032bb9686ff8mr2199759oie.243.1654168853341;
        Thu, 02 Jun 2022 04:20:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a1a0:b0:d7:1d2b:ec1a with SMTP id
 a32-20020a056870a1a000b000d71d2bec1als2581088oaf.3.gmail; Thu, 02 Jun 2022
 04:20:53 -0700 (PDT)
X-Received: by 2002:a05:6870:355:b0:f3:14f4:dd0 with SMTP id n21-20020a056870035500b000f314f40dd0mr2389156oaf.258.1654168852968;
        Thu, 02 Jun 2022 04:20:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654168852; cv=none;
        d=google.com; s=arc-20160816;
        b=Ra586uf9M1iLbX0I1xnZDYLlWNQ0FIcYEReOjulEgormuQ12bhLtkim8h8CocNylG5
         xNuXWbTeVI1WjXW+xBM4+GnaP5drRzwBAznszT4zELAgfjpchYYU+tr4a8Xs5LIo7mej
         QoN4F0C53sZguD0zoOYQb/G/LZ87rzLD7YMG+Q7BrsmUePKskW6ZG24xnIGXUlV28soW
         0eJUVUXyWgFaXcpkIwbb4woYLiS9GoW0Ruin53/SSDb6rAJpmRPY0YBvQCyN1LljxyRh
         U76KXuXJj7xHjgS8RBYtY54nJp9wq2hJ/4twsgNQIV1kL8Qpf/fF/HVxT8pK8YEKcW9+
         CD0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6r6Vaw+wZvpxvKWw2pORFiU+DbCU4N7wdhOQeTbklfc=;
        b=f1b0i1HtHUZjIVLE/p9BnYlJjz93A3wncDpIFKKVAsV0+mVg+WtDqtI86V+a+43Gc/
         ZF6ObUoXDHuRpk+6MNj20b+XPtyRMyyMtrfFVIefvVrCKqMlY+x43ebD08F5ZiraSYGt
         Ixtzj+ewJkE/6ZDx2GVkbnShhVq+BVnfR1OecUAmemLxPpmqc2EDPQmoGNuzMukd9NBn
         RLV3bx/gS+6zAr/DDlkW/e2Y3yYX6RO4JdyI3trDJgaxA7qYBNG4vLvwquSZB8EIyW0K
         ULwVzukyRiHLImZKuDXkej1wQNtZLw2/pqzs6pWNSMqvuI5lKMpJ3yh2bawu4wAgK7Qi
         qOyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=m0OEpK59;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id e1-20020a4a9b41000000b0035e8a81e5fcsi325463ook.2.2022.06.02.04.20.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Jun 2022 04:20:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id v22so7746105ybd.5
        for <kasan-dev@googlegroups.com>; Thu, 02 Jun 2022 04:20:52 -0700 (PDT)
X-Received: by 2002:a5b:4c7:0:b0:65d:313:6270 with SMTP id u7-20020a5b04c7000000b0065d03136270mr4614359ybp.363.1654168852326;
 Thu, 02 Jun 2022 04:20:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-6-glider@google.com>
 <CAK8P3a2eDDAAQ8RiQi0B+Jk4KvGeMk+pe78RB+bB9qwTTyhuag@mail.gmail.com>
In-Reply-To: <CAK8P3a2eDDAAQ8RiQi0B+Jk4KvGeMk+pe78RB+bB9qwTTyhuag@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Jun 2022 13:20:16 +0200
Message-ID: <CAG_fn=X601D5RtbkOMjZEKL+ZyQZG5Ddw7Uv=MOivbceAxPBAg@mail.gmail.com>
Subject: Re: [PATCH v3 05/46] x86: asm: instrument usercopy in get_user() and __put_user_size()
To: Arnd Bergmann <arnd@arndb.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=m0OEpK59;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as
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

On Wed, Apr 27, 2022 at 9:15 AM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Tue, Apr 26, 2022 at 6:42 PM Alexander Potapenko <glider@google.com> w=
rote:
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
>
> Isn't "ptr" the original pointer here? I think what happened with the
> reported warning is that you get one output line for every instance this
> is used in. There should probably be a
>
>       __auto_type __ptr =3D (ptr);
>
> at the beginning of the macro to ensure that 'ptr' is only evaluated once=
.
>
> >>> arch/x86/kernel/signal.c:360:9: sparse: sparse: incorrect type in arg=
ument 1 (different address spaces) @@     expected void [noderef] __user *t=
o @@     got unsigned long long [usertype] * @@
>
> It would also make sense to add the missing __user annotation in this lin=
e, but
> I suspect there are others like it in drivers.
>
>       Arnd

I ran sparse locally, and it is actually the missing __user
annotations in signal.c that cause these reports.

The following patch:

diff --git a/arch/x86/kernel/signal.c b/arch/x86/kernel/signal.c
index e439eb14325fa..68537dbffa545 100644
--- a/arch/x86/kernel/signal.c
+++ b/arch/x86/kernel/signal.c
@@ -355,7 +355,7 @@ __setup_frame(int sig, struct ksignal *ksig, sigset_t *=
set,
         * reasons and because gdb uses it as a signature to notice
         * signal handler stack frames.
         */
-       unsafe_put_user(*((u64 *)&retcode), (u64 *)frame->retcode, Efault);
+       unsafe_put_user(*((u64 *)&retcode), (__user u64
*)frame->retcode, Efault);
        user_access_end();

        /* Set up registers for signal handler */
@@ -415,7 +415,7 @@ static int __setup_rt_frame(int sig, struct ksignal *ks=
ig,
         * reasons and because gdb uses it as a signature to notice
         * signal handler stack frames.
         */
-       unsafe_put_user(*((u64 *)&rt_retcode), (u64 *)frame->retcode, Efaul=
t);
+       unsafe_put_user(*((u64 *)&rt_retcode), (__user u64
*)frame->retcode, Efault);
        unsafe_put_sigcontext(&frame->uc.uc_mcontext, fp, regs, set, Efault=
);
        unsafe_put_sigmask(set, frame, Efault);
        user_access_end();

appears to fix sparse warnings.



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
kasan-dev/CAG_fn%3DX601D5RtbkOMjZEKL%2BZyQZG5Ddw7Uv%3DMOivbceAxPBAg%40mail.=
gmail.com.
