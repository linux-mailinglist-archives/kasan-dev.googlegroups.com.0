Return-Path: <kasan-dev+bncBCCMH5WKTMGRB57IVKLQMGQEMMUMB4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C2A5F5891B3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 19:46:33 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id k9-20020aa79729000000b0052d4dd3e2aesf4029820pfg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 10:46:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659548792; cv=pass;
        d=google.com; s=arc-20160816;
        b=fmcpiFa7SbMIInW4MTDa2WfJGx8WySJjPL0kU7pQJv8oFXpuXnpe7mu/sqAOviI7Ub
         vPv1ZaK9kw3yovmfwzXCYrA77vHpnRN2aoMZu+ZMJN2qYISEYtK56sr5ZOXNNvTJlaIN
         IqRLyIjWDgRyaxeCA+o1reb2QCJptDPM3CbuAZ5qJBY1E8qvcbWR9uQizHi/IhNbmKou
         UzDCO3Vz5I9l2LNaJlpLfKWUb5xDwNGjZTuc18ZxLCUlUalhM6OSujRuzIAF2aMfpmOy
         YKPKRXp+zC4llyB5W3MR3qGriM48xV5cDa+6nDUAqgj02huHz6sUsrEIDXVeaAu+V/tN
         e0Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KHeh66e6ujgUpn2+2PHfceeVZ4GhHnpy2w52EtsWGx8=;
        b=viyhH84yp9DCdbtmX0lPBOyTr2vQxm+8K4TsJMRvuhXqO0aOmzkMff8oMcYKNYZOKu
         7o1DyhvEfTWRk4djaq9kTjTvmRl9tty5qDQ1UJW9Fyeqszc543tabSIjvdfFtU5gysHG
         CBb4B+FuBWPu4CPyJ6SWntYnCy2r1YTfWTyeCXF3vVNIiJeuHSs0TNMYGSJTf4JFCjYv
         HIzvKuQ6BC2DSpAFlLzuOT+MQDrOYr60/TIkI95w3ympsmAuHiI+xbjAdX1VNlftRmsj
         /IYT13CAeAC6svnuo5hSvd18+cPOgwTeb4/OnIKb0gLhn+00bx/pv/TZYdQ5DedQ92K/
         NKQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ECfvFXHN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KHeh66e6ujgUpn2+2PHfceeVZ4GhHnpy2w52EtsWGx8=;
        b=qQ5sZZayT192qCdyqOtgQ8NNY9Zz5I1qm/vXLKy1UmCKQCHC+k4XYT1sK4TxcJpXNg
         +ScQxjJf4GksoZwl9MHb6JznmtXZcXsX4FbExJqcwGuMwmHIf9dOowf4WZ3IEKM06Fyt
         QuszQ/HtyP+rvkaAs734675St9EE2+S/SZ/YVvvtzb2xxwDyp+48/p4bgZWJ6s1cZ+lp
         oqrqgRLTFq/xB93tErtbN4/In8WNEzD/p4whH9PCFoMvTCRYV/7rqzvzrvP/zj0p20Ma
         ShxmbwxlkiYT5zcMSRpl7yhSwzFueN2wvY/I+JmrPPS7JUCVsEz0ho1eseX/tqXh2GJJ
         cRdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KHeh66e6ujgUpn2+2PHfceeVZ4GhHnpy2w52EtsWGx8=;
        b=1Awg4PFniyHCUpIP/TyaYjc7SO+YFKGZOcjkByW2V5DFZbpyWTVdsj3TdM58rmwi0j
         aMMgAJSbSEuR5cp5i6SH7f3L/XL67bxMC9MxKQNFt+2lX9zPdklZrn6Mw4vXqnW52H69
         UZllWZHiv82BmZP4HrcyXv6AofCq/qIYYnQj93geUsqNCPZEXdO//gQeKoZbpBiLyC5f
         f9KUOHyInA9y/XZCyZpz1Rzz3nqk0MQ2GyMKRHYwaE1R28pMD9pW+Eg2lL2NMGLsnA16
         SZ3v5dAksiRxGZzp6KlMQaajAck+C4ZZLJZiZSexhcg11bhcfair5Ksv0ZNqRMCMoaKo
         OQlA==
X-Gm-Message-State: AJIora85Vvkn+yiqvZGph4cj6mDtkaTor2+DA+dhGNsf4oHYDmGOlkVe
	WuRBEj6h3MYXJdzoz4jnqTw=
X-Google-Smtp-Source: AGRyM1sZc2G0K8ZB58Su4EbN/V8dMRiCT4s8TVPLXxXwI7K+HHiSAtunp6VPwSq/SVHm1RloOjqKgQ==
X-Received: by 2002:a63:1a09:0:b0:415:fa9a:ae57 with SMTP id a9-20020a631a09000000b00415fa9aae57mr21429261pga.181.1659548791988;
        Wed, 03 Aug 2022 10:46:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:44:0:b0:41a:4df2:872a with SMTP id 65-20020a630044000000b0041a4df2872als5904729pga.3.-pod-prod-gmail;
 Wed, 03 Aug 2022 10:46:31 -0700 (PDT)
X-Received: by 2002:a62:cec9:0:b0:52d:414b:c70f with SMTP id y192-20020a62cec9000000b0052d414bc70fmr18143105pfg.20.1659548791222;
        Wed, 03 Aug 2022 10:46:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659548791; cv=none;
        d=google.com; s=arc-20160816;
        b=Qj/iutfOKMO81/giKYzIosBQ/rw8m6qcaio20qZZL83bTh87Ej6GW27lQya/zKRYPC
         Q5A5mkoXVea6hkg2zINuE6QvLBrVJfSQv/sD+UXVjGEsoAyveyhIZ85lfXRv4FC3Megg
         Y1oLkReMZN02cEm26YtW1onquRcnksoeBb5MbK8ahQj4zd1aG28WtXL77Edv4IZ25PB1
         RCLFRuwMYvjMRPKuV3UJydjRQrDFrYeux065XLjIbWJXpKxnQUE0Sy+og4s6OvItQRiH
         pWTBA8yGYRjvDiWUE0BC5H6RF0LT+uIGR/oaCylSpg6Cu51oYzU3bU8UES7zbRXRDS2V
         To6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kVM/3uyhal6qaeACSB8divgbMh2p6Q9rmvW6JHSngAY=;
        b=TR0rzsl3IC5HcPUyab1/rlfyPPiMVRgXWadJjsoD3bG3fIeSHw67A8zEMqtNHEDPLW
         wK0dBGRx28rI2Dt3loPyOtXjeOhuaRW5ecg8Is3u2VesaBsWRZjjkJVv/ChB7JPmijRA
         tgoCnByoMO3hLv5jJdepYPCw1bo85Ik84Ns0abkKAWtTFGb4FaEx+sebj8xCGJ3scZHg
         XXD1/8SnZDG0v/BMkkVZBwdKn9DLPhVh4y4LSF/jnWyN0jz2dRImm5D4FX+8N6zfBrxz
         3A8kmGchVffaZ1QcLms85hx1eH1OggJunJRpzgRQ8C3DL80dbmuq0u5M1tZMhsAy49Dx
         zn0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ECfvFXHN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id nh14-20020a17090b364e00b001f4f57cec93si115374pjb.1.2022.08.03.10.46.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 10:46:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 21so6813701ybf.4
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 10:46:31 -0700 (PDT)
X-Received: by 2002:a25:b9d1:0:b0:671:49f9:4e01 with SMTP id
 y17-20020a25b9d1000000b0067149f94e01mr22124946ybj.398.1659548790205; Wed, 03
 Aug 2022 10:46:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-12-glider@google.com>
 <Ys6YvvARDX6pWmWv@elver.google.com>
In-Reply-To: <Ys6YvvARDX6pWmWv@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 19:45:53 +0200
Message-ID: <CAG_fn=ViyCu8uGy5YQ_FdPmsMWzX5UpozfLXiotF_bDu5P70Lw@mail.gmail.com>
Subject: Re: [PATCH v4 11/45] kmsan: add KMSAN runtime core
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
 header.i=@google.com header.s=20210112 header.b=ECfvFXHN;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
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

On Wed, Jul 13, 2022 at 12:04 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Jul 01, 2022 at 04:22PM +0200, 'Alexander Potapenko' via kasan-de=
v wrote:
> [...]
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 2e24db4bff192..59819e6fa5865 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -963,6 +963,7 @@ config DEBUG_STACKOVERFLOW
> >
> >  source "lib/Kconfig.kasan"
> >  source "lib/Kconfig.kfence"
> > +source "lib/Kconfig.kmsan"
> >
> >  endmenu # "Memory Debugging"
> >
> > diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> > new file mode 100644
> > index 0000000000000..8f768d4034e3c
> > --- /dev/null
> > +++ b/lib/Kconfig.kmsan
> > @@ -0,0 +1,50 @@
> > +# SPDX-License-Identifier: GPL-2.0-only
> > +config HAVE_ARCH_KMSAN
> > +     bool
> > +
> > +config HAVE_KMSAN_COMPILER
> > +     # Clang versions <14.0.0 also support -fsanitize=3Dkernel-memory,=
 but not
> > +     # all the features necessary to build the kernel with KMSAN.
> > +     depends on CC_IS_CLANG && CLANG_VERSION >=3D 140000
> > +     def_bool $(cc-option,-fsanitize=3Dkernel-memory -mllvm -msan-disa=
ble-checks=3D1)
> > +
> > +config HAVE_KMSAN_PARAM_RETVAL
> > +     # Separate check for -fsanitize-memory-param-retval support.
>
> This comment doesn't add much value, maybe instead say that "Supported
> only by Clang >=3D 15."
Fixed.

> > +     depends on CC_IS_CLANG && CLANG_VERSION >=3D 140000
>
> Why not just "depends on HAVE_KMSAN_COMPILER"? (All
> fsanitize-memory-param-retval supporting compilers must also be KMSAN
> compilers.)
Good idea, will do.

> > +     def_bool $(cc-option,-fsanitize=3Dkernel-memory -fsanitize-memory=
-param-retval)
> > +
> > +
>
> HAVE_KMSAN_PARAM_RETVAL should be moved under "if KMSAN" so that this
> isn't unnecessarily evaluated in every kernel build (saving 1 shelling
> out to clang in most builds).
Ack.

> > +config KMSAN
> > +     bool "KMSAN: detector of uninitialized values use"
> > +     depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> > +     depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> > +     select STACKDEPOT
> > +     select STACKDEPOT_ALWAYS_INIT
> > +     help
> > +       KernelMemorySanitizer (KMSAN) is a dynamic detector of uses of
> > +       uninitialized values in the kernel. It is based on compiler
> > +       instrumentation provided by Clang and thus requires Clang to bu=
ild.
> > +
> > +       An important note is that KMSAN is not intended for production =
use,
> > +       because it drastically increases kernel memory footprint and sl=
ows
> > +       the whole system down.
> > +
> > +       See <file:Documentation/dev-tools/kmsan.rst> for more details.
> > +
> > +if KMSAN
> > +
> > +config KMSAN_CHECK_PARAM_RETVAL
> > +     bool "Check for uninitialized values passed to and returned from =
functions"
> > +     default HAVE_KMSAN_PARAM_RETVAL
>
> This can be enabled even if !HAVE_KMSAN_PARAM_RETVAL. Should this be:
>
>         default y
>         depends on HAVE_KMSAN_PARAM_RETVAL
>
> instead?
>
Ack

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
kasan-dev/CAG_fn%3DViyCu8uGy5YQ_FdPmsMWzX5UpozfLXiotF_bDu5P70Lw%40mail.gmai=
l.com.
