Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSHWVCLQMGQEG4ZUWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4404E588917
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 11:09:30 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id c16-20020a056830001000b0061c7b53339bsf6930345otp.4
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 02:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659517768; cv=pass;
        d=google.com; s=arc-20160816;
        b=SBW89diO+jiHWo3Wd7/IUvoDnqbuMDxSe4/vHw9XiipxyNHLdDbNpW1XJOHSlrXRoD
         LxaBWrSHsNBtGm4lFf7AVgpWMtQUSvdUjZ5BURY/tjHQJGTloj2e3Jt+Yi3B0pbF9cCp
         jIhy2lzJIGX1Ll2ZTKIsX013UP8qbW0pbhjONOod9DC1toXhIHWqMu/Gx80NyvY2M5YY
         AZC+Sl6pwrsmGNyRW/Gt/nL/FC/AX2OePucBKjvKxJiJLQFoexqdWxG4F/SiFwckIRYi
         MVL+LYJxDAKiJkd0Eup60PdOpAHpYwvsKa33xvk9Q/H2i9bVH53Yt+NLrlBRFz5vh/Ze
         RRGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R72n6gTABBChQb0Z0DtV34uHmXYg96jyIL6CuEllCwg=;
        b=Ycrtw7SMyCDvlPAHODXc6DmaGThKpIY+Azm3gbnwX6XcWGAy6hDZDVmhsfx2WIGhOh
         HatJcZf+13IQLWptGoZ9/L9rTfqxckWWwC4GafYTmLxdMH4fqvUepPKCDo+mJnqPdFxs
         eSw9eZVhXk4GI7ln39iqf97f/ifNDXIhGjSCS2yGDJtF2XTDvX1eXoAktlD4J13ta18z
         Az4aFYJDUwn00hK2yT+2ucL9MG61YcLhpWU/bAQzX9Ek9jdDCSefPXsTs7XAUewTsDRL
         dHtkFp8++A343rIi+gXG6xBeXYU+gJIMUvALGBjdZnASDy2YoLtUeU/vLyvkxM614g+Y
         XfPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qQJ0HEUz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R72n6gTABBChQb0Z0DtV34uHmXYg96jyIL6CuEllCwg=;
        b=MDtUax8iKIzjItYkT1vX56Qj53yzI99YFxMSA1Gh3jM44dhIe6M3/050zn7NqJjphm
         r6pZKZiX5ub+JyFlC1tPx22vDpg8UrRD8oltiw0EaQa+1OSaIPELsjibf4Vus/M7Av7N
         IidVxU6hFxlyfKxRVa0mwfv1rZXokDhtVwXg24FsFITjbkNUPa0JB0JFgbygYgFBlAh5
         zmsqsq5upkD9w/+Llf6gVg3mkBxkpgkrgzl1pd0zRrDKS2M+NDZ+X7qbGLsPgWqMHwF3
         LxDEBFGWbQxdoiLLzshPJ1KUkEG+Aw2KOaGJrA1oc1XVIzjrbZez/q1F37kQi4O8hDSP
         SQJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R72n6gTABBChQb0Z0DtV34uHmXYg96jyIL6CuEllCwg=;
        b=jMw207zHTGIj3hq4WGjfkgmOdlP9sI23rlCWCVh/dSMXPO+hq962NkgsEvX8O0MhX/
         uxpNObVQ8cqnieU1/BbTvD/l4rqbzlqQ9ywlwdPNG+1hw5txJdthHUkUg9G+zPqZAkQD
         PaQ8FF0JSb1c8Te5wgT69mRWh7gS6fcN69BW4oZGur6gDcejl6CsyyL2+qveIeHDRK09
         kivOC0C9ZISDd+W3CLZ1r8qPOWZ20NaXmtEyT1s0B0zC+yGKTmX63z/fDQyZG/8OctEK
         JML60EGaqGazyECqdTV2B+R2VEXWOYegeIcyzJY9/um0g3pYMrGHpxWve/BmOqfGLjNy
         Ya4A==
X-Gm-Message-State: ACgBeo2b8c8hYEVch75VwIoQlB83bAjGJXcOXIflmhhLpO3yN3DcrYIh
	5GGLmi4RnTq6F2l05Y/Ck48=
X-Google-Smtp-Source: AA6agR6SWte9Pv2VyMYq5L39r/kUsIwo5H0Ow5mCFoBoMUIQtERjbnC6k+dGdn6ogV0gXo67KlOOOQ==
X-Received: by 2002:a05:6808:e83:b0:32e:28e2:199d with SMTP id k3-20020a0568080e8300b0032e28e2199dmr1366055oil.222.1659517768576;
        Wed, 03 Aug 2022 02:09:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:586:0:b0:33a:fd04:6fc8 with SMTP id 128-20020aca0586000000b0033afd046fc8ls5194590oif.4.-pod-prod-gmail;
 Wed, 03 Aug 2022 02:09:28 -0700 (PDT)
X-Received: by 2002:a05:6808:e85:b0:32e:28e1:b260 with SMTP id k5-20020a0568080e8500b0032e28e1b260mr1365727oil.129.1659517767979;
        Wed, 03 Aug 2022 02:09:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659517767; cv=none;
        d=google.com; s=arc-20160816;
        b=PrWUKk/QDTDSVXsXsTqga7+w0MUFYRgfAOUTBFJdLlwnE0H08eF3Lz1YIKtRFZyzZi
         usrLHvwiDb29ImnC/EDTAGd2VwE9eT329vf9ia03YCSaqvcGoMI2n3BJhMq7FyyJDipu
         PoQ8akfe2XXFEysytkJNsHtEKD4rygZ0rWCm7KNZ74d5ntxYkz1+gPipxdw2IynXTkc5
         rUSkDutAdbLoiDRbD4/7x/OccmX3Kld6tSNhg/zHIdEITo+7cqoo6PUMGkme5y3B3V7p
         APOJ2VxOxqXv3BOGS+bWz6cURvPuTVkt6H3wsO1vZO8greBdmWcMBipt0I1pExZYgfUv
         Oegw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tfepPGt63PhV/uLLZC6OjKAhHWfosw2a1cPbmZc1NF4=;
        b=VrESY5gsRI8qbN8L29Rc6CW8Nr82v8CvARcsqDnPcCDirYSNmtivLzm4NYp1FSauiq
         e6MOZP58AgzVHD8XqfIlp5iKpJ6CyU3Ik6XkAXxlDzxjS0jYjHMKWWUqLwA3UA6x9CvP
         wnDcKqohekCCZrXRA1Pvc8qp7t5CU5T66tZzlhRAbTsLdUPUM2B5334efHxjYhR7GCZ6
         c0KspsjSc9CJBdRZwUqwNayVwL+mdCfWxILuzMMuhtdtU+vQAan0/qCrfKxkpG9GG0sA
         yZIL1xMlDAXId56f8iTjRaXZbbRknndYIk/ei2QLFfNnILJxRqrj40qZyyz6FIrisjrc
         VHhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qQJ0HEUz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id z3-20020a056870d68300b0010c5005e1c8si1521598oap.3.2022.08.03.02.09.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 02:09:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-32269d60830so165154097b3.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 02:09:27 -0700 (PDT)
X-Received: by 2002:a81:4892:0:b0:31f:9933:9cb with SMTP id
 v140-20020a814892000000b0031f993309cbmr23285753ywa.86.1659517767408; Wed, 03
 Aug 2022 02:09:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-18-glider@google.com>
 <CANpmjNNh0SP53s0kg_Lj2HUVnY_9k_grm==q4w6Bbq4hLmKtHA@mail.gmail.com> <CAG_fn=ViHiYCWj0jmm1R=gSX0880-rQ-CA3VaEjiLnGkDN1G4w@mail.gmail.com>
In-Reply-To: <CAG_fn=ViHiYCWj0jmm1R=gSX0880-rQ-CA3VaEjiLnGkDN1G4w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 11:08:51 +0200
Message-ID: <CANpmjNNSYgYHeA91QB8dU=_n73Ut3azY6EZT8cd6D-FcWZGw0w@mail.gmail.com>
Subject: Re: [PATCH v4 17/45] init: kmsan: call KMSAN initialization routines
To: Alexander Potapenko <glider@google.com>
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qQJ0HEUz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 2 Aug 2022 at 22:08, Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jul 12, 2022 at 4:05 PM Marco Elver <elver@google.com> wrote:
> >
>
> > > +/**
> > > + * kmsan_task_exit() - Notify KMSAN that a task has exited.
> > > + * @task: task about to finish.
> > > + */
> > > +void kmsan_task_exit(struct task_struct *task);
> >
> > Something went wrong with patch shuffling here I think,
> > kmsan_task_create + kmsan_task_exit decls are duplicated by this
> > patch.
> Right, I've messed it up. Will fix.
>
> > > +
> > > +struct page_pair {
> >
> > 'struct shadow_origin_pages' for a more descriptive name?
> How about "metadata_page_pair"?

Sure - this is local anyway, but page_pair was too generic.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNSYgYHeA91QB8dU%3D_n73Ut3azY6EZT8cd6D-FcWZGw0w%40mail.gmail.com.
