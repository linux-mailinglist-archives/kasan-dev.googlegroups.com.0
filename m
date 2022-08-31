Return-Path: <kasan-dev+bncBCCMH5WKTMGRBK6GXWMAMGQECI4J3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4740D5A7ED9
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 15:33:33 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 36-20020a9d0627000000b0063927bfccb5sf7542741otn.18
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 06:33:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661952812; cv=pass;
        d=google.com; s=arc-20160816;
        b=CBtxAc1oJBBCsAzOcYEruKSk4cVg++5Z98eaXVBaOnU3nwTobCXd7PC6KPDt4/xQ1I
         WIIy1eHUZxhUacDoujdKdHyZ62HmyLwi0X/dV9+ndsxGlhrMwxfslp7Rlmr6zjdadcbD
         QFau9pMBYq4i5JSY3Q6dV/SjryxSKa5xNc2molLEOVobNbmlnISgku78/j60G8Aq5soe
         JWIyabpD1Boq47sCzEjiiDPS/ngZK0tojTWeej9K1kEmPqzHZz7XATBvPu1bBwEC7C6Z
         222tBR0Z94qKF7PmJVsv5KPyfPJ85rk73K6Irq7lcZPn6ccSnnclZSypDt6fLMrPn5pA
         klTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lZRxUK8imGItjeQ+Lp6SdwvOwNP+rf1/0KvvQcvyJkc=;
        b=Oz4qzG7iJN+9s9QAVguRo3cxJPe+YcXDHJnc54q6XqyvIcq4zgAMdH4rMbcp7YaOFQ
         ofVKCq4VUokdWDGu2cloIIDx4XpDJsRV35vF/p9SIaxtC/lS1XZXx0RzSPivgXb7ddGt
         RK1gMXhgZULsTiH2VwNRrfMfxSxtrmR9J6KefaQDEbthUDjZSP4+6hP9GmusuvaJZlZ1
         S/eBT6/Yx1/ZKeYsORPfKH9vALNYze/NdOSXJVlyovgv+gO+bk90zFWeAVLE09ipdZEC
         bHji9tNAQzvizKC+o63K1L3CG+M1uQB2TdUCKkvUsuSA1osPcbnhE+Sx3TSb/x3shQOH
         XyBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lZE1wqPc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=lZRxUK8imGItjeQ+Lp6SdwvOwNP+rf1/0KvvQcvyJkc=;
        b=jsZjHQkKjFNP7d2ByrCrWlA5+fn6ilRWPf7kjGVe6cR20r5v+pPOyHbZLySQdulDnX
         bpF4YjJvy/vp91vrC9TXENDbU9MguEbxjTrkBdIrNn7z5kXnAelB+4niZlytm8fJPcBr
         gyLQl9QTUUBDfrfNcq/Czug4+gxawrVnAmt5NkMYCznTUkwLC/5njMOBjB3Ol+6lU7JS
         +0wmHahjQ3WxSFRQGdcKmM/H/AVyBqMSDK8IhF8VQsjsXnVmwBJDoFoPFVhHEQ4lu6I3
         /PIpjIdF/7nnMkPdXRjzF8SU8hN9aU53NUkHEYf7tnAo7BzwDZ9/gV+erh1zE2fZzstD
         L2jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=lZRxUK8imGItjeQ+Lp6SdwvOwNP+rf1/0KvvQcvyJkc=;
        b=ce3O7N3s/4WrCBdShaD66FstznQ0r+q0PWl0xWtxEW7+TZUhF4kAzOaY4XqHCB06h4
         GhK225FfHIhrMlFYfz4HC1E+9SF9xj1p0nyIwEKUa1qOMn/SXGliho4tgtIKg+G+S1fk
         vHWq65knkRDvj6DQH4AJf86fvUnmN2+rerpKR6SGfd/WvRsugDkEg8u8cMFnuIMOleTd
         SL9KuU/I3veiTwQvy/AgueEmnG3KoGpt+bbdbmlKs7miB1y89jpTJvRos/hiwNFJUzlX
         3LRUQHiTTl498Mupj5pjMgXcQV8dxAX3Jgd6D8bn9M3RdBP+wNi6NNdBFGkeQHlbgEGD
         4uVA==
X-Gm-Message-State: ACgBeo2pP1et8UkI8vvKmzkq+hU175l/6CJ6EPkyo7vMN6XG2ZeJfAO4
	rAXUJwaOmkJFe2wHecg7QZA=
X-Google-Smtp-Source: AA6agR7zwgdbfxcguWSWzrjZW6ymnWnfxVy75SDDGDCUkehASRWyR/6GGRzd4en+oVtIbh888MKEqg==
X-Received: by 2002:a05:6808:20a0:b0:343:2cd0:9707 with SMTP id s32-20020a05680820a000b003432cd09707mr1281388oiw.132.1661952811964;
        Wed, 31 Aug 2022 06:33:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a798:b0:116:c21d:f9c3 with SMTP id
 x24-20020a056870a79800b00116c21df9c3ls300566oao.10.-pod-prod-gmail; Wed, 31
 Aug 2022 06:33:31 -0700 (PDT)
X-Received: by 2002:a05:6870:6314:b0:10b:9595:62db with SMTP id s20-20020a056870631400b0010b959562dbmr1487086oao.128.1661952811612;
        Wed, 31 Aug 2022 06:33:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661952811; cv=none;
        d=google.com; s=arc-20160816;
        b=jPavG/ZYYbKJH4xGXZ0ZNEVzyqicoWw36czPcmisdN7Ymx1usFEDQIcII92iLGfV2u
         B8tX1HmWEQTO9MTBjM6BlJ8DBj9kf7IQ8MyjQNr8h3lCv1IVPUT1ktNKS3WbrjjNyRPN
         rKsOnBtqaRFpq6npo9qrl+qv0mezRPg3Ecps0Mm5SxP5hBoPXrKrvUOKEXmVJII0bdxy
         RIKet97riRfv20M6523WWusZNJ5OhTwWL+YSe6WXZhmqOQw0sCUu2Cz2SGGozBWyIPue
         F/a8Nab7tOHUvFvAlt5ZCl3OIil+iMrePH93Zkqh/FlzLANDCiJt84wlHlZTBRTV67Nk
         GwEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0+LvJ7VjdJUJkQtLqFzy6A2FisDBtX4zU7WtR7vEfb0=;
        b=uhgwTuygGwxw6gh6iRX0jNdDMImQqR+cp6ZdAHR/gRH5sYQhUZVPQTDhXO5HoCs9Hb
         LGrNYeGJwJzOlOSuIYMa7l4SLZr/njpLWKDeRHt3WEvybW6Ax+LP4iPLZ3169qfNcCyu
         JNFY/ubUUYlRi9q3XbUzYZX/646lVPdRwGObsuM9C1m0jObQOC3/LCznXqkrS3pOkdXO
         OGUgEDwyxASgtZPZO8mVCtPgj3cNVrXVflGrEkDNAEQHb3n56gC4VJCo32d/qjuqafk1
         4tJVeEO54N7xoROPuLJDuV+vpFtsBqbmfwp4oY5UDr6/7L6Z1DC3DT8w7GdDEF651Et1
         g43w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lZE1wqPc;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1552815oao.5.2022.08.31.06.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 06:33:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id t184so4161952yba.4
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 06:33:31 -0700 (PDT)
X-Received: by 2002:a25:bc3:0:b0:673:bc78:c095 with SMTP id
 186-20020a250bc3000000b00673bc78c095mr15327415ybl.376.1661952810986; Wed, 31
 Aug 2022 06:33:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-45-glider@google.com>
 <YsNIjwTw41y0Ij0n@casper.infradead.org> <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com>
 <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
 <20220825215754.GI25951@gate.crashing.org> <CAHk-=wj_nfiLk_bzjD8GWFFzm17syvOYqS=Y7BOarMSTkMiamQ@mail.gmail.com>
In-Reply-To: <CAHk-=wj_nfiLk_bzjD8GWFFzm17syvOYqS=Y7BOarMSTkMiamQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 15:32:54 +0200
Message-ID: <CAG_fn=UFbsbM1-cSvvc3aBMmFgasAWqeBrOXpzZ7_DjwU3wT6g@mail.gmail.com>
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Segher Boessenkool <segher@kernel.crashing.org>, Matthew Wilcox <willy@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
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
 header.i=@google.com header.s=20210112 header.b=lZE1wqPc;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as
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

On Fri, Aug 26, 2022 at 9:41 PM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Thu, Aug 25, 2022 at 3:10 PM Segher Boessenkool
> <segher@kernel.crashing.org> wrote:
> >
> > But UB is defined in terms of the abstract machine (like *all* of C),
> > not in terms of the generated machine code.  Typically things will work
> > fine if they "become invisible" by inlining, but this does not make the
> > program a correct program ever.  Sorry :-(
>
> Yeah, and the abstract machine model based on "abstract syntax" is
> just wrong, wrong, wrong.
>
> I really wish the C standard people had the guts to just fix it.  At
> some point, relying on tradition when the tradition is bad is not a
> great thing.
>
> It's the same problem that made all the memory ordering discussions
> completely untenable. The language to allow the whole data dependency
> was completely ridiculous, because it became about the C language
> syntax and theory, not about the actual code generation and actual
> *meaning* that the whole thing was *about*.
>
> Java may be a horrible language that a lot of people hate, but it
> avoided a lot of problems by just making things about an actual
> virtual machine and describing things within a more concrete model of
> a virtual machine.
>
> Then you can just say "this code sequence generates this set of
> operations, and the compiler can optimize it any which way it likes as
> long as the end result is equivalent".
>
> Oh well.
>
> I will repeat: a paper standard that doesn't take reality into account
> is less useful than toilet paper. It's scratchy and not very
> absorbent.
>
> And the kernel will continue to care more about reality than about a C
> standard that does bad things.
>
> Inlining makes the use of the argument go away at the call site and
> moves the code of the function into the body. That's how things
> *work*. That's literally the meaning of inlining.
>
> And inlining in C is so important because macros are weak, and other
> facilities like templates don't exist.
>
> But in the kernel, we also often use it because the actual semantics
> of "not a function call" in terms of code generation is also important
> (ie we have literal cases where "not generating the 'call'
> instruction" is a correctness issue).
>
> If the C standard thinks "undefined argument even for inlining use is
> UB", then it's a case of that paperwork that doesn't reflect reality,
> and we'll treat it with the deference it deserves - is less than
> toilet paper.

Just for posterity, in the case of KMSAN we are only dealing with
cases where the function call survived inlining and dead code
elimination.


> We have decades of history of doing that in the kernel. Sometimes the
> standards are just wrong, sometimes they are just too far removed from
> reality to be relevant, and then it's just not worth worrying about
> them.
>
>           Linus



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
kasan-dev/CAG_fn%3DUFbsbM1-cSvvc3aBMmFgasAWqeBrOXpzZ7_DjwU3wT6g%40mail.gmai=
l.com.
