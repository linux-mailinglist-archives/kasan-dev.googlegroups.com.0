Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBC63WK2QMGQEAQNUOVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id A9860945BA6
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 11:57:33 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-7163489149fsf7843693a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 02:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722592652; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+tdXnCd8qoYOwA2PCl8LTyu0hNXjNcVhRy1A9kRdJI+ZvXUS41OTlKrEXh0VK5kOD
         LLTXYitKGwukPtDw1kUoY/TL0GWKK1AKinOOKVdbWlfZVdrrwzvny+NlKvOumOsQ0CnR
         Ul1gxT7r0IGK0cYAEfTREYDc9CRZC8ACT5Oa2cRS2OrqeM/GMwMqOleFn78xQ/2/4QY0
         6Zj49Hmd8vx8foRhYQoUuiC06IQ9WN/38dXoGHMAsgiUmJbsXgLllhTXweRgobj8FYZr
         hodwghaIZDpCsxZlHXxYALdLawp2EWrtuW3TfTwWw8x9HjhRQRQwgcQ7OrsUrJDQ26r3
         DnJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oP/XFImOXn14BemExeYRCs8KYFT+N+iB7LzUH6B9y9o=;
        fh=mG5FEk6qVUK2eBmLUNebT2MJYpZL3m1EhYdLJkWVXU8=;
        b=QFNDMyxnUjM6U+lV+WlwhUXPCnSC+Rm3/uosGERKijzo/ZIjz5ANhL5vGYxki/QHJe
         CVLyNgyp7rJpzocyKgmx9rR3Op5G1jfQVbuuKuqMv9+DhYumW9Rp0Z3LDiWyuAlPGBcv
         rJfhIluQuuN8r7N0Ydw7q/Y7cJAtYJKz5Rg1bLZ5i0Q5z8XA/xBjfqOK03+A5V6Z30Ht
         rX+R5Jy3z+jIkQetx1MflCUtlHu1toIigllG8qZrrd8sCyItIaJRK9D34YNx78gxxVJJ
         loVsqkG+gtgst5kLeGRjTt4VegcvL02gKV4xHc7hx5EV9s7Qj2B+RhWbFDm42zIwWo1K
         BpnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NdRL1SUQ;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722592652; x=1723197452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oP/XFImOXn14BemExeYRCs8KYFT+N+iB7LzUH6B9y9o=;
        b=BmTtOH/dBn5VJlerWzVOz/B8KEbsForg/xFE9C0c3HG1iU49SKnPGsOAKZSi7d4azV
         Ew1fYNQAAh9TRNyVo8p2OkHS2dlGrZRoUZqKbkLJyMt2GkpnAhdx7cLIzdkh8ra91nxv
         vrPnMCSJxINQNsqcPBZgF0cTKOaHOKMA/0rpPK52+PJM946XJS9IRMz8P30mGc3/owvy
         +ud+it8kD+9esp0bG/CBi/4JHG08vsFxsJ0WRxcLAIuB850Fc6RrEOlthJNUC4NKFj3A
         EZREY1Q+PimIs7C15ZeYugRhSwEdtOmUjK+YbFTEL2LvsfugMBN11jLcniGE4EP+/diQ
         9OMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722592652; x=1723197452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oP/XFImOXn14BemExeYRCs8KYFT+N+iB7LzUH6B9y9o=;
        b=HHh6BfnCpGsWlV+Cb9vBpS4IETfec+r+IMU0vDThwgxMjptVIZSzh+Nwm51KXMk/Y1
         UZbIuQDikTfyIEq/1ZHlAf+MbGxvKyqXbyI3WSwQUYYOvfk4J6XPPYLwhSrmvA/h2s/0
         c9889SWtapkJtP5GzBS4RSI+2pvdJoWYBRZAvQYpa8urc7Z4MyzGi5w23a3PnaRExQzH
         FFhlWrbed2SUdMeJTgnMxPFVhQC9AsUVOMkc2jxLuKhfK64I39GyXZbmBSIcQc+Nyx3p
         Kb1I6WbSnZR+8Iy3HrbiwM4fA88ODhNRD7nb45dedCsYsdSjKsC2x/7/UgE6Cpe1gq97
         NOWQ==
X-Forwarded-Encrypted: i=2; AJvYcCVvwBbqkxHfQrlw0aV3ZLI3ecPAPxPLU+TKB1MWCB/FSC577ih/GDNI/WVI0yw1xfKXszKxJae7dB292tg3JPKKpymSmZ9B8w==
X-Gm-Message-State: AOJu0YwGd49d+ag2NMYy4ZDjloB2ELibcqCzPoG/kyQvcOxgqQeowzcE
	CH8oNzQ5uDB3v8g5iJgGBk3mIRw5Wv0QpkaGXoUyBT5eFUzicmqu
X-Google-Smtp-Source: AGHT+IEfTLqfehhI+B1biUuKdjCDj72o6y2Y0wNXm9aPo8h7Gi0fFlu+yqFWX5lmxf/ACLKQ1QzN9A==
X-Received: by 2002:a05:6a21:3389:b0:1c4:a7a0:a7d4 with SMTP id adf61e73a8af0-1c699550dd5mr4115991637.7.1722592651414;
        Fri, 02 Aug 2024 02:57:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1811:b0:2ca:f17f:84ef with SMTP id
 98e67ed59e1d1-2cf20f4df04ls170239a91.0.-pod-prod-03-us; Fri, 02 Aug 2024
 02:57:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8uRqdZNcnauhOs57idih87IpRYtUlFDPJLPE7JWuksJkH5n12qyiryVPMcAVOIIwGPiYfU4Tu88i5frvDsaCvcu8wYfaNDBa+ZA==
X-Received: by 2002:a17:90b:23d3:b0:2c9:9199:bf44 with SMTP id 98e67ed59e1d1-2cff9463fc3mr3500666a91.19.1722592650228;
        Fri, 02 Aug 2024 02:57:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722592650; cv=none;
        d=google.com; s=arc-20160816;
        b=g3rYNi/hpb+cGnqohasXe6zHlwl8eZGqwGRajtapcZMtLNd9GMuJdChZIWfn/M3WCe
         jB4nBJSQm3QqR0LQDJ35URlBRLwcvLj5R1vjT/rCeNxPFdI+vuRsjV4OepgREJWlUgBE
         UfgCIZeCkvP08h/iDZ5E+VjGTyEczg2uEAHxaRdGYTwAovTJLsjsLFqahpFqPa0LHjlZ
         cPvRAB2nCaAE5wHkEOtTnzM9w1OpvzeiYNy1oO5ZUFssWpm7MUClfJrSyLLt0zkvtSFU
         qAkinL8pcGzAzt4bh8VRE//5r81hh2hfSPd0F1BEpX0F+kyNWdmSp8oLqzGQBJcoWFf2
         9DBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=X0BnywGd6SV2Ld2s9hvxt+PjYwo9DGOXawX5efNb35U=;
        fh=cZut7927Rfv3D2DNiIHjp0rzzbgW2QkTKP/E6nW1T9Y=;
        b=Up6KQUD/zYg9JESeIBPf7PQQMP8n0hE3CE+fvAiseZ3ikNEnF7pcRlu79vBK6++ddu
         7nSlVoSk/7rJFVO3F8bMDb8jd9DU+EwEpbTFn5lC1jxOxysZGmPHTCdBkEQbCisWKr4k
         s+war8j6gxmLkT1ZylOsEPsr85veZ+HPgljG0c4BTH935i4t0al8PE1Ymzc3Ej62yvTD
         ulEb2JaliYXyxhCKmoxxOQFX4kk0haj9IIu+fglI1APweuD2rLoMp+mp0yZWZpammvLb
         1Vxz09UTUc/jzpwg1FCZWgyxO8hi+Ds89Sw7aAyeZCxljT9QUhUNcmW2TThTk3rUEPro
         UQEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NdRL1SUQ;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2cfcb858947si601292a91.1.2024.08.02.02.57.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 02:57:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-1fd7509397bso531445ad.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 02:57:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGAQFYvyjqFgaPtpSb2DsgUSSbCgTxZcI8HmWZZ7BPy7ZQCA7X8ON0T3cqfAIKS6RzZ2mfaIbW36MLZlmx7qSBH32XbcJQum2iBg==
X-Received: by 2002:a17:902:ec90:b0:1f7:3764:1e19 with SMTP id
 d9443c01a7336-1ff5cc4a18cmr1463485ad.20.1722592649125; Fri, 02 Aug 2024
 02:57:29 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com> <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
In-Reply-To: <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Aug 2024 11:56:50 +0200
Message-ID: <CAG48ez0frEi5As0sJdMk1rfpnKRqNo=b7fF77Zf0cBHTFO_bjQ@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NdRL1SUQ;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::632 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Aug 1, 2024 at 2:23=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
> On Tue, Jul 30, 2024 at 1:06=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> >
> > Currently, when KASAN is combined with init-on-free behavior, the
> > initialization happens before KASAN's "invalid free" checks.
> >
> > More importantly, a subsequent commit will want to RCU-delay the actual
> > SLUB freeing of an object, and we'd like KASAN to still validate
> > synchronously that freeing the object is permitted. (Otherwise this
> > change will make the existing testcase kmem_cache_invalid_free fail.)
> >
> > So add a new KASAN hook that allows KASAN to pre-validate a
> > kmem_cache_free() operation before SLUB actually starts modifying the
> > object or its metadata.
>
> A few more minor comments below. With that:
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Thank you!
>
> > Inside KASAN, this:
> >
> >  - moves checks from poison_slab_object() into check_slab_free()
> >  - moves kasan_arch_is_ready() up into callers of poison_slab_object()
> >  - removes "ip" argument of poison_slab_object() and __kasan_slab_free(=
)
> >    (since those functions no longer do any reporting)
>
> >  - renames check_slab_free() to check_slab_allocation()
>
> check_slab_allocation() is introduced in this patch, so technically
> you don't rename anything.

Right, I'll fix the commit message.

> > Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> >  include/linux/kasan.h | 43 ++++++++++++++++++++++++++++++++++---
> >  mm/kasan/common.c     | 59 +++++++++++++++++++++++++++++++------------=
--------
> >  mm/slub.c             |  7 ++++++
> >  3 files changed, 83 insertions(+), 26 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 70d6a8f6e25d..34cb7a25aacb 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -172,19 +172,50 @@ static __always_inline void * __must_check kasan_=
init_slab_obj(
> >  {
> >         if (kasan_enabled())
> >                 return __kasan_init_slab_obj(cache, object);
> >         return (void *)object;
> >  }
> >
> > -bool __kasan_slab_free(struct kmem_cache *s, void *object,
> > -                       unsigned long ip, bool init);
> > +bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
> > +                       unsigned long ip);
> > +/**
> > + * kasan_slab_pre_free - Validate a slab object freeing request.
> > + * @object: Object to free.
> > + *
> > + * This function checks whether freeing the given object might be perm=
itted; it
> > + * checks things like whether the given object is properly aligned and=
 not
> > + * already freed.
> > + *
> > + * This function is only intended for use by the slab allocator.
> > + *
> > + * @Return true if freeing the object is known to be invalid; false ot=
herwise.
> > + */
>
> Let's reword this to:
>
> kasan_slab_pre_free - Check whether freeing a slab object is safe.
> @object: Object to be freed.
>
> This function checks whether freeing the given object is safe. It
> performs checks to detect double-free and invalid-free bugs and
> reports them.
>
> This function is intended only for use by the slab allocator.
>
> @Return true if freeing the object is not safe; false otherwise.

Ack, will apply this for v6. But I'll replace "not safe" with
"unsafe", and change "It performs checks to detect double-free and
invalid-free bugs and reports them" to "It may check for double-free
and invalid-free bugs and report them.", since KASAN only sometimes
performs such checks (depending on CONFIG_KASAN, kasan_enabled(),
kasan_arch_is_ready(), and so on).

> > +static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
> > +                                               void *object)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_slab_pre_free(s, object, _RET_IP_);
> > +       return false;
> > +}
> > +
> > +bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
> > +/**
> > + * kasan_slab_free - Possibly handle slab object freeing.
> > + * @object: Object to free.
> > + *
> > + * This hook is called from the slab allocator to give KASAN a chance =
to take
> > + * ownership of the object and handle its freeing.
> > + * kasan_slab_pre_free() must have already been called on the same obj=
ect.
> > + *
> > + * @Return true if KASAN took ownership of the object; false otherwise=
.
> > + */
>
> kasan_slab_free - Poison, initialize, and quarantine a slab object.
> @object: Object to be freed.
> @init: Whether to initialize the object.
>
> This function poisons a slab object and saves a free stack trace for
> it, except for SLAB_TYPESAFE_BY_RCU caches.
>
> For KASAN modes that have integrated memory initialization
> (kasan_has_integrated_init() =3D=3D true), this function also initializes
> the object's memory. For other modes, the @init argument is ignored.

As an aside: Is this actually reliably true? It would be false for
kfence objects, but luckily we can't actually get kfence objects
passed to this function (which I guess maybe we should maybe document
here as part of the API). It would also be wrong if
__kasan_slab_free() can be reached while kasan_arch_is_ready() is
false, which I guess would happen if you ran a CONFIG_KASAN=3Dy kernel
on a powerpc machine without radix or something like that?

(And similarly I wonder if the check of kasan_has_integrated_init() in
slab_post_alloc_hook() is racy, but I haven't checked in which phase
of boot KASAN is enabled for HWASAN.)

But I guess that's out of scope for this series.

> For the Generic mode, this function might also quarantine the object.
> When this happens, KASAN will defer freeing the object to a later
> stage and handle it internally then. The return value indicates
> whether the object was quarantined.
>
> This function is intended only for use by the slab allocator.
>
> @Return true if KASAN quarantined the object; false otherwise.

Same thing as I wrote on patch 2/2: To me this seems like too much
implementation detail for the documentation of an API between
components of the kernel? I agree that the meaning of the "init"
argument is important to document here, and it should be documented
that the hook can take ownership of the object (and I guess it's fine
to mention that this is for quarantine purposes), but I would leave
out details about differences in behavior between KASAN modes.
Basically my heuristic here is that in my opinion, this header comment
should mostly describe as much of the function as SLUB has to know to
properly use it.

So I'd do something like:

<<<
kasan_slab_free - Poison, initialize, and quarantine a slab object.
@object: Object to be freed.
@init: Whether to initialize the object.

This function informs that a slab object has been freed and is not
supposed to be accessed anymore, except for objects in
SLAB_TYPESAFE_BY_RCU caches.

For KASAN modes that have integrated memory initialization
(kasan_has_integrated_init() =3D=3D true), this function also initializes
the object's memory. For other modes, the @init argument is ignored.

This function might also take ownership of the object to quarantine it.
When this happens, KASAN will defer freeing the object to a later
stage and handle it internally until then. The return value indicates
whether KASAN took ownership of the object.

This function is intended only for use by the slab allocator.

@Return true if KASAN took ownership of the object; false otherwise.
>>>

But if you disagree, I'll add your full comment as you suggested.

[...]
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 85e7c6b4575c..8cede1ce00e1 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -205,59 +205,65 @@ void * __must_check __kasan_init_slab_obj(struct =
kmem_cache *cache,
> >         /* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS =
*/
> >         object =3D set_tag(object, assign_tag(cache, object, true));
> >
> >         return (void *)object;
> >  }
> >
> > -static inline bool poison_slab_object(struct kmem_cache *cache, void *=
object,
> > -                                     unsigned long ip, bool init)
> > +/* returns true for invalid request */
>
> "Returns true when freeing the object is not safe."

ack, applied

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0frEi5As0sJdMk1rfpnKRqNo%3Db7fF77Zf0cBHTFO_bjQ%40mail.gmai=
l.com.
