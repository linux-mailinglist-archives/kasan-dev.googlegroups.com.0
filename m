Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBLGFRG2QMGQE2G2EMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id A116993C446
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 16:35:25 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-427fc86aaa2sf7063135e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 07:35:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721918125; cv=pass;
        d=google.com; s=arc-20160816;
        b=YjSNmFilDtj7mb+X9eASyQMjM+fNGbn/DrMh3qq96dT9B5oFli1oxFmTPgS/DeRNJF
         NkuELoPhLe1XZR7XTOTldU/bVumycTWBIXxKPcEbJoVdVyCyEaJKjdBjCMnW3izQl99M
         rMcqxjiJ6d837651R1w8akZf1Qah4yV3KrFeLsvjJF2Y5EphAEIEPvr1Pfgm6gqeQu+t
         nvWQSBmlIxBvQYUgZxMuL5luzzrur4tRZUkXWB/H9Ce9ay1eYELZ4bw3B6RpmK90aY7P
         EjRpbM+rjuXXc0CqIzmRJdDDxP7V31Hvol6Ak6zTnWpHwJpdwNbXEi6l6Nls4buBWOuk
         foxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sJPG3fvCQZuEyD0LeycbaO20aB80fIwls8nV55+f5PY=;
        fh=xvjRgKHEVN0CSfYjqxmlEIjFLSzIEPjYRoCy3H2KD0g=;
        b=UM9PSYWQW9tXoSk8iLKRSycNRf8jpNOvHnGeM3QGZ9CQA8Drw7Wi8S16V71IB7IVy2
         MRixapmXh/ATOAh9RqX91CuIFRXgpkGHwP2gthI0aVEecekv6QmpiinD1yi9gG6u493M
         SMzhPakOAgkW+Py7EW6GZ9+R3G4ZhutNre8QT7hv+uook854d6z3+jek4ylYJF2v8MAx
         JdEqUu2XBd+RNFI5rW91aVxfZ8yiVslonQZku828DSJ1kN8ZgKT7Htfttc+xHVxgJ/iZ
         UIX5HeGMXQ6JVo+0P/1dxuiq/99a00mA4vCOe66CHp1q6dkCSYZP1vs08DQ81vedUh5u
         L9aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gIifznfg;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721918125; x=1722522925; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sJPG3fvCQZuEyD0LeycbaO20aB80fIwls8nV55+f5PY=;
        b=Urjl1PUlfQjK4DGlkd8UgVyMqJXGPSUFaIBMyAu/Fs5t6pbpjUXlxUhCEBdlLfrjLK
         QlFxLayBDOko/tEaGHOmVGwn1yeLXx1XpjFa4+SR4+vNyf8pIPjN35MBpq87LyJNfc8I
         2m4cSob7M9cIzKmx6wLLymyD2XGzBoWDTo+FFirOuwwbAnslPmgCE5ktCge7vs6jlxvs
         IuflOB+X4qAG/+Cl78y8RL3hgw/jsC1Pvkf5O4+dAPGfGvs/EWccfDvBUvQ1acLDDoEC
         Adm5g7WUkqSuT1WjV1Ma0Hnr8w4bHQblGMpfBg+ntJnwHekWwqYHWt0eEeTfWyyWUDoC
         86yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721918125; x=1722522925;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sJPG3fvCQZuEyD0LeycbaO20aB80fIwls8nV55+f5PY=;
        b=vEKfK+FPeO4jtko1UgonXUafPGmX+QQA7DqiOvJ9x6Zlnhg70+OcUC13y+UohEAw9A
         +T2O8Z5wVpkhUmkrD3bhF1vkED9zQBfS3PAHDyUQR+z/9LxUQpumF2NEYSJ7gGwG1jl0
         4vann8m8CPWFwu2HBVT2J0EsTw14H2lT0myQjoJr+Y4JUqolObNyjZQ0KpyNSmwV1Mf3
         JNWSnIiwExJMvMEC3yJqAv+Rv9Qso2pJHuvzjUGLBSxrV5vOxqdBIbZuoGUc4SaiJtGA
         qwH4gNo0XCfPSzW+5/JeHTWAXvQmNran3waygGyLc8Q9aLDnp26jKIBCSHIyM2oAJHs6
         71FQ==
X-Forwarded-Encrypted: i=2; AJvYcCX/GTWrIlH2M9gmP3ww+EbqY61wKPncV4QKx+NNLK6hGaMohHsz3sz9LtFMffXGfzQ7umK3IcQ6NMDNEJKbIAfN9p7SqNi4WA==
X-Gm-Message-State: AOJu0YyFsndWW6E1T7awpnyLpv6zlfYLRdMJjgwXPTXkiJ2K+HEsSwaa
	pFh6PeI4ZR/mi6GU/OExqJwFoLMkwYQPixnRPqWlr45bg/djcYPZ
X-Google-Smtp-Source: AGHT+IGzGlq1cd6Fi4C6jWKQBKW54XuODHPNEj3T+EJSL2tA6VdT4UhEKx59bt1AHB/Zgb9/uU8S/g==
X-Received: by 2002:a05:600c:3ba8:b0:426:6688:2421 with SMTP id 5b1f17b1804b1-4280548cf54mr15883245e9.11.1721918124419;
        Thu, 25 Jul 2024 07:35:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c95:b0:427:ad0:2dd8 with SMTP id
 5b1f17b1804b1-4280388225els4822225e9.0.-pod-prod-04-eu; Thu, 25 Jul 2024
 07:35:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwibjAFdeVp1zGI5Dvbq6NSu7rxZfvb7V8Mgk+zXmSMv32RpsaNJ5Y+ixFFlAoRbbOZYkZZJZs2v4QdIpSa3Uppq6H8ZmLFFzVgQ==
X-Received: by 2002:a05:600c:4712:b0:427:d8f7:b718 with SMTP id 5b1f17b1804b1-4280550ccedmr19668385e9.24.1721918122503;
        Thu, 25 Jul 2024 07:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721918122; cv=none;
        d=google.com; s=arc-20160816;
        b=rdwArA7Dz7EZlu4hc830ETsXXQMAxuugHSlA4oom28Cr5QmGyVFnYYUPkXrq2GC6Vp
         35okMAWuxgrtMGcnffp8gDbnyS+pLTijqx97YaZU49gWFE5rrwWaY4MTbDfqol9kDlir
         IYuYav+tX7HdKKyNyoYXoMhSZlL1XoaduBPYI4wnDN1sEMrPp0hwSutTGNHtomxkOq0X
         Q+a5Hc9U7IbUQTQceZr9TH4yfxb8SGiViWjKNrH7qRBTxC1zRYaeNQD0mxt3Ahy4YdXD
         k6By8zXVTY7EN6MmMWPKxp5MZ3ynjBY9yx5Ujh0keblIxMvljfmz6EqtG6o6SiazSjqC
         tmnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=D+McA66aY10VJ6ghs/3u7Af6ixrbJytWpoKwjU1ZAzo=;
        fh=SvNyKjoyziqD2XqHS7PAwm2vHFYOOKNQdXE7DherZy8=;
        b=JDXkassom4wTNy6hvmCcAGipoZZ52EF3afad9bP5oxBQhd5CSwmVJjGD5abQxqZ6LM
         /zSlZuj/aQFPbvadil24qm7hYT8Bh3tM5y5qrFNFFl52nShyZKKDLwBKdeErssZSE7ib
         EahLe8I6o8JFIOZIsJhSRRXlRNSa+DINJuVvzZ12RXfnytODA8qS82kzUsLHqe6TVP8F
         68CEJzYt6ZvldAciRczwJwSfiOmMrVYTcVxrJ81JaXiOn+I9Ee+iOL9DW24Asgu/Keyc
         DsWRle8/2srNU9ftAqpeTz7F0irGszYMQql6PGP4QZRLqK5baxfIFoNaVSFFfJT63W35
         pnWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gIifznfg;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42805a4f91asi416725e9.1.2024.07.25.07.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 07:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso15343a12.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 07:35:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtJ3gfi8gy1oa8vFcBbcZhV08NeUX5+Fmsg9k9G6Lz6sL7OWXSZpJ+LihNsFOzFLQBxCbMAUQmPhxFphKVBqtdcWWei0oWHonMlg==
X-Received: by 2002:a05:6402:50d4:b0:58b:93:b623 with SMTP id
 4fb4d7f45d1cf-5ac2ca7f225mr247791a12.5.1721918121258; Thu, 25 Jul 2024
 07:35:21 -0700 (PDT)
MIME-Version: 1.0
References: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
 <20240724-kasan-tsbrcu-v2-2-45f898064468@google.com> <9e05f9be-9e75-4b4d-84a4-1da52591574b@suse.cz>
In-Reply-To: <9e05f9be-9e75-4b4d-84a4-1da52591574b@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2024 16:34:44 +0200
Message-ID: <CAG48ez0wJ51FnSRGtcjJrBB5iuEh4LS+1v7MNnSxS5JFeVy5-w@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gIifznfg;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as
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

On Thu, Jul 25, 2024 at 3:28=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> On 7/24/24 6:34 PM, Jann Horn wrote:
> > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_=
RCU
> > slabs because use-after-free is allowed within the RCU grace period by
> > design.
> >
> > Add a SLUB debugging feature which RCU-delays every individual
> > kmem_cache_free() before either actually freeing the object or handing =
it
> > off to KASAN, and change KASAN to poison freed objects as normal when t=
his
> > option is enabled.
> >
> > Note that this creates an aligned 16-byte area in the middle of the sla=
b
> > metadata area, which kinda sucks but seems to be necessary in order to =
be
> > able to store an rcu_head in there that can be unpoisoned while the RCU
> > callback is pending.
>
> An alternative could be a head-less variant of kfree_rcu_mightsleep() tha=
t
> would fail instead of go to reclaim if it can't allocate, and upon failur=
e
> we would fall back ot the old behavior and give up on checking that objec=
t?

Yes, true, that would be an option... behaving differently under
memory pressure seems a little weird to me, but it would probably do
the job...

I've now tried implementing it roughly as you suggested; the diffstat
for that (on top of the existing series) looks like this:

 include/linux/kasan.h | 24 +++++++++---------------
 mm/kasan/common.c     | 23 +++++++----------------
 mm/slab.h             |  3 ---
 mm/slub.c             | 46 +++++++++++++++++++---------------------------
 4 files changed, 35 insertions(+), 61 deletions(-)

Basically it gets rid of all the plumbing I added to stuff more things
into the metadata area, but it has to add a flag to kasan_slab_free()
to tell it whether the call is happening after RCU delay or not.

I'm changing slab_free_hook() to allocate an instance of the struct

struct rcu_delayed_free {
  struct rcu_head head;
  void *object;
};

with kmalloc(sizeof(*delayed_free), GFP_NOWAIT), and then if that
works, I use that to RCU-delay the freeing.


I think this looks a bit nicer than my original version; I'll go run
the test suite and then send it out as v3.


> But maybe it's just too complicated and we just pay the overhead. At leas=
t
> this doesn't concern kmalloc caches with their power-of-two alignment
> guarantees where extra metadata blows things up more.

If we wanted to compress the slab metadata for this down a bit, we
could probably also overlap the out-of-line freepointer with the
rcu_head, since the freepointer can't be in use while the rcu_head is
active... but I figured that since this is a debug feature mainly
intended for ASAN builds, keeping things simple is more important.

> > (metadata_access_enable/disable doesn't work here because while the RCU
> > callback is pending, it will be accessed by asynchronous RCU processing=
.)
> > To be able to re-poison the area after the RCU callback is done executi=
ng,
> > a new helper kasan_poison_range_as_redzone() is necessary.
> >
> > For now I've configured Kconfig.debug to default-enable this feature in=
 the
> > KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_T=
AGS
> > mode because I'm not sure if it might have unwanted performance degrada=
tion
> > effects there.
> >
> > Note that this is mostly useful with KASAN in the quarantine-based GENE=
RIC
> > mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> > ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> > those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> > (A possible future extension of this work would be to also let SLUB cal=
l
> > the ->ctor() on every allocation instead of only when the slab page is
> > allocated; then tag-based modes would be able to assign new tags on eve=
ry
> > reallocation.)
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz> #slab
>
> ...
>
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -450,6 +450,18 @@ static void slab_caches_to_rcu_destroy_workfn(stru=
ct work_struct *work)
> >
> >  static int shutdown_cache(struct kmem_cache *s)
> >  {
> > +     if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
> > +         (s->flags & SLAB_TYPESAFE_BY_RCU)) {
> > +             /*
> > +              * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
> > +              * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will interna=
lly
> > +              * defer their freeing with call_rcu().
> > +              * Wait for such call_rcu() invocations here before actua=
lly
> > +              * destroying the cache.
> > +              */
> > +             rcu_barrier();
> > +     }
>
> I think once we have the series [1] settled (patch 5/6 specifically), the
> delayed destruction could handle this case too?
>
> [1]
> https://lore.kernel.org/linux-mm/20240715-b4-slab-kfree_rcu-destroy-v1-0-=
46b2984c2205@suse.cz/

Ah, thanks for the pointer, I hadn't seen that one.


> > +
> >       /* free asan quarantined objects */
> >       kasan_cache_shutdown(s);
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 34724704c52d..999afdc1cffb 100644
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0wJ51FnSRGtcjJrBB5iuEh4LS%2B1v7MNnSxS5JFeVy5-w%40mail.gmai=
l.com.
