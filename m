Return-Path: <kasan-dev+bncBCCMH5WKTMGRB66O5P5QKGQEPWJP77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B96A0283331
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Oct 2020 11:29:31 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id h14sf35203ljj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 02:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601890171; cv=pass;
        d=google.com; s=arc-20160816;
        b=atqd00THb0AtaF42E1pEHksrzXma5Eq9qhakAfeCm8lDrPN/e/ueVkQWF2OUZNGUGe
         UpFU4pw/AerX6Mvygzk+lop5QQANg2K5GkKzGtpI1Hanv3lh15HW802Qlxm4V+gZfUgU
         1MpLSOw8QhdnSKhQyVtPvfWGC2phH9IByd89R2v1lLyGogi0BPoxSnXA2bcJYqBa8rTM
         6fr6A5vY6UaTUVT7DKxC3SJ5Ki/JYggwe/JNJQT0+wETgQFNA0EpFfx+7uOxN9bcN0B3
         lWes9wVtGVp06d4cr0nuew9zhg0SYDHaHSc4oaJt3zw1zR8l5leruxwG5vWEJZyflFUi
         cpqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L4QHbNUKrC+ih4/IlJVMl7IvtHyEK5clhGw+RP2XwOY=;
        b=0sL5NBuhsZH9reH95WiKiOanppql9sYwGAUdVhcBg/Y0xeEgd5pQYMxawu9Uy7MF5J
         NAddJXGZRl2cQogy0g+jqw1dLD2+aqouooqVnALT9wgth5N9BVqJj03Y52eT28riqBMw
         dX3SnYSSoAk0nWfnOiXjjQi/dqFuFDM4JaQOy13iDmUtiakJP19BQULndaneQt+okkYp
         IErj5klf3iGlz7yQJGCeRkRHklhsi+jEX37eG5Z3PlvLWYB3J5iyZnPaQZ3d+dFI9eF4
         sN5codFRYqTvXS+yzyRU4EgFIhyfhgZG6kl6P6Kexf3x6NS1Rl/Jm5TEPTLiA9YY9Hmn
         FcRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RD6Sa7SS;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=L4QHbNUKrC+ih4/IlJVMl7IvtHyEK5clhGw+RP2XwOY=;
        b=ONYd1HksuPQnPYOKX2zBTa0K298CVZwKV4OOeQC1PyZPn+HkxcyZGf/i2o1NdoeyAK
         6aHJP92fnkudSsdE8OlczViDL6TlDQYH6Pe5jsuxdGHkzcX9f/Z8R+266UfePYZMvwW8
         q8yYUZPK0+vdfVxhWHhvG95BbVmAj4E2/+FfdVBaJ8nwwv8UitoBkUkinUs2BjoQF19w
         d8ZZyVn2Nv6CZJXj7Uf1kOn1Ws84XwJw/K17WJzUhiRLtrhXfXtQINmV1TB3RFrd6nn8
         5cuX/Xe3gtLhWQPO9Pam+pxRylA19jHxzWVw3WmZVvPArMN1HJqeP5OIFhk2UKwOKZiH
         eO3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L4QHbNUKrC+ih4/IlJVMl7IvtHyEK5clhGw+RP2XwOY=;
        b=gfF0jzL5FizzWZxPECLpFB1JDy1PaBUDXmRoqT6jqPTsyzJ3ypc2gyUosCaans/v0O
         HkXX+wQ51+HX9GyBrmI/2WEHSFv7TIaOD04qxiqSv9Dw7j4UIGRTB6/7itutXn6MjyJz
         DvOAdNOuIXpLezgI6xXa8c9NU6ySqRv8PwnI7Gs0+7tCTvX+Db+TUdhSVv8pE2QX7ZIm
         Let1oiM4YWRCF4+hsWqN8YGgJWsAvn6FzXj2s6ejPs+UawezoOvHY4ZtUXvGa1N6Ix0X
         eE6g5DmN2nyuSeWO1imJg00/0Dq/pK4mOcBDR4wK7LuFJ3e+Ee2TicGbXKjTKTrKrjd1
         otPw==
X-Gm-Message-State: AOAM530KLxTvrtzq6KNJAJQxEFtF3G0RaaAgUa9Rte6KeKPzmfkmPI0t
	V4VHL3j9OFp2UeKD+AghSaU=
X-Google-Smtp-Source: ABdhPJy05XpfCg0lQ8eH6UrxjPVKhZ7It5t60LKiUg1hzYpQTA+4/GD9+ahPfkOKuRDzEjQMsDwivQ==
X-Received: by 2002:a2e:83d7:: with SMTP id s23mr4474062ljh.340.1601890171246;
        Mon, 05 Oct 2020 02:29:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1985779lfn.2.gmail; Mon, 05 Oct
 2020 02:29:30 -0700 (PDT)
X-Received: by 2002:a19:7108:: with SMTP id m8mr5909479lfc.335.1601890170234;
        Mon, 05 Oct 2020 02:29:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601890170; cv=none;
        d=google.com; s=arc-20160816;
        b=jvGPD4DIKREhk6fNqvaCcORVJtDS9jXX9GfKaYhIJF9SHV3S/azgYbroO7ibQdenwJ
         JdyzsnDxVAMWl0fWaSQYFSvi3P64rGZC19ejkD84fe5melYYxVUyRtt7y6VcmufEkrTM
         5s+Yccun4yukIGU3pfewSTNjp7cA/mMPN9nB31xZmE01YU35uZ3oRUn6zFPW1fTAlDml
         2FEnbLTWWpEEvD6nanp7CicIuMyA3xTXxtd4B4is+jtMaSJrz08IBKHvCMGBxFEnXB42
         XNYAtTkQ54wcJubSXe6dKuCOJcK4AeYHtvImtsIrkDciECsARNWrPog1uvBfHqkmOnSU
         BBpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NkkZ0AZItfPzXXyiWUs3wdbhFkdEuozzWE5YN7fX2Ds=;
        b=LhoU+X6PgBf3iM3hhqGZg5IayIFbIWc5rB6C495P3HCbrczJ2ZBfBr1lyQP7RhKcuO
         55DTKXC8f49jHCdhn02Y/XAcgUtP5d8ShTULvYnT+N3DoIla7Gzv9Uv7arxrrZZ9jIKh
         0uSMW1UCWE/Ad1CnplQgdNFNtxmHo3mx1HjcEf5xDI1Mko0MIeergT4FItSkBpzenUUK
         TGxPW3iDnxd7MfUu6GK6ZJ9qWP4TF3Gat1WNk5vYFluu8oaExJk/B2RRYfQIyVS177ER
         kN+DQ7IeK/eXceck9JTDMpvSte2QBHYaqehCc/WUZAGIHsCMAR9HUE5XkWccPvJrHS6e
         BkNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RD6Sa7SS;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id w14si77366ljm.4.2020.10.05.02.29.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 02:29:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id d81so2807999wmc.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 02:29:30 -0700 (PDT)
X-Received: by 2002:a7b:cd93:: with SMTP id y19mr15306469wmj.112.1601890169505;
 Mon, 05 Oct 2020 02:29:29 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-6-elver@google.com>
 <CAG48ez3X4dqXAEa7NFf6Vm3kq6Rk+z0scWqK6TV6jTo5+Pu+aA@mail.gmail.com>
In-Reply-To: <CAG48ez3X4dqXAEa7NFf6Vm3kq6Rk+z0scWqK6TV6jTo5+Pu+aA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Oct 2020 11:29:18 +0200
Message-ID: <CAG_fn=Wsxd+7COTzkqg-h82EzZgHq_bAM+u3u2rMh6VOmVQTdg@mail.gmail.com>
Subject: Re: [PATCH v4 05/11] mm, kfence: insert KFENCE hooks for SLUB
To: Jann Horn <jannh@google.com>
Cc: Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	Andrew Morton <akpm@linux-foundation.org>, "H . Peter Anvin" <hpa@zytor.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RD6Sa7SS;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as
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

On Fri, Oct 2, 2020 at 9:07 AM Jann Horn <jannh@google.com> wrote:
>
> On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > Inserts KFENCE hooks into the SLUB allocator.
> [...]
> > diff --git a/mm/slub.c b/mm/slub.c
> [...]
> > @@ -3290,8 +3314,14 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, =
gfp_t flags, size_t size,
> >         c =3D this_cpu_ptr(s->cpu_slab);
> >
> >         for (i =3D 0; i < size; i++) {
> > -               void *object =3D c->freelist;
> > +               void *object =3D kfence_alloc(s, s->object_size, flags)=
;
>
> kfence_alloc() will invoke ->ctor() callbacks if the current slab has
> them. Is it fine to invoke such callbacks from here, where we're in
> the middle of a section that disables interrupts to protect against
> concurrent freelist changes? If someone decides to be extra smart and
> uses a kmem_cache with a ->ctor that can allocate memory from the same
> kmem_cache, or something along those lines, this could lead to
> corruption of the SLUB freelist. But I'm not sure whether that can
> happen in practice.

From cache_init_objs_debug() in mm/slab.c:

                /*
                 * Constructors are not allowed to allocate memory from the=
 same
                 * cache which they are a constructor for.  Otherwise, dead=
lock.
                 * They must also be threaded.
                 */

So, no, it is not allowed to allocate from the same cache in the constructo=
r.


> Still, it might be nicer if you could code this to behave like a
> fastpath miss: Update c->tid, turn interrupts back on (___slab_alloc()
> will also do that if it has to call into the page allocator), then let
> kfence do the actual allocation in a more normal context, then turn
> interrupts back off and go on. If that's not too complicated?
>
> Maybe Christoph Lameter has opinions on whether this is necessary...
> it admittedly is fairly theoretical.
>
> > +               if (unlikely(object)) {
> > +                       p[i] =3D object;
> > +                       continue;
> > +               }
> > +
> > +               object =3D c->freelist;
> >                 if (unlikely(!object)) {
> >                         /*
> >                          * We may have removed an object from c->freeli=
st using



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWsxd%2B7COTzkqg-h82EzZgHq_bAM%2Bu3u2rMh6VOmVQTdg%40mail.=
gmail.com.
