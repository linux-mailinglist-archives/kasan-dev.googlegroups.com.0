Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQG4Y33QKGQE7X3LKRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 005FC204AF4
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:24:49 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id u24sf4759851lfl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 00:24:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592897088; cv=pass;
        d=google.com; s=arc-20160816;
        b=M58yeqPrHmM9jrkNhf5CIg5DRWgMG/khyWJhN+bFc8zUVDO4z+m5n962NXSlUbBWfh
         q49WwTKgj2ukFCaZ+ViM+rBj5rQBTj4KUEiyk+64GKWxjtgGIw5iG3Ofz0MCdV4ak2hO
         LbXOlQK8TF1yt5dJ1HYfcxRYPifS99E7VzPILxN9t2HPR+ropYq8R9anRKoGKgXvYKuN
         JUJd0mdh5gF5N/vVjFOMIr3butfjf9aY9o3p47KwfC+cG9N6jVnsb6qABj09FAydgDUE
         6mRz+ar29pIRUCm7JFiuBleqFZEpEyyZwAPPuhltUBu95lRw+CbQ1m1AhCH51OmXzFVL
         Afsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iokTA6kvW7oI7dbu5QOQrouqrzIV8L0+Su5sXWX1mC8=;
        b=iz4cKk7MGmLsQIT+axLS+fWWRGSFgS1M63TQ1e6BQddIqzfAhqnF1cjCR1l8T33mbz
         1PqZhlVTndWt7GFoX/UjDb7Ar/cD6xNWlafbzdKCNhQ3oztofKZWFQk9rSbFC2xi2J/q
         Ow5MwXx0cqto31vWFZUjCUHB3mxmiY+fx2WpH1zmhI+C1WvkgpqhM6ah8yOqnijVOxfO
         7/KhayyNsSjNnisPNF/KnI8RBp4j/s6mFM17bcLCMNKbZPxUDbLE+X7MrF4TdbqnA7Ww
         q1j11robe1ViBV/z55phclE7W3bAu4hZzBG8hYfezKzHndL3bghIrkw08VFtAQddPfZe
         pbcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rCYLtS8h;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=iokTA6kvW7oI7dbu5QOQrouqrzIV8L0+Su5sXWX1mC8=;
        b=Q4ThCaM9AxjzYKREevHnSBalRJTGImlJglLwsnDsC3dO4fVWpZAYCKZ+b8n4mww3F9
         YsTYeGqehGN3cTxiQ470/auo3SK+RY1opYlDcX4Ak2J7se8U0KKicD4XMqm21Vt7R85l
         u2qbG/OhrMxQ30Shqm9hH2r3MScybjWhxFsDHtG8K7M34B6v3Shufq2N74pQWEONB7zD
         b5iQtbtoB4TS4+IG/Dho13KCOOVWZD4KP16ec2EjdQq+Xyvbfj67nyNyKwzCepApT/rd
         9c12tmyDlalGlKe5rGPz5e6vQZke3QRcGQxbyqzgEPk8hqepWnV8Oa5jI+qESOzvlj1N
         Q0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iokTA6kvW7oI7dbu5QOQrouqrzIV8L0+Su5sXWX1mC8=;
        b=VBtznWR9aIgfUruOxon+5yaFr05nO3v7hkRQm8awRBjwDNfaScYCHpzJdehyIAAkMR
         0JLfisVUO9btbnKgm/tFKk1VbRkYTqIBbGsyFAb49w/62C1yXEeEVHTgOpW1B8fz5Bjh
         V/Ke9IHCaGDwiSjnH+XxU6HdvXlgOAWD4DrReMtxIgtO/vgKvZA+iCNK1T7hay7R7hkl
         Xnatw5Y1rGfyADc7alzvsxifsgRaeV8ObsfdeeK2E9sjehv8YKt1J9nRc0VWHWrAvXlO
         jINQpLBhWKrLrCeJkLaTIQu+ZEwIjIaGlXy+XI11P11R07y2xVaXNohTERlcH7jfNC+p
         KnwA==
X-Gm-Message-State: AOAM531yfjfCpF/xjK8QNu2PMvEgbURguEhVs0TSmEGxSNl15z5a98LW
	Gp1IHq0eQVmWOwN9D4/s5nM=
X-Google-Smtp-Source: ABdhPJx8mwW7di0p1K2TtwX126YN9E/Fyn553YBUHQiyuy0aJLvFuMKl4EpibIPcQTK8JykeBU+98Q==
X-Received: by 2002:ac2:5467:: with SMTP id e7mr11180815lfn.122.1592897088377;
        Tue, 23 Jun 2020 00:24:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a02:: with SMTP id h2ls3762912lja.6.gmail; Tue, 23 Jun
 2020 00:24:47 -0700 (PDT)
X-Received: by 2002:a2e:97ce:: with SMTP id m14mr10303428ljj.216.1592897087779;
        Tue, 23 Jun 2020 00:24:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592897087; cv=none;
        d=google.com; s=arc-20160816;
        b=OkILCkfLSKfSZVZRXIVjRoP+DX+IYVqZqKsvuEMKyWDHfapDIQs6Do0NjQiNF2ku7d
         C8Qmo74rdHoEMrIvgEP5+rpgtCS6DyzVQQ/7r+ayZFeZZ+iWYqz7fk/1+KdRp80JpJCl
         i5ozPTdaddvh2MY8OnoBMx3dcaqRY1VrqMkv04ijq3cJ7od4z2du3VSQvjouktzYmq+Q
         uSfrDlfGg76hy8xp/xdrsmG/d+2axlCEx/h75r/jZ7LrPzq89xo6vXxCRGrwHmpoYaPe
         GG5dRgoEBfzvWTLjfsHw2QMvAM9PUVpugQpi788NN1yTULP+3P6GviBUYbOO1lblGEDI
         bApg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uWsUrBI2cF3cgBJXHkC6C40URSuY/BmKIvQNeI/0//E=;
        b=MdYXVS4RMWfw9uUiR7TlbrBBBYZE/KzwLqY8CPn90Wf1qO6JZERDG9q/OKFjP6WUEM
         My7nbOPtR9y+EWRhHr7EFYLDe+BB0/d2Q4o+RZaVdO8E6UWsYvLuSLF6K5dmWk9rzskJ
         hvYeMCDmjbKrrdFLWybJ96hss+20p5PJjD02s3bizw3kh4Ijkt85CtVq6W1CyXSIbbsR
         c35oYq8ygLMzdYYf2SvINXg/GjkLd9NQYBeOKIV0vUZURQQH0KvDJ6h1VOuNfN5dOJe5
         GUi3W7SgGq3i5DjGRiZfz+T0GlqIJDsmXB1+Lc0JTTCqGl7QMbIFTD1WndRTP8s9mE0F
         3P+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rCYLtS8h;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id x20si1205436ljh.1.2020.06.23.00.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 00:24:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id g21so2080678wmg.0
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 00:24:47 -0700 (PDT)
X-Received: by 2002:a1c:4c16:: with SMTP id z22mr22271690wmf.103.1592897086960;
 Tue, 23 Jun 2020 00:24:46 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
 <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com> <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com>
In-Reply-To: <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 09:24:35 +0200
Message-ID: <CAG_fn=XDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd+u4wakSG+xQ@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rCYLtS8h;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
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

KFENCE also has to ignore both TYPESAFE_BY_RCU and ctors.
For ctors it should be pretty straightforward to fix (and won't
require any changes to SL[AU]B). Not sure if your proposal for RCU
will also work for KFENCE.

Another beneficiary of RCU/ctor normalization would be
init_on_alloc/init_on_free, which also ignore such slabs.

On Tue, Jun 23, 2020 at 9:18 AM Marco Elver <elver@google.com> wrote:
>
> On Tue, 23 Jun 2020 at 08:45, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wrote:
> > >
> > > Hi!
> > >
> > > Here's a project idea for the kernel-hardening folks:
> > >
> > > The slab allocator interface has two features that are problematic fo=
r
> > > security testing and/or hardening:
> > >
> > >  - constructor slabs: These things come with an object constructor
> > > that doesn't run when an object is allocated, but instead when the
> > > slab allocator grabs a new page from the page allocator. This is
> > > problematic for use-after-free detection mechanisms such as HWASAN an=
d
> > > Memory Tagging, which can only do their job properly if the address o=
f
> > > an object is allowed to change every time the object is
> > > freed/reallocated. (You can't change the address of an object without
> > > reinitializing the entire object because e.g. an empty list_head
> > > points to itself.)
> > >
> > >  - RCU slabs: These things basically permit use-after-frees by design=
,
> > > and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't work on
> > > them.
> > >
> > >
> > > It would be nice to have a config flag or so that changes the SLUB
> > > allocator's behavior such that these slabs can be instrumented
> > > properly. Something like:
> > >
> > >  - Let calculate_sizes() reserve space for an rcu_head on each object
> > > in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> > > call_rcu() for these slabs, and remove most of the other
> > > special-casing, so that KASAN can instrument these slabs.
> > >  - For all constructor slabs, let slab_post_alloc_hook() call the
> > > ->ctor() function on each allocated object, so that Memory Tagging an=
d
> > > HWASAN will work on them.
> >
> > Hi Jann,
> >
> > Both things sound good to me. I think we considered doing the ctor's
> > change with KASAN, but we did not get anywhere. The only argument
> > against it I remember now was "performance", but it's not that
> > important if this mode is enabled only with KASAN and other debugging
> > tools. Performance is definitely not as important as missing bugs. The
> > additional code complexity for ctors change should be minimal.
> > The rcu change would also be useful, but I would assume it will be larg=
er.
> > Please add them to [1], that's KASAN laundry list.
> >
> > +Alex, Marco, will it be useful for KFENCE [2] as well? Do ctors/rcu
> > affect KFENCE? Will we need any special handling for KFENCE?
> > I assume it will also be useful for KMSAN b/c we can re-mark objects
> > as uninitialized only after they have been reallocated.
>
> Yes, we definitely need to handle TYPESAFE_BY_RCU.
>
> > [1] https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&compo=
nent=3DSanitizers&list_id=3D1063981&product=3DMemory%20Management
> > [2] https://github.com/google/kasan/commits/kfence



--=20
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
kasan-dev/CAG_fn%3DXDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd%2Bu4wakSG%2BxQ%40mail.=
gmail.com.
