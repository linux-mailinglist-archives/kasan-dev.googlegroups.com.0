Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5X6Y33QKGQE2C7XCBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A33AC204C8B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 10:38:14 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id r10sf7739061lfc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 01:38:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592901494; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjjQDEIfyTOoaYAsAJalt+BWDVIZB8Q9TBztW33oJzJb+/3JmdDPpKHiAc7yu3rRL4
         OfTODzwU5F8DeWHLkUS1ZKbotfLSWkCGenFm5j+hxUuxNirJSk6Px9xZESk4ikwigIJZ
         sF/pLDFFPcQ0zIz94ETN//VGp24qD5COOr2KaWYPU+2KsQLOchRcHB/TqNvrKc1qdKLH
         vmbzeer2jtJwDsJuyrYvZ7266RQr2tmZW3z3xGEh8Czm1QuMQALTWm9SJ1i0w3hi7dWN
         5E/mtSLpzmcP+HT1hrBdvn2jmUBmgCD0T6YpqOC1Z2Ldpnhke/DQVWxxD9bAImOn+O9t
         ZpYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=21JblqEi2XZKhc7Jc6GOodbx5qKscLgvLNippYokyOY=;
        b=SqimyRSu2azLo39WM7kKq4m/m5SQSfB/hAXeZNjX24lDtS50MbKeOM7Snap+jrWQYS
         pGvkp4FStTF5gfPkhy+Sb4fT4dWBkQBpvgc5cY2M7NR3FPsHLrmwZCx47hmdVc0XTglQ
         Hwg7ieGykwNPJxJgHE83/RKSWNBGF7KlDBXO/hvNybUkkMCJ0Tx2uJJkRkua0SsjCGte
         pr5/vqWNpWr/k6YdCbGNOGfDgN6NiaNi1d014kp0vLDovs7Pq31gAVDRHUgAePovpQWn
         tVhjtZ0Od68C39JX0HrZgcmCFo55zxkLdzkw8cvDjiomBQ3uz4toQj55DmrLiIFHup5n
         oGDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NNOEMG0S;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=21JblqEi2XZKhc7Jc6GOodbx5qKscLgvLNippYokyOY=;
        b=pRFzLh1iybzf2VOsimCkSU7jtDkssTMF4sEu43d627cwpeKUh7cNtWUEATcofFnKVE
         u3lnTtawbvpzKlnxhmVcNEl5+KIbEbHrGMvn9xIxGRQBcpSsqVhK5TkwsFVXpka6CetS
         LJTXPKNc93BoOW7uvNIk+InRP621bplCRcnf1qPkgyZurardHOVchcskrYowLMiqtpPa
         867r+2h8dR83tzSsmb0ooGLo5H50TWSTc/mPFkzZogOl075bcjmbfJug9/mfU+RHOgHH
         Vh30FO4Ri/Y1XTc9ucEkLYdBXzTINLCnAO9a9q81V5jz3TU5+ZmOPCLyeKGhGFJHJ9D+
         ITrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=21JblqEi2XZKhc7Jc6GOodbx5qKscLgvLNippYokyOY=;
        b=Tk/CK9YzBRP6irmXAA/3TXm0NGZpGNEYr/WpW4V8bDI3GxGxWOtlKc0Pe/rh/fUGL/
         jVuWdOuoJC/hXxTPdACjCXE6UNdS8sEoJRJIgOMaOB6fe+jYXDKHEHqphYk1T1qUmAG9
         8rwdFHotYRHLjeGn5dmjaMJvkhYfP2OttXv48/N1SQ8yZQDKHhvDGes7WsQTO1pV/YwU
         TUB/SEJ1nNUNpnLqssh91NmtqLQqIQQmnO/A4eYF8dUe58XBBCpCbPP4l9NUGROjFT5k
         7ZgtIySJ/zwHQenX1F0AfoPfela1UwuJOl2uQrYnOmFta8o0TAPqwFOxBcm8JJIz2hOK
         MIPg==
X-Gm-Message-State: AOAM530ud/pGdVq4mguw7xxkZZn1WFTFCmWoT0zRrUw2K8QVXgl4EZ4H
	BJtVKfswPD0QEm0V8VSXYWY=
X-Google-Smtp-Source: ABdhPJyn8tt0f3YCufa1EKXhViDIfTaJul6uOVNblfbfvlUyM040tJFlxMT/zS+k9VPUvaZRYhjmvA==
X-Received: by 2002:a2e:b4da:: with SMTP id r26mr11018922ljm.28.1592901494192;
        Tue, 23 Jun 2020 01:38:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f95:: with SMTP id r21ls2759152lfe.3.gmail; Tue, 23 Jun
 2020 01:38:13 -0700 (PDT)
X-Received: by 2002:a19:435b:: with SMTP id m27mr12259779lfj.40.1592901493571;
        Tue, 23 Jun 2020 01:38:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592901493; cv=none;
        d=google.com; s=arc-20160816;
        b=DphzfVcZlyOtrcpBEoxHonclMhGlazDVIpJrMXI+ZgVZDRL8Pgz4Qd4fUPgPsQ6s8C
         22pOU6MDvvBJfLjnJj0vaMgJbdYJAsM2Hv480zWaaPl8dka3lBtrvL0M9+p0HCH+2oOn
         fl//6ao96cfJO9KStAThiFApgUQFPBiIlgtQr3SNqYXIG9PRlIa/QAG5qnFVpIz7I3SA
         61XBLfUr7bc2YoUKzwReTLyGmqcXXDFrVQ4rCUcIotqVWn6rm+yHyBLLbRQA9fTcI1sD
         1/XoJJqYFPnjdtrBXLNDJd88UTZHUkS/nkmbhAm5nHUbFGBZ2elqr32KLNZzmz+0t3aq
         8C2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4WsWkj4zSWAAdD1NjDPTNdEL45zLPcQEEtkDieAodAA=;
        b=zAdFpQPDncCTNKWoFhgbtnkhZp9sTqWYscLKFqFKT571x0ZM7ez+tOxb7fYHoK+AG5
         kmz4egos0VkQYeLBM5DDfxewR6hyJaMZL79vG7tixLzOSRBVyciBUXeWqk5G1lqPIYzS
         sTQt7LEEieejhSkZfS9uuy4KaM0uZyMXSRTimEZDv9O+qTeQ7TJ1gxFyDM17bd4+njlm
         0bjME7uHoj+MmGDBTx0RmDZcjLgT/5v2jGLDjAlxJhXQ6W1E3vmARIv9TQO2Km9X3NVI
         dWGk4Yxe0/5oVYA72MjzS9AeOKynPzt7Netjrroo32bycIWwBhSsnvrSm7puunnDrwju
         cOhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NNOEMG0S;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id b26si200983ljo.6.2020.06.23.01.38.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 01:38:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id q5so7195350wru.6
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 01:38:13 -0700 (PDT)
X-Received: by 2002:adf:97cb:: with SMTP id t11mr23818010wrb.314.1592901492799;
 Tue, 23 Jun 2020 01:38:12 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
 <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
 <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com>
 <CAG_fn=XDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd+u4wakSG+xQ@mail.gmail.com> <CACT4Y+ZfDfMGWn1wk6jq0VdkGdC2H7NifYpVCCXwCmX42m4Thg@mail.gmail.com>
In-Reply-To: <CACT4Y+ZfDfMGWn1wk6jq0VdkGdC2H7NifYpVCCXwCmX42m4Thg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 10:38:01 +0200
Message-ID: <CAG_fn=VEb7XYwi0ZnOXRx-Yss++OhnpKCO-7tFvCOp4pi4MLcA@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Jann Horn <jannh@google.com>, 
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
 header.i=@google.com header.s=20161025 header.b=NNOEMG0S;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as
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

On Tue, Jun 23, 2020 at 10:31 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Jun 23, 2020 at 9:24 AM Alexander Potapenko <glider@google.com> w=
rote:
> >
> > KFENCE also has to ignore both TYPESAFE_BY_RCU and ctors.
> > For ctors it should be pretty straightforward to fix (and won't
> > require any changes to SL[AU]B). Not sure if your proposal for RCU
> > will also work for KFENCE.
>
> Does it work for objects freed by call_rcu in normal slabs?
> If yes, then I would assume it will work for TYPESAFE_BY_RCU after
> this change, or is there a difference?

If my understanding is correct, TYPESAFE_BY_RCU means that the object
may be used after it has been freed, that's why we cannot further
reuse or wipe it before ensuring they aren't used anymore.
Objects allocated from normal slabs cannot be used after they've been
freed, so I don't see how this change applies to them.

> > Another beneficiary of RCU/ctor normalization would be
> > init_on_alloc/init_on_free, which also ignore such slabs.
> >
> > On Tue, Jun 23, 2020 at 9:18 AM Marco Elver <elver@google.com> wrote:
> > >
> > > On Tue, 23 Jun 2020 at 08:45, Dmitry Vyukov <dvyukov@google.com> wrot=
e:
> > > >
> > > > On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wrote:
> > > > >
> > > > > Hi!
> > > > >
> > > > > Here's a project idea for the kernel-hardening folks:
> > > > >
> > > > > The slab allocator interface has two features that are problemati=
c for
> > > > > security testing and/or hardening:
> > > > >
> > > > >  - constructor slabs: These things come with an object constructo=
r
> > > > > that doesn't run when an object is allocated, but instead when th=
e
> > > > > slab allocator grabs a new page from the page allocator. This is
> > > > > problematic for use-after-free detection mechanisms such as HWASA=
N and
> > > > > Memory Tagging, which can only do their job properly if the addre=
ss of
> > > > > an object is allowed to change every time the object is
> > > > > freed/reallocated. (You can't change the address of an object wit=
hout
> > > > > reinitializing the entire object because e.g. an empty list_head
> > > > > points to itself.)
> > > > >
> > > > >  - RCU slabs: These things basically permit use-after-frees by de=
sign,
> > > > > and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't wor=
k on
> > > > > them.
> > > > >
> > > > >
> > > > > It would be nice to have a config flag or so that changes the SLU=
B
> > > > > allocator's behavior such that these slabs can be instrumented
> > > > > properly. Something like:
> > > > >
> > > > >  - Let calculate_sizes() reserve space for an rcu_head on each ob=
ject
> > > > > in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> > > > > call_rcu() for these slabs, and remove most of the other
> > > > > special-casing, so that KASAN can instrument these slabs.
> > > > >  - For all constructor slabs, let slab_post_alloc_hook() call the
> > > > > ->ctor() function on each allocated object, so that Memory Taggin=
g and
> > > > > HWASAN will work on them.
> > > >
> > > > Hi Jann,
> > > >
> > > > Both things sound good to me. I think we considered doing the ctor'=
s
> > > > change with KASAN, but we did not get anywhere. The only argument
> > > > against it I remember now was "performance", but it's not that
> > > > important if this mode is enabled only with KASAN and other debuggi=
ng
> > > > tools. Performance is definitely not as important as missing bugs. =
The
> > > > additional code complexity for ctors change should be minimal.
> > > > The rcu change would also be useful, but I would assume it will be =
larger.
> > > > Please add them to [1], that's KASAN laundry list.
> > > >
> > > > +Alex, Marco, will it be useful for KFENCE [2] as well? Do ctors/rc=
u
> > > > affect KFENCE? Will we need any special handling for KFENCE?
> > > > I assume it will also be useful for KMSAN b/c we can re-mark object=
s
> > > > as uninitialized only after they have been reallocated.
> > >
> > > Yes, we definitely need to handle TYPESAFE_BY_RCU.
> > >
> > > > [1] https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&c=
omponent=3DSanitizers&list_id=3D1063981&product=3DMemory%20Management
> > > > [2] https://github.com/google/kasan/commits/kfence
> >
> >
> >
> > --
> > Alexander Potapenko
> > Software Engineer
> >
> > Google Germany GmbH
> > Erika-Mann-Stra=C3=9Fe, 33
> > 80636 M=C3=BCnchen
> >
> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > Registergericht und -nummer: Hamburg, HRB 86891
> > Sitz der Gesellschaft: Hamburg



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
kasan-dev/CAG_fn%3DVEb7XYwi0ZnOXRx-Yss%2B%2BOhnpKCO-7tFvCOp4pi4MLcA%40mail.=
gmail.com.
