Return-Path: <kasan-dev+bncBCMIZB7QWENRB4P3Y33QKGQE4XMHQ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 68CE8204C68
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 10:31:46 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id f16sf23462804ybp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 01:31:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592901105; cv=pass;
        d=google.com; s=arc-20160816;
        b=EFTUlbPpikMTqJJosZTsYWBJlGeDw9ILT7CeqjCbYtFpWfIgjJXLI8G/E+FZ6Rft4O
         v8oovszW4z9A3BGOwGAk/NW8EcyTZxsJxQENGV6gPxKgqLXh244UvDPfAaPdPW0MEySN
         v7cZWCvuAExy5xmtmI/n3hhssQDQU53UQSDzAO+KVzKEibDqjnmLGFbAxau1XTRVum7n
         Y+BdA5r68EOP3KuIKIF+k6T0hC0GXWCAnfDVfz/lofQWianTJgP+lvYFOE40ZbfWVtUs
         oImBBHG3WIR3x1jaPdnOCtYhTAMTFb8kZ6XdXrbhQrrLC5Tp0epZ6TKLL4aiKi+qe0H9
         thzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IKlsiH+RrlcDeom90DPn3O/AJFn5Ke5AkWe2vvR5SWo=;
        b=LpMiWU6XyoLicUlB5MBZtjHHOjrf4tLRytNZJO5ZN+KmLUJ+uC8dELrNLCJnc9Xbu+
         QZ2D7+DLPxZNj+knYp7IzSMaXumdk5/1e1NFB0m0z/3MsH0F62nLfVY3vIkpT2TTpNeP
         Yd527dPSe2CWKpFv3NWRsR9k1xGVsZQYMCehIVfHpz9jKrr+wyAv91If5OKzSQfbfM5a
         V6gYhhdAi4qIjXOAJZPE2hIh/NNIhqmzpSQr/8qUVMzgtEJjP0IyVpCOJVmGVenpI7RW
         cula7T7IT351qJQafhkVegYskuW13+OOVWA6UftcxDGp5i24oms32c7qN69DsFiDh+ib
         nESw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pyp7tjOJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IKlsiH+RrlcDeom90DPn3O/AJFn5Ke5AkWe2vvR5SWo=;
        b=Mt0Zwl+SxPxrgh2yPdt63GHjG61HFvQK1D54fD1X6Y46378TzlvSq7QjhFoES3nG2x
         arvLnhGTatamDced3+lIyamZiGZCkAFUqARTK7widMbssYH4RoV27bERnFDHDG+dkPT4
         EZ6UVhD22RG7tYsotpX41zZ5nRgQuSVlGt2zReh5riq7qwT9gTimTcTqIAB7FGqtHA2i
         gl79hbjOYKSmkdn66xp4RQLPVDmWfqaqyHqdsa7aJMvzqZ34CiPOEqShQNS+thJOs08Y
         yEzniCWqKrkfe+JoGyAv9Pv6wl2JCu25N8ErjBwdi/JxBB1p+twwQ4Fs881wVGLgw6/W
         zw5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IKlsiH+RrlcDeom90DPn3O/AJFn5Ke5AkWe2vvR5SWo=;
        b=jUaOFQG7NLiWRMPXNk+Kw9iXupWH/8Ghb1xdWooYV/NGRYdkn2/HCZ8eeSiGFoDTCS
         bc1IDHBTQGDKrOhtTtC3grtWdvEFVci/6Bg9JyfE6Nw8SI/bELberVuQAKHWWu9p+3zg
         c97YMapNn7POOoRELtUTTG1ZGR2i4aKP3W1zgCGPDDt1bhIUv/px4hZ7g5dI1ITErjo1
         pyAS2VUWiz45hDJUk51TVZNewRoQZhgXi/necL9GHZPZSxOsjKsQcrRXeiixVbbAy5c7
         BTCNHb2TUSkUcer9B8iGCcR56kt8t+aWxzMR91Waa13eZO0g9HsJ+PzTkIJAi3C9DPmW
         g6fQ==
X-Gm-Message-State: AOAM530N4XFrPn0aMxDZWrqdB04w1nznbasU2ypYZXFcaMqWk9KQtfhr
	t4CEz7zxMgMdSdmQwH7S3Ys=
X-Google-Smtp-Source: ABdhPJy+I0c1o6vgioPOVjzNRpnvROrdfG7eO7AZ1A2s1Tm2hLOXMnErlpCXBMKFK9+ojOa70ZhV8g==
X-Received: by 2002:a25:4901:: with SMTP id w1mr35222010yba.31.1592901105197;
        Tue, 23 Jun 2020 01:31:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c785:: with SMTP id w127ls7517919ybe.7.gmail; Tue, 23
 Jun 2020 01:31:44 -0700 (PDT)
X-Received: by 2002:a25:324f:: with SMTP id y76mr35403432yby.207.1592901104795;
        Tue, 23 Jun 2020 01:31:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592901104; cv=none;
        d=google.com; s=arc-20160816;
        b=nz+9p8GBsDQGZH6W/n1Py1mvmo8mG2kirVY7OmjYFJFrBtzZnuC+7x6xJ1YD1YdQth
         CmHTNBLb0zBVfICs2EwLSd0US/8Qq+EwKycWAK315g4JdOAXACnpvpmbGjISvRQLN4zd
         5glGtUaD8BbANMXIbv7r2xi1ZpNBoSnQ7kvrOyqDCFKloD1i+gVjxCOOytiORyUin+fF
         EAz2VnTbsXETaNpTh6bRmeeQERzvTciC9JNAl+vqO3WRVl4KVcaHBMR38mBeoXppvCc9
         TxghQFD07UMuinaLMqINCh17PgFIid4xttl42hAJRYOVBfonwUFNZOFUSv8ASHc9kqA4
         5m9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HCA63Bq1RhuGBZe+uCuPvGnPrsrwVNbQ3GCsOT/wmUM=;
        b=mGEWlTsMbSLo+20Ba6zEHyiWEmHhGsQzHWmhwZlYDrXZEU9Ygvo7+Pzw6tl59ltSOE
         sJuzsPclrCvc6uV7qG2l3oG1mFe7K6ho0hTRy4LIpGUAay+cq6LOYHzq/n1c2/lj1ORq
         qDED8ECIr5g2jx3R1IU3PO1my5800hyjTiX4FEJr+RKDbGzSWMc/9ifsdJZs936gaqmL
         8nexKWZQ3q6WqvWXKKsR/cQzVUg284WPyljN/Wq0QUzNL8kduQ12lo8ZQbvtT8sGw9UV
         YeNhNMBPGpuTCP7hFtVCeuOLlpSFNg4h5aZVxMtBSk49U9+qN2x5mF7yz2pl9oERULla
         vUaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pyp7tjOJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id a7si968256ybj.5.2020.06.23.01.31.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 01:31:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id h23so7646024qtr.0
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 01:31:44 -0700 (PDT)
X-Received: by 2002:ac8:7a87:: with SMTP id x7mr20922438qtr.50.1592901104200;
 Tue, 23 Jun 2020 01:31:44 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
 <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
 <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com> <CAG_fn=XDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd+u4wakSG+xQ@mail.gmail.com>
In-Reply-To: <CAG_fn=XDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd+u4wakSG+xQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 10:31:32 +0200
Message-ID: <CACT4Y+ZfDfMGWn1wk6jq0VdkGdC2H7NifYpVCCXwCmX42m4Thg@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Jann Horn <jannh@google.com>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pyp7tjOJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jun 23, 2020 at 9:24 AM Alexander Potapenko <glider@google.com> wro=
te:
>
> KFENCE also has to ignore both TYPESAFE_BY_RCU and ctors.
> For ctors it should be pretty straightforward to fix (and won't
> require any changes to SL[AU]B). Not sure if your proposal for RCU
> will also work for KFENCE.

Does it work for objects freed by call_rcu in normal slabs?
If yes, then I would assume it will work for TYPESAFE_BY_RCU after
this change, or is there a difference?

> Another beneficiary of RCU/ctor normalization would be
> init_on_alloc/init_on_free, which also ignore such slabs.
>
> On Tue, Jun 23, 2020 at 9:18 AM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, 23 Jun 2020 at 08:45, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wrote:
> > > >
> > > > Hi!
> > > >
> > > > Here's a project idea for the kernel-hardening folks:
> > > >
> > > > The slab allocator interface has two features that are problematic =
for
> > > > security testing and/or hardening:
> > > >
> > > >  - constructor slabs: These things come with an object constructor
> > > > that doesn't run when an object is allocated, but instead when the
> > > > slab allocator grabs a new page from the page allocator. This is
> > > > problematic for use-after-free detection mechanisms such as HWASAN =
and
> > > > Memory Tagging, which can only do their job properly if the address=
 of
> > > > an object is allowed to change every time the object is
> > > > freed/reallocated. (You can't change the address of an object witho=
ut
> > > > reinitializing the entire object because e.g. an empty list_head
> > > > points to itself.)
> > > >
> > > >  - RCU slabs: These things basically permit use-after-frees by desi=
gn,
> > > > and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't work =
on
> > > > them.
> > > >
> > > >
> > > > It would be nice to have a config flag or so that changes the SLUB
> > > > allocator's behavior such that these slabs can be instrumented
> > > > properly. Something like:
> > > >
> > > >  - Let calculate_sizes() reserve space for an rcu_head on each obje=
ct
> > > > in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> > > > call_rcu() for these slabs, and remove most of the other
> > > > special-casing, so that KASAN can instrument these slabs.
> > > >  - For all constructor slabs, let slab_post_alloc_hook() call the
> > > > ->ctor() function on each allocated object, so that Memory Tagging =
and
> > > > HWASAN will work on them.
> > >
> > > Hi Jann,
> > >
> > > Both things sound good to me. I think we considered doing the ctor's
> > > change with KASAN, but we did not get anywhere. The only argument
> > > against it I remember now was "performance", but it's not that
> > > important if this mode is enabled only with KASAN and other debugging
> > > tools. Performance is definitely not as important as missing bugs. Th=
e
> > > additional code complexity for ctors change should be minimal.
> > > The rcu change would also be useful, but I would assume it will be la=
rger.
> > > Please add them to [1], that's KASAN laundry list.
> > >
> > > +Alex, Marco, will it be useful for KFENCE [2] as well? Do ctors/rcu
> > > affect KFENCE? Will we need any special handling for KFENCE?
> > > I assume it will also be useful for KMSAN b/c we can re-mark objects
> > > as uninitialized only after they have been reallocated.
> >
> > Yes, we definitely need to handle TYPESAFE_BY_RCU.
> >
> > > [1] https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&com=
ponent=3DSanitizers&list_id=3D1063981&product=3DMemory%20Management
> > > [2] https://github.com/google/kasan/commits/kfence
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZfDfMGWn1wk6jq0VdkGdC2H7NifYpVCCXwCmX42m4Thg%40mail.gmai=
l.com.
