Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNUUY73QKGQE2YTEANQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7E9F204DE0
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 11:24:06 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id t145sf3355783wmt.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:24:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592904246; cv=pass;
        d=google.com; s=arc-20160816;
        b=aAAVyXW7R3A3mzqfpUru7WgR28NqW52sTmR1R2RePUVQlAdLC/bUHUpen2mjtBQvQ9
         QmJ+u70YX/dPj125PVjGLoQDoSne6/NcMP8OO5eIYj41sUjBp1q9vzNR/7RACYmh7fPZ
         Gf/tVm+NvW2EWIAQehayqZpU2HOHeK4QD447PhSZ/3+WAyfUYOsUcYHxwfM4t6Wl+4W0
         cBd4oM0jqcsaVBnITniaEG9TuouMDxdBYzQGanQtRbPzW0NBtE1hlLRwCTtTqvdmW/i8
         k67uHW2yv70HtGlqcXe7pFvw0dtNga/suVTkchTfL3djjkAiwMkZeYYK4AmQOav9r//C
         J34Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=izM9KX8CxlkDT/eBkaxr2mGU3ehfTZMeiUSnYRVLb2o=;
        b=ESPNvdTP6zrw4cXruzmSXk2KqnNKMOlhhyALaXcE+Rf0emzQj2ZrV44asI464xAR3D
         f7kKeUlvqTVNaAlW61yO9wjeHTgoVJN/joQ7jLuNx/jFt+psR9+PxTOszB43vZHzRXor
         AQ7jRxFt1PADERiU1+n6aznLPYweaFTy6CJg9X/Rg0jmwI99rS78GNijohVByualbus1
         04VD3Jliv+W8C1yCTvMGsHVGy7JIeHf8bdDNav/W2/M1zuIblYU5wXc0qTcBBHPdN7bW
         8bTqFmsl96CZBm02AvgVIlwap9fzU3sbh7eXKQgg34XnORz5VKgZOOsNfZaujXgFAi07
         QuyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P5j+klQm;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=izM9KX8CxlkDT/eBkaxr2mGU3ehfTZMeiUSnYRVLb2o=;
        b=F6bX/Wl8mzCHlEcy230wvlEU6ZruJUBjmY+aTzIuK43pwZQVx8Vu5HstPJ61YOchMT
         lid7zzXe5R/b70mvlanHS77Kz3iX4JG7pkgEe8iQBOe8AtDICBlvlzDTRC0P1gT7xD2V
         BgmiFnaMzEu6YjtNWrJGXPBXt6kaaKcBR3mUTjQjvMBk4nPcA+GJVmC2/7Svrr9HEQqU
         MKP4rqhY7LwcLZ14lPZaoM1Qhurk/nXbbFa+nnN65D+3/1Lma20eC0K4uTDGOweC8WSi
         SsX7fqC9Hr2b7maMeRpYma2QCbUZOdJoRLRLI9Ad0IchxX4qzEpDcBWFfW6dvGNUd+gk
         c4FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=izM9KX8CxlkDT/eBkaxr2mGU3ehfTZMeiUSnYRVLb2o=;
        b=h8QoDWUdZ2SvX1n9dyeTtFyAAUQgFYaQxWvfqPp7CE7YRqI5W0LmIaIvHDTpgjryCQ
         qu741E/QWc/ndR4WJtb2C/R4u+q7pzAnKQZtERGGCytBfqvph9J3sRigviuv9tMN7IfR
         42BaBWyeUvXRhtd+C39e1+DQ8Yat/67WSmKp2VSzhq08Q0roEemKCtoUWlXT4M8R3IFb
         FWUBLE/KJhhwuk+Alk9UU5UhGhofy/K67SgF8VIr0pGfiBX/+2To8pUo8u6efpwuD8ac
         qsJJ4+r2jsBLuetvWYFGlzQjpbR4qKyX326el4oPuCsENdhGWdEPdWfg0gYdpPMxC+VO
         j1og==
X-Gm-Message-State: AOAM530fHdWRkocdGeLCXF73BYd3PJ1lEbRHVhKqpSGIuxUPrMY4E31h
	q193DiK2ucbmSYnYeU3SX5Y=
X-Google-Smtp-Source: ABdhPJwgdi+50eMgRS4caxSw16PdCI4z/GNlE3Ct9dqUplujjtwUzq0/Z1Tbg+qNdNWF/js85VLR7g==
X-Received: by 2002:a1c:acc3:: with SMTP id v186mr6043285wme.79.1592904246480;
        Tue, 23 Jun 2020 02:24:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2885:: with SMTP id o127ls1119793wmo.0.canary-gmail;
 Tue, 23 Jun 2020 02:24:06 -0700 (PDT)
X-Received: by 2002:a7b:c043:: with SMTP id u3mr24316070wmc.185.1592904245908;
        Tue, 23 Jun 2020 02:24:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592904245; cv=none;
        d=google.com; s=arc-20160816;
        b=X+ExzR8soT+Y/V0VPx67jxYuddYC+HlsL2oeYI2t45b0gpsGWADQXvvzG3ZFXsNoEp
         1xXXOhGQ9JtuPQH4QjmyH01AhGqOSGL2ETnifE7PvuADhQupkkOFDlD28IQa73qVbJWL
         G20saWLGKd3r00c8YNvSPFsCp/SQvqsSr2YrPM6/8NI63VE9ajnG+dIwuwCHa0RSWWBM
         kd4tHUP3dvMekZLXsJBfSAb2hiYqL1FRXZuD2nDPZlM3w/f/oBQEKSL7GCfV875Yuhbz
         CExJR4iIzLTPtBxTJhUwlJA/jqzQrKzu6gYBv9w/gJrQqEOmIEsScyVSqvsp5p4BpBhh
         x1pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wxjhgLY6Z/ti9Feqdaan9z5FrH6qnMdHUeGIKwlfPu8=;
        b=e3vuBVOCV505T1h5ZYZejx+Q1NJ4D0uRCPAHMgwwnTuRurjxpmgCUv08b6kY5ufOQ3
         qQ+QKqOQZOfUoMdszBb7lukPwqKqG8grQwvDuTtnyFuwprml2hosC/IOK0dI1M9posZp
         go9f7RTe9ZhE5wtOANt9kvVV+IyBd3uD2MnvOlsB8Go+5DvguApsKnKtu5TYXnKQMu5V
         cbHIT32uOEjej2Bqbj2IGhsHWRB65UVxkgrda4ElX6eQeaXwjDijU85S4iDKH+uXA6Ju
         hEAbfIn1FULHmDmVmdXSkuf/RN352Mu2rCwlI65p9usqSh8fCt27OS09HzyT/MjUfYMu
         5xVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P5j+klQm;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id u17si915782wrq.1.2020.06.23.02.24.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 02:24:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id a6so17770084wrm.4
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 02:24:05 -0700 (PDT)
X-Received: by 2002:adf:82b8:: with SMTP id 53mr3937384wrc.172.1592904245346;
 Tue, 23 Jun 2020 02:24:05 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
 <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
 <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com>
 <CAG_fn=XDtJuSZ9o6P9LeS4AfSkbP38Mc3AQxEWd+u4wakSG+xQ@mail.gmail.com>
 <CACT4Y+ZfDfMGWn1wk6jq0VdkGdC2H7NifYpVCCXwCmX42m4Thg@mail.gmail.com>
 <CAG_fn=VEb7XYwi0ZnOXRx-Yss++OhnpKCO-7tFvCOp4pi4MLcA@mail.gmail.com> <CACT4Y+ZHoQ5ZPfsvaiQMXrrTxv9-LgP+v_o5Ah2gFBwqQjv-+g@mail.gmail.com>
In-Reply-To: <CACT4Y+ZHoQ5ZPfsvaiQMXrrTxv9-LgP+v_o5Ah2gFBwqQjv-+g@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 11:23:54 +0200
Message-ID: <CAG_fn=VWwfpn6HNNm3V8woK7BcLgAJ9k8WYNghwxz7FF6+QZRg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=P5j+klQm;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as
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

On Tue, Jun 23, 2020 at 11:14 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Jun 23, 2020 at 10:38 AM Alexander Potapenko <glider@google.com> =
wrote:
> > > > KFENCE also has to ignore both TYPESAFE_BY_RCU and ctors.
> > > > For ctors it should be pretty straightforward to fix (and won't
> > > > require any changes to SL[AU]B). Not sure if your proposal for RCU
> > > > will also work for KFENCE.
> > >
> > > Does it work for objects freed by call_rcu in normal slabs?
> > > If yes, then I would assume it will work for TYPESAFE_BY_RCU after
> > > this change, or is there a difference?
> >
> > If my understanding is correct, TYPESAFE_BY_RCU means that the object
> > may be used after it has been freed, that's why we cannot further
> > reuse or wipe it before ensuring they aren't used anymore.
>
> Yes, but only within an rcu grace period.
> And this proposal will take care of this: from the point of view of
> slab, the object is freed after an additional rcu grace period. So
> when it reaches slab free, it must not be used anymore.

Thanks for clarifying!
Then both KFENCE and init_on_free should work fine with that change.


> > Objects allocated from normal slabs cannot be used after they've been
> > freed, so I don't see how this change applies to them.
> >
> > > > Another beneficiary of RCU/ctor normalization would be
> > > > init_on_alloc/init_on_free, which also ignore such slabs.
> > > >
> > > > On Tue, Jun 23, 2020 at 9:18 AM Marco Elver <elver@google.com> wrot=
e:
> > > > >
> > > > > On Tue, 23 Jun 2020 at 08:45, Dmitry Vyukov <dvyukov@google.com> =
wrote:
> > > > > >
> > > > > > On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wr=
ote:
> > > > > > >
> > > > > > > Hi!
> > > > > > >
> > > > > > > Here's a project idea for the kernel-hardening folks:
> > > > > > >
> > > > > > > The slab allocator interface has two features that are proble=
matic for
> > > > > > > security testing and/or hardening:
> > > > > > >
> > > > > > >  - constructor slabs: These things come with an object constr=
uctor
> > > > > > > that doesn't run when an object is allocated, but instead whe=
n the
> > > > > > > slab allocator grabs a new page from the page allocator. This=
 is
> > > > > > > problematic for use-after-free detection mechanisms such as H=
WASAN and
> > > > > > > Memory Tagging, which can only do their job properly if the a=
ddress of
> > > > > > > an object is allowed to change every time the object is
> > > > > > > freed/reallocated. (You can't change the address of an object=
 without
> > > > > > > reinitializing the entire object because e.g. an empty list_h=
ead
> > > > > > > points to itself.)
> > > > > > >
> > > > > > >  - RCU slabs: These things basically permit use-after-frees b=
y design,
> > > > > > > and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't=
 work on
> > > > > > > them.
> > > > > > >
> > > > > > >
> > > > > > > It would be nice to have a config flag or so that changes the=
 SLUB
> > > > > > > allocator's behavior such that these slabs can be instrumente=
d
> > > > > > > properly. Something like:
> > > > > > >
> > > > > > >  - Let calculate_sizes() reserve space for an rcu_head on eac=
h object
> > > > > > > in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> > > > > > > call_rcu() for these slabs, and remove most of the other
> > > > > > > special-casing, so that KASAN can instrument these slabs.
> > > > > > >  - For all constructor slabs, let slab_post_alloc_hook() call=
 the
> > > > > > > ->ctor() function on each allocated object, so that Memory Ta=
gging and
> > > > > > > HWASAN will work on them.
> > > > > >
> > > > > > Hi Jann,
> > > > > >
> > > > > > Both things sound good to me. I think we considered doing the c=
tor's
> > > > > > change with KASAN, but we did not get anywhere. The only argume=
nt
> > > > > > against it I remember now was "performance", but it's not that
> > > > > > important if this mode is enabled only with KASAN and other deb=
ugging
> > > > > > tools. Performance is definitely not as important as missing bu=
gs. The
> > > > > > additional code complexity for ctors change should be minimal.
> > > > > > The rcu change would also be useful, but I would assume it will=
 be larger.
> > > > > > Please add them to [1], that's KASAN laundry list.
> > > > > >
> > > > > > +Alex, Marco, will it be useful for KFENCE [2] as well? Do ctor=
s/rcu
> > > > > > affect KFENCE? Will we need any special handling for KFENCE?
> > > > > > I assume it will also be useful for KMSAN b/c we can re-mark ob=
jects
> > > > > > as uninitialized only after they have been reallocated.
> > > > >
> > > > > Yes, we definitely need to handle TYPESAFE_BY_RCU.
> > > > >
> > > > > > [1] https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open=
__&component=3DSanitizers&list_id=3D1063981&product=3DMemory%20Management
> > > > > > [2] https://github.com/google/kasan/commits/kfence
> > > >
> > > >
> > > >
> > > > --
> > > > Alexander Potapenko
> > > > Software Engineer
> > > >
> > > > Google Germany GmbH
> > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > 80636 M=C3=BCnchen
> > > >
> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > Sitz der Gesellschaft: Hamburg
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
kasan-dev/CAG_fn%3DVWwfpn6HNNm3V8woK7BcLgAJ9k8WYNghwxz7FF6%2BQZRg%40mail.gm=
ail.com.
