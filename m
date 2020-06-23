Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLWZY33QKGQEHONFA5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id E59BC204AD4
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:18:08 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id 16sf13666022pfo.23
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 00:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592896687; cv=pass;
        d=google.com; s=arc-20160816;
        b=iPu6cr/R+T1FNjJaPFSmhU+2GpPLq90ksqzDLaUfNmhEenpsoPnDn4DSD4M/qMjHfk
         b6jCMLnztllcw/QR9WRO9dmenygoJcEnFHW5OItHYy+gtMsz3p6sLJCn0junx6l0OBH7
         CnTDy2Jz+C03tWaFsgJai0tUdeZoCO48sqkZgo5q4GlSHp5J68YEh2ZDhkGNW0Z5KCNK
         UAlU/xjLQWpQgrEsMM2oSNcqr5bRT267BZYRf4FhS1PxWtC/5ywKV8Qk2fGp3BoMxzzI
         baqzxFfbgvKB0DW6anG0gf7kwy0bkp7DpisP/TkAhgB0Zf7PMVEtn6Tnj4yD9+SJhK1m
         0VjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oUDrq0SPapJNXP7EkRcT6d5qFyH5yBqGXQfJmfoG7ZU=;
        b=kudjnFKoEisF7uhoPb/2Uf9TgkWo1LOnbpStXMk2RhC69GIaYZkz8fZme+HuBbHWN/
         UGTbHoecQrXasMjX8B+WnJwbT2qzeAnRQuNAokTXrGqlLXbCymOLpnqmZvdj5udRGn7s
         JID2TvTAlpP1TSF2aWsW670F9N1bDytGA4gk7QaaHLPiZyaT3kOfrfYMir1DGvYYUsE3
         CqzhnyokG+bLKz4svLKbnyf9wcgYX+sNzplOPZkf2bAVoYLLmZTV6qnz0Sru8GqjWWAY
         Di7g6oYH6TYKEHfK6EluPjulu6vA9UOKesv8JLj8DK6SUVTNrC5rYdbwtIg2PZLy04ju
         HscA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFGAJQQi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oUDrq0SPapJNXP7EkRcT6d5qFyH5yBqGXQfJmfoG7ZU=;
        b=piMYlFirHaqMYArLBFkGdgvyJdDi6ghIhBR7o01ptLtUzaiPu6KPL0nANE9Vcgm9wA
         zQCL0WWLdhL0C280K6Tw+dKp4kMEytSzlfS/AMjZZuACLyUAxHDx9YmNqtcu9nvYwN1V
         YtGHAiEHfz+71a/uHMt1/GDglRKKZWrTv87r0oqaFN+oCsoEqXhacYjFORpUBEPx4gnS
         fDu23CkGlE3FKRSANvXc67WohcCXA84YenhcBXnko0ijpXDuF9fkoDy57QcKPmV0IYpP
         LjhT6A7guHfX6iTSvV9xN/7u30jzx2eJvc9DpLidNepYSj2GnYkmtWsL1mGjkmPBDKXN
         KOsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oUDrq0SPapJNXP7EkRcT6d5qFyH5yBqGXQfJmfoG7ZU=;
        b=TJLYfOn8OKJpk5DAaz1fnVH+8s1Avz0EcuW5v15BOoFEaR2486VaH1XBCPMSfUI84n
         10zPFFoTCdkhw+daT84616f9l4YRJqUgzhJv0QH+KWSqd/9DK5uDgc87U3GVR34TCFOP
         9TW84pV6RysHaqxQZbTpQywQX5JHCNn/BcJiO0NdN8kHNMOrwzNmjbld+8IsP+vbyDf0
         otOs8+yCnJBgg/TPSwoCMHcdobUocNyYVepQRDRJ9wlBhRucwM3pqYzmWUR1swEuDzba
         xb/FkXgo9AQBVC5HspG/9hF4oNaAovuw48Y8qvu7Qyu+aa3s2cSKMMZRCgcVTe5Xgmyb
         +4lw==
X-Gm-Message-State: AOAM533ggLDe2UI1Qx9J2OXG/V8OJNo/4oNPKFGvs8Ia7rjcmx6RGYgv
	IvIFlEIESbdSJsWC9oTnghk=
X-Google-Smtp-Source: ABdhPJxV8DDAR+AjMsF2tcuNNeCy0RqweYBi4T9ChDlo9WePTT76G+2MqPw6rdawePmLCqsze1s82Q==
X-Received: by 2002:a17:902:be06:: with SMTP id r6mr17145828pls.310.1592896687022;
        Tue, 23 Jun 2020 00:18:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:565:: with SMTP id 92ls4552255plf.2.gmail; Tue, 23
 Jun 2020 00:18:06 -0700 (PDT)
X-Received: by 2002:a17:902:7896:: with SMTP id q22mr23219719pll.237.1592896686474;
        Tue, 23 Jun 2020 00:18:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592896686; cv=none;
        d=google.com; s=arc-20160816;
        b=RrIqc8cC2pZ1I9PJ+h636qZ4AgC8x6J0lmrCPlv+4xpH4cyLOflRT/qMK9C4oMz14b
         37r737EuVPQOCI6DX7YTTziE/tYqQx+vUnrMIbdkt1vs0WraDEFp6DTPyWGVeOC8x/Cc
         gQ6i1GgCcy/Lj2Mqj5dAKr4UMLyWwWlM1Wa4JdLGUDb0aaUaWdKbg4MQVxtRjmWi4dx1
         4cDfa9ZMy7GzXCMr+b3gKgV8lZ9qFYEoxH9sYaii6EPPgiYBO/drg0fdyRDzwmxIoaf7
         qJr3Mw9CpOGIq1EE4j6AhuaVy3VRlZCOAQVkeWKCbyRa31npz3EY4ti3daRKWH6AWDuT
         bQbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/MteRsl9kXDCB4cggamm2Lh5J0tgrSbPos+TELxySHU=;
        b=xEtMiFCbyAJ8qU3ez0qUFzxfMbr/8CmdqhqHOwse8Kv2DYa/WbyVC7Id2r0dl/PoPy
         bk6Lh8Eidn8YSvRgsba3Hd/557P1oP+n2rTB5T/MQb/E2PDiIqNEkRIihGZjK4Ub28tg
         IMF5lTmb7YdYj6h5wA32dWUKGHv4CONfuhPFkN7iwcRfQKqNOsjnRQnKYOOPS3oA0Bb+
         +PcUvol1axIW9KLUt671HEN8PD5ea5vxyI0Osjp7/U2m9AumqtuEEe87aJD9izdkmRd3
         lQqprfslQmhHQS9LhW8CanN5gWJxLCKah2jnjB5EyAaBJlm4Nv7/ZhpMBUlMj2wLBm7C
         +8mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFGAJQQi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id 89si705323pla.5.2020.06.23.00.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 00:18:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id t25so18004067oij.7
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 00:18:06 -0700 (PDT)
X-Received: by 2002:a05:6808:34f:: with SMTP id j15mr15871155oie.121.1592896685597;
 Tue, 23 Jun 2020 00:18:05 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
 <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
In-Reply-To: <CACT4Y+acW32ng++GOfjkX=8Fe73u+DMhN=E0ffs13bHxa+_B5w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 09:17:54 +0200
Message-ID: <CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X=UkQ4wt2SbtFAjHA@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jann Horn <jannh@google.com>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GFGAJQQi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Tue, 23 Jun 2020 at 08:45, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Jun 23, 2020 at 8:26 AM Jann Horn <jannh@google.com> wrote:
> >
> > Hi!
> >
> > Here's a project idea for the kernel-hardening folks:
> >
> > The slab allocator interface has two features that are problematic for
> > security testing and/or hardening:
> >
> >  - constructor slabs: These things come with an object constructor
> > that doesn't run when an object is allocated, but instead when the
> > slab allocator grabs a new page from the page allocator. This is
> > problematic for use-after-free detection mechanisms such as HWASAN and
> > Memory Tagging, which can only do their job properly if the address of
> > an object is allowed to change every time the object is
> > freed/reallocated. (You can't change the address of an object without
> > reinitializing the entire object because e.g. an empty list_head
> > points to itself.)
> >
> >  - RCU slabs: These things basically permit use-after-frees by design,
> > and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't work on
> > them.
> >
> >
> > It would be nice to have a config flag or so that changes the SLUB
> > allocator's behavior such that these slabs can be instrumented
> > properly. Something like:
> >
> >  - Let calculate_sizes() reserve space for an rcu_head on each object
> > in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> > call_rcu() for these slabs, and remove most of the other
> > special-casing, so that KASAN can instrument these slabs.
> >  - For all constructor slabs, let slab_post_alloc_hook() call the
> > ->ctor() function on each allocated object, so that Memory Tagging and
> > HWASAN will work on them.
>
> Hi Jann,
>
> Both things sound good to me. I think we considered doing the ctor's
> change with KASAN, but we did not get anywhere. The only argument
> against it I remember now was "performance", but it's not that
> important if this mode is enabled only with KASAN and other debugging
> tools. Performance is definitely not as important as missing bugs. The
> additional code complexity for ctors change should be minimal.
> The rcu change would also be useful, but I would assume it will be larger.
> Please add them to [1], that's KASAN laundry list.
>
> +Alex, Marco, will it be useful for KFENCE [2] as well? Do ctors/rcu
> affect KFENCE? Will we need any special handling for KFENCE?
> I assume it will also be useful for KMSAN b/c we can re-mark objects
> as uninitialized only after they have been reallocated.

Yes, we definitely need to handle TYPESAFE_BY_RCU.

> [1] https://bugzilla.kernel.org/buglist.cgi?bug_status=__open__&component=Sanitizers&list_id=1063981&product=Memory%20Management
> [2] https://github.com/google/kasan/commits/kfence

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMDHmLDWgR_YYBK-sgp9jHpN0et1X%3DUkQ4wt2SbtFAjHA%40mail.gmail.com.
