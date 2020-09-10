Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPWK5H5AKGQED6BVRMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 32CBB264B9F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 19:41:19 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id w38sf6182445ybi.20
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 10:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599759678; cv=pass;
        d=google.com; s=arc-20160816;
        b=kMx5I1O3UE1HfI3kb/N0IBc5d8Q/WkPzBTIDk8yzHaaeMkito27IRVja3JqGmFH3WS
         v+uc80NsZ9WoCJpnZR+Cu9euHaaFIu/Nh8w54CIb/TGR7LVQ5j8XSswNlNxhlsln67ki
         zmkTSb3OtOEAaQX/QRYj2bCVf6u9AWgd0AZTmGm7RNuXQEWMfBmt/iQvDmYKUC9kYfLc
         a0c1jp0PBTGGG5NAZpqPZdmxigWEI5XkPaVpGhlVR9zMrco7eBDZEZwjnZ2+OlgBxoJJ
         9bjRZ0/52j+j0q+8+C+YfoC843IA+SRiY/6PkouZ3XwT8A7ZJT6Bs9BgPjq0bSHgSgQ4
         ijGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MK05VgguVEiTMhLF/Y9ur+5/edmwShZA+ZEoZ5c6tIo=;
        b=fbxNrtpm2+lr0eJ3d5O5+7/wLH7uvW3Jg7ZQ/pVqbFC2aP1/9nFGS3Y3VRzjqVofqI
         2PO8CNMdaWy112JszItvLbHdl8fM5kXacnzP6qbs9hSRpWlKM1u1xNcIlM95fyUFfZJm
         /NHz/+aGubvKduDVuOkaB6bkwyGuGvOa2lhSm7tWQbTFlDemksqiuJsmx55T2xolOrNi
         4BjDLmNuMKvhTCanOfUA4I2C7rBgmBugcnDuep4+Ehh6mxU2yYm1i3kpsM6QI3+9ckQP
         Ty2AUJPYkgUEKUd1JFFT1q3SuyrKQDfWmquEhoM0j916UvQGvwB0jLLSmREHpisQQ7Kw
         Tu1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s1IboDV+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MK05VgguVEiTMhLF/Y9ur+5/edmwShZA+ZEoZ5c6tIo=;
        b=IrfqSK76/KyPZcFvYKJZvA4sPq8OxlH936MIa4QyT6t49cjHaLWP2ow1BAn5KumVnK
         cPq/X0eJ0TnFGfgF9kvjkjWIK2v6jYvFyII/FAeHCxhcfUTcOyC6JO6rX+sGSVx+2GTw
         vzh07x2O3OCCZ0uKAR3et/sJTJozo/SrWIMHKdSFCgBN/WwQsJotpEQj0fuJQ588YaIQ
         7l+cErf2Cig9VBMqCIvfgCkPoXqQOU7gBeqVIDqEOUhdWtGLwdq2INm3SeXXfmrs4NDd
         BghFyCf8FZqssb63ZlVSZ7kp0EO3PArxXiOQnHefQScA3PXAU8KzCSMI+IvvlW5Y9Rn6
         jeFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MK05VgguVEiTMhLF/Y9ur+5/edmwShZA+ZEoZ5c6tIo=;
        b=OuHvipVuywVrGM9EfIbje1rpr+OiRgPNzogLxvCTnRrOqzck0/fSGnHrxGNLqHh/Vf
         RiEbY2neEplAeMoZgwT6vmbkvRF3aBTgScXGRRDs5pkyTrpUjEIsMdPx8NgptTiYDFUh
         UazXWW+kCGSUeM8Hc0agj5KNC/e/Jvc7WSk3I0vAWRYPgi/nbugeq1cxomVgwmxdlG1c
         EswnWsDjTSrEvMLRgyLC8MoL6S5kWdqqEAnrsNNFXa/2IKep/pdImShaoQ/ncHtJocwA
         Zu4I2PMY4EYJ7fKxfI2zsWC/l2uZHjaSODtAF6y0oRSMWZVCg2WoEfA62vVPzS1wkJ4s
         cWEg==
X-Gm-Message-State: AOAM532BEHLOJqzLWorD4hKOKFbnUr8K+dH2QrJzK5xWc25vyXk7TfN+
	NQyR2pi5FxWuD7+kAVkZ72E=
X-Google-Smtp-Source: ABdhPJxBWwgUDAIeFyHGmhVChVP+X63kSNMlLqABCrJ0bDrrCaiibta+78QroaxGW80JEv9Zb9lyHA==
X-Received: by 2002:a25:9b88:: with SMTP id v8mr14561362ybo.96.1599759678216;
        Thu, 10 Sep 2020 10:41:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b29b:: with SMTP id k27ls1252760ybj.11.gmail; Thu, 10
 Sep 2020 10:41:17 -0700 (PDT)
X-Received: by 2002:a25:cdc4:: with SMTP id d187mr14934073ybf.521.1599759677671;
        Thu, 10 Sep 2020 10:41:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599759677; cv=none;
        d=google.com; s=arc-20160816;
        b=lekmBRP2CxYDcBCqntJBvI5tD6I6zs7gnB2TgWd6FLEk/gRdvPhfNAtNd7TFopkg1l
         5J9aanarznwUa/235YIZARLDBrffzv335nLmVv6cZeWfR7hoELy16VJcov4AuzCVQNaw
         FKkf41tggr8ZhmV11ZO8Q+ayfdQLE9lD6Dv3RO0yXePOz+FaETJPJr+DeVk5A++ls7/u
         r2KWgLTbMK39FjbvlzrCXU+2bIeBdJwwiW06tw9B+V5ErI4iq45H8NxuJUCiOWXYl1Qo
         LKpLiYQAIwPnmt7pfY+1VuCVDQPb9fucJnzfpfWD7p1/NC2jZu264Kg62XxAfEqWhNtf
         IP5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4ATdJdtrrGQs40AB3pAJaPiKELI+qIaGQiGwD413skg=;
        b=oiFYrY55u5RewcuJ0QB631uq+ZWDpNMDMpBn7RWVIpzIy6Q/32KMN88M2nE+cj83J4
         tntLQn59jpYJWqt+7vw8DRYDUYbjGu9ABjiYZ2CpIYPY5Rgo1apI5eouPWsg/0cUVRJ0
         dVEp03cqSTHlyhPmeHRVQSydfCWrdzv94wRdRKfdl3Csmst4HT8Fn26hTW8Jh807nOA3
         R/JveeDSF5MuTd+oEJhspaA0cOaF5pU2opPz7Zikc001XjjshgRFFYAn6idKOlcTbkUz
         VDX9pc8wwi/XxDzCmSDaR7coKBneYp2XU8PjON0lqpgLEaQgpXThgFfZMjiMeT5krlOW
         sGUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s1IboDV+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id 198si536690ybe.4.2020.09.10.10.41.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 10:41:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id x19so6728804oix.3
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 10:41:17 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr709168oib.121.1599759676956;
 Thu, 10 Sep 2020 10:41:16 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+bfp2ch2KbSMkUd3142aA4p2CiMOmdXrr0-muu6bQ5xXg@mail.gmail.com>
 <CAG_fn=W4es7jaTotDORt2SwspE4A804mdwAY1j4gcaSEKtRjiw@mail.gmail.com> <CACT4Y+awrz-j8y5Qc8OS9qkov4doMnw1V=obwp3MB_LTvaUFXw@mail.gmail.com>
In-Reply-To: <CACT4Y+awrz-j8y5Qc8OS9qkov4doMnw1V=obwp3MB_LTvaUFXw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 19:41:05 +0200
Message-ID: <CANpmjNOTJsZeH_sMx=3XNZuvCih+A9m3uTeSGcmpNH9YbiF2sQ@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s1IboDV+;       spf=pass
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

On Thu, 10 Sep 2020 at 19:11, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Sep 10, 2020 at 6:19 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Thu, Sep 10, 2020 at 5:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> >
> > > > +       /* Calculate address for this allocation. */
> > > > +       if (right)
> > > > +               meta->addr += PAGE_SIZE - size;
> > > > +       meta->addr = ALIGN_DOWN(meta->addr, cache->align);
> > >
> > > I would move this ALIGN_DOWN under the (right) if.
> > > Do I understand it correctly that it will work, but we expect it to do
> > > nothing for !right? If cache align is >PAGE_SIZE, nothing good will
> > > happen anyway, right?
> > > The previous 2 lines look like part of the same calculation -- "figure
> > > out the addr for the right case".
> >
> > Yes, makes sense.
> >
> > > > +
> > > > +       schedule_delayed_work(&kfence_timer, 0);
> > > > +       WRITE_ONCE(kfence_enabled, true);
> > >
> > > Can toggle_allocation_gate run before we set kfence_enabled? If yes,
> > > it can break. If not, it's still somewhat confusing.
> >
> > Correct, it should go after we enable KFENCE. We'll fix that in v2.
> >
> > > > +void __kfence_free(void *addr)
> > > > +{
> > > > +       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> > > > +
> > > > +       if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
> > >
> > > This may deserve a comment as to why we apply rcu on object level
> > > whereas SLAB_TYPESAFE_BY_RCU means slab level only.
> >
> > Sorry, what do you mean by "slab level"?
> > SLAB_TYPESAFE_BY_RCU means we have to wait for possible RCU accesses
> > in flight before freeing objects from that slab - that's basically
> > what we are doing here below:
>
> Exactly! You see it is confusing :)
> SLAB_TYPESAFE_BY_RCU does not mean that. rcu-freeing only applies to
> whole pages, that's what I mean by "slab level" (whole slabs are freed
> by rcu).

In the case here, we have to defer freeing the object, because unlike
real SLAB_TYPESAFE_BY_RCU slabs, our page here may get recycled for
other-typed objects. We can update the comment to be clearer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOTJsZeH_sMx%3D3XNZuvCih%2BA9m3uTeSGcmpNH9YbiF2sQ%40mail.gmail.com.
