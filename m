Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBGVZ3P5QKGQE6SJAAKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EBDA280E47
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 09:54:03 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id r16sf241203wrm.18
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 00:54:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601625243; cv=pass;
        d=google.com; s=arc-20160816;
        b=IESt7ZNQwKNvjwmmOa8SDm/qK8YA+F3TKHGR8zmo60LI2HC1GVJmiygI7J6M3lVqt4
         Eas9oeu6DbYDCUNwLNuuHlXzvTLEBQL6MT1NlYS1hIV/38DrEEe3mcEu8xbi3VPOoXM5
         pYAlAmCuvnf+U1ZwhiopQNeIgGOVzW5MiwljxLKN7GhKR13hYrxgwTPO0el9OJNDz+kf
         S0jnwp+C1DQTbmCDCgf1ve8siXm6mI1vAAbCDoS0qKU46axiXmEE7g1mUUVIYzRN/vjQ
         OK3BICuYX+/XxTrrBLz8UhUHb0rQyUg3q4TMLNCQaXoByVMubaHDxCkPZu/Wlj1g1TOh
         wOFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=F+/EN6DXWUCHQqnbBpuji+/LdNwFX1IdnePZaRnWzeI=;
        b=HRcyEFSFmrv7maT7o80Pu+COOpsqkDRggw90Mmpobh0KgMoD+ktgRSNq813z+LtZb9
         rBq3P66NWWLHAeplV9/cM4DYOv4MOrmvg3CzyNf/Wr0tbITtFsSp/BN168VnAmeiQQNy
         Cz4/415eS5Zwzf/P0bwew13J78SB/W7LH/GvRe8ebx3Tg3Bcxi6Dz1LNlr2aRZgQ4pYB
         FT+y6vdj+8Thpgyel8dauWLk2bccLaYGdsO0miTbEKNbr7TbSCLfSD340c2nCIbxyuE6
         iWtwMbOrgyzOujS65KII4HNUb7jdhbZWNUr763h5E9WqH7ArcqfVEP5+H9ZC96GphLLg
         U1fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZImYzlgj;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F+/EN6DXWUCHQqnbBpuji+/LdNwFX1IdnePZaRnWzeI=;
        b=Me0XYNFoAkGcnIpW1ScmCeBYO6OOlxn0+r1A682SK2QhMZN2A0lCn3DwKOFnlsYHkQ
         fjg3YT7ad8isiQibUN5OA8UVE6FPaa+cTm4ip+FugnrEl8/K2EDoBoRQ3AyzYlrukfzU
         mr83K0bdjsEKZqyssAfB4JC/UDyekT3aHSTgzRbyTJuZwOyX6rTMgWoTjNyzLV2ntR/P
         6O1WNxx1pKQAV0/wd0fKdzNNxPcTASLYddjELBDGMJXpPlppq8LzJ3Dar9mMQ7HiItZK
         uKIn3IdCjuiBIFJAlgu0zClH83aDnkHRT2O3QDYTO670IuWRCJAs/gA+6W50mMQXWvQR
         jIhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F+/EN6DXWUCHQqnbBpuji+/LdNwFX1IdnePZaRnWzeI=;
        b=kZu/4QIAz+hPM2ywdLkQjZRtJEoyA6m96nfwW3dFUR4gJkyByZOqUtTESVXzaR6WMu
         TnIbEu+A/R954GTYI6yc6dLFd8KKZ0LI37QmyZfMWkfbZjucEWqwBgwce2eKmyQm0Bvt
         PhIDybwfLcFuIA6k3gOLY0KOXMuhts6sOrnylapyYNlutXb6xSuH4cOaRzJqyjft2Ugw
         HTF4rnYjtIjmYuAhKHqbUlm6P9gFdD7XeTpJGkvW0CifuqtXmud6Gppsm6wFI6XCSOeE
         96S/ouFr4Oky3kYmhkZN/1jMLL8JkjGCrQvBlpIYnULbILKAqd8ucUbvcnaoGWR3VyBJ
         P7yA==
X-Gm-Message-State: AOAM533tKvWhEHfHRxsqth6vocCDBUbdZdIA6pGBhJkJGb4jip1TobRR
	A5Y2XJTr5R6z7zjsCDdRp0Y=
X-Google-Smtp-Source: ABdhPJz3uqI/BvxBgtrIfgaxUFwXUfL2tvURmz7ouMlZub1clLLAINJ0Ept0ctSAcid4iCjEpyrkMw==
X-Received: by 2002:a1c:7205:: with SMTP id n5mr1402563wmc.175.1601625242842;
        Fri, 02 Oct 2020 00:54:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4154:: with SMTP id o81ls378860wma.0.gmail; Fri, 02 Oct
 2020 00:54:02 -0700 (PDT)
X-Received: by 2002:a1c:5685:: with SMTP id k127mr1399115wmb.135.1601625241978;
        Fri, 02 Oct 2020 00:54:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601625241; cv=none;
        d=google.com; s=arc-20160816;
        b=rQqebrtyCjPEJMHuMMuZgjQXSa9Uzzzz2ewiK2wMKxoj4FxCEyOrVhGYVhmCE9C/0l
         qWx1Fcz5Y+34yM+BejcHM3pRLXVIoYl0xoVX9BVpSsKI4PmdACC7E0ORrH0d0uuEKECA
         T/4gyeEFCHfnD2AMw+AZKxKtQ7PCXrgrdzuxUbARiLf6eEOcFywUL5s3C3CWrG5QYh4W
         a0t29u3J5NfVmO/QxhKKvkwJwEQeV06zcluR9Vc7fM/t29ChDFQv18oJOY7KZhy/6jPL
         FmV1cxNvNTh6jRRuqOffsxw6WOWmFe/xz2n+lA1mDL/GYtdmPQhJmym8zjwQiSdMS3IE
         kJzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e6vV2mQW9X/bc3rvl043TXcmZeVV1Y9QdMUbU/DoAeE=;
        b=0D0ovvImZ1j3+v+Oyx9qoIyrSffmtPi/MOTxhb4d3K8HjDbZrnS8s8yprToEyavDdN
         mm+1+XwnVdkDAVLP3smeucgoa8W0qP0xkS6satlk7lkHv2Oip0ShAl2xQRIORyuhpx6r
         LaJo66d9d9dlhXgWWvLInNbnQ3TSO+fF7tjOuWE7XN+j21bepSIH/h76UIBuvD+fQx+y
         V49KwWGOAHkD+Buvrs4gsswIgpmJfbSUf+sn8+kwCflVJEPtbjOXFdGxn+f8Rvtjd4cs
         MyCehe2WyPBY+hCibZXbtnApSmu40am0yLZaSvAqYZfkmzkkK1wgzGdGcmtV0TjcRgsJ
         QbcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZImYzlgj;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id 126si18832wmb.2.2020.10.02.00.54.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 00:54:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id j2so697100eds.9
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 00:54:01 -0700 (PDT)
X-Received: by 2002:a05:6402:b0e:: with SMTP id bm14mr1055829edb.259.1601625241408;
 Fri, 02 Oct 2020 00:54:01 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
In-Reply-To: <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 09:53:34 +0200
Message-ID: <CAG48ez1MQks2na23g_q4=ADrjMYjRjiw+9k_Wp9hwGovFzZ01A@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZImYzlgj;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Oct 2, 2020 at 8:33 AM Jann Horn <jannh@google.com> wrote:
> On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.
> >
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. The main motivation behind KFENCE's design, is that with
> > enough total uptime KFENCE will detect bugs in code paths not typically
> > exercised by non-production test workloads. One way to quickly achieve a
> > large enough total uptime is when the tool is deployed across a large
> > fleet of machines.
[...]
> > +/*
> > + * The pool of pages used for guard pages and objects. If supported, allocated
> > + * statically, so that is_kfence_address() avoids a pointer load, and simply
> > + * compares against a constant address. Assume that if KFENCE is compiled into
> > + * the kernel, it is usually enabled, and the space is to be allocated one way
> > + * or another.
> > + */
>
> If this actually brings a performance win, the proper way to do this
> would probably be to implement this as generic kernel infrastructure
> that makes the compiler emit large-offset relocations (either through
> compiler support or using inline asm statements that move an immediate
> into a register output and register the location in a special section,
> kinda like how e.g. static keys work) and patches them at boot time,
> or something like that - there are other places in the kernel where
> very hot code uses global pointers that are only ever written once
> during boot, e.g. the dentry cache of the VFS and the futex hash
> table. Those are probably far hotter than the kfence code.
>
> While I understand that that goes beyond the scope of this project, it
> might be something to work on going forward - this kind of
> special-case logic that turns the kernel data section into heap memory
> would not be needed if we had that kind of infrastructure.

After thinking about it a bit more, I'm not even convinced that this
is a net positive in terms of overall performance - while it allows
you to avoid one level of indirection in some parts of kfence, that
kfence code by design only runs pretty infrequently. And to enable
this indirection avoidance, your x86 arch_kfence_initialize_pool() is
shattering potentially unrelated hugepages in the kernel data section,
which might increase the TLB pressure (and therefore the number of
memory loads that have to fall back to slow page walks) in code that
is much hotter than yours.

And if this indirection is a real performance problem, that problem
would be many times worse in the VFS and the futex subsystem, so
developing a more generic framework for doing this cleanly would be
far more important than designing special-case code to allow kfence to
do this.

And from what I've seen, a non-trivial chunk of the code in this
series, especially the arch/ parts, is only necessary to enable this
microoptimization.

Do you have performance numbers or a description of why you believe
that this part of kfence is exceptionally performance-sensitive? If
not, it might be a good idea to remove this optimization, at least for
the initial version of this code. (And even if the optimization is
worthwhile, it might be a better idea to go for the generic version
immediately.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1MQks2na23g_q4%3DADrjMYjRjiw%2B9k_Wp9hwGovFzZ01A%40mail.gmail.com.
