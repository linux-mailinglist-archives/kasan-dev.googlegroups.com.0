Return-Path: <kasan-dev+bncBC7OD3FKWUERBFEZVOYQMGQEH7SKSWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF3B98B2AC6
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 23:35:17 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-69942c6d975sf18139586d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 14:35:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714080916; cv=pass;
        d=google.com; s=arc-20160816;
        b=BSCt2idUz6VE/lCXsbry47GyY32g8oZuBjU/jBrBHA/X7yHuxAYKerHDKAate5wq/U
         X0sPzsQEpBt2Zy8gZkQIkiHaOHgPUl6G2UkJP/JoGsrW7UDIGCEFZ9gQUa4+AAiVMdVQ
         BlbNCrLwauSkFg2qxZxiCsrNaoDofrNbnjNkybaUR53ngFbte1/tAw/0MXJg8HWlcB3O
         Ruui4nVg1YFkUnC61JeLdWF59IvGZq7KpLGhRXYHZylaDYCp+xIabmiUHZUiAjqRu2rd
         Pme8xYitZbHpFU5d2QOL1a+UpeFVWLji11a6vsrZdcyx9Z11vEU6pKaoSrRa3zQppVzJ
         PFyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XUkSCzzhgAUOFU51IAGdGzTe9cAZgItrD7WgsdxoMsc=;
        fh=sLW1M+1xkKardvhsH0jalvOfEjLYhk8jaM4lMY4eZYs=;
        b=TBfAajUEhdMDQf9/2XQBbjUjZ7zcfrvgaSgzTruC0Y2jAE2O7oxJwzZ0cqWeXaH/YV
         IFZjAUjVWLl5c3otuJ/6/jE1W/tLw0vA5qDbBFF1U0V5pgPaz1BZblfzEjkbZmJWvJw+
         Jao3SCAzI5ppxa8jetw/nKQC5KyUy+A3Tsej4WNyUhaGRWBvfEgdD3wpPzU7W1zBEEkR
         5KMhzX8bukmLjqA1bwxR/oUxac2UWtpiFgPBrPRUSmP4ySjpzp93SCd1FgNMFMr1vvAf
         a3Fx3WNvjPXPLQAob3X4+Ua3qJRgmpzqAobaaabHs5uYhlZ9C+MyL+lZVlm0MuvCUxkh
         cnUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ukasH5AP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714080916; x=1714685716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XUkSCzzhgAUOFU51IAGdGzTe9cAZgItrD7WgsdxoMsc=;
        b=Q2frSgBL4Cl0sEGj5MPMpgR+dwbbkiDpPsprYFOGAUypRJbeGmlOv/6q87xfJ4BDj1
         vrx9XkSFq2Qtn7CIbYcfIA9wP3WyG/gTSGp2gsKWxj5JjgcePMtwqjLcx9FeuS8YOnSR
         r3AWzkIFYoAvJMihNxCPN2t6ueAMuVwmnqti+bXu1yI0GuRNPU5OQaYUIL8TCsYxQfF/
         zxqIR76Wg+ABN17JL2q9P+rwCQVBj9u6OohORvi1XPPu93TICfpq4G2F8+VvV3PIskNr
         V5r8TIuAuggkd9PsM/yMrMCYSnnYQvc8HgVxfF4ecqik7z9wFE+xwf8WBkL46IlsuwLz
         AiuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714080916; x=1714685716;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XUkSCzzhgAUOFU51IAGdGzTe9cAZgItrD7WgsdxoMsc=;
        b=PXNhv4OW+P/YoLkcfDEJY8IyhRhfIUe+Vp0EPkluA+Ccbd/5JtUZDQ98Foq07VnOpd
         uKXV3VG0kgupJOoYXRLaP10eMtENsqzCtrpqkZg3OKzByDwKg0BBp3vAK3w4BrpcLdrI
         rFPN7/SNcKn4iL3N0oUwHT6Y1b5pg2Nqrk9FZS4SIDMnVSPo/9W0gWF1u7wFKN9MOVu2
         Fx1AYD2ylaIswxudZAV/Jw5PSSyWo8FaBYo0KO/jctT4TtkvxqK+7xBE51eHm2tXq8Bi
         rnCVM+sp99YhsTPnYattEZz4RW7waUgDJ+kOQFmFihgRoPaAIvVqs2gtg4X/1deySqTD
         ZmWg==
X-Forwarded-Encrypted: i=2; AJvYcCUym/C6Zu5Av8J8ib9hXyjM4WgD+1nX1/q+TKZH7nd3SA4wlEpszzyJ3EXdN6jP5fw80NfbbDM1zu3iNfkhL1pxmxcbjsoTlg==
X-Gm-Message-State: AOJu0YxjAC11hzazk+uQOpf0dxB0i59Dv0lY7eKpaMhH7sttGt9gUJj/
	zer4eLgi51XaJKQYRWM7jA4JVAi3ZdUEfASyTgAbEl1KUIaqyvWF
X-Google-Smtp-Source: AGHT+IFc/D/ah/AxMNWTkV1APsgrV7+4TFewfjpj4D6Th17wK85HS7YEac9LZ5wx/nFireKFo0vGTg==
X-Received: by 2002:ad4:5764:0:b0:6a0:76d8:e79a with SMTP id r4-20020ad45764000000b006a076d8e79amr1156915qvx.19.1714080916507;
        Thu, 25 Apr 2024 14:35:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:248c:b0:6a0:7a69:93c9 with SMTP id
 6a1803df08f44-6a09c4a897els10278786d6.0.-pod-prod-02-us; Thu, 25 Apr 2024
 14:35:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXxlHJLPFl8D/kECQANnro9kK8QzeE7iMK6TDNbU4TL8t4eV/CR3d/AyVXltlIlpE3hMBBEOYXjbchPwL1wS2hzV5pGHwMj4SWzg==
X-Received: by 2002:a05:6122:d86:b0:4de:d0ee:7751 with SMTP id bc6-20020a0561220d8600b004ded0ee7751mr725293vkb.11.1714080915520;
        Thu, 25 Apr 2024 14:35:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714080915; cv=none;
        d=google.com; s=arc-20160816;
        b=y+wPiy/VJqXddaXgjyfgIZh7Hk/PoyKF42ScHzF0Pk7d+supQ8/JBQpUiGAXfgiR0c
         QIKDGO9mqCI8W3Wm2w6J6GBrtg/rir5Nyjaop4Kc2QR9vvHTqGCVIFIJsKUO0almBv0A
         hh6eMXgtYUtCUbyE5y2RegIOx8jNz66R3mPISr+rP9gBugzq5H8syL3y4FcZScsXD0D5
         3HfHLBbHUp18oqOZ+d8yw+dFTJD9zmRPlRjoVZT28CIzlG2s9rYHBGYfvVL/rB4/cTtb
         22zHlaJMlOH2zVTPCE8+HZ7K77eRIMRUlcVPb0gupI63pP7ppvehqHv7p3r5m1yseW5T
         X1tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dNAVjZRL3SNvhEv7UtPjNVw2qSZLNXEHiDVYNBop7Cg=;
        fh=ZjvEX3i56DUmyo+bQQcCPdZbsRPJ6oCwczTGgLLIVJ8=;
        b=ILyPMok0z/hbCJ1GOnbQENM6VLC0Pgxz+X2ttLgCZAiWK+xgE3DT2Qz/bgp9Uvd9KH
         2fr/YTjm4cU3upmS6SgZsc3CwBaTB1hedGAVXRdPxFNNQithKNECEIUOHTNFFsh+pgiq
         nhgWvxCwO9wS0T2LL2KbUkrA2WqTkr4El+EYUEP7Xe7nnJYhrRFvGDz0gBgl9HcBs2i0
         p0S8s615VPgnbAP3E04HUVUxBJfY3QAIKT4meruDY2HrBZJzAAG/Vq59a+D5brWMDFNg
         fkrvNea4Cv4lDDJiMI6qv/LFsiC6bVOjVxcUweBxCinpn/beQrh+dy7SebDhWFJyuLly
         72vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ukasH5AP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id n186-20020a1fd6c3000000b004d41fe2c37csi1552148vkg.5.2024.04.25.14.35.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Apr 2024 14:35:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-de54cb87998so1608085276.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Apr 2024 14:35:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUs6lLT+xgFUq4mvdVCN0I8vWAVk4uKUI1IlFl0ksg3zsnbKvaO1OPiXoSIdiJuKbAK3qObDOr4KDM/sE5rXPo4YP1XIdvD3q4OKg==
X-Received: by 2002:a25:c5cb:0:b0:de5:56ca:759b with SMTP id
 v194-20020a25c5cb000000b00de556ca759bmr991751ybe.2.1714080914454; Thu, 25 Apr
 2024 14:35:14 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <202404241852.DC4067B7@keescook>
 <3eyvxqihylh4st6baagn6o6scw3qhcb6lapgli4wsic2fvbyzu@h66mqxcikmcp>
 <CAJuCfpFtj7MVY+9FaKfq0w7N1qw8=jYifC0sBUAySk=AWBhK6Q@mail.gmail.com> <202404251254.FE91E2FD8@keescook>
In-Reply-To: <202404251254.FE91E2FD8@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Apr 2024 14:35:03 -0700
Message-ID: <CAJuCfpHcz+GVjFqcjxq4=tCzJyPZFFRATWDNChyEUyV_Ru+g5A@mail.gmail.com>
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Kees Cook <keescook@chromium.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, akpm@linux-foundation.org, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, songmuchun@bytedance.com, 
	jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ukasH5AP;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, Apr 25, 2024 at 1:01=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Thu, Apr 25, 2024 at 08:39:37AM -0700, Suren Baghdasaryan wrote:
> > On Wed, Apr 24, 2024 at 8:26=E2=80=AFPM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> > >
> > > On Wed, Apr 24, 2024 at 06:59:01PM -0700, Kees Cook wrote:
> > > > On Thu, Mar 21, 2024 at 09:36:22AM -0700, Suren Baghdasaryan wrote:
> > > > > Low overhead [1] per-callsite memory allocation profiling. Not ju=
st for
> > > > > debug kernels, overhead low enough to be deployed in production.
> > > >
> > > > Okay, I think I'm holding it wrong. With next-20240424 if I set:
> > > >
> > > > CONFIG_CODE_TAGGING=3Dy
> > > > CONFIG_MEM_ALLOC_PROFILING=3Dy
> > > > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dy
> > > >
> > > > My test system totally freaks out:
> > > >
> > > > ...
> > > > SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D4, Nodes=3D=
1
> > > > Oops: general protection fault, probably for non-canonical address =
0xc388d881e4808550: 0000 [#1] PREEMPT SMP NOPTI
> > > > CPU: 0 PID: 0 Comm: swapper Not tainted 6.9.0-rc5-next-20240424 #1
> > > > Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 0=
2/06/2015
> > > > RIP: 0010:__kmalloc_node_noprof+0xcd/0x560
> > > >
> > > > Which is:
> > > >
> > > > __kmalloc_node_noprof+0xcd/0x560:
> > > > __slab_alloc_node at mm/slub.c:3780 (discriminator 2)
> > > > (inlined by) slab_alloc_node at mm/slub.c:3982 (discriminator 2)
> > > > (inlined by) __do_kmalloc_node at mm/slub.c:4114 (discriminator 2)
> > > > (inlined by) __kmalloc_node_noprof at mm/slub.c:4122 (discriminator=
 2)
> > > >
> > > > Which is:
> > > >
> > > >         tid =3D READ_ONCE(c->tid);
> > > >
> > > > I haven't gotten any further than that; I'm EOD. Anyone seen anythi=
ng
> > > > like this with this series?
> > >
> > > I certainly haven't. That looks like some real corruption, we're in s=
lub
> > > internal data structures and derefing a garbage address. Check kasan =
and
> > > all that?
> >
> > Hi Kees,
> > I tested next-20240424 yesterday with defconfig and
> > CONFIG_MEM_ALLOC_PROFILING enabled but didn't see any issue like that.
> > Could you share your config file please?
>
> Well *that* took a while to .config bisect. I probably should have found
> it sooner, but CONFIG_DEBUG_KMEMLEAK=3Dy is what broke me. Without that,
> everything is lovely! :)
>
> I can reproduce it now with:
>
> $ make defconfig kvm_guest.config
> $ ./scripts/config -e CONFIG_MEM_ALLOC_PROFILING -e CONFIG_DEBUG_KMEMLEAK

Thanks! I'll use this to reproduce the issue and will see if we can
handle that recursion in a better way.

>
> -Kees
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHcz%2BGVjFqcjxq4%3DtCzJyPZFFRATWDNChyEUyV_Ru%2Bg5A%40mail.=
gmail.com.
