Return-Path: <kasan-dev+bncBC7OD3FKWUERBSHSVGYQMGQE3VA65MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 600008B2553
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 17:39:54 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2a4fc4cf54dsf1387417a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 08:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714059593; cv=pass;
        d=google.com; s=arc-20160816;
        b=sn97P4RQ0yxAlnuacUKmr50owW/rERP0pvhgJFj32l/uxZauSCn7YTiLSmf1bmJKSK
         7CcL9vSh/C2tQPnpro5HaGkhah+9+6rp0n2Nx60SdetUiI7lmnYg8gf7FzQPg+l1cbGv
         dqOr4Vt30bIX+O7N+c+GN1/WGoa9DA9JI34EZLK4fA1MccBDW4DN/vl2o0PvPLAfRyn7
         E3Y5syYMUNU/G+LrrrXmA2dwzDOEuGvJbq8dReY7SQww/W/oP7NZkpxsX07mexXfvy+Q
         CBFaQR2JnStuVR8xoCKN3qpO9pDasVkfZ5JRAvnCeCaHl37Gk5pkC4elVl5iGOPjG2X1
         VajA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QbtzZgGNuCQJdNDvSxuZ1mD8XsV1XHcFMqwl1tso6VM=;
        fh=uQSUtqrMOtCPlRU0tiFveX5YpMjvONMJJPkTwtPnurA=;
        b=mlrCVFBKmquEyD5n8YQpm5ZRj2pdYwocq4cUVKyQPuSvAloUu8mvJirxrYpbiOIAk+
         DL4ywdX5oSdH+RwUZ+vE3ovAX9YmQo8R+AmPt/PKIgxvZ1cS7NVrG29oAt1MbdPIc3Bk
         r17uSi92oi/CwAOtTO08ysQx3Fm4ZwuwobervekhdMFQmyBZrQY/qYi7Tn9YnSy6y7Ow
         S6L77wshbyqpCzVBV0ct/Zd3B/mF6bPhBH8EYsz+SKUMZ4kbnXFfCU0Nsp8ovn1UNkWW
         PyhvNGGKUPR5ybEOYx3wE/0v1nUd1SbQ3Pjn18FVtKJDfuhN+9KFLdFPPj5fCy/M2EHL
         Dp5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V2vLmzNO;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714059593; x=1714664393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QbtzZgGNuCQJdNDvSxuZ1mD8XsV1XHcFMqwl1tso6VM=;
        b=a0fwiSYS85ejZTcxHiUSfRHYpf5TKDDj2eoC8IxEqmamxRUgHCDq6OszHABEJ06kSw
         sJVB3yAXt0rGzQkS7qsiprE8QdUjKdtDvaXkgWdQ65jY0tzOuzPt8xLMddSobu0D0yMT
         8a6WpKRepNoUYAkTobsZ8abKQagRA/Fp/dzIie1ft8Gl3nypGZcv7BJ5a+gvTIDh6syI
         XET89AjEV2W+m5zhiLmTlWgMyRhNBjNomhmdn8gUXQi2YZKRqy4rOInM4Ik0VjvBTbLS
         QETnykzJtlGysoWdbwPGgGN1V/nV+y6h7ZN1rO692K4Ljozs3rZAJ+IlYHgJieHE4RuT
         BspQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714059593; x=1714664393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QbtzZgGNuCQJdNDvSxuZ1mD8XsV1XHcFMqwl1tso6VM=;
        b=ahX3ADCTEqKvBL8onVR2pr1HYRI04vb4rFXjGUOPW2nXep6r5Dfrdk8D3jmwb+63of
         OwxCnsiX/MEBPJwpineXP++E5/NNgr/6iUU7Og0piifK+XdZAb/NNHTpjIz8Hpn07ir3
         H+ZHogqnfxMAvVeLT9jLrOKZ8Ym46DJsLqLpszrOyQVUcXsMKbil0chcfx/tyislsJ26
         WFgRAjQ28wAfCMIyx6KyvtH6d/UdzL6Jloxy2wATCKz1nzuW3YmxhayuyTMENYMbABxN
         1TY7ivWK7ThHcOrUxRSb9efl1R1KYLYFz4tBuGwRfyAgZMy7FRwpIiKXuNA2Y0tL+HHL
         yOLw==
X-Forwarded-Encrypted: i=2; AJvYcCU+40ZMIVmkppgfW5w5GnLeAUe1b9xTZS1r7uYb3mSxlsflkECSTZTzNeyPrgvb4BJsDCMIVKNvAt1u5v+1kW9Fb8QsR7MHrw==
X-Gm-Message-State: AOJu0YzcFp1nuVE5M+JItLJwRapXs5b5f9CZbLnYsl/lVKSmG6HDDqpi
	6uOCf+uoB+T68c2XHsJY9rAbwweQ7x881qXEWgR19oD8FvzJzyi2
X-Google-Smtp-Source: AGHT+IHP0e8WeO8hl4Gp2Iiy8BrtlwLZYvvjJpzZuCnREiK4DyU6BSQAhpaVLfPXhFFa0DSbq68Mew==
X-Received: by 2002:a17:90a:e7c6:b0:2ac:86c6:fe with SMTP id kb6-20020a17090ae7c600b002ac86c600femr5971386pjb.1.1714059592581;
        Thu, 25 Apr 2024 08:39:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c8c:b0:2ad:f9ea:5084 with SMTP id
 98e67ed59e1d1-2afa00218ffls736891a91.0.-pod-prod-03-us; Thu, 25 Apr 2024
 08:39:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCr/pf9nRrNnSuy2zFtR+uk+BoR7Qe+fMcItsmqyp5mOIqhTyEtqiNyRAAJmzn9cad222mmYjN0H45vV6YffT9HOguT5koGG5UGQ==
X-Received: by 2002:a17:90a:4485:b0:2ad:4321:5bcf with SMTP id t5-20020a17090a448500b002ad43215bcfmr5903886pjg.10.1714059591479;
        Thu, 25 Apr 2024 08:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714059591; cv=none;
        d=google.com; s=arc-20160816;
        b=vG196vSBqlBOqQfgBXHJerPlk9k8AO7AXQaLBhI4heIhD3waNkHgiwxsvfeW1Z0fCF
         LZEZV3SKWsoBDUHY/OWMZVEhfU9t54UG3eAvMro3Q9gv37AbGt97KiUH3mtt+nl+CL4E
         Oiz267wbyGLcwk3fCoiglwwesZKzhj3jNwYQg6EL0nvVyuXvzVaLBSrsy3vQhhRzewkv
         /F92BRo+CuwlLob8OuxBXMI+nVu8vTnjVCQdwyeV0nESOZhpT6PGJcEa73GiGs022RQc
         oFva3z9Zpl96ORjA/EMjFw+MLJlUyEnBAo5ko7EGBzVnm47AGTb32Xl1eldkKvqTIKTz
         oOAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e0BChCss6w1nIzeILAtQLE3LhBpW3YXUB4HhPqTq7zU=;
        fh=WGbFgvp1Gb0yBaLIJNetfUZpbpiMTvKPgUpsAHKX67s=;
        b=B/PYQbKjz4minjMRTD224EksZxxaELALoS8vGpPb+LSMzoSclmGHAX+EEEcttt9TFo
         ob3IfHZ/JJmj2j/3e/sGWemsGDfFV+/A47l9o9l3TOWDeOdyXXKD5ZjDFTGCw1T2eV0I
         x+cAjvfFWZ0EHYbna6IjvcwVm6if/XlWqIn6yeSxcCFZ+j7ex3SqfVS+eKr03h9wsTc8
         CqpUtrfmteGtN3dmjrOIfftk6Fenuvmb4ZkSGvuqI6H6+oKqRxrcyMQSo6s3mwHPX0xl
         sz6W58ERJEbEVNgJRyDV7wDnw8W0CISvFH70M2pvhtBJRpbp4ds3PAmHOVBryt+SkGna
         L4Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V2vLmzNO;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id h1-20020a17090aa88100b002ae98dd6341si545184pjq.3.2024.04.25.08.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Apr 2024 08:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-db4364ecd6aso1289763276.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Apr 2024 08:39:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUJwvzYvJsiaKSJGCQvFVkW3+NmuPSeegMN3M1Co0B5dGazzXJSDS0+QYdLS+CgWahq/HbctnyPGAP7hqyK1x5wOeEuqcGrdvhosw==
X-Received: by 2002:a05:6902:54b:b0:de1:849:a6f3 with SMTP id
 z11-20020a056902054b00b00de10849a6f3mr5525501ybs.7.1714059589879; Thu, 25 Apr
 2024 08:39:49 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <202404241852.DC4067B7@keescook>
 <3eyvxqihylh4st6baagn6o6scw3qhcb6lapgli4wsic2fvbyzu@h66mqxcikmcp>
In-Reply-To: <3eyvxqihylh4st6baagn6o6scw3qhcb6lapgli4wsic2fvbyzu@h66mqxcikmcp>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Apr 2024 08:39:37 -0700
Message-ID: <CAJuCfpFtj7MVY+9FaKfq0w7N1qw8=jYifC0sBUAySk=AWBhK6Q@mail.gmail.com>
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Kees Cook <keescook@chromium.org>, akpm@linux-foundation.org, mhocko@suse.com, 
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
 header.i=@google.com header.s=20230601 header.b=V2vLmzNO;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
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

On Wed, Apr 24, 2024 at 8:26=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Wed, Apr 24, 2024 at 06:59:01PM -0700, Kees Cook wrote:
> > On Thu, Mar 21, 2024 at 09:36:22AM -0700, Suren Baghdasaryan wrote:
> > > Low overhead [1] per-callsite memory allocation profiling. Not just f=
or
> > > debug kernels, overhead low enough to be deployed in production.
> >
> > Okay, I think I'm holding it wrong. With next-20240424 if I set:
> >
> > CONFIG_CODE_TAGGING=3Dy
> > CONFIG_MEM_ALLOC_PROFILING=3Dy
> > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dy
> >
> > My test system totally freaks out:
> >
> > ...
> > SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D4, Nodes=3D1
> > Oops: general protection fault, probably for non-canonical address 0xc3=
88d881e4808550: 0000 [#1] PREEMPT SMP NOPTI
> > CPU: 0 PID: 0 Comm: swapper Not tainted 6.9.0-rc5-next-20240424 #1
> > Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06=
/2015
> > RIP: 0010:__kmalloc_node_noprof+0xcd/0x560
> >
> > Which is:
> >
> > __kmalloc_node_noprof+0xcd/0x560:
> > __slab_alloc_node at mm/slub.c:3780 (discriminator 2)
> > (inlined by) slab_alloc_node at mm/slub.c:3982 (discriminator 2)
> > (inlined by) __do_kmalloc_node at mm/slub.c:4114 (discriminator 2)
> > (inlined by) __kmalloc_node_noprof at mm/slub.c:4122 (discriminator 2)
> >
> > Which is:
> >
> >         tid =3D READ_ONCE(c->tid);
> >
> > I haven't gotten any further than that; I'm EOD. Anyone seen anything
> > like this with this series?
>
> I certainly haven't. That looks like some real corruption, we're in slub
> internal data structures and derefing a garbage address. Check kasan and
> all that?

Hi Kees,
I tested next-20240424 yesterday with defconfig and
CONFIG_MEM_ALLOC_PROFILING enabled but didn't see any issue like that.
Could you share your config file please?
Thanks,
Suren.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFtj7MVY%2B9FaKfq0w7N1qw8%3DjYifC0sBUAySk%3DAWBhK6Q%40mail.=
gmail.com.
