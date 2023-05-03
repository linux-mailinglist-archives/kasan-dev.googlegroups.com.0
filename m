Return-Path: <kasan-dev+bncBCLL3W4IUEDRB4HMZCRAMGQENKNTZXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id E01F56F5608
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 12:24:49 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2a83a0b7c32sf24566291fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 03:24:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683109489; cv=pass;
        d=google.com; s=arc-20160816;
        b=LbxKnVfiyPpxTR0s+yD2viqfNRjpnWL/GAn0T40s1OSjkvXUM5R72JkKfx1z/35VEd
         7GEojKmM7mZSu16PBzTUfOS7ZDZRYDs4pH5J6RVFrH1Kg0SHrDH80VfeL3OlIRtDp0QI
         N9kPwMZCbXw/9JyenZDm/ef7Uwj+mAE2cVjbwVZNDkqFiAgUlui6+lgRr3sF/VF6c94A
         RmW8PJM9styQKIhG89ew5NwXydbYBzESThGffh5LSYPK5MBz6h5/6MrtXm3IswhEJmOU
         sSZKvU6jsjilfX1Lbv1KQWdjjbSlU0FZ6KlsnLyJOiGE+bvCFsZo0G/PgD8kKQDJ0LsO
         WCnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=Z+mB2rI3XK5Wbj6XuzcMFrIdG6862PmonuvD4zUnhdY=;
        b=wpxSlOWJtQiMSYTRJLmjIqw4W0JxlQCaQ7/Gb4JuX32liE6wWMh8Qg0zM2Dv7eW4Fw
         +XgcxUJtm4RqBUroz8R5QZoou91/y6Fj/s2F5YIm96ftB6P/9n0JZpjGo/ff9n9moL8y
         kiAt9VDeSP4XOVTor1x7/0eT10NroBRrkjz+RgmoJMDHeJW+2jHrndw4CpIPcopmP+Od
         PKmp+lAwmkZVEketP0l7jmHE6E45TYc0V3eGrZZQ2UJkBdlgT2LOn362n7xe11wNIF4V
         R1fr1GxGQJFomHDPNeflYwh6q0ljFe9AEKbTDs1lrjF1f6iipAW9Zk4zppyvsMOwSKCq
         3Okw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=Quzj5nGN;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683109489; x=1685701489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Z+mB2rI3XK5Wbj6XuzcMFrIdG6862PmonuvD4zUnhdY=;
        b=sTx0+4Tbvt/nO3JZyVyYDxyXq8Q9PoinBj6xCF/3GOKGhXHZg4zb5hZiFrWrVEhvkH
         DBlZiapjLSeVHQqC/tyVFGoxIVaTe8rUaXdxqLQKvxDl3YmmxXcUoCUUH84MZRQX1+Sh
         ROMIh/1Nwc7f82iU1ijDu2H6Vj9DJQeP1JYelVqrU8G3FInD3ZKjPGKYv8mYmQ2rT1Ee
         FtpJ+cMsnde3o/IiHeIw2mdyfiRtD4+bjtW5eRNzksiPRwJOcw1dujKvqVzKIOUzpVMJ
         +PCJQLX1x1vfFw9K73exteYKmqY/KI0Bjbihxye8EK5mAR6qhYFjlMer2Au78Yp4moSh
         Fnwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683109489; x=1685701489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Z+mB2rI3XK5Wbj6XuzcMFrIdG6862PmonuvD4zUnhdY=;
        b=TfyIZt7R1j2+n8EgBE45YqIJQW0xGiDM83nYqwcr8KSN6WZLDv+OWP/SQwiDKEHIFd
         cX4TAY9vyf9XiQuhdMHxm3fYh7haKoN3dmZvMec+8PAMxYUsKv2nrIK9FUyDz2IdyvHL
         tli7JVcCKkwwMj5vk+Eern7WVpZUbckJ5n0+dws6VXJcqQ1LTXBtIxkbuXMY7mBoO3XY
         vlpJm8w/2mdfEMVkZ6joV2y9mam+iEUBa9zT9yFU2DWlhHv5JBEYB9VrX/FCxfj0xsPg
         z4tPT2TJXT2iY5r4HwM2BhhI39I+5o7I068yukgzfCR36iL0jXcrn5JnUlr/Sj3EyPPA
         0n3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDya3lML1ArQn3H/jN1VmkUIDLOUMkzb/yIP0frcZApO9QklsDF5
	sDf908Ro4Pu/f0Nmamc08nI=
X-Google-Smtp-Source: ACHHUZ4keAPeUwpCXslZ9sJirlMe4btjjBPny2MTXQkYrc3SCHLxRKDN8XPkJ/hNvONyfTBppnO/aw==
X-Received: by 2002:a2e:8402:0:b0:2a8:cac1:e614 with SMTP id z2-20020a2e8402000000b002a8cac1e614mr4703070ljg.9.1683109489131;
        Wed, 03 May 2023 03:24:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls288510lfb.0.-pod-prod-gmail; Wed, 03
 May 2023 03:24:47 -0700 (PDT)
X-Received: by 2002:ac2:5a46:0:b0:4ed:300c:10b6 with SMTP id r6-20020ac25a46000000b004ed300c10b6mr411360lfn.21.1683109487800;
        Wed, 03 May 2023 03:24:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683109487; cv=none;
        d=google.com; s=arc-20160816;
        b=WP6jGjA3ihYA5WxokP0/esl+ZHIojSxM03fwuudr+UYHQxmFZo66MTs1NB9dPYvXYN
         HzArVBrHT3FObbP19Cjo41eZDci5nhdsIZI/sPeqoMm0pm6e6Fuu4LYuHKsmZgQZUCDJ
         a04LYnUxkJcJOyhTrxRZ2DMdvYaZCl4jywaQut2iRiXE5VrDOed7Dj8OzEv7cTAL0jXL
         OWHByT2AW/8dXFuvV24kLbibBs+ReI9ObKUJKt/45vwHg5PhCdVoWTo8cjpPqMtzrnIz
         /1KQU03QnkrQ6tWY5Yyuf5Mh69X2D2CB1CoQHPDl+FBELS1uBxsa2iMkbVXMOZy/Iwp0
         b0SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Tpt/x44GXFeJEGwRhl0L0vcgkKGbeVaoUu3OBEyeFn0=;
        b=FEkgTR3A5AOOpFfYYtoxN2xbTqosD4QGjFNaJrocCCiiWDrlsKGR+S4OuxzTr1xmvh
         mStumQzumCSiEfmTYlfyBQorTORK+CfbABfnCrJoDq3EmfE4ongG2LB7hWOp4DuYTLOd
         UmmXsO6nNPZwZGo6XzxR8BGAVnGGEoXKwBRpsFFjSMFJ3Ov/TuPwcq2BStNJAizSGHsY
         ciMqaZ4FSllyR/7Eld/Y4sZXpyKyOOnojrQfkKoN4ukQElrz9o5PFZgckgryliB33g3P
         PlwlrKw9UaIACr8Ef/9FAHJtdreMmVyMPtp77MQ1bx2GfqFg1QI3GMCsomOiKqi19kkf
         I2zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=Quzj5nGN;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id h28-20020a0565123c9c00b004f13b703015si49750lfv.6.2023.05.03.03.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 03:24:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 8404614E2D2;
	Wed,  3 May 2023 12:24:45 +0200 (CEST)
Date: Wed, 3 May 2023 12:24:44 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
 akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230503122444.49f18657@meshulam.tesarici.cz>
In-Reply-To: <ZFIvY5p1UAXxHw9s@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	<ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
	<ZFIOfb6/jHwLqg6M@moria.home.lan>
	<ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
	<20230503115051.30b8a97f@meshulam.tesarici.cz>
	<ZFIvY5p1UAXxHw9s@moria.home.lan>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=Quzj5nGN;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=tesarici.cz
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

On Wed, 3 May 2023 05:54:43 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > On Wed, 3 May 2023 09:51:49 +0200
> > Michal Hocko <mhocko@suse.com> wrote:
> >  =20
> > > On Wed 03-05-23 03:34:21, Kent Overstreet wrote:
> > >[...] =20
> > > > We've made this as clean and simple as posssible: a single new macr=
o
> > > > invocation per allocation function, no calling convention changes (=
that
> > > > would indeed have been a lot of churn!)   =20
> > >=20
> > > That doesn't really make the concern any less relevant. I believe you
> > > and Suren have made a great effort to reduce the churn as much as
> > > possible but looking at the diffstat the code changes are clearly the=
re
> > > and you have to convince the rest of the community that this maintena=
nce
> > > overhead is really worth it. =20
> >=20
> > I believe this is the crucial point.
> >=20
> > I have my own concerns about the use of preprocessor macros, which goes
> > against the basic idea of a code tagging framework (patch 13/40).
> > AFAICS the CODE_TAG_INIT macro must be expanded on the same source code
> > line as the tagged code, which makes it hard to use without further
> > macros (unless you want to make the source code unreadable beyond
> > imagination). That's why all allocation functions must be converted to
> > macros.
> >=20
> > If anyone ever wants to use this code tagging framework for something
> > else, they will also have to convert relevant functions to macros,
> > slowly changing the kernel to a minefield where local identifiers,
> > struct, union and enum tags, field names and labels must avoid name
> > conflict with a tagged function. For now, I have to remember that
> > alloc_pages is forbidden, but the list may grow. =20
>=20
> No, we've got other code tagging applications (that have already been
> posted!) and they don't "convert functions to macros" in the way this
> patchset does - they do introduce new macros, but as new identifiers,
> which we do all the time.

Yes, new all-lowercase macros which do not expand to a single
identifier are still added under include/linux. It's unfortunate IMO,
but it's a fact of life. You have a point here.

> This was simply the least churny way to hook memory allocations.

This is a bold statement. You certainly know what you plan to do, but
other people keep coming up with ideas... Like, anyone would like to
tag semaphore use: up() and down()?

Don't get me wrong. I can see how the benefits of code tagging, and I
agree that my concerns are not very strong. I just want that the
consequences are understood and accepted, and they don't take us by
surprise.

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230503122444.49f18657%40meshulam.tesarici.cz.
