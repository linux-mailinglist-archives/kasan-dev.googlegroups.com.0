Return-Path: <kasan-dev+bncBCS2NBWRUIFBBEXUXKXAMGQEENC5Z2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 28842857363
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 02:27:48 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d0f26547easf1100921fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:27:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708046867; cv=pass;
        d=google.com; s=arc-20160816;
        b=gxh4zK2HtiFAEVOGKekYadgogwvwsJhufD44JyJkfxlbxOFkHdef4weZlFpTeeOBvR
         QgG+7rsEBRCnZlMGhqW02bwHohF81AztLWTHJnKtTmKSicp74D6Ulnc7kLT4TrnG2CU5
         52Q4YdLxsM2oyYLo5sKFMMVl+Lr4tY1038kv6C4cjxQOkbzb5xbGx2iwpQUj0n3+/XKc
         JMOFFy4SsAxtAUs993AwjW1LPsqOEJGlaGOlJsKkYVlmutntu0biFmhdSzc0FumqEs9s
         HQUTxKw2s2x0loa9dAuEYcsxmdS2B2oAyHesWDLAidnzhAsGWSOx4WWROHH0+ws9+Qjv
         em5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ivVGBrMNQyhOhHoEdHnowdQ5fXjC0vqC2BiL2SlueMM=;
        fh=nbCCflvfcxlHcnTaOJxsXR2R/j9CxUpaTNexrxqwpxw=;
        b=lx+5FQBWkGOqmTrQ9AB3JHSkb7fM1vCJi9TVpWnysMnxOU9ZbF1B09ussrlJtwfhua
         JbCox6zYiWQ6Bx0jXxWxI9KC0DzkRqwZ0/sOcLUK5hDg9xbRAYVZJhyKsHSqJclrVjEJ
         5EhK+iBUNMI9kbsuzygnQbRPSkpVv99hTqKKqp2r3N1tsmH0At3Nov7yloGqn3a6hTaE
         ixbB2Iatx16AvARDEJgbSiz5QS143/czjdkfEJlfD7iM3QA2mbAf6WIim4u3rPPMTgBB
         Vn/T9pByQJU9KEtC2rmv1Xq89hDeidX05FPJj4g9FHDcKHF+D4r1EnJVMdD47AY1bDgM
         wdlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eikRcSiI;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708046867; x=1708651667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ivVGBrMNQyhOhHoEdHnowdQ5fXjC0vqC2BiL2SlueMM=;
        b=Y2JJgaUheRwMKgYOtIMZp3BUFKYPbnrqHSPnicn+gTUKoSOOXCCGKVOxhDQH5uRFYW
         vt7SBM0wpcEsHjgwEWtHXKbaVzAi50fhXo5xwsAa2dyFiJ8/WlWvZuObsXxj9c7KLVXj
         /Mtfqqgkkt1nJfBtkzwyD2OCD6/01jJB7TW2kQUIbJKyJq3NKoG6Ds0x9wCJ5fafQ5Q7
         LJLKk+NIl3/BbwOXgWT4iCUX92rq9Ph0bCIhnhnJy4yBxi8ySUOhp+Osj4HsWxidce4m
         ggkZyzY9hL+qq+yYNjzLjelLob3M+gl3BrGvrw0QOsHSUGZK+wl7IRYT67haTeeccyjE
         KVRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708046867; x=1708651667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ivVGBrMNQyhOhHoEdHnowdQ5fXjC0vqC2BiL2SlueMM=;
        b=TJw8PG3xoQ+OamT0iIpoE1r70LZjMqnLSLBlbkzziJ0on6swino+05kTJG3tASUHLq
         OPJJhQL/Dx7ZuK3s8wmACXNjzlNeJL/FYAozXw6yUGlJBq9xcJpNUiraIQ4rm7AyZVul
         De1jTTPxbdAbOSSTEhlTccuuZDFxPFUASRI8gKcsJgqwKyoqnti5f/DnZrxxPcO1G9ga
         RrCr9VAmHPkPv1c/4G9Lderevmfy+kEsORrj8NgUKd5MCUNFdQRcx62qSKhdzXYyMsuL
         xZTTw0TjGDR7HReWAnzEVn3t7t8ITSlaGPHXjtfsd/nbNat0porZ/DV3KosAJOmhNN6Z
         sucw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmtBgIWWBADZQnI3dxVy6KhKrc2nrB15jUMWQPVlyb5msQhELKRGubzDxXmXFIi7NUJoZwta/eb1uBD68lX/XFM2WyvafZgQ==
X-Gm-Message-State: AOJu0YzvWNAc7WU8uBBcHkTdYN4Q6PCAYN2+zYPfDde5VugxWZZEvshr
	qHi86MO67gxcnxIQ3kzb73mrEhNtIsVMvQb7udPcpOQqVSkjMcUb
X-Google-Smtp-Source: AGHT+IEwc/H70GbZQdKtkRQWJkwpj4skh/oye0WQnNi5fWHp/Qxw5OxAk4yeQNBNGcMvsMOhXrkTSw==
X-Received: by 2002:a2e:9049:0:b0:2d1:a4f:9143 with SMTP id n9-20020a2e9049000000b002d10a4f9143mr2493839ljg.17.1708046867156;
        Thu, 15 Feb 2024 17:27:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1714:b0:2d0:e31c:273a with SMTP id
 be20-20020a05651c171400b002d0e31c273als86236ljb.1.-pod-prod-04-eu; Thu, 15
 Feb 2024 17:27:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVXiezch4ZgyHQFtn8L2Sc20yTijBspQnXwWQJ0WOLbaPEFrZQGPxYSXH+gU7Om+uC5hhytisFNzFENZjvak8m85aLK+VJPdb83Tg==
X-Received: by 2002:a2e:331a:0:b0:2d0:ce44:5ac0 with SMTP id d26-20020a2e331a000000b002d0ce445ac0mr2538842ljc.8.1708046865087;
        Thu, 15 Feb 2024 17:27:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708046865; cv=none;
        d=google.com; s=arc-20160816;
        b=DIcUR85TLyv8zxjNS0koVbJ+TyU9VIwJxQP9x6X7MK7lHeBRfCym1J5oNd+st/C8Hi
         SSmE6dMgBhNmnsgjtozRbwdocXQVRbE95BXwTagucr5yIg3g2uOqcxBU9Mnxjst8AbXe
         g3zMiqsbo9jMxJW6mmDIdyWYxWdoykYCPnaGZwUo7sZNiQr7RmCJ604arz74gB8KEaia
         pg83GjvH1xL6Br95dlsm8nZhF57aeY6uvs5ElRtY6MITnER/4Zu7uP3LaykINLHO9PWi
         eh+iTWGlZVkLE0Ts9uV15v0AdRgiHLKw6bzzHkNJTj/yEytnR/AcEhPpEpYoZcozzg5e
         pcZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=eetpFPzcLKuw5HxOpWYVmhh5wz1OkHFu3WKeFY7241g=;
        fh=AXAb/EIPldF8fTCz27UB9ek+BYwmfJdsNgI0w/L/dH8=;
        b=YsObWY7xUAwPxLie46Z3j+93jnv8t9Rknf7jrK55x9azzzcfi4hroSy5yPu2vIzYQ0
         YjQ7M0WvFe1M3zR/0aVINtMKhxqxNtwKUv6QZ/OtDaZEFYTlBnOjqujMFh1ZgzvP1SVC
         9mGt/bDiQph2th+wDHjI1X29Su/rHxg9gESSFnjR7m80idJLaFD9BXgJVWJW5xiQ3Bza
         zhb0UQq6xlUWeGim2KvPNhkxwdpv6MRGOucCKcAQfFMEBgZziD2e7Gxl8nHUrN8PwP1W
         7XjbLIinxYmKKWbFcn/fR9G34+PBm/UgAX5u+iQE6msAzh5ww4zFJiitktclA22rpW5n
         j1hQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eikRcSiI;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [91.218.175.176])
        by gmr-mx.google.com with ESMTPS id i11-20020a2e864b000000b002d20ec0a329si91665ljj.2.2024.02.15.17.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 17:27:45 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) client-ip=91.218.175.176;
Date: Thu, 15 Feb 2024 20:27:16 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Suren Baghdasaryan <surenb@google.com>, mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd@th3rlagul4nn>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
 <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
 <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eikRcSiI;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 08:22:44PM -0500, Pasha Tatashin wrote:
> On Thu, Feb 15, 2024 at 8:00=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Thu, Feb 15, 2024 at 04:54:38PM -0800, Andrew Morton wrote:
> > > On Mon, 12 Feb 2024 13:38:59 -0800 Suren Baghdasaryan <surenb@google.=
com> wrote:
> > >
> > > > +Example output.
> > > > +
> > > > +::
> > > > +
> > > > +    > cat /proc/allocinfo
> > > > +
> > > > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> > > > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kma=
lloc_order
> > > > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc=
_slab_obj_exts
> > > > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc=
_pages_exact
> > > > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable f=
unc:__pte_alloc_one
> > >
> > > I don't really like the fancy MiB stuff.  Wouldn't it be better to ju=
st
> > > present the amount of memory in plain old bytes, so people can use so=
rt
> > > -n on it?
> >
> > They can use sort -h on it; the string_get_size() patch was specificall=
y
> > so that we could make the output compatible with sort -h
> >
> > > And it's easier to tell big-from-small at a glance because
> > > big has more digits.
> > >
> > > Also, the first thing any sort of downstream processing of this data =
is
> > > going to have to do is to convert the fancified output back into
> > > plain-old-bytes.  So why not just emit plain-old-bytes?
> > >
> > > If someone wants the fancy output (and nobody does) then that can be
> > > done in userspace.
> >
> > I like simpler, more discoverable tools; e.g. we've got a bunch of
> > interesting stuff in scripts/ but it doesn't get used nearly as much -
> > not as accessible as cat'ing a file, definitely not going to be
> > installed by default.
>=20
> I also prefer plain bytes instead of MiB. A driver developer that
> wants to verify up-to the byte allocations for a new data structure
> that they added is going to be disappointed by the rounded MiB
> numbers.

That's a fair point.

> The data contained in this file is not consumable without at least
> "sort -h -r", so why not just output bytes instead?
>=20
> There is /proc/slabinfo  and there is a slabtop tool.
> For raw /proc/allocinfo we can create an alloctop tool that would
> parse, sort and show data in human readable format based on various
> criteria.
>=20
> We should also add at the top of this file "allocinfo - version: 1.0",
> to allow future extensions (i.e. column for proc name).

How would we feel about exposing two different versions in /proc? It
should be a pretty minimal addition to .text.

Personally, I hate trying to count long strings digits by eyeball...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd%40th3rlagul4nn=
.
