Return-Path: <kasan-dev+bncBC7OD3FKWUERBZ6JXSXAMGQEJ6ZLRBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 379E185785B
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:03:37 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5952618dad5sf1952205eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:03:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708074216; cv=pass;
        d=google.com; s=arc-20160816;
        b=zHsjeJd8XluLC9y99RMBZ2AprDmACUYFqI0ejcuejeUPymMpbp8MQkL2DZkZOWw85c
         JZrnua7yFTlXzkCAxszlbSQzMxXJIBV7SnJw0Syr7u+XBLRjV5pYWDnMXApJRzeiYfj4
         GlOnC18SsidrMEIg1HIBI/6I54jgAPCcL7MReFT/OotraGvVylfQGwiy1N7lJRkAX7YU
         jjj3Zs7lb2hDotb6NEpqMxzRgFGjeJkhICiHxUkex5sj9QpO7gwV0MzduCRmpkUayMvk
         HRiBYcsbqIECRBwj1dX+fHvvAskQ4cewZMPmpqoHlFoBL9JygXyt21Dt7E7JiVQtn667
         w9DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1W+4a6WuBzhYFgNDPtOGGxWAIFWocnbnyg3/xfrNGRg=;
        fh=5fIMGJQ3A7k9J/fjb6YP97XOwSjzjSBZcivz/EPNMys=;
        b=ql2E9v2tC3v1esvjAToH3LyxmZGePIuB5sRTJeA1q2uJTBHtv5xDenfjMSsyMhalWe
         87jPyI0d+/1ago66nwBFAfPp78Rii9rstFaRUeTZ2BnaLEWFnpam8GVNr6JQsp0QyE1Z
         CPyRSGpihnhYWTzWOhaQDbL8rEwNWIHe79VeaorKueByPXTJ7xBFFfBEWlqkgShl2Qd2
         MK4YN9E2IdABFg5XcEGzv6aiE/LyOawL4SDEKThlXEhN2wR5JLXZAlWNGozDO1b6dwGD
         F1nkeImDNWlf1oYwUzUYZ69h+2Jebmsuj0iY+lRGevTtooV3nh7c0Q9mL93/Uy4MOR12
         oacg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wO9ZUtrG;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708074216; x=1708679016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1W+4a6WuBzhYFgNDPtOGGxWAIFWocnbnyg3/xfrNGRg=;
        b=OPYYO8p7OYSTR5+P4U4J6ShbwIlltdpojhz54VKQhDL6kLZOt9RfyOsUj/GXfKFOPU
         D7EDOqwZ96IzXg4iy6/oDuCMeoQ6Qgw5eEN5hHe1rON8POLOawiR1TyX4abR3tRuG1VY
         f0yrgykE+GNvX5iYdxr1LWK1+/pK8G37Pe32l0drISkJq1auBExz2VKRWIWj+14oADZs
         eE+/ktH5AJ/I4UodS1X/3VqnT2JjMTdaY3TW6Ebv0Gl1Y9M7trU63D5MnYMcg8Daso5I
         UH1YOhpIVxmDRM41uNtqEanXQu16CRG3KnBTlvW37oNzJcFWmDG1HbW50Zh/IREb+lq4
         UbHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708074216; x=1708679016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1W+4a6WuBzhYFgNDPtOGGxWAIFWocnbnyg3/xfrNGRg=;
        b=uKNswv21pVJG7GyuLabvn2KvvPz3xjbh3yUdUQflq0WSxBWOZLFKasUwAjEMHBnaMC
         CGNRDxs2BAFHc4hzDpLI3XW3VlYgzbzebQ66nm8qJ2arY9k4iTA6gls3Ck/LnFI67nz4
         FEal6N3HYRCu1It5gqrVuAdVtOUNaCcgc8p4PCghEVgW0HnULbjcw55JXnXvrFiKd+x4
         4oZmcqRfWORfKnezdRxIMllPeiS2jUB4lT46DfFEycOV1tC5KNN94P7JPEydbzJyr44/
         7owzylq2Za/WMvQoBRwNQ/K6V6+2+nXcAf/e7hMD/vvPpav+hpdtagx+SGyevsoQvUaU
         z/yw==
X-Forwarded-Encrypted: i=2; AJvYcCVvz+YArnHyks0befTaWr+RMDVIntC520sl3mwitbHzqDK2IbNWD/o70zSwDA2QumjhIRhGZnXDJFOeLG+9QfQL6X4h/1Pu7g==
X-Gm-Message-State: AOJu0YzaUjKepVL0chzGVW87THmh9Rd6DrAMjTvUzCfvMpmstGD+ou/M
	ReB6wkHr6U4c9U0o05aXZMbuUNCz88y+6KiBbFgbGTwfY+VAHIFpuvc=
X-Google-Smtp-Source: AGHT+IHCF3RfB65DBaDNlgS8WRiRWiGVdTdTSeca9p+8qZeuYzWU/LDVhvcub9rQ/GI8Dud+FF624w==
X-Received: by 2002:a4a:b78b:0:b0:59f:8466:5748 with SMTP id a11-20020a4ab78b000000b0059f84665748mr3864311oop.0.1708074215910;
        Fri, 16 Feb 2024 01:03:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d7:0:b0:59c:8811:7841 with SMTP id e206-20020a4a55d7000000b0059c88117841ls592388oob.2.-pod-prod-05-us;
 Fri, 16 Feb 2024 01:03:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWqo+gGuXuCeuiCuENYp5k3Wu1ZQbtaEj9LIZasrswXwPEbgkh8xKNC9UnZI8ZQwnbrFJqJHK/gflJlYW2hvNE71M8lxvtYT6JnOA==
X-Received: by 2002:a05:6808:23cb:b0:3bf:dfa8:5190 with SMTP id bq11-20020a05680823cb00b003bfdfa85190mr4580671oib.10.1708074215186;
        Fri, 16 Feb 2024 01:03:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708074215; cv=none;
        d=google.com; s=arc-20160816;
        b=gGIcA2Zd02CZPdmi6Hy4Dl66CHqbEXKx6QMHhfedHBT/2RX//hknwSnIJB6a0tCHIF
         QaBgxPThWkUae4Xxyhu5GRIy4PHCUOB4WEwQMSIT68L28UAODRkFgeTPTvBuPAgZJyMq
         BAKL8pBm86V7Edt82vx8UY+rH8dxOiaPqP4UrG0i3V/bfa8nQTvLRw7IwYx0WDMpeac1
         Dm/Fxmy+9c+PtIAAk462nu/4a6538qoFf1bSCK3mwOgH0ekn2gxWJz6y68K8CBK0vH2b
         Va2Ug//SuF+uYMTFL34YtcyiEepa6RdC4q0a+s2WcaAGGhsD/oK0qpNNsizWaALiUv4n
         dFEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GIsEikU4izdqkDoN+ZKv97zMNiSEQemJahB5wDm74LU=;
        fh=+46uxO8WnjsfQ3e3XyNdytO4co0fKk7bzIAAh/hzjlE=;
        b=JI1L5wuilznpvmxOsCur0q9XAg7Y4y5wPMKHZW781JSsN4Lj+5y5K56Cnn4CgEE2Uw
         ObY5Dge7SABKa6I1Fu7bpvlDEyZQJOyCJJjFSmvCoiXixxK+RpSYSM/FSJYICSQZ1g/z
         jc2yy39YnhW5iqQITwisqtVjIPEisFOL/yxvRF7Ithd6XbCTG8reENXnpeoKqvrLCKhA
         cVO+jQZKZUD06bc7KefJtjrkuyxMc1toK1bvs88WrTb/5zUE14bocNOEz90gVm5sVROW
         jOPIEOFaHiNXZs90vynRQ5LT8zIVSGfwYJssC9RNo4jEM7rTVqMhiwpQ3CvWb6KVpQwi
         eQsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wO9ZUtrG;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id g16-20020a0cf090000000b0068f10446451si148117qvk.7.2024.02.16.01.03.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 01:03:35 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dc238cb1b17so1697442276.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 01:03:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUFpDxgYyKJwUe2TLG2nWtsI7kA/uMgXFkDSiW8cqQMEQ6yiU3Y7RsDZ24YDPilVDSeKjS8S68K5X+a2rpt3bsaijphDCf081TQOA==
X-Received: by 2002:a05:6902:200b:b0:dcb:be59:25e1 with SMTP id
 dh11-20020a056902200b00b00dcbbe5925e1mr5215694ybb.30.1708074214367; Fri, 16
 Feb 2024 01:03:34 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
 <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
 <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com>
 <iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd@th3rlagul4nn> <CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1=Ew@mail.gmail.com>
In-Reply-To: <CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1=Ew@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 01:03:22 -0800
Message-ID: <CAJuCfpGbZtUEb+Ay_abmOc=Tc4tuTtLVSK4ANpwvwG_VTAD9-Q@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Pasha Tatashin <pasha.tatashin@soleen.com>, Andrew Morton <akpm@linux-foundation.org>, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=wO9ZUtrG;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
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

On Fri, Feb 16, 2024 at 1:02=E2=80=AFAM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> On Thu, Feb 15, 2024 at 5:27=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Thu, Feb 15, 2024 at 08:22:44PM -0500, Pasha Tatashin wrote:
> > > On Thu, Feb 15, 2024 at 8:00=E2=80=AFPM Kent Overstreet
> > > <kent.overstreet@linux.dev> wrote:
> > > >
> > > > On Thu, Feb 15, 2024 at 04:54:38PM -0800, Andrew Morton wrote:
> > > > > On Mon, 12 Feb 2024 13:38:59 -0800 Suren Baghdasaryan <surenb@goo=
gle.com> wrote:
> > > > >
> > > > > > +Example output.
> > > > > > +
> > > > > > +::
> > > > > > +
> > > > > > +    > cat /proc/allocinfo
> > > > > > +
> > > > > > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_pa=
ge
> > > > > > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:=
_kmalloc_order
> > > > > > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:a=
lloc_slab_obj_exts
> > > > > > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:a=
lloc_pages_exact
> > > > > > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtab=
le func:__pte_alloc_one
> > > > >
> > > > > I don't really like the fancy MiB stuff.  Wouldn't it be better t=
o just
> > > > > present the amount of memory in plain old bytes, so people can us=
e sort
> > > > > -n on it?
> > > >
> > > > They can use sort -h on it; the string_get_size() patch was specifi=
cally
> > > > so that we could make the output compatible with sort -h
> > > >
> > > > > And it's easier to tell big-from-small at a glance because
> > > > > big has more digits.
> > > > >
> > > > > Also, the first thing any sort of downstream processing of this d=
ata is
> > > > > going to have to do is to convert the fancified output back into
> > > > > plain-old-bytes.  So why not just emit plain-old-bytes?
> > > > >
> > > > > If someone wants the fancy output (and nobody does) then that can=
 be
> > > > > done in userspace.
> > > >
> > > > I like simpler, more discoverable tools; e.g. we've got a bunch of
> > > > interesting stuff in scripts/ but it doesn't get used nearly as muc=
h -
> > > > not as accessible as cat'ing a file, definitely not going to be
> > > > installed by default.
> > >
> > > I also prefer plain bytes instead of MiB. A driver developer that
> > > wants to verify up-to the byte allocations for a new data structure
> > > that they added is going to be disappointed by the rounded MiB
> > > numbers.
> >
> > That's a fair point.
> >
> > > The data contained in this file is not consumable without at least
> > > "sort -h -r", so why not just output bytes instead?
> > >
> > > There is /proc/slabinfo  and there is a slabtop tool.
> > > For raw /proc/allocinfo we can create an alloctop tool that would
> > > parse, sort and show data in human readable format based on various
> > > criteria.
> > >
> > > We should also add at the top of this file "allocinfo - version: 1.0"=
,
> > > to allow future extensions (i.e. column for proc name).
> >
> > How would we feel about exposing two different versions in /proc? It
> > should be a pretty minimal addition to .text.
> >
> > Personally, I hate trying to count long strings digits by eyeball...
>
> Maybe something like this work for everyone then?:

s/work/would work

making too many mistakes. time for bed...

>
> 160432128 (153MiB)     mm/slub.c:1826 module:slub func:alloc_slab_page

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGbZtUEb%2BAy_abmOc%3DTc4tuTtLVSK4ANpwvwG_VTAD9-Q%40mail.gm=
ail.com.
