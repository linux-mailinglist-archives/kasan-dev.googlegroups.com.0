Return-Path: <kasan-dev+bncBC7OD3FKWUERBLWJXSXAMGQEVC2NUBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63943857854
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:02:39 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6805f615543sf30242986d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:02:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708074158; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jw0qSqCQ4+3b+Sx8cF7ZkduCssGh7i/rQOoDHNvO/2/pCBYkyKl8DmwxT5BzB2O7WK
         nM34cuoL4URspnNhi1u0gLRUuMPFev9fpmGu027qNruAFoL1/y12Ud7L7Bm77u7BwHFp
         4puwvziG5wyWW0KgdOE9enmNo07vprmQy4OdKxKWAzY3RFjFZlruPp7FSzPEINMXrilT
         NJmyMHwHfktAs/2mdDGPcgF/TS8pDf3ZDy6rmN/M+ln2WG+GmpGSX0+uZxXPkC0/DS2e
         ixadTDW8BtRPVPN+eTtH2mggsimx2ZmgSgJP0LIeKJ1ucaFb6/Y3J1Nfoe66YFsVZt/4
         Puyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xbMt3qvcCOUDQL8TVjyzZ97hEFCis2rOFhWXig23BYU=;
        fh=xosW7na0xvIonjAu2xd5NVrRA70XpYQpPFFZQGHjsLE=;
        b=CeCywb8sQcDlA6yovDwH63IKDorHIeFRH7JEAzWQF0AexGYoTk7b4dGyGEWL0VoZYG
         2khFKUknQjma8CYHcqmblzFm+MpU1dPT4wS3dvjLBr128KQooJXBBUQtNmipQIRYlwHZ
         hJODhkUpve8x/Plj9QwHXG0Xxns1HmKbreFkzmMr7bEgNcqWBICA846XAiHgUvgWHogY
         mouiJh3Yyt//DPWP7FACMcdkcWbEq63jLMxGa0CDtR4ua/aLHcyCQygoVgoEgZ4oTunS
         iWjL25G8ikDlbqu9TfDNG+pl68fbiJHMZ5pMTVekCXHbKUVq5mI/+3C4tKDZhZUPPdwm
         rH3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OEAxVbYy;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708074158; x=1708678958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xbMt3qvcCOUDQL8TVjyzZ97hEFCis2rOFhWXig23BYU=;
        b=FWDVJpFR7dQp93oWqH5gbMzUngK6z14B9eFR5yU8yd5/xVjQk4XLN6ZGQagfXRhVTQ
         dd05oaQiGLu3zkXz3Zs6k8ihgwvpO1NxFWcfSVibfUBx+VrRO0+x96oS6qfBOW00LWNb
         ubqP6i7eEJRspfFhNaattdgg3X7IuMiyAqtHBHcVr21QXJPfw1/bCWMSVYHeDE1rIqGX
         Vf/9a/QLzpNZ0YAKq1Dat0QoGGc8FZs9ler+fATZfeq1xJIk90AhkHh08LNEuq8OdhZ9
         D7GPUdjAZxZuMhLZEJS/5sJb6ljFxS01ZVMlQGCQVO0wVlA0FGBzkEA7t45zXINb78aK
         ZioQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708074158; x=1708678958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xbMt3qvcCOUDQL8TVjyzZ97hEFCis2rOFhWXig23BYU=;
        b=Qc7c0q/ExwRb1XrAiykYXi6jTIKQtGbMLrd9KEuGcYtGGxFqAVhJkhXVXFeNwweMz9
         b2R8HWUJyHXk46xwvICDRTVHM4QVeRlj8p49VY5aLeEf8dHY1Dx+neJ5ZR+TIxrTUhIF
         +MlBMDNucvPjZWioqld0etYq+fviJNBVqJkKblwUImpvi0mVamDbIc2mPvTLxJKaAZLn
         wm6Qd71lixnpFvomPUm4Tu9Y/ylOCYuY5GwCpEd4BhtHHthWva29W/Llmx2yTUtlA4xy
         1o4D2TmiMAUizCdYl2QIg0QNqq97kGM91L8bN85jBu/gd0xNKcm2Gweaf0otLNF33J9C
         MJDg==
X-Forwarded-Encrypted: i=2; AJvYcCXQxOg4n/OPE/lQPd0hiS3+kVgpSKV2nh1uFlwTkegJ0uUfBI1RdMd74vXKBStIhg+qUgskyTQ1dZphYeVqeIIcRYZFrmyPcw==
X-Gm-Message-State: AOJu0YzJ0WHYyzO7IrKEgR3wVH9RAusaLTUIQ45nxanevQJFmLADVshx
	sDBuYF1k6W9w6jnHehktwN9LTHHa+7R7Vj8kAZRvqm/OBCup2FyN
X-Google-Smtp-Source: AGHT+IHTcoCv/IuyNpPcZJhyD796SMa/1Dq+toGLAOEjTN4vOjej5I87/vOF6C5HAwbzYez0+4CP2Q==
X-Received: by 2002:a0c:b542:0:b0:68d:128a:5c52 with SMTP id w2-20020a0cb542000000b0068d128a5c52mr4090954qvd.25.1708074158195;
        Fri, 16 Feb 2024 01:02:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2401:b0:68f:2d1e:ea76 with SMTP id
 fv1-20020a056214240100b0068f2d1eea76ls219921qvb.2.-pod-prod-09-us; Fri, 16
 Feb 2024 01:02:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWVrv6HL3ZZQdAns4AG8fEV1CofufYLUyIUGKDIyye39VkWW4yIoGm+gV3e2g+gS1HHBfuaXZz8IyPZgAbO1UcBUvuTgDEA5RDCTQ==
X-Received: by 2002:a05:6214:23c8:b0:68c:bcc4:f312 with SMTP id hr8-20020a05621423c800b0068cbcc4f312mr5430980qvb.61.1708074157430;
        Fri, 16 Feb 2024 01:02:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708074157; cv=none;
        d=google.com; s=arc-20160816;
        b=KmITEBhcmaq6Nr0HDpYPw5eSpLEEvPdWWF69CeMIEG1Jw77WBadToOwopQ+YdcEG/C
         Rm8bdq8z4lMxPsoFDXCZGDVwu/lvZ+tX2ufK8GaRGFYouVQMW4rqK3ikbU+QqXzx9e07
         frVIHSjQeZJFQL1SkkxQC37GWCOxxujR0jAUkb++s00G4C13bmyMiohvdKG/itJKaaiT
         E7Z3lqMpYu+CzEbOeVJNGjew0mQuGzcgNGhwBJm2z9FmvbieT0oarrF5M1pNjMX4WmnU
         uNb9JBNsTB8z3MSwLLanQYlHIH0er3szm+TyDurVKmnSbQitZvXQIpB30weZoIlBxztB
         1vFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aC0zV0jURwgzq9Q6615BgsaS7tbK8PR71BWfZKB9Bg0=;
        fh=kZoQyahlPmuuBKXQE9GKne3rcKxvj0xXbf2aef9tal4=;
        b=hW1yiaKnri0MZBZ/H5KuVSsTvWupE18VAxZp99PEG//phBQoF1aYSie9cxhwwWXzRm
         vvDHzxo73cFdDsa1v8im2xswsL4tavxIo73ew6CLS6bSHm5bR6f4AlhL3SfaAuGH8sJT
         xFlBlswngP8+AwM4fbUrdA66pLJuKB7CtRsiYBvEGgMpKWBi7ZVtdwei4W4dPibSgU91
         iLq1j3UQyalcOB93iNXDSXITmvKBpdNuwmipQo5aTkrvqYAHxRgAzdxIN5cqQ5P/lzw4
         gXJfYVPIU55TnA3yO0SQ3Tz2UY68ZW0IM0F12Pg0RpqN5jJOl5arGO2eVLWhle0H9FYC
         geMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OEAxVbYy;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id j16-20020a0cf9d0000000b0068f337572ecsi33149qvo.0.2024.02.16.01.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 01:02:37 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dc6d9a8815fso1914983276.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 01:02:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUNCZZAmu9O/qb4r/6xE/xwwA+PKjqKeG7EL5VmuRXwAZDJO0XvC30rZIzhhddtpw/x55T7hOPC8Wt0o9iChmEHgQyZQE33Lw3vkA==
X-Received: by 2002:a05:6902:1b85:b0:dc6:421a:3024 with SMTP id
 ei5-20020a0569021b8500b00dc6421a3024mr5156888ybb.43.1708074156727; Fri, 16
 Feb 2024 01:02:36 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
 <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
 <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com> <iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd@th3rlagul4nn>
In-Reply-To: <iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd@th3rlagul4nn>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 01:02:25 -0800
Message-ID: <CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1=Ew@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=OEAxVbYy;       spf=pass
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

On Thu, Feb 15, 2024 at 5:27=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Thu, Feb 15, 2024 at 08:22:44PM -0500, Pasha Tatashin wrote:
> > On Thu, Feb 15, 2024 at 8:00=E2=80=AFPM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> > >
> > > On Thu, Feb 15, 2024 at 04:54:38PM -0800, Andrew Morton wrote:
> > > > On Mon, 12 Feb 2024 13:38:59 -0800 Suren Baghdasaryan <surenb@googl=
e.com> wrote:
> > > >
> > > > > +Example output.
> > > > > +
> > > > > +::
> > > > > +
> > > > > +    > cat /proc/allocinfo
> > > > > +
> > > > > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> > > > > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_k=
malloc_order
> > > > > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:all=
oc_slab_obj_exts
> > > > > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:all=
oc_pages_exact
> > > > > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable=
 func:__pte_alloc_one
> > > >
> > > > I don't really like the fancy MiB stuff.  Wouldn't it be better to =
just
> > > > present the amount of memory in plain old bytes, so people can use =
sort
> > > > -n on it?
> > >
> > > They can use sort -h on it; the string_get_size() patch was specifica=
lly
> > > so that we could make the output compatible with sort -h
> > >
> > > > And it's easier to tell big-from-small at a glance because
> > > > big has more digits.
> > > >
> > > > Also, the first thing any sort of downstream processing of this dat=
a is
> > > > going to have to do is to convert the fancified output back into
> > > > plain-old-bytes.  So why not just emit plain-old-bytes?
> > > >
> > > > If someone wants the fancy output (and nobody does) then that can b=
e
> > > > done in userspace.
> > >
> > > I like simpler, more discoverable tools; e.g. we've got a bunch of
> > > interesting stuff in scripts/ but it doesn't get used nearly as much =
-
> > > not as accessible as cat'ing a file, definitely not going to be
> > > installed by default.
> >
> > I also prefer plain bytes instead of MiB. A driver developer that
> > wants to verify up-to the byte allocations for a new data structure
> > that they added is going to be disappointed by the rounded MiB
> > numbers.
>
> That's a fair point.
>
> > The data contained in this file is not consumable without at least
> > "sort -h -r", so why not just output bytes instead?
> >
> > There is /proc/slabinfo  and there is a slabtop tool.
> > For raw /proc/allocinfo we can create an alloctop tool that would
> > parse, sort and show data in human readable format based on various
> > criteria.
> >
> > We should also add at the top of this file "allocinfo - version: 1.0",
> > to allow future extensions (i.e. column for proc name).
>
> How would we feel about exposing two different versions in /proc? It
> should be a pretty minimal addition to .text.
>
> Personally, I hate trying to count long strings digits by eyeball...

Maybe something like this work for everyone then?:

160432128 (153MiB)     mm/slub.c:1826 module:slub func:alloc_slab_page

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1%3DEw%40mail.gmai=
l.com.
