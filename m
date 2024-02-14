Return-Path: <kasan-dev+bncBC7OD3FKWUERB5FGWSXAMGQEWY2IBNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3681785532A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 20:24:38 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59a3956d3d8sf66107eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 11:24:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707938676; cv=pass;
        d=google.com; s=arc-20160816;
        b=sNCA1jFzF6fMpm1nivSkwINPw3gRvv+u1/+teb6yOLSWYSK3jwER0HZxFczseosMGL
         SfNCh6X90anBm/ibYeyth7TD928jHHNJl7ygZM0EtwgKmTB2xwzl3EQ49m9oZT71QT9c
         /p+OLIgg1wWHGqyAmsN8vtHuFYgCecYfp3vQcryee5vepZEqN1YegwCKazUvcmzIyD5U
         wC51PRadYV8AqeAjb590jEgwK5mpOfA/Auz839zD2ztFdsn5xnoL5iCxehEBhdU3as1G
         ybPE4sDzc3hjvmOw3/pjQkuqZrz9NfcLX+c8KzWuMQAW24Ob6qWafBOlgeyeihYOB5rw
         rGgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QnCZ162J/xKJyMMSkH8rOCICJWBMEHD2zRT8HYmCsuw=;
        fh=eD57s6EuSwk9GF6J+ooOzD9ZJNhpLII0pSFA0Nc+wsI=;
        b=JSG1ZXlpH+oHJEn6OgMnqnCTirRKnHXANqT0q4DT68Na/pjLMYN6SidXLe3rewd5Rw
         p/swvlPJ+ffavHfY2M66QuRLMr5XXAxUutNrVz7SMJX4EgEbpy1RLYCxZoCmzd330gNf
         6vlewsrXoLvEvPJSAahy98iiqqtuzO+tUfOAVqGS+MYDT1Pl/YAEGq8RqlWIwRcFPsH0
         xT3n3sfIgXkow/nCpn/8flhqTbgogA7A36LRY52O9jHawpKQSa4IXSkJzcZoFCRNYyAi
         IUVG3I+4zKyB4yi0qoP7Ei6lLt9oCdcHvMFLVfvN3MeL3BlPsnsd2ZdMVV7ROTM9JLvZ
         XF7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Fvvwdfg1;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707938676; x=1708543476; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QnCZ162J/xKJyMMSkH8rOCICJWBMEHD2zRT8HYmCsuw=;
        b=tHpjJT8Ox9XRE0HedLexck4nDoNQpia15M0KjJLthrzMMUzNs/MyUOn6YaZkiMFEeh
         pF0Ow3xWWIq3E9hkxz/H7s7aobM+wf8HXITbFTJgx3FNxrcth4A7b2NA15vZ1Ohn7t62
         UOSoW+pTaoV4hxu2/NTDSQ1Om+Ph3cD69+jpsBOCmyUzE3XacwiJfRXnTRUXoXHAZY9u
         LJMpUfjv3RYJRFvuKFMkTLdGDhuaBKzAtXO6Ygrqk/PINqNcCxoaeKIGNtK0MqH3j9bj
         RMzZTQT3tn63VOj3W9dAsnfvkauE1ZArWy43Mb+ZSBsZ+ryFYP0HmX3fPk7ZDy+KmRFu
         wEng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707938676; x=1708543476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QnCZ162J/xKJyMMSkH8rOCICJWBMEHD2zRT8HYmCsuw=;
        b=PTDq6+AB91ajcQcH45WohN+1eetpIGq3z2oIcOqmxtlcjT2YkLYX/ZrPSxHkaLzt+m
         iXEA3hTkaMStnsF6+MKRFBhYZUVvWDPHU4v+iqWgeXvRzbNkGTuugprlJ93pmQOjmRbA
         8TpDf8wWlQCVOIieQ0mV/l+h18Q3rN1CfDYqq8ZFmU7ch0ph4tymGX9oj/fQn9NllFMh
         Ns03/+wlhslh3TdU2sxwKUwOXhKdSrkw2RxGY3UUKJavkpTI+uBiG8KFMfuJ6BkJNkZo
         58v6qBVrPBWf4KXoRILqWhapKMCTAy+lkEhPVc1rk7OPKD46mr97bo/JfbTcEe5V581+
         lmlw==
X-Forwarded-Encrypted: i=2; AJvYcCXtVznjiQyLWIsACLacxVPC3n5DzCjpZbt2xwMT38UG5pDQaZKhLFzMWpAxNZ6vZRjCY4MIFFvmoEz6iSXKY1K7p8TwGqV5oA==
X-Gm-Message-State: AOJu0YydVv6beRDwJZFwclTriQJyGJrBd8LC/K2pj3utuMKEb9cxvwLE
	rfViC7tMEVB2BPsSERWi9hyRqScIXRgkH9bmYZCtkYO+wbASV3df
X-Google-Smtp-Source: AGHT+IGh1kSqHSRwcT44aTfuNXrbmzEX1jTRvFP5M8AXo7NrPGWUvNm3q5X+WeO1KDEbCyr6WX4P1Q==
X-Received: by 2002:a05:6820:1b8e:b0:59d:d34f:7eda with SMTP id cb14-20020a0568201b8e00b0059dd34f7edamr4728278oob.0.1707938676768;
        Wed, 14 Feb 2024 11:24:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:584c:0:b0:598:c95b:c3bc with SMTP id f73-20020a4a584c000000b00598c95bc3bcls453331oob.0.-pod-prod-05-us;
 Wed, 14 Feb 2024 11:24:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXj3luf3ZY3ghV1mYLeVJfkymm/YJJscwFKc3Qk5xHmJ2bxvH1y6/oTYNGipEhH7LAQz480WkQXZqeN92DZJnGHMNlg/H27BsXq0A==
X-Received: by 2002:a05:6808:f0a:b0:3c1:3489:f451 with SMTP id m10-20020a0568080f0a00b003c13489f451mr1124929oiw.54.1707938675697;
        Wed, 14 Feb 2024 11:24:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707938675; cv=none;
        d=google.com; s=arc-20160816;
        b=i8I0Gt8PQaP8KbdVnvw4XNencY9zNG3VgWI8vGnGmznhIR7BW+rODChbmgv7q+o0C7
         y2S7bdhZYPcIPDE9on0SBmiKkgBfGSnRiplY8ii77LHBs7+JRIlVCytZWv2PNxzatQa3
         DM+HNGsTiR9es+mf3uj4euBnczwXH8o+xpfvNFUwu4VO4ZsgH7wHHMaR6XDZpeqdRBz2
         GtJVi/kKqXPooqbZEnd37AvtO48vIKFrH3MyzcGZ8ApoAfWE3mtiqUZ3b2yDucaNGiOl
         ci5WPDNh60ap/BRZIJn7OCvOmmADQuMqBTezeYdrFtVP1inMCOnTItDMfXFXm6ZTNT3C
         80rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QCBYE/AD/BvL6op5scnwP5wjSjqsrmapht1Ra223I1c=;
        fh=jkSxAsTYIuOv76pgnzgMv5meZpF6Pa9xuV83hnq9oKk=;
        b=STqRoXDG6dW1x9879DAVnnXbOhWRAT5YvHFyyFB3OfLckG5rD7GoXrKra9fD+t8ZeY
         6Im7IPAi71ZXkcgNlmMEYUp0ysSWeVHrA2iagyzHQhX6bR6QimYLOz0wVIVj77EH1YKe
         DDztjgaHhI3DSjae6Kt3q9nWiEx21jkQJaAJVxVziC8GvfS/3KzNEnMhvv6CNM+OPsqA
         HDqzs3nrGq0/T7h8FisqjpIv5x/FicAfcMEV+hI9Iz+RSMkbF5oEdwIybzgOaamISr2a
         T5w+iHGL9PgroFPqhIB5cRuVMV4m7gI2LYYBOBsHGwoKBN+fu366xvSKj0kONxejXd54
         csNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Fvvwdfg1;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXczTV//lXOx2smAOVNiJDZwx7DJv/yc1qrmi0c581iZhC7KhHqSAKJmkFo2Dap9ErVtfNQR3Kq13fYdAi5GTLVE3P0ms8Oz3xPDw==
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id c13-20020a05622a024d00b0042aa4e99da3si627368qtx.5.2024.02.14.11.24.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 11:24:35 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id 3f1490d57ef6-dcc86086c9fso6274276.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 11:24:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVLa9HZWuRM4HrJjeXajWNpzE+nrJusoDKMLmrDZLDXKmg8+Tt2rcKLrJ6q8zH1AMjYKpGLMncqHdhfh2B3je7IeU84rIv0aal4Hw==
X-Received: by 2002:a05:6902:143:b0:dcb:cdce:3902 with SMTP id
 p3-20020a056902014300b00dcbcdce3902mr3406955ybh.55.1707938674882; Wed, 14 Feb
 2024 11:24:34 -0800 (PST)
MIME-Version: 1.0
References: <Zctfa2DvmlTYSfe8@tiehlicka> <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com> <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com> <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com> <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <20240214085548.d3608627739269459480d86e@linux-foundation.org> <7c3walgmzmcygchqaylcz2un5dandlnzdqcohyooryurx6utxr@66adcw7f26c3>
In-Reply-To: <7c3walgmzmcygchqaylcz2un5dandlnzdqcohyooryurx6utxr@66adcw7f26c3>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 11:24:23 -0800
Message-ID: <CAJuCfpGi6g3rG8aVmXveSxKvXnfm+5gLKS=Q4ouQBDaTxSuhww@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Michal Hocko <mhocko@suse.com>, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=Fvvwdfg1;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2e as
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

On Wed, Feb 14, 2024 at 9:52=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Wed, Feb 14, 2024 at 08:55:48AM -0800, Andrew Morton wrote:
> > On Tue, 13 Feb 2024 14:59:11 -0800 Suren Baghdasaryan <surenb@google.co=
m> wrote:
> >
> > > > > If you think you can easily achieve what Michal requested without=
 all that,
> > > > > good.
> > > >
> > > > He requested something?
> > >
> > > Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> > > possible until the compiler feature is developed and deployed. And it
> > > still would require changes to the headers, so don't think it's worth
> > > delaying the feature for years.
> >
> > Can we please be told much more about this compiler feature?
> > Description of what it is, what it does, how it will affect this kernel
> > feature, etc.
> >
> > Who is developing it and when can we expect it to become available?
> >
> > Will we be able to migrate to it without back-compatibility concerns?
> > (I think "you need quite recent gcc for memory profiling" is
> > reasonable).
> >
> >
> >
> > Because: if the maintainability issues which Michel describes will be
> > significantly addressed with the gcc support then we're kinda reviewing
> > the wrong patchset.  Yes, it may be a maintenance burden initially, but
> > at some (yet to be revealed) time in the future, this will be addressed
> > with the gcc support?
>
> Even if we had compiler magic, after considering it more I don't think
> the patchset would be improved by it - I would still prefer to stick
> with the macro approach.
>
> There's also a lot of unresolved questions about whether the compiler
> approach would even end being what we need; we need macro expansion to
> happen in the caller of the allocation function

For the record, that's what this attribute will be doing. So it should
cover our usecase.

> , and that's another
> level of hooking that I don't think the compiler people are even
> considering yet, since cpp runs before the main part of the compiler; if
> C macros worked and were implemented more like Rust macros I'm sure it
> could be done - in fact, I think this could all be done in Rust
> _without_ any new compiler support - but in C, this is a lot to ask.
>
> Let's look at the instrumentation again. There's two steps:
>
> - Renaming the original function to _noprof
> - Adding a hooked version of the original function.
>
> We need to do the renaming regardless of what approach we take in order
> to correctly handle allocations that happen inside the context of an
> existing alloc tag hook but should not be accounted to the outer
> context; we do that by selecting the alloc_foo() or alloc_foo_noprof()
> version as appropriate.
>
> It's important to get this right; consider slab object extension
> vectors or the slab allocator allocating pages from the page allocator.
>
> Second step, adding a hooked version of the original function. We do
> that with
>
> #define alloc_foo(...) alloc_hooks(alloc_foo_noprof(__VA_ARGS__))
>
> That's pretty clean, if you ask me. The only way to make it more succint
> be if it were possible for a C macro to define a new macro, then it
> could be just
>
> alloc_fn(alloc_foo);
>
> But honestly, the former is probably preferable anyways from a ctags/csco=
pe POV.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGi6g3rG8aVmXveSxKvXnfm%2B5gLKS%3DQ4ouQBDaTxSuhww%40mail.gm=
ail.com.
