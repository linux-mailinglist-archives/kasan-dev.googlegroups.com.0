Return-Path: <kasan-dev+bncBC7OD3FKWUERBE7KWOXAMGQER4FUBNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 18EE6854FA5
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 18:15:01 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6e2f6e00f69sf2061116a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 09:15:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707930899; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfwmufCdFPuqvq87GDF583wdjPdjLvYabBEgpEgOk11tLIBjITrkQACEMqpewOeItv
         FBw8eNoffAmmvklge42wnZTFceFrT8J4wFi0SUoDwbPyGGzCCEKgN8Slwrd3uz+ibf/M
         MtfHh/ByfvbLKwBjUzOiOXLOOU2JoprToodydMZhr1g3m5fPngA+Ntsvan3qp6jd6ve9
         hmjuwVUEvzkZYNc4bxSIWfVOI1FfXI8Iegl68pPgctNM6Xv70gpfcxehyOg5Q0RWA+1h
         3XaYOjc2Oabo8t0CNSfuS4gf+iCtHhJehSTJW01iRIqYIPxueP6CRDRjismP+uRCBHIk
         dqZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WxI+ypBNzbu6JlogKvYGH5zVZDWTe8wuJ0sGIJIY3II=;
        fh=AjYtLYYCk17QOQ4KPojysixEXfux2knpj443O7LljTo=;
        b=tauSs0SG75XjZS+KxknW/yNIwcOYSPU7ELcQFDxPQrP8Ic4c69t+8e/yxsWk+OavCV
         nD6o8HrLJb7oTYgCA6FkXanb8+OQdb4mwshTq1Zh0mVL9YRr6PGhIxgS2SawV6nEqszp
         8m6B7/sQHGsVfPK/KWyA0QRYbxXhaHmhj+DNB7nxT5YrK7v0/vIfLEAM2Ha/rJEgcEXF
         f92kRbl9dtwauGqGoEQdyUgsxnJjA7gOwRRR87KpU/gCcntN8JX84L/w9ppfc0E0XH6U
         et5TdN7LL1/qq7Jeu+wi/q9hJ9S7Xgw+U3oi7XwArSl4u/X9dmFrA9Sxearyob+qKGu0
         HUXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OlYhYypd;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707930899; x=1708535699; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WxI+ypBNzbu6JlogKvYGH5zVZDWTe8wuJ0sGIJIY3II=;
        b=TpiLO9o3D1icYUrlAakdCBC5Q018R1bGRiiGEFaNq76X1npVNkWEpNfj+CYSa+9V7d
         99jqYz5nCHvnHBoXkjur+xUx8dRoT88JCxjJRmnkYqAR+Y7Mse4CAmmVmDf3Xv3rdCy4
         ipN6c7tPC2SpFLkokoC0vc+URAjm0+UJw4MeVDbSoXqhGTb82k2wWM/Tw0QbwStsRRTk
         MuerQKsqU9E1gHGdGH874WLGacKvNY4vsVclKE7SpeeRn5h1q7YkrHnX+30UEuDkvxza
         bZawWArPWNb1mwKNHukYva9k0Em3Luxn17pgM7y4Xgi+8GzBwB2XkD5jmQOpGQMeR+Z5
         nVPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707930899; x=1708535699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WxI+ypBNzbu6JlogKvYGH5zVZDWTe8wuJ0sGIJIY3II=;
        b=dC18lkmkSGt8xRwRogQmiq5+A5joSD9bCjemLFqjPYOrF8HWPLM/XlpjWnXF1hMzAL
         e+yG2sTgOBLLeAmIGG/Pm0MLpKmB+5zOfiaakVw76ybZRQt6KHmpQfpzud/Jk/0cQAt2
         Pmqd7L9ZRHvlGsjWw3O5Wh3EFZ1BiQS6vyez7iLsPUTdqQSNuwch2ftDpDXwWaq2/uXM
         pfj4Ka/FCDoWCCFsMlu9yrxKyPRbf2/cXChjA6TqhQYYBN/RuX+zZA/kAdaVJkfi2f2i
         zKmd3tOR9KGn/z6HScuyjFQkcMJgyIn5NDFX2F+rgSJS6pmlLJS+PMcM97qDCxEBUsiR
         mn1g==
X-Forwarded-Encrypted: i=2; AJvYcCU9RXxcJy/k3Q7ORIFzL+bzukyMjrodW4AVzvhPEYZ0ZtgFmyCzJ8bEPs1Dbc8QX2tTki4LG02LtEy3JOFYSvOonMEee1P+qw==
X-Gm-Message-State: AOJu0YzAPkh9ZxYIF5mf05YtcLQ4iFhEc/3cu9FBnkFyoIRxRd33qn2x
	/emqOysVCy6YN46ktyBUlFeR+pHtWLV925/VGIMaOKX8U4vD3ODf
X-Google-Smtp-Source: AGHT+IHr1em22+WHrNWH43zReyD7AkxjDtLCcmUo0K6Tw2LNrJ3w5aBDsQ0HqqMbnrwEOaQzdHnDhQ==
X-Received: by 2002:a05:6870:523:b0:219:840f:d7d with SMTP id j35-20020a056870052300b00219840f0d7dmr3627440oao.17.1707930899506;
        Wed, 14 Feb 2024 09:14:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6c03:b0:21a:d868:61d7 with SMTP id
 na3-20020a0568706c0300b0021ad86861d7ls2195389oab.0.-pod-prod-03-us; Wed, 14
 Feb 2024 09:14:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXceyhV2Q9G+9QDDVMo4hOx1WgWRTuGKudLHVjmfrMSw6q9e4WwwX+kREDdHoFbAll0s2xIPfxK7Uw5wFV3n3L/TqVcZTz/MBcPTQ==
X-Received: by 2002:a05:6871:8a9:b0:21d:e9a1:1b53 with SMTP id r41-20020a05687108a900b0021de9a11b53mr3060765oaq.13.1707930898680;
        Wed, 14 Feb 2024 09:14:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707930898; cv=none;
        d=google.com; s=arc-20160816;
        b=gocXieaLZbKXIHb6yKhMaZ0i6zIEqdXNLETYps6VsUh2jkay+vqzXTsjKHj0mR4rE+
         tEg8tPOPj/uUudt2A6MPyOskqU3p/XnzwUr54uBGgHzE8/UbRtAUfCHi7aFT1S0dHZwE
         AIp2Z56nFdqSbbFOzJVMLyi00J3YeW/vu78PUDJ4Yqf3wkV26ypjRHj6JU6m+AKS5b0Q
         i1X5OCKBSZNrV25JN8dYPbQX2UQN5lpWX7mxWri5eokm1ADQtEK1uAvKB/jLt7ZhEj0m
         AaRTUu+TiUlO+o/lCv+DwtG8e1HT/SWHqpEvRFIsrAR/YbmRwrIPrRMa0I0IqCLlLFDH
         KRUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LDg0vk5u/oyOZlQ8e31c3DglAzpuw7KxG8umDKGdfj8=;
        fh=JHLjIOU0DYuk2Xb52zLfv9KBEQkw04t9/Pl6v9H/IYM=;
        b=EnLRb6rhZbxQWZ259WBQ6FogPR2paNcN3EMIgu7htmT4+Jah53V9cx16byF/vXGeqQ
         KEkgpksXL7t47n/B/5js3IU3fEk/bFpGoa01mOFxonKYmNXmP3KrjbuNUcSqfDwNilVk
         e48BVgG3jT/vFXlj5/9yRPwncIJKqOnBmjckIEvcs5zm29aPid/oau/eV6w91ozyorQH
         ML1vd/VH/wGKVcA/i1ekT/6ZI5q/sbSm7+hRL3zKvmBAY6nGiJfjXC5fMs5Ndr6XKSEg
         5LRtB3tpg55wHZtglJY2gD2uJaMU6FxKZd5nJYPhfwg5WIwnBdJjQdO7iape+jOwpmJj
         f5gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OlYhYypd;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXh7SwmopvnRdxK/NXFLAZjRiN0bf3XE2VdpPMKq3oy1hJlAoQ65uYzCMUwEUPW5Epb+LHmpHl52PCHtECVl8SDH00IRe3KAYrwtw==
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id he22-20020a056870799600b0021a0d307f23si1093461oab.3.2024.02.14.09.14.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 09:14:58 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-d9b9adaf291so4254870276.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 09:14:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUAAXARB+2wgyxR+iu5LjHCrQtRPeZyM61Zd3Nx1zE4oUd44zhIqCHDxxRx80PPgRf0s8fV3M8nrtUycUffbiSMWccvEqmv8esssw==
X-Received: by 2002:a25:7443:0:b0:dcb:e82c:f7d with SMTP id
 p64-20020a257443000000b00dcbe82c0f7dmr2936932ybc.41.1707930897779; Wed, 14
 Feb 2024 09:14:57 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com> <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com> <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com> <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com> <20240214085548.d3608627739269459480d86e@linux-foundation.org>
In-Reply-To: <20240214085548.d3608627739269459480d86e@linux-foundation.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 09:14:46 -0800
Message-ID: <CAJuCfpE3yQyMXX5izocnWaDuB5ATfqHi-JcvcTQSvmf9c2zS4A@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, David Hildenbrand <david@redhat.com>, 
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
 header.i=@google.com header.s=20230601 header.b=OlYhYypd;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as
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

On Wed, Feb 14, 2024 at 8:55=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Tue, 13 Feb 2024 14:59:11 -0800 Suren Baghdasaryan <surenb@google.com>=
 wrote:
>
> > > > If you think you can easily achieve what Michal requested without a=
ll that,
> > > > good.
> > >
> > > He requested something?
> >
> > Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> > possible until the compiler feature is developed and deployed. And it
> > still would require changes to the headers, so don't think it's worth
> > delaying the feature for years.
>
> Can we please be told much more about this compiler feature?
> Description of what it is, what it does, how it will affect this kernel
> feature, etc.

Sure. The compiler support will be in a form of a new __attribute__,
simplified example:

// generate data for the wrapper
static void _alloc_tag()
{
  static struct alloc_tag _alloc_tag __section ("alloc_tags")
      =3D { .ct =3D CODE_TAG_INIT, .counter =3D 0 };
}

static inline int
wrapper (const char *name, int x, int (*callee) (const char *, int),
         struct alloc_tag *callsite_data)
{
  callsite_data->counter++;
  printf ("Call #%d from %s:%d (%s)\n", callsite_data->counter,
          callsite_data->ct.filename, callsite_data->ct.lineno,
          callsite_data->ct.function);
  int ret =3D callee (name, x);
  printf ("Returned: %d\n", ret);
  return ret;
}

__attribute__((annotate("callsite_wrapped_by", wrapper, _alloc_tag)))
int foo(const char* name, int x);

int foo(const char* name, int x) {
  printf ("Hello %s, %d!\n", name, x);
  return x;
}

Which we will be able to attach to a function without changing its
name and preserving the namespace (it applies only to functions with
that name, not everything else).
Note that we will still need _noprof versions of the allocators.

>
> Who is developing it and when can we expect it to become available?

Aleksei Vetrov (google) with the help of Nick Desaulniers (google).
Both are CC'ed on this email.
After several iterations Aleksei has a POC which we are evaluating
(https://github.com/llvm/llvm-project/compare/main...noxwell:llvm-project:c=
allsite-wrapper-tree-transform).
Once it's in good shape we are going to engage with CLANG and GCC
community to get it upstreamed. When it will become available and when
the distributions will pick it up is anybody's guess. Upstreaming is
usually a lengthy process.

>
> Will we be able to migrate to it without back-compatibility concerns?
> (I think "you need quite recent gcc for memory profiling" is
> reasonable).

The migration should be quite straight-forward, replacing the macros
with functions with that attribute.

>
>
> Because: if the maintainability issues which Michel describes will be
> significantly addressed with the gcc support then we're kinda reviewing
> the wrong patchset.  Yes, it may be a maintenance burden initially, but
> at some (yet to be revealed) time in the future, this will be addressed
> with the gcc support?

That's what I'm aiming for. I just don't want this placed on hold
until the compiler support is widely available, which might take
years.

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE3yQyMXX5izocnWaDuB5ATfqHi-JcvcTQSvmf9c2zS4A%40mail.gmail.=
com.
