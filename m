Return-Path: <kasan-dev+bncBCS2NBWRUIFBBXNXWSXAMGQEBZXFKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 03BC7855393
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 21:00:31 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d05e887307sf6795561fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 12:00:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707940830; cv=pass;
        d=google.com; s=arc-20160816;
        b=kEx/V2DwSaCAPyxRBT7st1C+t+JtaaNVSa9tDM8R+gLwUdqS/2ZzG7sz4xf69LxbXO
         032800uY81mXym0vWzmajZIIjOUNBryCtHzNQa6Fmx4t53iewvgscmsoLuX/a5Wqt3ZA
         vU0/9It7mTl6McM/pZdtcpE/3rcKm5oAO77rnCZtRt3szN7ccHX1+V11Y9DKcZ0wtLLJ
         55gIMjS0b49Qwc0ahBSrRFUWs6IbcHJYwhL5l/+3/xvZcAvAUtJy3rnRUBVbVCIlrkzC
         +Kj+X+BU4cSTHMgQoqMtXHPCMhn+I1JUngBFdd3BCdNEfS+3nNLKmdNLOF6xMzQfRuwi
         yW+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=21bYJbkmxbRSstXi3NddYVyxw5+ld9jR61wpSePdLb4=;
        fh=jKPVQmz3txTaOTAP0oPdQausssChN0nnl7KtMRCdLrU=;
        b=Rj5O8JbdzKcSRKSp1ER8wUMF32e98P1LxH0zdb562Njw7qxS9+V8fk2jxU/zgk459v
         8ivuXfDxPaHUg1kTtsot2FfIiq7LPwfm0FrIwTOhILmTjN5gZkLRY/+AC6FaG0aLyAom
         NgMqDbSh2ikziiWJVpUPoGCAnyx3tU4oR8HQ78sp3w5KaaWPsDvm1e5YhTZhKQcIXOF9
         e6jEwxIHREcSj2/+Kzqzi9nwdeyJr/Wty22LNYgdJkra/1avfqid1A5nBDLOYfncOcgR
         wfeNB3z366Jcs6/6dWD9OZfEsM/+ce2KO8Y8zNNL/RdtbynwiWZ0XY2EWAu1ARgTxlKk
         NsHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=V0Dtva7q;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707940830; x=1708545630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=21bYJbkmxbRSstXi3NddYVyxw5+ld9jR61wpSePdLb4=;
        b=WljUwQyyNpOPHS/7wIeOtH1Juy6MjiKWCy0fbR+J2Ai5Cva2RJEYdnlixYJysLI/TB
         oLW4OrAw/g3Q6ryTuDf8gJ1JelvhQGacJoEeMWlnqWpenGL+XUST8taKfyFfpCWw2KOK
         QLVZfTENKq7kykqgX+8Elor9rJ04Dn6b0+jrahLAmxWGPo0AIw+L5YuVtI3jpgDXDk50
         gegfpyZ337hvfuvgseIKbUwjQCnIDWmy0W3Yx84zyKtt6R/6Zgho0NG+rKUW+rdSNLC1
         jHn167bJiWFMw1McfLOKvj71KOBrtiq74HDkliCutTtQTFfYQjW7uYR1ib7+lUqNGJ0e
         T3BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707940830; x=1708545630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=21bYJbkmxbRSstXi3NddYVyxw5+ld9jR61wpSePdLb4=;
        b=HEzReuJr3kwHeYL+F3KOY994F6q+ghJpdDlhE/HZJ2cu7YoPotWg1duPpOu26z5VqN
         HOvrORxyfqyJ/4pOkaNSUT0sVpJTKXIb6j3z3NP9lBjcLCib6w94WG42oGxFAFj0F98W
         1iby4ATVrSpkn1a3q8AqkVtC17vE6/0rzTKb+2pPZMc1cpBuR7NsAJqLFgGnt/quy4k3
         oYfEmKbEPJG5vA6bTKcWlt5EjjL7c5/r2GBuFTStfdZT7706NFyr47y2P2TJuGSSjE1f
         TPwGWNkAR2NCSwiMeim+buRWZyt0M1Y6ZE7OaSfZEVw9PYNkrtQvjliBXp84wnfZlSKg
         xEeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVpsTkY9JT7otT2QhhEt2KWFxlWLplK6n1K+xXeNm5Kl8g5f7YCie1I0Ka65SDQy+RQLlYc3AoHMVHdWDA+TfZokAnufPPXWg==
X-Gm-Message-State: AOJu0Yx9ldiZWSvhUFrDv+8xRzjQa3+yeqqy/4BQ6Sxps4vNWn3eFHsq
	leGcMK4QPEAv8EXRYlaEkzUOJlSdsNy3ENl3tY381TM5TGWtl7UZ
X-Google-Smtp-Source: AGHT+IGhtaoONWjSr7JN/qb9tMlzMIFmiGsfOyjUwMAAgtjxTw5qgA4zuWIwVM6CQzyPm/oVWukv4g==
X-Received: by 2002:a05:651c:94:b0:2d1:1f8e:b005 with SMTP id 20-20020a05651c009400b002d11f8eb005mr425329ljq.6.1707940829723;
        Wed, 14 Feb 2024 12:00:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a26c:0:b0:2d0:a0fd:c342 with SMTP id k12-20020a2ea26c000000b002d0a0fdc342ls615896ljm.1.-pod-prod-00-eu;
 Wed, 14 Feb 2024 12:00:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9nrY8FKFMNTXq83eZ+dtG5IJUMuTdgTE2Dx23J2E3CIE92G7/UrfmQhemBsiYRq3kzB/g0TWljAvVRGYMQqhfhqtpArmA0tudVw==
X-Received: by 2002:a05:6512:3d17:b0:511:ac5c:e02f with SMTP id d23-20020a0565123d1700b00511ac5ce02fmr989228lfv.8.1707940827839;
        Wed, 14 Feb 2024 12:00:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707940827; cv=none;
        d=google.com; s=arc-20160816;
        b=NRorVxflCKZVEDialmyCnYwaOGAEbPf43n7Kipsb62Uij/w8MypJ3jDzNx9jNtDS08
         Aag/sr5lPJsIQtqRYsRlAIDfnqknTZKS810W71vEZKTfcNo66K0n1iqyVkzWa/FcruDL
         N6fYzx4vDi2Zz1Blr6iUklc7vke2ZBFLQskeFS+Mb7TG0wzKA6ReB3Ipp8FUKx4Qdfky
         c1KoLcoM0w9VX03BzV2HFa45zT5kQar1P5KHer0hFAPZ3uLPnj7ingsnhXFVUIfFr+wj
         QEteW45nLuY6Z4GFE8hxjS3tPDKoRPukiG6faSUhdkRN28vuUd1/h+elCDj+GtIRazVz
         ycrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=pf30Mbuh5b/kObn023v7ccfUflKK/+7eCEEfg4Q4/Xo=;
        fh=c13cXfcSCoUDcWK5pKorlgCZ+OMaz4qHt7gODiPWcBE=;
        b=iVNcFzY3MdugrodLoJaFnJk0J9SBwcF4eYlyBdLOXat4ExQLqWUhryPIFHXZpDLM2n
         lG2zbWVGIVbDVqCEP06jC6lEBODhnPeXcY3yfjVqb1K31aXSZX86uI1ZzU+C0NlbYwNm
         nMCPTWLxqJbMUQbLN0ZtfWZBzJ6reZ+rQxd6190klGwPh9SGTZLM+FZ3KuSD9jy3tIyE
         DcfJKVpl4ykQON+bqmeJeHhS2hvn9FVn4pb3bruxwYktw1qe1OZe8AMSFKcINd0yftJQ
         TMwgVRTCeqL+061htLGlr6v8jlCWPooprgCqgR6OvHxzkRJaQtQdn+YlvPKolzvy8Rw3
         9FzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=V0Dtva7q;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCUfDL5SVUmCpbznq+UzIkmOZtuRAKM+5QkwK3gPlXgGTICiExj3ewXePVMAEj/VDQCqPfSSXa5YkLSH/wVz6yY5oz1NNpJ4Tl/cXA==
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [91.218.175.176])
        by gmr-mx.google.com with ESMTPS id i11-20020a056512224b00b005119e6adce0si151212lfu.11.2024.02.14.12.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 12:00:27 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) client-ip=91.218.175.176;
Date: Wed, 14 Feb 2024 15:00:15 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <stxem77cvysbfllp46dtgsgawzdtkr662ymw3jgo564ekssna3@t7iw7azgyqvy>
References: <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <20240214085548.d3608627739269459480d86e@linux-foundation.org>
 <7c3walgmzmcygchqaylcz2un5dandlnzdqcohyooryurx6utxr@66adcw7f26c3>
 <CAJuCfpGi6g3rG8aVmXveSxKvXnfm+5gLKS=Q4ouQBDaTxSuhww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpGi6g3rG8aVmXveSxKvXnfm+5gLKS=Q4ouQBDaTxSuhww@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=V0Dtva7q;       spf=pass
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

On Wed, Feb 14, 2024 at 11:24:23AM -0800, Suren Baghdasaryan wrote:
> On Wed, Feb 14, 2024 at 9:52=E2=80=AFAM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Wed, Feb 14, 2024 at 08:55:48AM -0800, Andrew Morton wrote:
> > > On Tue, 13 Feb 2024 14:59:11 -0800 Suren Baghdasaryan <surenb@google.=
com> wrote:
> > >
> > > > > > If you think you can easily achieve what Michal requested witho=
ut all that,
> > > > > > good.
> > > > >
> > > > > He requested something?
> > > >
> > > > Yes, a cleaner instrumentation. Unfortunately the cleanest one is n=
ot
> > > > possible until the compiler feature is developed and deployed. And =
it
> > > > still would require changes to the headers, so don't think it's wor=
th
> > > > delaying the feature for years.
> > >
> > > Can we please be told much more about this compiler feature?
> > > Description of what it is, what it does, how it will affect this kern=
el
> > > feature, etc.
> > >
> > > Who is developing it and when can we expect it to become available?
> > >
> > > Will we be able to migrate to it without back-compatibility concerns?
> > > (I think "you need quite recent gcc for memory profiling" is
> > > reasonable).
> > >
> > >
> > >
> > > Because: if the maintainability issues which Michel describes will be
> > > significantly addressed with the gcc support then we're kinda reviewi=
ng
> > > the wrong patchset.  Yes, it may be a maintenance burden initially, b=
ut
> > > at some (yet to be revealed) time in the future, this will be address=
ed
> > > with the gcc support?
> >
> > Even if we had compiler magic, after considering it more I don't think
> > the patchset would be improved by it - I would still prefer to stick
> > with the macro approach.
> >
> > There's also a lot of unresolved questions about whether the compiler
> > approach would even end being what we need; we need macro expansion to
> > happen in the caller of the allocation function
>=20
> For the record, that's what this attribute will be doing. So it should
> cover our usecase.

That wasn't clear in the meeting we had the other day; all that was
discussed there was the attribute syntax, as I recall.

So say that does work out (and I don't think that's a given; if I were a
compiler person I don't think I'd be interested in this strange half
macro, half inline function beast); all that has accomplished is to get
rid of the need for the renaming - the _noprof() versions of functions.

So then how do you distinguish where in the callstack the accounting
happens?

If you say "it happens at the outermost wrapper", then what happens is

 - Extra overhead for all the inner wrapper invocations, where they have
   to now check "actually, we already have an alloc tag, don't do
   anything". That's a cost, and given how much time we spent shaving
   cycles and branches during development it's not one we want.

 - Inner allocations that shouldn't be accounted to the outer context
   are now a major problem, because they silently will be accounted
   there and never noticed.

   With our approach, inner allocations are by default (i.e. when we
   haven't switched them to the _noprof() variant) accounted to their
   own alloc tag; that way, when we're reading the /proc/allocinfo
   output, we can examine them and check if they should be collapsed to
   the outer context. With this approach they won't be seen.

So no, we still don't want the compiler approach.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/stxem77cvysbfllp46dtgsgawzdtkr662ymw3jgo564ekssna3%40t7iw7azgyqvy=
.
