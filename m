Return-Path: <kasan-dev+bncBC7OD3FKWUERBVP6ZKRAMGQEUS4XJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D5E5B6F5FAE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 22:08:54 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-38eab7030c2sf1165842b6e.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 13:08:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683144533; cv=pass;
        d=google.com; s=arc-20160816;
        b=mGPdZanKsHIQNrZYU2888+O9dKvLwz9lPkKs+9is/GeG3TrivcWOMnJJuEah4hHOOn
         2qs9AibwrqeD6AdQyR5/a1Avl6c7JwJDi002RXyN4sFyUmAEgJM+ukvs023F6L1Sv+jh
         rQwZsL1hBTs+V/C3gGOPEidPTkDhKAlQADJuBfFStOZ3EqWhP7pqtqf0ityaxBt8FHl0
         sykxIKjzitw4ucHdYAUfQ+PM87jpU7YH7FMTdfcBHSmoXMTzSNtXJ7iHxxtRMTznuyde
         0YO9xffodxngVG1d/rEMTRV7xHV+iD4/+ZK5fZzPoluSM/7s3fvTDG7MWiL9u9c+80Oj
         a+rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ssYkb3GBrInyV9dwFSaaxSOg8Y7f/CfEwYQT9qk43+A=;
        b=gts+987bbc8SGLbxCSXW2GHcs0mvzmxaOVbVA5Klo5czieHuHotKFBG+bwd65cLVH1
         Hb+CItfx0NnpVPoLoeVH1Z6YYKhEHYNQvbDVgNuWpUkMJaqmHSoGQo5bCDs+9DPCuukt
         PgQBvQKDSI9vpc5tVNgC/jaFTFw5JIXzp37tGd1VxxaxsahXzz5pivKzXdXjP3dU3M5u
         99dp02zGEmpmZU2nsMNO1JT6rjA/PdglJuahksfE/sB9i9Wxfyl9nmMq/gfU9z8xeBQI
         SYZlY/cr/cg6r1bsuUeuUigTsnD5NdTK444+1Dwya1iMcTietBFp25l4IvD+hOdarMmI
         q+SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZBFmhNUt;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683144533; x=1685736533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ssYkb3GBrInyV9dwFSaaxSOg8Y7f/CfEwYQT9qk43+A=;
        b=JOf95fcEdA4pBvI9Yy3xTb0JenpXi/aURNWw67nTBPCrKU9dbT5T7+Oj+Jvt1ywD2T
         UY17uBtZUslL32YqkXVxRxu9eZzJ46K/QGaGvd5QFQSl42nzE/mwhPWtN9hk1vnMn0F3
         /mRdF+C2107Od+0lPrZpqe9cjIUM6djoMuiAkd4JQLMgM+yXF+2wc8XrK9SGYGx3uhhl
         pYHTuJmkUoRPq7r5XcFShenQXn6kLz4v/R32L+fpJSyvPGJ+UWA2rJ4Qw8FUlO7rtKd7
         rfFAp68Q2EXJI8J/UHQF8NgPrUzNTJ1aSPKgjeMvWw7HvOS79gdqa4Oqn1//t6I+2hUW
         cI7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683144533; x=1685736533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ssYkb3GBrInyV9dwFSaaxSOg8Y7f/CfEwYQT9qk43+A=;
        b=PREC1rzj01dINyZNcvX1vSsWGsaq0JLNAJ05sXRiyGJIYDV51AGJT+H6ZkYdIS4F/r
         aTM/JwgwA/eJCdei/PMI3ThClZOjYo+yDI3PTfHK3KvSN8dk0kH7vRmoWZgC8SJ/3vVR
         jY0f/vhJoMHaox/ZtMEBX6vzDtLP7SCXUqxDw7vZs6LcITWsJMMC8Go/JkeYD8pyXeK4
         m3jyC7g08vqh1XFJt6y6PQ+duyHfdDHpRXXEi2pbSj+PgN2Lhih/6FUfTtCK7/D57qdj
         C7ygJmIPbRtf0KQG3cRlDKYagthAHrlbOqZEimwzYqYh3E9eSBCN6X66STnlVV7Ek3vf
         ppRA==
X-Gm-Message-State: AC+VfDysExoXoIxuziUGXYf1HubjfmnspESebOdsOa3tboLfHwtSTY2Q
	dO5aDMLyZEHAS1Vbeqh7hOg=
X-Google-Smtp-Source: ACHHUZ6QZthnx4JfJlEccyRpIZBBdLHqSyt76+mwS7k8KD6fVtZad81yJK4d9D6ns+tUofe/1kIxdA==
X-Received: by 2002:aca:da56:0:b0:38e:55f2:3cf3 with SMTP id r83-20020acada56000000b0038e55f23cf3mr295485oig.4.1683144533624;
        Wed, 03 May 2023 13:08:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ac86:b0:192:8bb2:a874 with SMTP id
 ns6-20020a056870ac8600b001928bb2a874ls1601714oab.9.-pod-prod-gmail; Wed, 03
 May 2023 13:08:53 -0700 (PDT)
X-Received: by 2002:a05:6870:9575:b0:184:49b2:784e with SMTP id v53-20020a056870957500b0018449b2784emr1421810oal.29.1683144533171;
        Wed, 03 May 2023 13:08:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683144533; cv=none;
        d=google.com; s=arc-20160816;
        b=seaqVDGYFKaiSlDXr0MyAqPNMYt6/ij1FBiuVyL6yj1WkyDIPdVrqIK2hd78lZs29W
         DrnIZcW88eeSdekjBvpI5eK9HABSX8BwCZ60A5xYUtbE9/UXUBd96mOSCy2KlLNpaAU6
         0JeCMWJwA8xD/ZP/7oFRv+k9DATcQGU+7+rillQbbSfuP4/fElazB0vOWiqFyCvN4nhS
         rDrd0gI0Jo5GmHUGZmUAETp7mInCdUWaxdJp9XxGMzThjAMRjs9IIs0fdmmmIoursUC9
         ARosVSaz6IG5wyktfI/hJJ42XSpzUTyjL/pZTslvdFJRcua4oN+8lyc3/hUJPn2CPTpp
         3K5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uaEl0+ttAfDVYkQkgOF9inVIlQxPo4MAHa3r5TcHPqs=;
        b=FCfoL/CgjCIXAF400mCB3BZRMtgewp0OolriPShNAn9NCyXC44U0AK8+9JN/KPAxCl
         7PZaSLB5BtTF/RtnjdfnKa5tJAxhRF8jYJTLxkzRgZ1ExwxbXfi4b8FraMnpJMGLJEZm
         6qPhXTTa/2Zr+/sdQAjyE5KKACworTfQY9OnhqkVBPGWl3bwj/R0+/Ktyh8bE8cSYndA
         LzL9Cs8KDFyqBQ7pu7zzgnym2qaBR3E/AjDwVeiw8YqOWxK/Ry0j5Yqa9Ny/EvzK8m/F
         M1k1hh5wMt12H4uKY+eNvq4Isg6OYPAzYWpsjepsRfPfQtlkG51RjrHPLV3Zct2sMXxx
         Pj3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZBFmhNUt;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id lt11-20020a05687142cb00b0018b384bd2b1si154671oab.4.2023.05.03.13.08.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 13:08:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-b9a6eec8611so5484793276.0
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 13:08:53 -0700 (PDT)
X-Received: by 2002:a25:3450:0:b0:b9d:9f6e:f1d5 with SMTP id
 b77-20020a253450000000b00b9d9f6ef1d5mr3049024yba.16.1683144532379; Wed, 03
 May 2023 13:08:52 -0700 (PDT)
MIME-Version: 1.0
References: <ZFISlX+mSx4QJDK6@dhcp22.suse.cz> <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org> <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org> <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan> <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org> <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
In-Reply-To: <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 13:08:40 -0700
Message-ID: <CAJuCfpG4TmRpT5iU7bJmKcjW2Tghstdo1b=qEG=tDsmtJQYuWA@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
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
	cgroups@vger.kernel.org, Alexei Starovoitov <ast@kernel.org>, 
	Andrii Nakryiko <andrii@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ZBFmhNUt;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
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

On Wed, May 3, 2023 at 12:49=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
>
> Hello,
>
> On Wed, May 03, 2023 at 12:41:08PM -0700, Suren Baghdasaryan wrote:
> > On Wed, May 3, 2023 at 12:09=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote=
:
> > >
> > > On Wed, May 03, 2023 at 08:58:51AM -1000, Tejun Heo wrote:
> > > > On Wed, May 03, 2023 at 02:56:44PM -0400, Kent Overstreet wrote:
> > > > > On Wed, May 03, 2023 at 08:40:07AM -1000, Tejun Heo wrote:
> > > > > > > Yeah, easy / default visibility argument does make sense to m=
e.
> > > > > >
> > > > > > So, a bit of addition here. If this is the thrust, the debugfs =
part seems
> > > > > > rather redundant, right? That's trivially obtainable with traci=
ng / bpf and
> > > > > > in a more flexible and performant manner. Also, are we happy wi=
th recording
> > > > > > just single depth for persistent tracking?
> >
> > IIUC, by single depth you mean no call stack capturing?
>
> Yes.
>
> > If so, that's the idea behind the context capture feature so that we
> > can enable it on specific allocations only after we determine there is
> > something interesting there. So, with low-cost persistent tracking we
> > can determine the suspects and then pay some more to investigate those
> > suspects in more detail.
>
> Yeah, I was wondering whether it'd be useful to have that configurable so
> that it'd be possible for a user to say "I'm okay with the cost, please
> track more context per allocation".

I assume by "more context per allocation" you mean for a specific
allocation, not for all allocations.
So, in a sense you are asking if the context capture feature can be
dropped from this series and implemented using some other means. Is
that right?

> Given that tracking the immediate caller
> is already a huge improvement and narrowing it down from there using
> existing tools shouldn't be that difficult, I don't think this is a block=
er
> in any way. It just bothers me a bit that the code is structured so that
> source line is the main abstraction.
>
> > > > > Not sure what you're envisioning?
> > > > >
> > > > > I'd consider the debugfs interface pretty integral; it's much mor=
e
> > > > > discoverable for users, and it's hardly any code out of the whole
> > > > > patchset.
> > > >
> > > > You can do the same thing with a bpftrace one liner tho. That's rat=
her
> > > > difficult to beat.
> >
> > debugfs seemed like a natural choice for such information. If another
> > interface is more appropriate I'm happy to explore that.
> >
> > >
> > > Ah, shit, I'm an idiot. Sorry. I thought allocations was under /proc =
and
> > > allocations.ctx under debugfs. I meant allocations.ctx is redundant.
> >
> > Do you mean that we could display allocation context in
> > debugfs/allocations file (for the allocations which we explicitly
> > enabled context capturing)?
>
> Sorry about the fumbled communication. Here's what I mean:
>
> * Improving memory allocation visibility makes sense to me. To me, a more
>   natural place for that feels like /proc/allocations next to other memor=
y
>   info files rather than under debugfs.

TBH I would love that if this approach is acceptable.

>
> * The default visibility provided by "allocations" provides something whi=
ch
>   is more difficult or at least cumbersome to obtain using existing traci=
ng
>   tools. However, what's provided by "allocations.ctx" can be trivially
>   obtained using kprobe and BPF and seems redundant.

Hmm. That might be a good way forward. Since context capture has
already high performance overhead, maybe choosing not the most
performant but more generic solution is the right answer here. I'll
need to think about it some more but thanks for the idea!

>
> Thanks.
>
> --
> tejun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpG4TmRpT5iU7bJmKcjW2Tghstdo1b%3DqEG%3DtDsmtJQYuWA%40mail.gm=
ail.com.
