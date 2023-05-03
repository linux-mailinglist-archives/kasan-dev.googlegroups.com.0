Return-Path: <kasan-dev+bncBC7OD3FKWUERBNPSZGRAMGQEXZXTERY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F6666F5AAA
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:09:43 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-76359b8d29dsf763503439f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:09:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683126581; cv=pass;
        d=google.com; s=arc-20160816;
        b=unFFb2UrPFMM1mjz57Hd5HoYk0UX4BTkTk/2mjpDH3Jex9XvUVETTbg1vmTDoZumzS
         bITXeWBlLQGQo4QlZ4FOTJ6ouxeBP+n/LAtW3ApajMODZY7V1oC4gQNZlvASGT22zxpu
         Fdp2gO7nJjIyvjkAQz8AuZvTO4FkIWN7zWzLZE8wHW551I+VsR8BVnTqQV02wBnlJJc5
         Pubz5UqdjTaIiHY2u/Nus3Kp5XCkCtwWtdyy1aMAWuuorLukO70TCAK9GU+I8TkuvlOP
         qFCT3EnmbKkVAlqamlyt6y9/svS2snJP5ii0Y5N1pTZFq/4bNod2gD/HtxocAgPEkMUA
         XLqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TMZl2z/XIHVwBQbDquGwwLG6n9zmj7CPtN962qyH/Gc=;
        b=UGQriBCSh1+yb15P5+qCY5lWRCZOkU04aSgGF0tvHGIsoVIfoefECEGcnziOpVlO72
         yFOp0MoEpCvXMxmBHro1BktETM2/cEC9rn9UnxLHfq0INx55lAQgCy/SMI3mc/OcfUoG
         5sYw+j9qMW0xhX8RFg/Dps5NP1E1WqIdFFOjcr+WqYb7qB8Vm5SAQIPejlzwxQInuxnt
         pfjwepwG5Db5QjmoxHlHnkCDUrR3DapMO/Egn5Eeb2pFZaCqhglO2LgKdPw0+AY0ybFO
         ScsFdq1KB0qcdPcHc2OMzDjAVVVkGe0GFQCugN8jWULJTndFArvGIrF015TXb0BYNbU0
         6zSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=VExKdzK5;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683126581; x=1685718581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TMZl2z/XIHVwBQbDquGwwLG6n9zmj7CPtN962qyH/Gc=;
        b=SywP/9l0p+Jf73nsoav9a4il4nywL1g6nHcQYmq0TDbTjBv0e2hbuqI5rRnlalAKzr
         R1mGwj+LF/0SRxDVhSqv68/n94EiZsto0OWQgAX22EX+mlUZ6/wQkFISWuXJOusglOW7
         ztdAkzTfiIdzRbPFfwKYz38fY7TEzF2n86JIJmq6/xR8zsYrzgHyTG+9NMtbORob1jVl
         fos7KnDEXsWk6oKSX5CA5MH8s6Rq8ya6qT0texbiiBE7VakbZ7srGFw4ARv7XNlO65S/
         FdY/3Zr0rQsQUk2DpEfvINMlyP00ndtHb3BndCWzLZrNHaXPxtTsNh1xLeZZXDL3ByUb
         sblw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683126581; x=1685718581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TMZl2z/XIHVwBQbDquGwwLG6n9zmj7CPtN962qyH/Gc=;
        b=Gqg65Fnc+kJUysPV0WVQ3Fu1T19yfgTRtrvSMorodZd5/BSPhxB4IX+Si7Y5/tSFxG
         V3QTsQzN2lD61QPLqBtIGFkWWfHE8sX2ij9EYoIa6FvT684ixc9TK6noV3ZpFoAcP+Of
         YDMKBaxn8d6TuwEEUslRdeIf0WwTiH1jDvocqln5ivSs614NEa4PuJ71TMYybWvFRk+W
         Velr4R6WIyvPoOtKoEiBULj88a2eKMwgXiZBc3QzVrEN2lBHJ5z6Tb1P5/8OxPVnuxIX
         /h0D9UznQLg9sFXxENzIortXlQgaRVM08tP2ZhnR7VQj5PYdN9O63tGrf+Ow9ZxACym2
         OQ7w==
X-Gm-Message-State: AC+VfDwj6L/9vsEThS9hLYM6h28PzmSY4R+a6zvIA/lSyQYauzHmLSPo
	vU+9v74dx439Qud1aq8WOhk=
X-Google-Smtp-Source: ACHHUZ6p92Gyv4Bkdas6chS9vHkZwjYI0VrcyZelNxCb/xYA8K9C990DKo65iFZB4Y+G6DGbNqM7PA==
X-Received: by 2002:a02:848c:0:b0:40f:99a7:7df1 with SMTP id f12-20020a02848c000000b0040f99a77df1mr10528337jai.5.1683126581745;
        Wed, 03 May 2023 08:09:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1ca8:b0:326:4b:d61a with SMTP id
 x8-20020a056e021ca800b00326004bd61als5088466ill.1.-pod-prod-gmail; Wed, 03
 May 2023 08:09:41 -0700 (PDT)
X-Received: by 2002:a92:290f:0:b0:32b:7087:5bbf with SMTP id l15-20020a92290f000000b0032b70875bbfmr13824713ilg.9.1683126581152;
        Wed, 03 May 2023 08:09:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683126581; cv=none;
        d=google.com; s=arc-20160816;
        b=TgjYGFfV3IUzXWanYugzsi4FJZ7QjXEIB2vc5XylTVHTfo9Cm0DXC2I+aczCMjFdAt
         coztEsIzEV1So7h3MHewbjP6IVe+vz41fXU9LYn5CwGeto02ik5tzU/HIciKDb8RaxF8
         k8CyzRnkQlY3WRzKgV8J+0pOSkGAXYyJZZbQdS7CugJRJUdoGWh861Bb3WQ3DSlFqD/c
         oii4TkElITwrS1PNXmlE2E0NPygOGbzKJKrqOYZUae8L28zUYbEEb7RD8z/2Nq8fvkrG
         3nSQop3i9n61jbe7LRXoytO4TN+sUceUENAPHo0R1dmmuiPsSZvEwHr2xPMlPApRlMvJ
         0wNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=njkpY9V26txLi7xPErO/sERUlWcV1pHNyq5uOqiF2eY=;
        b=TRchONAkf3SZuZi/PKC+6U+hLd/e7PQYMJgQrx6ruCC/Rm355ZLU7EEUsyh4GUW6ku
         Q4fWUHXT/KdC1LvVioDEG8+vdfX3oyZXp6P/CD3BXhl0L9KERkubbuwOxHbmtxHSnam+
         z83E6PwZ42fsLy+w7ix4/qf1e8tM/KcNxEt6twBI5o4aLcRhex7dzwU5AVDnElcR1W4T
         n9/ffTF9XpIzcDzgfMNJ+bEKx9yeERFj6ZCBoDa/Kn3yz13M6h53uVFpNFF+cks21X4X
         PJCJ7IJku0n9pgefzXHPedawoEMf7tHd79f70hGZTMgRIP+y/tLr85MuS/mkCG7G+RY+
         RBvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=VExKdzK5;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id j7-20020a92ca07000000b003312406cad0si452139ils.0.2023.05.03.08.09.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 08:09:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 3f1490d57ef6-b9e66ce80acso3183054276.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 08:09:41 -0700 (PDT)
X-Received: by 2002:a25:dc4a:0:b0:b9f:1992:112e with SMTP id
 y71-20020a25dc4a000000b00b9f1992112emr4038060ybe.9.1683126580275; Wed, 03 May
 2023 08:09:40 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
In-Reply-To: <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 08:09:28 -0700
Message-ID: <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=VExKdzK5;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as
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

On Wed, May 3, 2023 at 12:25=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Mon 01-05-23 09:54:10, Suren Baghdasaryan wrote:
> > Memory allocation profiling infrastructure provides a low overhead
> > mechanism to make all kernel allocations in the system visible. It can =
be
> > used to monitor memory usage, track memory hotspots, detect memory leak=
s,
> > identify memory regressions.
> >
> > To keep the overhead to the minimum, we record only allocation sizes fo=
r
> > every allocation in the codebase. With that information, if users are
> > interested in more detailed context for a specific allocation, they can
> > enable in-depth context tracking, which includes capturing the pid, tgi=
d,
> > task name, allocation size, timestamp and call stack for every allocati=
on
> > at the specified code location.
> [...]
> > Implementation utilizes a more generic concept of code tagging, introdu=
ced
> > as part of this patchset. Code tag is a structure identifying a specifi=
c
> > location in the source code which is generated at compile time and can =
be
> > embedded in an application-specific structure. A number of applications
> > for code tagging have been presented in the original RFC [1].
> > Code tagging uses the old trick of "define a special elf section for
> > objects of a given type so that we can iterate over them at runtime" an=
d
> > creates a proper library for it.
> >
> > To profile memory allocations, we instrument page, slab and percpu
> > allocators to record total memory allocated in the associated code tag =
at
> > every allocation in the codebase. Every time an allocation is performed=
 by
> > an instrumented allocator, the code tag at that location increments its
> > counter by allocation size. Every time the memory is freed the counter =
is
> > decremented. To decrement the counter upon freeing, allocated object ne=
eds
> > a reference to its code tag. Page allocators use page_ext to record thi=
s
> > reference while slab allocators use memcg_data (renamed into more gener=
ic
> > slabobj_ext) of the slab page.
> [...]
> > [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.co=
m/
> [...]
> >  70 files changed, 2765 insertions(+), 554 deletions(-)
>
> Sorry for cutting the cover considerably but I believe I have quoted the
> most important/interesting parts here. The approach is not fundamentally
> different from the previous version [1] and there was a significant
> discussion around this approach. The cover letter doesn't summarize nor
> deal with concerns expressed previous AFAICS. So let me bring those up
> back.

Thanks for summarizing!

> At least those I find the most important:
> - This is a big change and it adds a significant maintenance burden
>   because each allocation entry point needs to be handled specifically.
>   The cost will grow with the intended coverage especially there when
>   allocation is hidden in a library code.

Do you mean with more allocations in the codebase more codetags will
be generated? Is that the concern? Or maybe as you commented in
another patch that context capturing feature does not limit how many
stacks will be captured?

> - It has been brought up that this is duplicating functionality already
>   available via existing tracing infrastructure. You should make it very
>   clear why that is not suitable for the job

I experimented with using tracing with _RET_IP_ to implement this
accounting. The major issue is the _RET_IP_ to codetag lookup runtime
overhead which is orders of magnitude higher than proposed code
tagging approach. With code tagging proposal, that link is resolved at
compile time. Since we want this mechanism deployed in production, we
want to keep the overhead to the absolute minimum.
You asked me before how much overhead would be tolerable and the
answer will always be "as small as possible". This is especially true
for slab allocators which are ridiculously fast and regressing them
would be very noticable (due to the frequent use).

There is another issue, which I think can be solved in a smart way but
will either affect performance or would require more memory. With the
tracing approach we don't know beforehand how many individual
allocation sites exist, so we have to allocate code tags (or similar
structures for counting) at runtime vs compile time. We can be smart
about it and allocate in batches or even preallocate more than we need
beforehand but, as I said, it will require some kind of compromise.

I understand that code tagging creates additional maintenance burdens
but I hope it also produces enough benefits that people will want
this. The cost is also hopefully amortized when additional
applications like the ones we presented in RFC [1] are built using the
same framework.

> - We already have page_owner infrastructure that provides allocation
>   tracking data. Why it cannot be used/extended?

1. The overhead.
2. Covers only page allocators.

I didn't think about extending the page_owner approach to slab
allocators but I suspect it would not be trivial. I don't see
attaching an owner to every slab object to be a scalable solution. The
overhead would again be of concern here.

I should point out that there was one important technical concern
about lack of a kill switch for this feature, which was an issue for
distributions that can't disable the CONFIG flag. In this series we
addressed that concern.

[1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/

Thanks,
Suren.

>
> Thanks!
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg%40mail.gmail.=
com.
