Return-Path: <kasan-dev+bncBC7OD3FKWUERB2UUZ6RAMGQETAMSHTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8320A6F6EA1
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 17:08:28 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1ab0d11847esf4470015ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 08:08:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683212907; cv=pass;
        d=google.com; s=arc-20160816;
        b=qQC4a5BdAVfNgrvpJvQkdJVdUmq/2PUcJ3fTKWOlP1chbybhEydpqJUPDl6ruvyh2s
         Uw7iRKoD3S9NOT9KnokPLn0w+DK5s+UB7zfxvAIAaMBsEjqdz+H67ichwzjliTBsR7yv
         EQFqDQbTxLTqfu7YYZSCdzk9OfVTHRzr37JkYcHbRrdkWELdIYVvsgZV8pb5DhyOVVli
         ADvc/Z5z+1z4+mb4m/3X/INO6Ix8kL/dvgRWmUotCSq8GL7ZzjUrPzM3oRDhrgKkDY1k
         pSep88YUHsS1FL8/7Z/9cNKmuriEH9crj+9ptqN+I2RIb8kTgz7oIah2Uub55v7WPThK
         tUhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8FdHCMlrb6AJ/FLBVmBxsTi4lcHaiaky1Wn4NTtw8r0=;
        b=urYFKvrUgOVUrMiKaY20JZPgLROpO1gxkbUGqHCetdhStT+6HtjcyvZeJq0wcrKdIL
         SuQf4ob+q9QH5o8VT4XwgmpTmmaF+hVBx+SVWUGLQNIJ/jphLod5Ub+aOmf0i4LLKHa3
         DVHZLQqrK4XTctbkL5pv3C5mGN6Nj+MQ1K1mfJnoXcRfa2rGDsaIKc4KBSQs23ZQ6GPr
         XNzCFSoj76MysUpmFKbRT2jGACARKQ8vS7iCFVWtkNhwtu/kJ0313eTGh2+U69PbvJeE
         tLA3yYHQ4yhBY3d9Bn9ojOKYS+mDgPXTVwFJp6+jj4L+0YEewQ3/9giyxysgAyuYpCQc
         nbeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FNofsLdv;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683212907; x=1685804907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8FdHCMlrb6AJ/FLBVmBxsTi4lcHaiaky1Wn4NTtw8r0=;
        b=aADTw0lnwI/w4ygD3BGsbC1uoBuAMI8tqgo4hdl3OQAPHfDj9UY8cfpEI5RpznX/Ke
         yaigAe3VT7WA4E31EKIMjZ2DxpWzkGdKK88nj4kn2dUMVXBS8pA5+AkEkcVGJsHcAHX5
         bZcsvn/tl9UMHCzniaNyNRqbhU/um5umDLK6oWkpjBjHgyNOxr68iTgcZ6nDVIOO15qu
         O6gBppcIZhlV2HuDTURGlBkKd3+oOTLYjBxYAI0bACWpNcP/1RPy6bYLO7IgC3JYs/4I
         mXA9yxosJdvbGx/x5cwqhcf2W/EBS5v5x1OYF6p9ohE9PU8f4oMNUVLTro5QDNeonxXR
         gx9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683212907; x=1685804907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8FdHCMlrb6AJ/FLBVmBxsTi4lcHaiaky1Wn4NTtw8r0=;
        b=SpGzlGij82vOIcZYU7rSQ91qy8mG1iu2yPihNfFuiMEblGeqYvq1hu9cYaXGJ2zBz+
         0CukALnl1qyJESt8pdOnU/91LSqp8nZhaxFg7FPi54OXp4Bx8j5yzFwvoXul6oP6N6OJ
         nElzpWpovaJ9XDHSUipBqbnKy3ikKW8OeBLvmfTRCnWTOfoeNOFa6A+NR9D+FuD5lU4H
         lU6DBQZb23hSxZv/37UnOD1+GAM7/0JO21CeR8tFkpV+TV+8Zuvr1WzuKb7iQD83eXnN
         bWSh08fYYJ9/lHlRblxVDj4whwqvkmsgvI3a6QA+gm4itcTX5xOAf1c9lM3iCdm3G/m8
         lGmQ==
X-Gm-Message-State: AC+VfDx0h/CwYOuX+FDmKWUhp0Em0f0XUUJw7QmzkEphCGuol9b9WCiz
	kyk5cKknvYNgml/rMLevmWc=
X-Google-Smtp-Source: ACHHUZ4FfWh5kWkeolxoahXP83uyDsDNqvA00GnTaFj9GqIhlixfWRYezyENcVTHgqnxiUHIRJuc0w==
X-Received: by 2002:a17:902:db0e:b0:1a2:8c7e:f32a with SMTP id m14-20020a170902db0e00b001a28c7ef32amr1288146plx.8.1683212906923;
        Thu, 04 May 2023 08:08:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:f91:b0:63b:5c82:42dd with SMTP id
 ct17-20020a056a000f9100b0063b5c8242ddls6530509pfb.10.-pod-prod-gmail; Thu, 04
 May 2023 08:08:26 -0700 (PDT)
X-Received: by 2002:a05:6a00:1252:b0:63d:3aed:44fb with SMTP id u18-20020a056a00125200b0063d3aed44fbmr3230079pfi.21.1683212906172;
        Thu, 04 May 2023 08:08:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683212906; cv=none;
        d=google.com; s=arc-20160816;
        b=aPIHvW4oq8i2lNB7YgveFOwHJ8FDq4mXmQhxBUG+Cg96f5I/5f8xlf0Fqn4v9NIsVo
         fSzPUeS1Y/Gh3rviKGwsKeVn6PRteLJtGtS+SnfeOd7uI4q5GFZvQQEmIld0mRVLXEcB
         +sKGy4DNBx8BCxwjv9Z6LoZu8m4sjOFAdbW6argJSXV8lyaz++SV0Wpu1aaq1yot58Sd
         9odB1jnptgo9wqPQldZEAqK/555/xpygCWBbx3P7ut8BgGYPPDdWODbe0RJM1sGq/Krk
         rqhXkBiHalqlTCk56oA9kD3eih9HH8+tlRey+QECEDtKAJ5kSqJVAedJ06HzoPqxOY8w
         KbEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vpI3TgDyhkti03RqKX4aJ+LI47o/coVvQYc1czzI8zs=;
        b=P1Hwn+J7d8T5NbnSaChRo5qPWx4KZhpqUjRLblRo3n512xnS1bRuCcOQERpjHG+r6i
         ZbEEw1xjTf8JffW1tpAusOXjEetJeGl6kHlkXej47WyzJGYE94g8Tbpvz7qS51UtW5CA
         it9p7BUHnqwB/Vlnn8E0XuPdjM4S7JO6d1++T2ZwAlrgxoKMpnRY2wyiQYXneW8MgJyS
         uX3Cpv8SngIVP+TLZK1Ce/ULOzQruMJWsvUoQkgP3vT7GQBZKdgsWoAxwu2rgjRlVcra
         +CfnoD2kveAV/KxZzaUngSeBSIOsfkG+FPtYnLP9RlsamANJLy4xKrFGB5THucKm1yiE
         T9YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FNofsLdv;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id cw13-20020a056a00450d00b006438069d21bsi108743pfb.1.2023.05.04.08.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 May 2023 08:08:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-b99f0a0052fso873464276.3
        for <kasan-dev@googlegroups.com>; Thu, 04 May 2023 08:08:26 -0700 (PDT)
X-Received: by 2002:a25:b21f:0:b0:ba1:78df:20fc with SMTP id
 i31-20020a25b21f000000b00ba178df20fcmr253521ybj.21.1683212905109; Thu, 04 May
 2023 08:08:25 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com> <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
In-Reply-To: <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 May 2023 08:08:13 -0700
Message-ID: <CAJuCfpEkV_+pAjxyEpMqY+x7buZhSpj5qDF6KubsS=ObrQKUZg@mail.gmail.com>
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
 header.i=@google.com header.s=20221208 header.b=FNofsLdv;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as
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

On Thu, May 4, 2023 at 2:07=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrote=
:
>
> On Wed 03-05-23 08:09:28, Suren Baghdasaryan wrote:
> > On Wed, May 3, 2023 at 12:25=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> [...]
> > Thanks for summarizing!
> >
> > > At least those I find the most important:
> > > - This is a big change and it adds a significant maintenance burden
> > >   because each allocation entry point needs to be handled specificall=
y.
> > >   The cost will grow with the intended coverage especially there when
> > >   allocation is hidden in a library code.
> >
> > Do you mean with more allocations in the codebase more codetags will
> > be generated? Is that the concern?
>
> No. I am mostly concerned about the _maintenance_ overhead. For the
> bare tracking (without profiling and thus stack traces) only those
> allocations that are directly inlined into the consumer are really
> of any use. That increases the code impact of the tracing because any
> relevant allocation location has to go through the micro surgery.
>
> e.g. is it really interesting to know that there is a likely memory
> leak in seq_file proper doing and allocation? No as it is the specific
> implementation using seq_file that is leaking most likely. There are
> other examples like that See?

Yes, I see that. One level tracking does not provide all the
information needed to track such issues. Something more informative
would cost more. That's why our proposal is to have a light-weight
mechanism to get a high level picture and then be able to zoom into a
specific area using context capture. If you have ideas to improve
this, I'm open to suggestions.

>
> > Or maybe as you commented in
> > another patch that context capturing feature does not limit how many
> > stacks will be captured?
>
> That is a memory overhead which can be really huge and it would be nice
> to be more explicit about that in the cover letter. It is a downside for
> sure but not something that has a code maintenance impact and it is an
> opt-in so it can be enabled only when necessary.

You are right, I'll add that into the cover letter.

>
> Quite honestly, though, the more I look into context capturing part it
> seems to me that there is much more to be reconsidered there and if you
> really want to move forward with the code tagging part then you should
> drop that for now. It would make the whole series smaller and easier to
> digest.

Sure, I don't see an issue with removing that for now and refining the
mechanism before posting again.

>
> > > - It has been brought up that this is duplicating functionality alrea=
dy
> > >   available via existing tracing infrastructure. You should make it v=
ery
> > >   clear why that is not suitable for the job
> >
> > I experimented with using tracing with _RET_IP_ to implement this
> > accounting. The major issue is the _RET_IP_ to codetag lookup runtime
> > overhead which is orders of magnitude higher than proposed code
> > tagging approach. With code tagging proposal, that link is resolved at
> > compile time. Since we want this mechanism deployed in production, we
> > want to keep the overhead to the absolute minimum.
> > You asked me before how much overhead would be tolerable and the
> > answer will always be "as small as possible". This is especially true
> > for slab allocators which are ridiculously fast and regressing them
> > would be very noticable (due to the frequent use).
>
> It would have been more convincing if you had some numbers at hands.
> E.g. this is a typical workload we are dealing with. With the compile
> time tags we are able to learn this with that much of cost. With a dynami=
c
> tracing we are able to learn this much with that cost. See? As small as
> possible is a rather vague term that different people will have a very
> different idea about.

I'm rerunning my tests with the latest kernel to collect the
comparison data. I profiled these solutions before but the kernel
changed since then, so I need to update them.

>
> > There is another issue, which I think can be solved in a smart way but
> > will either affect performance or would require more memory. With the
> > tracing approach we don't know beforehand how many individual
> > allocation sites exist, so we have to allocate code tags (or similar
> > structures for counting) at runtime vs compile time. We can be smart
> > about it and allocate in batches or even preallocate more than we need
> > beforehand but, as I said, it will require some kind of compromise.
>
> I have tried our usual distribution config (only vmlinux without modules
> so the real impact will be larger as we build a lot of stuff into
> modules) just to get an idea:
>    text    data     bss     dec     hex filename
> 28755345        17040322        19845124        65640791        3e99957 v=
mlinux.before
> 28867168        17571838        19386372        65825378        3ec6a62 v=
mlinux.after
>
> Less than 1% for text 3% for data.  This is not all that terrible
> for an initial submission and a more dynamic approach could be added
> later. E.g. with a smaller pre-allocated hash table that could be
> expanded lazily. Anyway not something I would be losing sleep over. This
> can always be improved later on.

Ah, right. I should have mentioned this overhead too. Thanks for
keeping me honest.

> > I understand that code tagging creates additional maintenance burdens
> > but I hope it also produces enough benefits that people will want
> > this. The cost is also hopefully amortized when additional
> > applications like the ones we presented in RFC [1] are built using the
> > same framework.
>
> TBH I am much more concerned about the maintenance burden on the MM side
> than the actual code tagging itslef which is much more self contained. I
> haven't seen other potential applications of the same infrastructure and
> maybe the code impact would be much smaller than in the MM proper. Our
> allocator API is really hairy and convoluted.

Yes, other applications are much smaller and cleaner. MM allocation
code is quite complex indeed.

>
> > > - We already have page_owner infrastructure that provides allocation
> > >   tracking data. Why it cannot be used/extended?
> >
> > 1. The overhead.
>
> Do you have any numbers?

Will post once my tests are completed.

>
> > 2. Covers only page allocators.
>
> Yes this sucks.
> >
> > I didn't think about extending the page_owner approach to slab
> > allocators but I suspect it would not be trivial. I don't see
> > attaching an owner to every slab object to be a scalable solution. The
> > overhead would again be of concern here.
>
> This would have been a nice argument to mention in the changelog so that
> we know that you have considered that option at least. Why should I (as
> a reviewer) wild guess that?

Sorry, It's hard to remember all the decisions, discussions and
conclusions when working on a feature over a long time period. I'll
include more information about that.

>
> > I should point out that there was one important technical concern
> > about lack of a kill switch for this feature, which was an issue for
> > distributions that can't disable the CONFIG flag. In this series we
> > addressed that concern.
>
> Thanks, that is certainly appreciated. I haven't looked deeper into that
> part but from the cover letter I have understood that CONFIG_MEM_ALLOC_PR=
OFILING
> implies unconditional page_ext and therefore the memory overhead
> assosiated with that. There seems to be a killswitch nomem_profiling but
> from a quick look it doesn't seem to disable page_ext allocations. I
> might be missing something there of course. Having a highlevel
> describtion for that would be really nice as well.

Right, will add a description of that as well.
We eliminate the runtime overhead but not the memory one. However I
believe it's also doable using page_ext_operations.need callback. Will
look into it.
Thanks,
Suren.

>
> > [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.co=
m/
>
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEkV_%2BpAjxyEpMqY%2Bx7buZhSpj5qDF6KubsS%3DObrQKUZg%40mail.=
gmail.com.
