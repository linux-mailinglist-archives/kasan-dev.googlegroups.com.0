Return-Path: <kasan-dev+bncBC7OD3FKWUERBNUDZ6RAMGQEH3GLXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id C80F46F6DBE
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 16:31:20 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-24e3f2bff83sf324584a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 07:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683210679; cv=pass;
        d=google.com; s=arc-20160816;
        b=edLTMqVCSZDTNk59AOleIuMZjGg0HSD8NptVco6o9Ihfw+Tg0twguCd29Udi3JDLX4
         RTWoFTG/8DhxRYr+R/O4jRa8mAD//pxwKMk/amHmEogjHLA9MT+P+BPPFpW4ZR4v9TXi
         cPFDi9x8BbQwTqjZU3inBhtS1C+ia3ytezomP7fiSofffbiIYqBeowtOp7jzlyUth1dr
         bCsryEvk1VXnbiSpUQoya7tCTqbflqsjxjQgNS7Zo1s6ll7QpcPtc/WzSZm15hMo1erL
         QhzuS8+VUTd/rEEhiHdMpsKIbxpUUrZV2DHZVxWSHPIS4vO4pXYgtxImEtyXO1wfk8Uw
         GOCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cKswtSoekDpR2kQB29sSYr400z6My651EvSsonYVMGM=;
        b=pEn8t+N+KyYvkiArF8mw/bAVMaMQZI4Rd+fBp9NCjAe1ayV3iqALf42VzAsZbgM6dP
         C2hEHJDKlB6OrrBySHrZhaoAB3BEnd/zkzzLShmQwtxRttslfdnW1DEXqaNEVJk10Tyf
         I4fxpQITgHu89fj3SlueTnJ/13zvqB2l0Kl9qQIProP+si7bMPYRm7IM00cr5xMYqT80
         QhSqiucq/qFYSJg9zJbcVbCxpuZ49knoweAaDFLgk7CpiXEAaeBnZU21lPjqlScaCly1
         DJcjCYpIFQ85CNBdwJKJVpVm4XyDKwofmN0OeOgCGtsjL5iXMYq9DHgLYw/XBD86DoPQ
         fp/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=B5odhRz5;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683210679; x=1685802679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cKswtSoekDpR2kQB29sSYr400z6My651EvSsonYVMGM=;
        b=fH31EFALCrDDI8Rfzre6mv7hQfroJGvzE4IciA15OE44WjretzCqFqZTvX0bifKXrs
         IeaPy2KgyXQUVS+txLu6yIeBJtH4SdcfeuB93uoUf0ppJh6R1GDija4jJrig+SrVB9Gx
         Xm2UxL1C03csbFYqNkJ9j9MbCZZBNgfjA7JnOD8+2dRonKOWGRdVSwOuD1SX5W8a5WNU
         Dk6ahHaHBv9AHf87G/UnSGYtJBk6+L7UupFiZAf0AP6GetGJDdA+GuWsc7oZkhsr7ihy
         h1eZgBg9/Bsm5JRBcZVHPQuwYDwA7fPfbDstUlbIUBtrt5RJIn2EHld0fPizy4PrE9IG
         JATQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683210679; x=1685802679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cKswtSoekDpR2kQB29sSYr400z6My651EvSsonYVMGM=;
        b=RTGF5EHEvsor3D5z5oj+NKEHZOVs7l7qp+zl9tb0ufA9GS75E6CNVXd5CNDNdOI0Q/
         ssnFhFqt1KRFKwViN8MASwEAvuy3kljgHd0O0i41ecGlsFUsQ4Tcs/SKIXOGc7PO6mjB
         FDzh/3i0eH641X3LzfPBvGkKX62T2tnOAA7l3E599BDj0uDHv8YBxNNtKzGSsRRMDwXc
         qxtG1f98T/y+l0cTexc5C95NI7DhrXPSG1yf4HQ4/frT2tmzHaolJ6ukirU3liMAi62N
         ZwV8XZANy7b6LC7sQ5bpa74ig5or1r3pCt7ySuXohwLbfE7u9OLHlKDE9qcP5DfAixU1
         BVeQ==
X-Gm-Message-State: AC+VfDz/8ZmrnnYrPylxYJ7IWitrSEhOBY+auUedBfU/EQncJwEFLkn2
	Mv6ivlt5PQGScR7G/BHmNfc=
X-Google-Smtp-Source: ACHHUZ7RLXfKBklz+imHRQnFoxgUb5JD/nYv/FRsWza3s1isECHd4j23DKkyoYhR2iSZX2e006P9DQ==
X-Received: by 2002:a17:903:2352:b0:1a6:6be8:fc9 with SMTP id c18-20020a170903235200b001a66be80fc9mr1281390plh.0.1683210678856;
        Thu, 04 May 2023 07:31:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:830a:0:b0:632:a3f8:4f4e with SMTP id h10-20020a62830a000000b00632a3f84f4els358506pfe.1.-pod-prod-02-us;
 Thu, 04 May 2023 07:31:18 -0700 (PDT)
X-Received: by 2002:a17:902:eccf:b0:1a6:f93a:a135 with SMTP id a15-20020a170902eccf00b001a6f93aa135mr4708339plh.61.1683210678124;
        Thu, 04 May 2023 07:31:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683210678; cv=none;
        d=google.com; s=arc-20160816;
        b=mkgaPhMOxzqTEa8EWcdnR0zkQ3vN2Yu6bZToMpQ7G4FtgEZB9gBT5Tfi7Igwjva1hD
         n8SW0GDNRxRA5r9vT+fDEBzCtvdttmtp2jTuSu+NNoYNNdDth/AxmZ1QAat8oMiIf8Vl
         2kBz4+z+i4S/iR2yh9H8mIpqjf24fesGonzKNyeYz2K8Y5lbaHU6vLaxlPWf1c2mOffh
         UyNsWw0Nlc/c1eD+rJgWi2EMjrULnUCRXwRMjbd8lYc3PG8HA8tPhDMDszPhwmUrD7y8
         /HP5L0zqAwbd5gYlGSReQz1YUVjzgf1FsaOtPCgZYRbwhpqxS//d6rN9T4SKjA6Lnioh
         pCig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JS6msPuToyJynO3sTVIKpHDiqUqJNNgVeQDo4ExI+FY=;
        b=vclFIwLXLCJ8fLzBLdDzmEltHMVRqtnzRYJuUKdKezpjcCPudtvvdiNUZ28OKtZgwt
         Q4DQhIDrXzJKrei41mDWlVqjUkZvYFwiIoYHbpBRLEz8o4NQDCLaOvmRJgsg6wJ5n2QB
         WB//Vxaru5WEOLdTa1Sf6xeMtDjLdlNOLwkM9//GaIFTOGfL+ze15XQ6qrMueLH2p/TQ
         Ru0DwXMy671W1xeCTjBR5AMY49s7HtkdM+vaiNivxVbdmeybQmzPKVXLyVCPgotWq377
         tFwi6g0T9iJAy9ODZ6bHd9kkQnu/9/L4Js1QjuQ0aI7pxIq+c8CcDpFOnf/RToS9ye75
         F7kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=B5odhRz5;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id bj21-20020a056a02019500b005289dd0b142si747867pgb.3.2023.05.04.07.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 May 2023 07:31:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-b8f34bca001so784093276.3
        for <kasan-dev@googlegroups.com>; Thu, 04 May 2023 07:31:18 -0700 (PDT)
X-Received: by 2002:a25:cec1:0:b0:b99:4ac6:3c75 with SMTP id
 x184-20020a25cec1000000b00b994ac63c75mr122983ybe.10.1683210677091; Thu, 04
 May 2023 07:31:17 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-35-surenb@google.com>
 <ZFIO3tXCbmTn53uv@dhcp22.suse.cz> <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
 <ZFNnKHR2nCSimjQf@dhcp22.suse.cz>
In-Reply-To: <ZFNnKHR2nCSimjQf@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 May 2023 07:31:05 -0700
Message-ID: <CAJuCfpF7WeVuJpmZN3KEu=FAUH34xfYG4wPg-YNjxj+GtmdBXQ@mail.gmail.com>
Subject: Re: [PATCH 34/40] lib: code tagging context capture support
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
 header.i=@google.com header.s=20221208 header.b=B5odhRz5;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
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

On Thu, May 4, 2023 at 1:04=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrote=
:
>
> On Wed 03-05-23 08:18:39, Suren Baghdasaryan wrote:
> > On Wed, May 3, 2023 at 12:36=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> > >
> > > On Mon 01-05-23 09:54:44, Suren Baghdasaryan wrote:
> > > [...]
> > > > +static inline void add_ctx(struct codetag_ctx *ctx,
> > > > +                        struct codetag_with_ctx *ctc)
> > > > +{
> > > > +     kref_init(&ctx->refcount);
> > > > +     spin_lock(&ctc->ctx_lock);
> > > > +     ctx->flags =3D CTC_FLAG_CTX_PTR;
> > > > +     ctx->ctc =3D ctc;
> > > > +     list_add_tail(&ctx->node, &ctc->ctx_head);
> > > > +     spin_unlock(&ctc->ctx_lock);
> > >
> > > AFAIU every single tracked allocation will get its own codetag_ctx.
> > > There is no aggregation per allocation site or anything else. This lo=
oks
> > > like a scalability and a memory overhead red flag to me.
> >
> > True. The allocations here would not be limited. We could introduce a
> > global limit to the amount of memory that we can use to store contexts
> > and maybe reuse the oldest entry (in LRU fashion) when we hit that
> > limit?
>
> Wouldn't it make more sense to aggregate same allocations? Sure pids
> get recycled but quite honestly I am not sure that information is all
> that interesting. Precisely because of the recycle and short lived
> processes reasons. I think there is quite a lot to think about the
> detailed context tracking.

That would be a nice optimization. I'll need to look into the
implementation details. Thanks for the idea.

>
> > >
> > > > +}
> > > > +
> > > > +static inline void rem_ctx(struct codetag_ctx *ctx,
> > > > +                        void (*free_ctx)(struct kref *refcount))
> > > > +{
> > > > +     struct codetag_with_ctx *ctc =3D ctx->ctc;
> > > > +
> > > > +     spin_lock(&ctc->ctx_lock);
> > >
> > > This could deadlock when allocator is called from the IRQ context.
> >
> > I see. spin_lock_irqsave() then?
>
> yes. I have checked that the lock is not held over the all list
> traversal which is good but the changelog could be more explicit about
> the iterators and lock hold times implications.

Ack. Will add more information.

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
kasan-dev/CAJuCfpF7WeVuJpmZN3KEu%3DFAUH34xfYG4wPg-YNjxj%2BGtmdBXQ%40mail.gm=
ail.com.
