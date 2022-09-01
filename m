Return-Path: <kasan-dev+bncBC7OD3FKWUERBUFEYOMAMGQEVS5TASQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id CE8015A9BD8
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 17:40:01 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id x27-20020a25ac9b000000b0069140cfbbd9sf4678964ybi.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 08:40:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662046800; cv=pass;
        d=google.com; s=arc-20160816;
        b=W91uCTsdjndsoLghYsUzLstTBcrgJ/qZe2Vp9ujTUtxllzOdtZus79X5f64s8luTgo
         XzMWR+zuxvkDEYk/qbwB14ZaSNVHU9JGFC5UePzR7yrJpPR73ySuMuyBf6QUvC3Og6xA
         wK+WFva/J4X/itdnAB8HEIkAs08xhB9x3iM/dSiofzxNLC3CsZyKtuAdmvYElV2/8jYI
         ldTP6RD3DbPFN3HkENveIqVkBBwJN6URb4JQVpfskX0jLa+NbyZJMdVoXfswDVLneFgE
         A+fD6iOektS/hPr+zLLWIO5JRmyi56zg2gpUKt1beHxc53xYOwHfT9AnGVkTYUN7iyDX
         0NIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uYPy9EHduo40KlYnpvmAqI7d83iYmUFR/F4YIfCq75o=;
        b=QvZMv8UUVgDJGlmjgSb9llZkbwxIHLOLoP0w/V4mUYWiQnBemzFPU/Cqx904XoKpQ8
         hQjWNVjf4hlo9jjj/htyoR2qu0nYP5DFVAUlltBUdw0pKF8mscogGvDn+9ulWOAQw6mQ
         A3rvy3MduZtAGGtMYTUVWLVJDhrLRHLRckqQZOA9LBXPUZ2G1yLX9sqvays/ufMWolOD
         9r6xkOjQAxrRlYVI//Sew1X67N1YEKOVoDA/l7FKNrIpZx9Pvi+QLjDD9KCXNjN0zwyQ
         PLwDLxeL0o64O91XjeakEyHNAS/T+N+RSgeyCcm3yWWlktVqZ1a5uzytsCcwe47hhTM3
         tN6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CNR1Ntmy;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=uYPy9EHduo40KlYnpvmAqI7d83iYmUFR/F4YIfCq75o=;
        b=r4j+ahOhXCGKB6wqZDvv4ASOJBNg1Ah8dcV6ebqnvnqrmuDnO4WrjCPXEJweFLCO2d
         Bgck4UuQEybdTdzauNvt8iB5N1ygp8k+3fFKCzsrBq024p2AXYbPDmef4R2F92RmBjQq
         tpbbhyGTUFoAvq3tYllJa4Bkk//r8tVgkAAag1kA+ydh5l5UKi6NBlJ7ETKig1EEyO4S
         wg0qPg6mZ7Xtz8u8LMV2iLBNyXtivXzA2usCnu/UR8pkeUOBplEZ6J5MHp96TJnw7iVA
         77FVRMDD8dT0uHt3+k0aQvUncjxJ5l5D4TONIEof0wbKKe1Us0vpDedPsJqRNt15qMQ+
         UiEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=uYPy9EHduo40KlYnpvmAqI7d83iYmUFR/F4YIfCq75o=;
        b=oZO6oJEwxAN2wiWWfTro1pSlIjqsE2hCT4/DLZDl1PvYQSZ4pQgxRNl1+wXFyKihFf
         1uf3NrGXN7Xr8KRyidqUI2tXT9pQnj64bQSXKG8JYRpp7k/3cUfmdQwKbvcBOPS3FskO
         QWYc6haN/lyPXFJcuB0K951ReODfQ9pwnPfENNO1+jpidtyU44Y3LBc1CZYhpVHl3O53
         db3d4eIY8TrjZzqCv6gSFSn5XGLxX2Lozkq7+wbeAr07Sk1WgUSlnEX4NDMpmqEFeowi
         xsLPvRDUAKsronVM71Rto5qEpE0GBx2W9Ek7hXmWvHxuHAiATxN1K41ADC1EEUnnsIc3
         4OKA==
X-Gm-Message-State: ACgBeo1PQwabDfINu4270q3EdniQ2MmLbMD4vNY9SK9WBM8DFxb57MDu
	wJGOFn1C/MuSX1g3OqlaF8Q=
X-Google-Smtp-Source: AA6agR7Tu7hlOsU8EOI/KsUs6sJMZTjkncKitUjoYYec6BFmT4dJrLel+iMHEz+VQtmsLU92sOTzlg==
X-Received: by 2002:a25:d2c4:0:b0:694:3e58:339c with SMTP id j187-20020a25d2c4000000b006943e58339cmr19359655ybg.515.1662046800509;
        Thu, 01 Sep 2022 08:40:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6882:0:b0:66e:7859:9c23 with SMTP id d124-20020a256882000000b0066e78599c23ls1267896ybc.1.-pod-prod-gmail;
 Thu, 01 Sep 2022 08:40:00 -0700 (PDT)
X-Received: by 2002:a5b:184:0:b0:67b:ae2f:3625 with SMTP id r4-20020a5b0184000000b0067bae2f3625mr18093879ybl.366.1662046800040;
        Thu, 01 Sep 2022 08:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662046800; cv=none;
        d=google.com; s=arc-20160816;
        b=x86rLeqs5LrVFe4pTrQgQ3xbiKyFme8UG4BSzi9ED6suhEgzzEYxc4F2rYkwcqyH9+
         MlnxlJeDMIExuvXozSBSuEIR/FnPpqHc8q7t+fHzxTxSV7yECTTprhLU25bYLBVJzNJJ
         B011LZDMO11VU9h+iko1EfGidPjjeUZMELh6U4KhDu3CAB9/Idv5rLoVf9iEhsX1pNp4
         WgwzPD0/qOPDFp059ptF+LhGTOAJxv/q6sTzlOO6gFZOccHfZDcP/ksQaWPX3Y2O7tfM
         cP2ZlNrSs8lv4nTmpxkWHsHC/L9IU/q25z0QTvOcP2PNpiYMu7Y6qON6ZSrcrklkpDf6
         efcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3cE853tliEpPWpHjkdjBsm55bguibJ1NOZ2l+ytqvIs=;
        b=Ee3mK2+FU5TW3+4saiNGYwLPz1TG5nxqcjy4n7/kbNHq6V5938EiedJRC6UBjZkFEm
         0YyySYv45la4RK4CePcsWK92fU2Mzd43uhXPLPfiUOWeBC+4+lkLDAuzQktgPb3lSqO/
         xlLuzJj347NFcCHRSQ5Tx9Wd+SweBgmXv/SclQp+rphcNPYxFvgijrGdKLWuMZ86T82f
         sqfS4CtstXhUyT12ZKF/GpkLITWUkEpDO5jmlBCy5Q7GEByu8V1u3AjP+j8QPT9l5gKw
         GzloPBRGLZ7G6TMMboSF85I+H806gVaRADbmBDlJ4EPKQ0EjIHbVWVhIPGNXAZgJWzaJ
         rrnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CNR1Ntmy;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id cm21-20020a05690c0c9500b003306f06af42si873747ywb.3.2022.09.01.08.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 08:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id c9so9153141ybf.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 08:40:00 -0700 (PDT)
X-Received: by 2002:a25:b983:0:b0:695:d8b4:a5a3 with SMTP id
 r3-20020a25b983000000b00695d8b4a5a3mr20405655ybg.553.1662046799565; Thu, 01
 Sep 2022 08:39:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <404e947a-e1b2-0fae-8b4f-6f2e3ba6328d@redhat.com> <20220901142345.agkfp2d5lijdp6pt@moria.home.lan>
 <78e55029-0eaf-b4b3-7e86-1086b97c60c6@redhat.com>
In-Reply-To: <78e55029-0eaf-b4b3-7e86-1086b97c60c6@redhat.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 08:39:48 -0700
Message-ID: <CAJuCfpEgWx4mmiSCvcMOF0+Luyw1w-hVyLV-cvhbxnwsN6qg0g@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: David Hildenbrand <david@redhat.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CNR1Ntmy;       spf=pass
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

On Thu, Sep 1, 2022 at 8:07 AM David Hildenbrand <david@redhat.com> wrote:
>
> On 01.09.22 16:23, Kent Overstreet wrote:
> > On Thu, Sep 01, 2022 at 10:05:03AM +0200, David Hildenbrand wrote:
> >> On 31.08.22 21:01, Kent Overstreet wrote:
> >>> On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> >>>> On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> >>>>> Whatever asking for an explanation as to why equivalent functionality
> >>>>> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> >>>>
> >>>> Fully agreed and this is especially true for a change this size
> >>>> 77 files changed, 3406 insertions(+), 703 deletions(-)
> >>>
> >>> In the case of memory allocation accounting, you flat cannot do this with ftrace
> >>> - you could maybe do a janky version that isn't fully accurate, much slower,
> >>> more complicated for the developer to understand and debug and more complicated
> >>> for the end user.
> >>>
> >>> But please, I invite anyone who's actually been doing this with ftrace to
> >>> demonstrate otherwise.
> >>>
> >>> Ftrace just isn't the right tool for the job here - we're talking about adding
> >>> per callsite accounting to some of the fastest fast paths in the kernel.
> >>>
> >>> And the size of the changes for memory allocation accounting are much more
> >>> reasonable:
> >>>  33 files changed, 623 insertions(+), 99 deletions(-)
> >>>
> >>> The code tagging library should exist anyways, it's been open coded half a dozen
> >>> times in the kernel already.
> >>
> >> Hi Kent,
> >>
> >> independent of the other discussions, if it's open coded already, does
> >> it make sense to factor that already-open-coded part out independently
> >> of the remainder of the full series here?
> >
> > It's discussed in the cover letter, that is exactly how the patch series is
> > structured.
>
> Skimming over the patches (that I was CCed on) and skimming over the
> cover letter, I got the impression that everything after patch 7 is
> introducing something new instead of refactoring something out.

Hi David,
Yes, you are right, the RFC does incorporate lots of parts which can
be considered separately. They are sent together to present the
overall scope of the proposal but I do intend to send them separately
once we decide if it's worth working on.
Thanks,
Suren.

>
> >
> >> [I didn't immediately spot if this series also attempts already to
> >> replace that open-coded part]
> >
> > Uh huh.
> >
> > Honestly, some days it feels like lkml is just as bad as slashdot, with people
> > wanting to get in their two cents without actually reading...
>
> ... and of course you had to reply like that. I should just have learned
> from my last upstream experience with you and kept you on my spam list.
>
> Thanks, bye
>
> --
> Thanks,
>
> David / dhildenb
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpEgWx4mmiSCvcMOF0%2BLuyw1w-hVyLV-cvhbxnwsN6qg0g%40mail.gmail.com.
