Return-Path: <kasan-dev+bncBC7OD3FKWUERBDVB42MAMGQEDOY3QHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 617485B1515
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 08:49:51 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-10e88633e1csf9168357fac.21
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 23:49:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662619790; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJSd63nlH2sPBJXAtZ4AmGSyMBjk8bRnO1A9GKFXEkSnKt5THtc6x2N5Jg5Van3NKP
         fDAnPyk83bcbhM200E5aKYX0mSiDtPQKLFCKg5gi6K4wPIx/BY191xTUPrvmTxz3e5qN
         dz7Ih0W8OkbrgJ/UYwdvb3YNGp3pwfqgaGEEkxMayRi8Vzh5/ftQhhoHF8vHyTn7lLa/
         TBHPrRhk7HnXzwXhrhamgAVMFwHwkAyLQyYcXFkjnCI3T7xM5be3Oup6Sk8LhKT0kqyf
         FqcUQv+k8h1TBWA2zDUF40aFVu5Zv3F2db2IH07In5KAFcxmZvmaHI1CtpIDssci59Dq
         g/yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dmT+OS27JcYZHZt2WSkTOwxiu3m2Kh9QWQo0QV91E3M=;
        b=SOSpqK2jMw5QQ6xlBRk72CtLS34AMN5vi2TyxxiqtVceWFD26wnlH62QM7xEGhk/Pk
         BdoX3JTZMHoJ5Y6MvC1GPe5B5qN2RF3s2XoFvDpvst2OX+riTvz2ekGyhAicn3AOmxdx
         waLEKgP8ylwAGN3I9f3kRI2g8qhMJO5jBfFrZQpPRDlihjhu2SSNXDxvCYqGKpG304WV
         XkwJIF8EKiKT7vNt4nCkJsmdyYCEqj2F2zWG9c5YQuGQBjhRbF1OSyXBvwkvoN45VzOb
         sJzJJ2W0JbNuu7oJbKIl30Oej+vdiFWayWgCkoEIU1qqYKcV0Gbd/0C+ry/yIeyWz1Q8
         OIUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="JG/SHVRf";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=dmT+OS27JcYZHZt2WSkTOwxiu3m2Kh9QWQo0QV91E3M=;
        b=XbUOM40Od9ghP3L0XAKGUFeqVwyWRxjRyAyRalO5dw/23gw40uCmtpwh7sR4ABz6Eb
         pwEIawkM9BLfXWjmJ+PszxvWejQ6x8aGb22bDEq5UVplPYg8uuuurW5UBYk7GOQXKtbm
         s+i0fTnJL4uExWBrsUn3JK5VNv57/dVx6Zvsu0H49YHhbK6/v9ubWn0jrFKTUom4nE9u
         a3giKHrvHwUL+HoafZt26iLUgmlzjHW+BbWOQ2HIVrna7FAWYYjPBeSafqWE2HESQWm6
         +7b9f9kg/W2cfro2jA9miJg36eEQbbU20k9mxXeaBe9P36rT+z1zKm8vg6X24WUgz+Aw
         cNrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=dmT+OS27JcYZHZt2WSkTOwxiu3m2Kh9QWQo0QV91E3M=;
        b=2XMCApuNoj2yDTp8Ff6lbdYmRxvHu1rcZVxtUgKm3EZrYZYCuzrT6taKggOPr928J5
         IAB5vbwrKL9jxCCMhDgqQKUIyVMv90Sik2aqf0AHGTJM+WFtNJcM7WaIy4Ci289OcGV9
         dXzRKy74N1qB1wZaUFxdmV94ZjH/aceS56XAsJfLEz+EzOfE2pM0Aa9/nTA3zNDxorgj
         DXOYSNa33E98OZ/GAkBdGlTU01ofjcLjs/sUIk1BIm/pKvx/A9Z0FXPR/h2sOVAFBwKy
         ethTeeEaetVv/0wYWVIZz5nA9SZkn9Jfjv4hrz6w15+V5xYDZYlIXCzilpUI9JMulYPK
         CXFw==
X-Gm-Message-State: ACgBeo3X+F7pezRb05cVQjMRs2yEIopUWEhd6N1udkOcr4QdQjIUyk0M
	vxSZPmuMv1JiLzW+yXs88Ho=
X-Google-Smtp-Source: AA6agR443IQGh239yZLBzWvCz/60/OUrhwJhMcibrBlKr4w4ELkNhDMLsc1ADEgellrpCynfWZj0SQ==
X-Received: by 2002:a05:6870:80c8:b0:128:fef:aa3c with SMTP id r8-20020a05687080c800b001280fefaa3cmr1133196oab.184.1662619790147;
        Wed, 07 Sep 2022 23:49:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e1c2:b0:11c:88f5:79d7 with SMTP id
 g2-20020a056870e1c200b0011c88f579d7ls332781oab.3.-pod-prod-gmail; Wed, 07 Sep
 2022 23:49:49 -0700 (PDT)
X-Received: by 2002:a05:6870:d212:b0:125:f06d:1a92 with SMTP id g18-20020a056870d21200b00125f06d1a92mr1078144oac.242.1662619789749;
        Wed, 07 Sep 2022 23:49:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662619789; cv=none;
        d=google.com; s=arc-20160816;
        b=krKMPQ4aH/3t35NhnHXNNuOIs0GMm8dpurQP9cfyeizx2ZAtG785Ov+N70uY+kwwQR
         QgTtxBkfpk89v7nl2IBe9evvmMAeuMLgSHGDSamRoxIKYVHlBbj3JatJko3JIFonqj/S
         W5JJNRKwOd6Z8Mre/monNWh11Xi3ZF28jcUvvQtDJjsnQpO90013riO3KkrLySt5bn7M
         +zToypMov7YDPf8DIzoMBaOTVxwW9GpW6K7SX+z16cF15W4bGd7alBAOLb4tbxUGG2Tj
         KIgBxsDNRZRTjXScf9WumltqWpXmrjJDFzNizMvyHJjwTlt0DDyVOcWsNTS1gsNPtHpn
         VBmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6UU7RPsFxQr+5ujpTkN8WcG542NNzl57+boNHvVA5zY=;
        b=wO6RH9oPPyUGEuXAhiqfDtvlc/suwU/i4VDAhZgyfg+KiUmtT1wzj8XEhnKkfdTsbt
         /b38FugHlvBy8GGp+nEYLnfgxAK1eqS7l5P8KYKDZPf0ypQlOYTtWrlqptPc/j0DB431
         7MPIqbqREH6s2miHa67+qZdd4HWS1pN3Hg1FG+f4+cmuBEUxcGM3VAKbJxIxGgSJKylT
         QOpFyBtjNnkkF26FxvRRtD8A0cbLzAlkC6e07N+dMHeE+634iYagG7p/MTpzIzxgUWdx
         Wg5neA583AJvbdluPCS4NzLff+AffwcaLSugxCNXaVwjX7R20ZOXkS+FU5uOaHkp3p9U
         HCqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="JG/SHVRf";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id o7-20020a056871078700b00101c9597c72si3565134oap.1.2022.09.07.23.49.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 23:49:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 202so20299329ybe.13
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 23:49:49 -0700 (PDT)
X-Received: by 2002:a5b:cc4:0:b0:6ae:2a6c:59e6 with SMTP id
 e4-20020a5b0cc4000000b006ae2a6c59e6mr1980963ybr.59.1662619789134; Wed, 07 Sep
 2022 23:49:49 -0700 (PDT)
MIME-Version: 1.0
References: <YxEE1vOwRPdzKxoq@dhcp22.suse.cz> <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan> <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework> <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework> <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
 <20220907130323.rwycrntnckc6h43n@kmo-framework> <20220907094306.3383dac2@gandalf.local.home>
 <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
In-Reply-To: <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Sep 2022 23:49:37 -0700
Message-ID: <CAJuCfpEQG3+d-45PXhS=pD6ktrmqNQQnpf_-3+c2CG7rzuz+2g@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>, Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>, 
	Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Benjamin Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="JG/SHVRf";       spf=pass
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

On Wed, Sep 7, 2022 at 11:35 PM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Wed, Sep 07, 2022 at 09:45:18AM -0400, Steven Rostedt wrote:
> > On Wed, 7 Sep 2022 09:04:28 -0400
> > Kent Overstreet <kent.overstreet@linux.dev> wrote:
> >
> > > On Wed, Sep 07, 2022 at 01:00:09PM +0200, Michal Hocko wrote:
> > > > Hmm, it seems that further discussion doesn't really make much sense
> > > > here. I know how to use my time better.
> > >
> > > Just a thought, but I generally find it more productive to propose ideas than to
> > > just be disparaging.
> > >
> >
> > But it's not Michal's job to do so. He's just telling you that the given
> > feature is not worth the burden. He's telling you the issues that he has
> > with the patch set. It's the submitter's job to address those concerns and
> > not the maintainer's to tell you how to make it better.
> >
> > When Linus tells us that a submission is crap, we don't ask him how to make
> > it less crap, we listen to why he called it crap, and then rewrite to be
> > not so crappy. If we cannot figure it out, it doesn't get in.
>
> When Linus tells someone a submission is crap, he _always_ has a sound, and
> _specific_ technical justification for doing so.
>
> "This code is going to be a considerable maintenance burden" is vapid, and lazy.
> It's the kind of feedback made by someone who has looked at the number of lines
> of code a patch touches and not much more.

I would really appreciate if everyone could please stick to the
technical side of the conversation. That way we can get some
constructive feedback. Everything else is not helpful and at best is a
distraction.
Maintenance burden is a price we pay and I think it's the prerogative
of the maintainers to take that into account. Our job is to prove that
the price is worth paying.

>
> --
> To unsubscribe from this group and stop receiving emails from it, send an email to kernel-team+unsubscribe@android.com.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpEQG3%2Bd-45PXhS%3DpD6ktrmqNQQnpf_-3%2Bc2CG7rzuz%2B2g%40mail.gmail.com.
