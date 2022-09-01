Return-Path: <kasan-dev+bncBCMIZB7QWENRBPHBYGMAMGQEU7W2YSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E9F755A9249
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 10:43:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id v67-20020a1cac46000000b003a615c4893dsf9527610wme.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 01:43:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662021820; cv=pass;
        d=google.com; s=arc-20160816;
        b=LTWtTvWxES69DkHmeRgYIgjRWcKZzgVSAGIkBKicLfA9GJYYMhCDepPgLfVLJEtfRQ
         m+NlPrjeg0nUm2In5v9HkWuGSQmss1kyefWUfE7coWqgv+mj8JjkHVoCCNcuvVTd7iK3
         sr3UR/acKkutIbhsUMddKKO7FJyxya+d+KBDdtM/pjSVTv408UNMo2qMh7RVQ9FP6mSk
         f9YpcVyw/xqhaTjmw0ezqpS3qXSVZ/UYRo2XMUk945XGQ0I5hWiHmnN5MKGvYn/1/7vg
         og1sip5eh+4epJ3fzAHekxZjz+miiTcytvRLGXFbj8NHhIv08Ch7nxI5xHt+B43PD7mC
         VLLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=brNm8dGVPmqYBVEn28Z6yC3KzdTNzUVEBYBdManyalw=;
        b=MDVTvFYz7J5vjVUuziRd5596SWXRTJUw/Cs6YHYNw7qErxIOIwxuY3vkLvmvNmBkmP
         SgQJQSvlrrNyX3BQcpFAHMxArtR6HJl6N9uw5BsPDXOBsazXIsdrc5+U1WKq9dPZ/CAp
         PsHF6Vqq4XPEjWA/LzwZ8AsKSsW6OaWc7DI02gRKTOY4+lgXIkSZM0ljiSMJnCyLevUW
         6GCo8frXebyi6RKpHVt2PfSaUgpsxEqub1ZlVCdIfzU4b3D+75FewWyZ0l65NtXCLK71
         uEzCF602waplj/UovjWt9HPpl6aMQRjW71u2CIbqJkrEpB08QYOKuDbrQ5CZDj2BeuF0
         cOpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q7AjWjhm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=brNm8dGVPmqYBVEn28Z6yC3KzdTNzUVEBYBdManyalw=;
        b=WIJHuQNX0PrXWL1X7nYMOMaVXGPQuuh56b39ZB9fsdfJmEj8gVH8OEUA48IzcrVpKV
         ZK72YoORhF3XhN2lOWsFUhN5YTIyEw381ncE5bGMRnPwXCwfyZE0nHKfhpSudsgztZu+
         /v146ySaCOEExi48NzhWmFEi9WarzqkupsoUF1xQ98l+HBdq+01W548Q1kFY/8T0MUUh
         t5SROmW3eiqJHJJX9ty6GWI4mZybBxW+EByRYkF8rHNKcFynf+Y/N8ODNlqzWj09Xotp
         2iwKaxw9ZAqsx53EZac2rfLdhvxQWTiYSsw2Z992/XS3knQsxXlMd2TraxzIFaJ51vL/
         Rz0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=brNm8dGVPmqYBVEn28Z6yC3KzdTNzUVEBYBdManyalw=;
        b=hRe3HE9A4isIjRytKNjf/DKZcHrvdloOhFk6CfWBXQdj9W3M/o678bLSo4IobRNFja
         lLYSnBuxa+dsCG5qLQA1i47yfpo84pGycIo5rhbmwuavTpQIFKdNw1Orc43RrAbaJ6S+
         rcpauzePDMoBj1tfsWFWWBoMMBhEB40AShdZ/6sOp3ZyEZDpPbl1Yg8+982y83EfeWDB
         ImrPyVAX7nC2xptUmSkS9rvWJPGO3Yj7vblLeP62SD7inNRe9hyR/dn1ThANRLtqpbyi
         ORCmx8khPpwgZ1/hOCprJAslpXBlMobz03MdVtUqMxnN/mTM+APlUEZ05B4UzEIhLvKX
         Jbmg==
X-Gm-Message-State: ACgBeo0AclybspCnVBCsYblABYgLUc6lKZuf4rkf4wEfYXbyE6ZXCrKs
	gDzxoPdDyTaUbG2yWhHRGvk=
X-Google-Smtp-Source: AA6agR6cbc/Ol4Fm/tRcpwjqH5SrcRuzliAVwE23ffci2jTQ+UBVoU/rKKUtDBjAyMsMq4fqN+rZPQ==
X-Received: by 2002:a05:600c:474c:b0:3a7:3954:8818 with SMTP id w12-20020a05600c474c00b003a739548818mr4372052wmo.124.1662021820675;
        Thu, 01 Sep 2022 01:43:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1705:b0:225:58db:7886 with SMTP id
 n5-20020a056000170500b0022558db7886ls1932360wrc.1.-pod-prod-gmail; Thu, 01
 Sep 2022 01:43:39 -0700 (PDT)
X-Received: by 2002:a5d:64e1:0:b0:226:db58:868b with SMTP id g1-20020a5d64e1000000b00226db58868bmr10672620wri.79.1662021819637;
        Thu, 01 Sep 2022 01:43:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662021819; cv=none;
        d=google.com; s=arc-20160816;
        b=F6Dq2NR7e8gkuIkpBDiS3i5kBR/HcECZrDP7n0a7YWg1lz6UuNHmSkLCUDo96e4xp5
         bEAz3TcSMSPGfS3qzP0Snhx2SQJSbPsfgQpG0s15yubZSJvwb9frhnjxqVzagTSg30Gt
         J0t4xaZDMgsCzqJcb8rV7A+51I3v0FMzLn2eoUZNMlIQ4Jn0EqppZKwellSc3p2EYKb+
         qWUb9WkxDu3UE1bvHUFGkIo2vE0zZF2i8sYMi4IHF7P5mJpNcCYMIgFe+QGXXMistdLJ
         6M5NO3mRWCB3OIGCjFs+Wmr2Gsqxl/JPDbrld0RGMSYaYMl8BUUaa5uUIrSZ21/3bw2L
         MQng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VH72CkJdWHRYjuIFqG3YYZtTrJw2Fhi5jnFxkucPCHY=;
        b=opY7A0Oor/kwGr/nzHtNdIMi5jofQHKc36THocWUnNCv+8ob7yhVrlbZ4xIUWNKATG
         kvsGaRtkIu1j09V8eqpphdaDQyNIBr/jtVyhp/EHBqxVfgPBbdPIlMKkLtmdkiH2jrQQ
         4XMBY/Wh4yQ4srbpcEVPbTdAFS3SBJ78n/oqq5xfcAPI36ldBSwgOh1bAdRs+7DTX/7f
         CI5tX0PpXq8X9/Caaxg0lDAWcoyx8wJ4jFGMNrO4iC8y3KwZkvXVbpgc8CacUNltzs4t
         rUscUq9PeBR0UfmTGlMC9OXC3tYyI5d15sFKEFhN3CrxmN2Ft0utVI4M563/itH4ihSq
         ctNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q7AjWjhm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id k126-20020a1ca184000000b003a5a534292csi429915wme.3.2022.09.01.01.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 01:43:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id bn9so17124342ljb.6
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 01:43:39 -0700 (PDT)
X-Received: by 2002:a2e:be88:0:b0:25f:e9a8:44b8 with SMTP id
 a8-20020a2ebe88000000b0025fe9a844b8mr8851946ljr.92.1662021818766; Thu, 01 Sep
 2022 01:43:38 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-23-surenb@google.com>
 <CACT4Y+ZX3U1=cAPXPhoOy6xrngSCfSmyFagXK-9fWtWWODfsew@mail.gmail.com> <20220831173010.wc5j3ycmfjx6ezfu@moria.home.lan>
In-Reply-To: <20220831173010.wc5j3ycmfjx6ezfu@moria.home.lan>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 10:43:26 +0200
Message-ID: <CACT4Y+bMeqvWQwqzG3nfcf0-VOjU7usxht5mKgUwMcOpWKRjxQ@mail.gmail.com>
Subject: Re: [RFC PATCH 22/30] Code tagging based fault injection
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, shakeelb@google.com, songmuchun@bytedance.com, 
	arnd@arndb.de, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q7AjWjhm;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

 On Wed, 31 Aug 2022 at 19:30, Kent Overstreet
<kent.overstreet@linux.dev> wrote:
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > >
> > > This adds a new fault injection capability, based on code tagging.
> > >
> > > To use, simply insert somewhere in your code
> > >
> > >   dynamic_fault("fault_class_name")
> > >
> > > and check whether it returns true - if so, inject the error.
> > > For example
> > >
> > >   if (dynamic_fault("init"))
> > >       return -EINVAL;
> >
> > Hi Suren,
> >
> > If this is going to be used by mainline kernel, it would be good to
> > integrate this with fail_nth systematic fault injection:
> > https://elixir.bootlin.com/linux/latest/source/lib/fault-inject.c#L109
> >
> > Otherwise these dynamic sites won't be tested by testing systems doing
> > systematic fault injection testing.
>
> That's a discussion we need to have, yeah. We don't want two distinct fault
> injection frameworks, we'll have to have a discussion as to whether this is (or
> can be) better enough to make a switch worthwhile, and whether a compatibility
> interface is needed - or maybe there's enough distinct interesting bits in both
> to make merging plausible?
>
> The debugfs interface for this fault injection code is necessarily different
> from our existing fault injection - this gives you a fault injection point _per
> callsite_, which is huge - e.g. for filesystem testing what I need is to be able
> to enable fault injection points within a given module. I can do that easily
> with this, not with our current fault injection.
>
> I think the per-callsite fault injection points would also be pretty valuable
> for CONFIG_FAULT_INJECTION_USERCOPY, too.
>
> OTOH, existing kernel fault injection can filter based on task - this fault
> injection framework doesn't have that. Easy enough to add, though. Similar for
> the interval/probability/ratelimit stuff.
>
> fail_function is the odd one out, I'm not sure how that would fit into this
> model. Everything else I've seen I think fits into this model.
>
> Also, it sounds like you're more familiar with our existing fault injection than
> I am, so if I've misunderstood anything about what it can do please do correct
> me.

What you are saying makes sense. But I can't say if we want to do a
global switch or not. I don't know how many existing users there are
(by users I mean automated testing b/c humans can switch for one-off
manual testing).

However, fail_nth that I mentioned is orthogonal to this. It's a
different mechanism to select the fault site that needs to be failed
(similar to what you mentioned as "interval/probability/ratelimit
stuff"). fail_nth allows to fail the specified n-th call site in the
specified task. And that's the only mechanism we use in
syzkaller/syzbot.
And I think it can be supported relatively easily (copy a few lines to
the "does this site needs to fail" check).

I don't know how exactly you want to use this new mechanism, but I
found fail_nth much better than any of the existing selection
mechanisms, including what this will add for specific site failing.

fail_nth allows to fail every site in a given test/syscall one-by-one
systematically. E.g. we can even have strace-like utility that repeats
the given test failing all sites in to systematically:
$ fail_all ./a_unit_test
This can be integrated into any CI system, e.g. running all LTP tests with this.

For file:line-based selection, first, we need to get these file:line
from somewhere; second, lines are changing over time so can't be
hardcoded in tests; third, it still needs to be per-task, since
unrelated processes can execute the same code.

One downside of fail_nth, though, is that it does not cover background
threads/async work. But we found that there are so many untested
synchronous error paths, that moving to background threads is not
necessary at this point.



> Interestingly: I just discovered from reading the code that
> CONFIG_FAULT_INJECTION_STACKTRACE_FILTER is a thing (hadn't before because it
> depends on !X86_64 - what?). That's cool, though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbMeqvWQwqzG3nfcf0-VOjU7usxht5mKgUwMcOpWKRjxQ%40mail.gmail.com.
