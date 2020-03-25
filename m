Return-Path: <kasan-dev+bncBDK3TPOVRULBBZWU53ZQKGQE3W7BKHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C148D1930C5
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 20:00:54 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id f185sf1038535wmf.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 12:00:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585162854; cv=pass;
        d=google.com; s=arc-20160816;
        b=D95naXwDSJkZ39H3yOjZNklRXeWnN6nlh8FKnNoVQdz7x8JpvUaZqxDtCgA6f9zwvO
         XdRtG1GeHt8yCMJzGZix6h62U4BbrycCsWH9BVODdlM0mLzYDhtFZTPIYHz6qDRstmzO
         iiYockZ4AdvmJdL01Tr6FxV1KcDEh9MtoIPpGNYmPDccAv1F2ffacB9dpenFRSKcgbY0
         n7jwlVlfFOeVfkWlgzOVsUKl1UJ5UBrx5C4ydnv4Rm1SGnFHvSme+LJUEF4pcv6V1EFm
         FrDKk0wx2+w3BtW6Aw3I2TmfrVhy3G3xw8H3Xk7WwBYXNlr3b4Z70hbNH4VchU1MuMlw
         L5WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mLdgkPSHWDmwFmbJBlGZStzd3yLkraSmSuzBPVkOA6s=;
        b=vY4vi2gHbnXd0c6AofMWvy+zLIydqd+OGNUj7NpkYgZoIbZ01qEokqmIDUzauUoFxJ
         a9yJh51UnLMSv6Pi60L0KA2psZhRXHpX5vWZbwrgBezQAaOcT+MpFbeBqQFxSim/z3SC
         ZEhs2QHR4k02DxartSRtpZIPC6TBYgojpMCugwSwqk+ljq3mKZsbMMGxThJ1PmUtQ7x9
         cLbviX9Adz9Kyy382o98Gjz6sivJCRk8H12p0uDgT+2dxZo1gw3rNqwIE9cdjLDrKeV/
         NkKrAYNRcCOjxpRuYrxkOpMBoAj5ki435Xt9MP8RFWKQCN726nJmCear3OW4saLllDN/
         Jd4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Kp/K7lRB";
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mLdgkPSHWDmwFmbJBlGZStzd3yLkraSmSuzBPVkOA6s=;
        b=a3TbT0RdSy6RrPBB0lFh01U2BL5dUHsm1khdotq+T1cJEpcKDnu8e2gK37QPSo8cKr
         1z1PHn9PgSURJNUyvYK5Pe+F4eV6UyHXKm9Fd66Si/jYw7R6yl+SMjGc+NxmVcAZBZWw
         PNHE0tLD21pC/a17NNauL8Sne6bVK2luC6sB5U0O3ilWPgPEUgTQ2Agm7v1VvMFLJFzw
         b6aTlD1wYGYRUIKud3ZxbnfgrZj98i0rnwdNdgX2Sv4oaciZIxV/DwHpAt4aIC8+usAE
         aiiydbPdNcn0lFvfky7P0ZdUeLMf3qj6jr2pHoh8J8VpekbaPnq+9HP3h1qVilpVuBr8
         oK1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mLdgkPSHWDmwFmbJBlGZStzd3yLkraSmSuzBPVkOA6s=;
        b=griIPewGiR9GT+gF3mXQsdox7W5Qw5OmcrB8Nb5nkOT+qe6bJHNC/KMaNXVEIM1fEk
         8K3Xd32wA6Ae5je/YHefJI+tqbMXNBiNJNtEQcklkNkp28M4nyPLZt7l41Umfc9JKtho
         W9PLuIQnhjMw3MQP90WAeVT177smfxjDPdt1sx28pLrqGZoMmmPvMLmoZf1CyNpC2sbb
         gRomUoNNcDT/CZ5YMKskHVEHjTWayXWimx8u8VRLCQrh/rSh5qfexH8CxeS1PlGFKYgs
         vTiL2CFwCDzWMO07w4uwhsNU+6glESf+vZQJpTl9oFGK3QDHkCMtynT9HkErftDihOQo
         sm8g==
X-Gm-Message-State: ANhLgQ0zBpZ39TnuD0emZwzvdCzGKs31NzD4yzeN1SLZqJKi7GdY8WWP
	0gYmzTduLkgHMaMoegMuEMU=
X-Google-Smtp-Source: ADFU+vuVARtSJ+LOxEUetE8ic6PZ+nZvy1icPWluhzgv3UFtoEG5LQ7zIkfJ5kTiG+72Yh64kCJvCw==
X-Received: by 2002:adf:e8cc:: with SMTP id k12mr5115177wrn.144.1585162854402;
        Wed, 25 Mar 2020 12:00:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2250:: with SMTP id a16ls1562890wmm.3.canary-gmail;
 Wed, 25 Mar 2020 12:00:53 -0700 (PDT)
X-Received: by 2002:a1c:1fc9:: with SMTP id f192mr4993385wmf.4.1585162853857;
        Wed, 25 Mar 2020 12:00:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585162853; cv=none;
        d=google.com; s=arc-20160816;
        b=OUaYkMmbgYsKulAh6WdAZ8isiy3iaV1ELZ0V/1KTl7bWIL741ENgHbqT6YJf07idVp
         bsQdp5PW8vE7u/0BFq4sb9rCQPPUfr5+W9Zr3joJyzs1v3YSXLP3I/dYZ59frKLzZ0vo
         IvLpjMKkOIhFK6IDXBsppT+Mdr8ev+8uPZWBKSzQTpnay5ZIJJzYB3qIG3vww4G/YfRZ
         /cOzzweLZZV3/BISfqHJD0Z7/aKGZyBVNauIKS9YBYVq0w3Ozcu+3jBgn4mUIS23if3c
         B9t7+LbVxJdICXHj1cLJLDG7x5TByTuw0RIbXmT8HeEkekzZ3gwSfxk94UlBRGqXvwpv
         Z3xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+glaYb/lBngljiO0dwm1DyooyffnH+1NHphBxBjNzNA=;
        b=tPWoBa5wP0QuDd9nXp4e6Q4gHkWC1v8Wq8vxK+sdWBbFlP4Z9BHrDsZ4rt+V7MR5kC
         zCNWA3yjKwxzg2tdqYC1jBEbkzRNjfwpBtcodH/HSGqkCid2Y4dJUVM/cKywoaR/Q51f
         mTAFSTTk7JeoJC9NniOEBcWNFB8O2Ntva33yqc9N4/Om1KmkIFYyuveE2kAeCWQj9spq
         VwWhl2DRP63rPLun8ibrXBodH7oIhoF38CAs0jKy2OukFsq5y2I4eiFVr8gqVBEM8gQ9
         aOtkQ7RPEjflFVAk/UNzcvsC87xvv4ahdMNN3vQd/lvudzfJupNCH5BLfT6p+mmXoxZx
         FgXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Kp/K7lRB";
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id l8si913wrr.1.2020.03.25.12.00.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Mar 2020 12:00:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id 65so4665140wrl.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Mar 2020 12:00:53 -0700 (PDT)
X-Received: by 2002:adf:fb0a:: with SMTP id c10mr4937818wrr.272.1585162853207;
 Wed, 25 Mar 2020 12:00:53 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-2-trishalfonso@google.com> <alpine.LRH.2.21.2003241635230.30637@localhost>
 <CAKFsvULUx3qi_kMGJx69ndzCgq=m2xf4XWrYRYBCViud0P7qqA@mail.gmail.com> <alpine.LRH.2.21.2003251242200.9650@localhost>
In-Reply-To: <alpine.LRH.2.21.2003251242200.9650@localhost>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Mar 2020 12:00:41 -0700
Message-ID: <CAKFsvU+1z-oAX81bNSVkuo_BwgxyykTwW9uJOLL6a1ZaBojJYw@mail.gmail.com>
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
To: Alan Maguire <alan.maguire@oracle.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Kp/K7lRB";       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Wed, Mar 25, 2020 at 5:42 AM Alan Maguire <alan.maguire@oracle.com> wrote:
>
>
> On Tue, 24 Mar 2020, Patricia Alfonso wrote:
>
> > On Tue, Mar 24, 2020 at 9:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > >
> > >
> > > On Thu, 19 Mar 2020, Patricia Alfonso wrote:
> > >
> > > > In order to integrate debugging tools like KASAN into the KUnit
> > > > framework, add KUnit struct to the current task to keep track of the
> > > > current KUnit test.
> > > >
> > > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > > ---
> > > >  include/linux/sched.h | 4 ++++
> > > >  1 file changed, 4 insertions(+)
> > > >
> > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > index 04278493bf15..1fbfa0634776 100644
> > > > --- a/include/linux/sched.h
> > > > +++ b/include/linux/sched.h
> > > > @@ -1180,6 +1180,10 @@ struct task_struct {
> > > >       unsigned int                    kasan_depth;
> > > >  #endif
> > > >
> > > > +#if IS_BUILTIN(CONFIG_KUNIT)
> > >
> > > This patch set looks great! You might have noticed I
> > > refreshed the kunit resources stuff to incorporate
> > > feedback from Brendan, but I don't think any API changes
> > > were made that should have consequences for your code
> > > (I'm building with your patches on top to make sure).
> > > I'd suggest promoting from RFC to v3 on the next round
> > > unless anyone objects.
> > >
> > > As Dmitry suggested, the above could likely be changed to be
> > > "#ifdef CONFIG_KUNIT" as kunit can be built as a
> > > module also. More on this in patch 2..
> > >
> > I suppose this could be changed so that this can be used in possible
> > future scenarios, but for now, since built-in things can't rely on
> > modules, the KASAN integration relies on KUnit being built-in.
> >
>
> I think we can get around that. I've tried tweaking the resources
> patchset such that the functions you need in KASAN (which
> is builtin) are declared as "static inline" in include/kunit/test.h;
> doing this allows us to build kunit and test_kasan as a
> module while supporting the builtin functionality required to
> retrieve and use kunit resources within KASAN itself.
>
Okay, great!

> The impact of this amounts to a few functions, but it would
> require a rebase of your changes. I'll send out a  v3 of the
> resources patches shortly; I just want to do some additional
> testing on them. I can also send you the modified versions of
> your patches that I used to test with.
>
That sounds good.

> With these changes I can run the tests on baremetal
> x86_64 by modprobe'ing test_kasan. However I see a few failures:
>
> [   87.577012]  # kasan_memchr: EXPECTATION FAILED at lib/test_kasan.c:509
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.577104]  not ok 30 - kasan_memchr
> [   87.603823]  # kasan_memcmp: EXPECTATION FAILED at lib/test_kasan.c:523
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.603929]  not ok 31 - kasan_memcmp
> [   87.630644]  # kasan_strings: EXPECTATION FAILED at
> lib/test_kasan.c:544
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.630910]  # kasan_strings: EXPECTATION FAILED at
> lib/test_kasan.c:546
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.654037]  # kasan_strings: EXPECTATION FAILED at
> lib/test_kasan.c:548
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.677179]  # kasan_strings: EXPECTATION FAILED at
> lib/test_kasan.c:550
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.700242]  # kasan_strings: EXPECTATION FAILED at
> lib/test_kasan.c:552
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.723336]  # kasan_strings: EXPECTATION FAILED at
> lib/test_kasan.c:554
>         Expected kasan_data->report_expected == kasan_data->report_found,
> but
>                 kasan_data->report_expected == 1
>                 kasan_data->report_found == 0
> [   87.746304]  not ok 32 - kasan_strings
>
> The above three tests consistently fail while everything
> else passes, and happen irrespective of whether kunit
> is built as a module or built-in.  Let me know if you
> need any more info to debug (I built the kernel with
> CONFIG_SLUB=y if that matters).
>
Unfortunately, I have not been able to replicate this issue and I
don't have a clue why these specific tests would fail with a different
configuration. I've tried running these tests on UML with KUnit
built-in with SLUB=y and SLAB=y, and I've done the same in x86_64. Let
me know if there's anything else that could help me debug this myself.


> Thanks!
>
> Alan
>
>
> > > > +     struct kunit                    *kunit_test;
> > > > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > > > +
> > > >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > > >       /* Index of current stored address in ret_stack: */
> > > >       int                             curr_ret_stack;
> > > > --
> > > > 2.25.1.696.g5e7596f4ac-goog
> > > >
> > > >
> >
> > --
> > Best,
> > Patricia
> >



--
Best,
Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvU%2B1z-oAX81bNSVkuo_BwgxyykTwW9uJOLL6a1ZaBojJYw%40mail.gmail.com.
