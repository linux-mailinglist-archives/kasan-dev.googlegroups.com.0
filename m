Return-Path: <kasan-dev+bncBDK3TPOVRULBBT4RRH2AKGQEQWQMOWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C030E198477
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 21:30:23 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id s6sf8000613lfp.15
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 12:30:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585596623; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZTo/aBWDhb8fkRsyh4Y2ieSpRXM0DGtQ7+UR3RBXooM/WPY1Rt1WZWTZx5zX+bku0H
         OjVqFlNIWjqTB5y7V3VEnPrEeZx+jmnfoe/fLzl4r3kgKKkctEnadXbJaZ2IkaEr9jWy
         Zn//HI2pGI95w03suDVDSDorvB7kaju8XxYB0JwtpOwccElkpCSUAUt2g5s5nrLx0uFN
         oULg+0DL6wTH+KM6FD0SnPMzQDQq/AjEt111iWSbQC6hXWoyRDYDavTBGSnoEi/lslMT
         RFeJO5sd++DdWCcoyT6iTnj7gr+d94gJFC8ItXYUuypE554m3iw0j+5kXXqhbg/vDQAy
         ZbvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O9BEysugJVjp6Q+/rttO45XpOgKViiwh11Lrj4Ea5hw=;
        b=YHWbIkPU160mU5QUG0vJmGXIXMbPFhaRi691dKiUjE/sVqgjPSzsfc0GXnuHaMRO4V
         TMHwyACe48RFJQyidigHElE/5ZPv7sMk3D/9f5g5TL9plAVZQOCeLtFQ1ZXaY7V9bZ01
         cgXYjMYlYBI+ptvEjSCvMGLqhKaRiPIXDdVEmdKI9bi6bdTxPez8LAs2/uisqyTOx56J
         HI2wL0x/aZxkh7/oVneDQBcPl9uBLn+jxSNizfRvUWtziSMgoPx6u5SGXBIu7XmVAlO9
         hb2GTpKzTeTUDOkMhaaD/pHDpL8hCs5wFbrFLVWSF60YZuufynrtKx9we6kjWDOwrd9M
         Bqug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iBPtY4oe;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O9BEysugJVjp6Q+/rttO45XpOgKViiwh11Lrj4Ea5hw=;
        b=sWgcTEUdpDV3YjOxb5ZxlZCku2iSapYyXX8WGpz31rgq1zz5HAhSl9z8wqmc7cpqoE
         C1sMghECbdFNLqoKgrsqnGx8EYwobf2HDFpQQfK5+LNjU4/Aldey3ucS/oLghW7o3tZW
         yj3cWKCvN0eUyu/rRL/NRvdy+Sn1PeTjapf86SIH6I4N2wkW8QAbJcyyHYyJZZgKNfSk
         ZlSLTVuIcKw13nNldA00K+fpGxH9/3xGvP7HxVLJpF7jWMp9Geum0C+BFAvYbRWviI6D
         qXn7ABnGXacv0K+AMMZcfqVHmOIgBz1mvvNBmLqqHQdaHDWThbp0P7VI2ZMzwBf0KH+K
         Lgaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O9BEysugJVjp6Q+/rttO45XpOgKViiwh11Lrj4Ea5hw=;
        b=STZ/ePPzDLl/WdQwoXpEl/FsPneZGzW0EBt1aDnQypvTgQBCmRu4m/rkwRP5Rqnc0P
         5gJPhS6gZaAnGrKezZRFehdCpMxSFkWaCJjo7+bFgVAVmk+hzmbo4RcrpKRXb996qOzE
         P5PHJJw64fHt8Qn9oN7aknwg2nGI45ChINe7IewgLYIcTY760ex7vOA1BSAA+LhRVNXt
         kUim+6Bs4XFVgvM7LcgXL042ye64aQOMEAGG0SjjjEoGvAK8z6O7WWK4zel87HRw2ZLi
         WkXghlOBJ2PKLUeKw2cz2Wj5xeCfzJ2xe8AJi/5L66Is2zcOmD1gRGUWF6SHVZJGturL
         pNEg==
X-Gm-Message-State: AGi0Puas3bBH6Zv+hE7S5J8egQmnSWgVVm4UrxahBAHZ+PlH1KU2EmkD
	T1q+xGxlBVU+Xen084VPYXA=
X-Google-Smtp-Source: APiQypKR339vY4JTLumF77f07umRoY/y0W5VKAEZ9r/hKX7buPLeM/NXLC+OZqKF54eEVJUj06Pq8w==
X-Received: by 2002:ac2:5622:: with SMTP id b2mr9288097lff.128.1585596623133;
        Mon, 30 Mar 2020 12:30:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:549a:: with SMTP id t26ls2238385lfk.9.gmail; Mon, 30 Mar
 2020 12:30:22 -0700 (PDT)
X-Received: by 2002:a19:4f0c:: with SMTP id d12mr9025816lfb.117.1585596622000;
        Mon, 30 Mar 2020 12:30:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585596621; cv=none;
        d=google.com; s=arc-20160816;
        b=TTSq7oMxSGtmQjtpkr5UZYsYmbjjXw0DVhvMIJp2WrMp44C2khh5eaYiFyk/ULmzFn
         Wy67DJZV10F9GI5hI6KvuEbLZ+kz1dKrcAlF+ndnHIb+SpMQpOCetLZ1UrpCq+MC5po/
         ZtIJLQ4FBYdZ02y+gNVaBfBWsHk922mVfszcJhLiT8FuzVwefWlhSIU6/VDpOx+uKH7C
         sPtqhifxdo1WNcyZMqyKZepG4dgRqR5Qhnl8Pay6HXhnZGGA2sck5qm1CVw4hUe9Nh1l
         QykQYOT1xg2s/9YtINc/+grmnKhKYa7SjVMz6B9EbxojEMqx5HVds265blDb68m7uqFz
         +c0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9nFnsvCKEDa/dsrzABSlGZiV3kPYg9feDGQT4TvurVU=;
        b=RPgSa4SAUEcLI7TiPqOIyZSzMxF8g37xZgK4QWvItEaRkZTc0TDFhrq8NwchHdsc8V
         9qYX6OcUsovb/zJ06h5aaCz7IoEImkaBTD+mmRGV3dbt54F+9ze4ZoKcaBZN9zmogARb
         aUEEVc2VCTzjrdSYMChZkGKRET31aZ5eC64f8rNfpua1IxR543PaNnmVrwA5DyeGJfQx
         p57I3uStQIh8A+ZbBjdl5W4FfCMDj34E35TSHC4GailCkrMz/xMCt4IEWxT6pqWZSokY
         8UQDl/UqMXn8fj4pvGbtvyXkDyEGEuzq+jTc/A3Xh5EmWS+ON63kEl9oBsv6oZBr/A/v
         Y7Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iBPtY4oe;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id s22si640016ljp.0.2020.03.30.12.30.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Mar 2020 12:30:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id c187so98084wme.1
        for <kasan-dev@googlegroups.com>; Mon, 30 Mar 2020 12:30:21 -0700 (PDT)
X-Received: by 2002:a1c:62c5:: with SMTP id w188mr865008wmb.112.1585596621197;
 Mon, 30 Mar 2020 12:30:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-2-trishalfonso@google.com> <alpine.LRH.2.21.2003241635230.30637@localhost>
 <CAKFsvULUx3qi_kMGJx69ndzCgq=m2xf4XWrYRYBCViud0P7qqA@mail.gmail.com>
 <alpine.LRH.2.21.2003251242200.9650@localhost> <CAKFsvU+1z-oAX81bNSVkuo_BwgxyykTwW9uJOLL6a1ZaBojJYw@mail.gmail.com>
In-Reply-To: <CAKFsvU+1z-oAX81bNSVkuo_BwgxyykTwW9uJOLL6a1ZaBojJYw@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Mar 2020 12:30:09 -0700
Message-ID: <CAKFsvUKAThbewNmtA7S4wzXODADwG5XJgiDu9o2o5+xz5ux5fA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=iBPtY4oe;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342
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

On Wed, Mar 25, 2020 at 12:00 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> On Wed, Mar 25, 2020 at 5:42 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> >
> >
> > On Tue, 24 Mar 2020, Patricia Alfonso wrote:
> >
> > > On Tue, Mar 24, 2020 at 9:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > > >
> > > >
> > > > On Thu, 19 Mar 2020, Patricia Alfonso wrote:
> > > >
> > > > > In order to integrate debugging tools like KASAN into the KUnit
> > > > > framework, add KUnit struct to the current task to keep track of the
> > > > > current KUnit test.
> > > > >
> > > > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > > > ---
> > > > >  include/linux/sched.h | 4 ++++
> > > > >  1 file changed, 4 insertions(+)
> > > > >
> > > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > > index 04278493bf15..1fbfa0634776 100644
> > > > > --- a/include/linux/sched.h
> > > > > +++ b/include/linux/sched.h
> > > > > @@ -1180,6 +1180,10 @@ struct task_struct {
> > > > >       unsigned int                    kasan_depth;
> > > > >  #endif
> > > > >
> > > > > +#if IS_BUILTIN(CONFIG_KUNIT)
> > > >
> > > > This patch set looks great! You might have noticed I
> > > > refreshed the kunit resources stuff to incorporate
> > > > feedback from Brendan, but I don't think any API changes
> > > > were made that should have consequences for your code
> > > > (I'm building with your patches on top to make sure).
> > > > I'd suggest promoting from RFC to v3 on the next round
> > > > unless anyone objects.
> > > >
> > > > As Dmitry suggested, the above could likely be changed to be
> > > > "#ifdef CONFIG_KUNIT" as kunit can be built as a
> > > > module also. More on this in patch 2..
> > > >
> > > I suppose this could be changed so that this can be used in possible
> > > future scenarios, but for now, since built-in things can't rely on
> > > modules, the KASAN integration relies on KUnit being built-in.
> > >
> >
> > I think we can get around that. I've tried tweaking the resources
> > patchset such that the functions you need in KASAN (which
> > is builtin) are declared as "static inline" in include/kunit/test.h;
> > doing this allows us to build kunit and test_kasan as a
> > module while supporting the builtin functionality required to
> > retrieve and use kunit resources within KASAN itself.
> >
> Okay, great!
>
> > The impact of this amounts to a few functions, but it would
> > require a rebase of your changes. I'll send out a  v3 of the
> > resources patches shortly; I just want to do some additional
> > testing on them. I can also send you the modified versions of
> > your patches that I used to test with.
> >
> That sounds good.
>
> > With these changes I can run the tests on baremetal
> > x86_64 by modprobe'ing test_kasan. However I see a few failures:
> >
> > [   87.577012]  # kasan_memchr: EXPECTATION FAILED at lib/test_kasan.c:509
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.577104]  not ok 30 - kasan_memchr
> > [   87.603823]  # kasan_memcmp: EXPECTATION FAILED at lib/test_kasan.c:523
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.603929]  not ok 31 - kasan_memcmp
> > [   87.630644]  # kasan_strings: EXPECTATION FAILED at
> > lib/test_kasan.c:544
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.630910]  # kasan_strings: EXPECTATION FAILED at
> > lib/test_kasan.c:546
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.654037]  # kasan_strings: EXPECTATION FAILED at
> > lib/test_kasan.c:548
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.677179]  # kasan_strings: EXPECTATION FAILED at
> > lib/test_kasan.c:550
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.700242]  # kasan_strings: EXPECTATION FAILED at
> > lib/test_kasan.c:552
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.723336]  # kasan_strings: EXPECTATION FAILED at
> > lib/test_kasan.c:554
> >         Expected kasan_data->report_expected == kasan_data->report_found,
> > but
> >                 kasan_data->report_expected == 1
> >                 kasan_data->report_found == 0
> > [   87.746304]  not ok 32 - kasan_strings
> >
> > The above three tests consistently fail while everything
> > else passes, and happen irrespective of whether kunit
> > is built as a module or built-in.  Let me know if you
> > need any more info to debug (I built the kernel with
> > CONFIG_SLUB=y if that matters).
> >
> Unfortunately, I have not been able to replicate this issue and I
> don't have a clue why these specific tests would fail with a different
> configuration. I've tried running these tests on UML with KUnit
> built-in with SLUB=y and SLAB=y, and I've done the same in x86_64. Let
> me know if there's anything else that could help me debug this myself.
>
Alan sent me the .config and I was able to replicate the test failures
found above. I traced the problem config to CONFIG_AMD_MEM_ENCRYPT=y.
The interesting part is that I ran the original test module with this
config enabled and the same tests failed there too. I wonder if this
is an expected failure or something in the test that is causing this
problem?

>
> > Thanks!
> >
> > Alan
> >
> >
> > > > > +     struct kunit                    *kunit_test;
> > > > > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > > > > +
> > > > >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > > > >       /* Index of current stored address in ret_stack: */
> > > > >       int                             curr_ret_stack;
> > > > > --
> > > > > 2.25.1.696.g5e7596f4ac-goog
> > > > >
> > > > >
> > >
> > > --
> > > Best,
> > > Patricia
> > >
>
>
>
> --
> Best,
> Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKAThbewNmtA7S4wzXODADwG5XJgiDu9o2o5%2Bxz5ux5fA%40mail.gmail.com.
