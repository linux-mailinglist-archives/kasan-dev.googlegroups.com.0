Return-Path: <kasan-dev+bncBCMIZB7QWENRB3PLRP2AKGQEPLWJX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 42742198D5E
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 09:49:02 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id v10sf17213608qtk.7
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 00:49:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585640941; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbJIYX0UnI7NbjKPE67K2xtWo4ktb/OfWi0Sox2Lg1BGSQDa1UH3kkPGhWXiPnJxdj
         mAcWhy87K6Y9U1VJPkxKb9Bu4lDYarKIBWTjK/ZW/YDCIhOYAOc8z98NhEOXDF2cRTj1
         o6li4cjHMXroQ9TkyrEIL+H7AvLBGZr4s2HLDjwyaobeMxd477r7vcau6zR0DvnG+BqZ
         3zN1PxZUnLO1PWHoi6eUGYpzJazscn4rfjKejD3soR81rjK5A+C20vKqOvoNKvtKDfQV
         sVjydAwGcyfNZOoxi2lyOcBgtCM1c2CRDaP6X13LyInG4ZbpZBmP2sWjY+sC3oPjkKHL
         ruoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uRKuiV0Z7MLzuFtPbR1Oj7iOwCnPHKtOmrVw1oQzHqw=;
        b=ZbsR/mVOu8Q8RCGVo0FPc+bbn/QLBgukxm5ancEZ0dNERiY/5Eri5A9/sAuZLiNhGT
         YhE4YEwIygTI09K55xT7nTGkPJeUYMiTe2OAurnDC2rvWm5ovTxqUAyYoxE9fi07cqSk
         7F5Y9Vzw8u3dVqWfmd8xEH0LWreLIU5pRFGJ7kv4ylQ27od3Z7NQl8Rd0Ka/V4rgfevj
         uGvIewMDir38HB0g5wFvqX+nlKjpK64LuOfFuoNQuCROloE3JHoqESIqHOfq5tHJRNpP
         /yOLdNwlh7W0j6hjF4uzrogn0TONxPcvEc9U9i1hQl+snkAoZjWZbBc1yN534FINc2iZ
         /BDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=li86dJqj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uRKuiV0Z7MLzuFtPbR1Oj7iOwCnPHKtOmrVw1oQzHqw=;
        b=Hq/pkyjoLm5nkiz7CUCQJlFSK5Sdspneh/0PDpai65LamLdADPAk2YtCn+bos5Zmid
         MByPXmGEJ5knkMga9Rke7hkMKStfTRBc+QBvHSruOWA6/7Z+kW1e/OZZy33CReADQ2zB
         ZoVbweTQM6ETzwsPKpJIsVgssE87ZZ3ZbQc/GljIc5wa9/mdD1B8EAynqy+WKj13Lptr
         dRg2mmlZ69iEQU+9Ap5C/Tj8KDT+mMbDBVDjy9cInRcdunIpgQtHX3fY2qSc0/pSsVO+
         5zudOFFiMiMlH4/4hGo9EwdqA+kj/BncTYk5huVBPLePyV69OlST7uxPmf1HFUKkoAPn
         YtUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uRKuiV0Z7MLzuFtPbR1Oj7iOwCnPHKtOmrVw1oQzHqw=;
        b=iPOtcLWg9SLIOBCNOVH9mr+OuMmjQMsrcVX4jwcr+qtcKMWO54ArYVfpFk+ChyxoEi
         qCXp8v+c3GbrUfwAAwqHdwCaEUN4HfAzCC3mgStJp5GAHVqz6jHtDcTS3eU0V4JNDrw1
         lLt8Q5fqrEy1+4YVXDHyYO9CrIlPVegsCms+cvbJoIr9oRAxGOyMgsbZNqoA6Tb3u6ff
         E66k6oj3tvHWRWwrbOtGbVmSVn71mFgkK2k7rfP6ChSckwaIHMgxuWcHfoRW9TRds2AY
         EBMVDC51lm9VIg7GKCJdI4PfgZWWHzZQwFL57uEOrvKJcpA5rAIyBI0yXtvirgKWPoJF
         H5bg==
X-Gm-Message-State: ANhLgQ2CkSQcAWfQdhHJRlIvYuvx2RM48I2YG3ynVnoqHWV0gaqqf3l9
	kWDfnw5fgpdvtAUgNzRy1QM=
X-Google-Smtp-Source: ADFU+vsUzwGaNpznLi+LUxFIJhbHPdcgHZHAS4wknH/LUJY3jnKb695KBjoFj8T7yqlHwLxxI2wQRg==
X-Received: by 2002:aed:25f4:: with SMTP id y49mr1181211qtc.50.1585640941300;
        Tue, 31 Mar 2020 00:49:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:dc83:: with SMTP id q125ls10054931qkf.9.gmail; Tue, 31
 Mar 2020 00:49:00 -0700 (PDT)
X-Received: by 2002:ae9:dd83:: with SMTP id r125mr3740970qkf.105.1585640940878;
        Tue, 31 Mar 2020 00:49:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585640940; cv=none;
        d=google.com; s=arc-20160816;
        b=0Thdogf1dGlldOVbx5ItgejUUjhEG4uOIudq2LSzAspETHKuRA88Cn7TjVUJ8dTO7e
         pf9bHlic9IRxuEXpK0pNdAMjKyeWtqaUzgGW/xw/EG9evsZXY6D7m2ipdTTMsIAQ9TVp
         5JEYBeH8GDxw/ZhnTnFWfeAPySnX6DbILmRU3UaJsEvc1bJZUllpszEFpNY0WxJY9YGi
         Oj+02dQGyUuqyMua5/mEhl+H+VUlSOC/3te7wuG29g1Mf5sckXJAL2PpUEwnN7cYtY4U
         3q6qWzaeB/wQ2VzW81xRhTw/loVPrgtATH5d4XYvLZllrnf3l9mHsiDKEhSRF666BgYU
         E+LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8aHUg6XrjD62/TPddIO5S5ykgm6UeR5UcXZG3bY/H0w=;
        b=EOhGjEKgm5L3T7Jhmx/enwTbvMIiVOhY5Y0NcVVYkkbiDkfWz5EpR8hS9yNknngHqu
         DGaZxSsvbeg5Dou9nuFZ7uOt3NDFE9IrpdnXBx1oTYFy7LVSdmBf6yMMbHEzyQ93Uw4N
         LQVCjqQt5OSVRF2yUxbNWYDu12eWnWhUASD9DoHZLoJgpEq9qG3Z42pXS3Blw2b9oSfW
         V2xsjpkuFCgqoOz64rMHKUPr2g1YnoZCnYW9j7p84gXIrBi/mvRtOlcuVQ2eIT25pgJx
         lzD/LTXNskL/dgfxK40i8E/1hjU8wd6bsK77Y2tKIRobkBnPVDlbjLipIjuesRsiPBnQ
         elpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=li86dJqj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id p11si1225442qkh.3.2020.03.31.00.49.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Mar 2020 00:49:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id c14so17575773qtp.0
        for <kasan-dev@googlegroups.com>; Tue, 31 Mar 2020 00:49:00 -0700 (PDT)
X-Received: by 2002:aed:2591:: with SMTP id x17mr3856732qtc.380.1585640940271;
 Tue, 31 Mar 2020 00:49:00 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-2-trishalfonso@google.com> <alpine.LRH.2.21.2003241635230.30637@localhost>
 <CAKFsvULUx3qi_kMGJx69ndzCgq=m2xf4XWrYRYBCViud0P7qqA@mail.gmail.com>
 <alpine.LRH.2.21.2003251242200.9650@localhost> <CAKFsvU+1z-oAX81bNSVkuo_BwgxyykTwW9uJOLL6a1ZaBojJYw@mail.gmail.com>
 <CAKFsvUKAThbewNmtA7S4wzXODADwG5XJgiDu9o2o5+xz5ux5fA@mail.gmail.com>
In-Reply-To: <CAKFsvUKAThbewNmtA7S4wzXODADwG5XJgiDu9o2o5+xz5ux5fA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Mar 2020 09:48:48 +0200
Message-ID: <CACT4Y+YtpOUHBrdd5n2ajueMreh4Bz8uvR9NXU50=mNQD9-OEw@mail.gmail.com>
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Alan Maguire <alan.maguire@oracle.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=li86dJqj;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Mon, Mar 30, 2020 at 9:30 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> On Wed, Mar 25, 2020 at 12:00 PM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> >
> > On Wed, Mar 25, 2020 at 5:42 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > >
> > >
> > > On Tue, 24 Mar 2020, Patricia Alfonso wrote:
> > >
> > > > On Tue, Mar 24, 2020 at 9:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > > > >
> > > > >
> > > > > On Thu, 19 Mar 2020, Patricia Alfonso wrote:
> > > > >
> > > > > > In order to integrate debugging tools like KASAN into the KUnit
> > > > > > framework, add KUnit struct to the current task to keep track of the
> > > > > > current KUnit test.
> > > > > >
> > > > > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > > > > ---
> > > > > >  include/linux/sched.h | 4 ++++
> > > > > >  1 file changed, 4 insertions(+)
> > > > > >
> > > > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > > > index 04278493bf15..1fbfa0634776 100644
> > > > > > --- a/include/linux/sched.h
> > > > > > +++ b/include/linux/sched.h
> > > > > > @@ -1180,6 +1180,10 @@ struct task_struct {
> > > > > >       unsigned int                    kasan_depth;
> > > > > >  #endif
> > > > > >
> > > > > > +#if IS_BUILTIN(CONFIG_KUNIT)
> > > > >
> > > > > This patch set looks great! You might have noticed I
> > > > > refreshed the kunit resources stuff to incorporate
> > > > > feedback from Brendan, but I don't think any API changes
> > > > > were made that should have consequences for your code
> > > > > (I'm building with your patches on top to make sure).
> > > > > I'd suggest promoting from RFC to v3 on the next round
> > > > > unless anyone objects.
> > > > >
> > > > > As Dmitry suggested, the above could likely be changed to be
> > > > > "#ifdef CONFIG_KUNIT" as kunit can be built as a
> > > > > module also. More on this in patch 2..
> > > > >
> > > > I suppose this could be changed so that this can be used in possible
> > > > future scenarios, but for now, since built-in things can't rely on
> > > > modules, the KASAN integration relies on KUnit being built-in.
> > > >
> > >
> > > I think we can get around that. I've tried tweaking the resources
> > > patchset such that the functions you need in KASAN (which
> > > is builtin) are declared as "static inline" in include/kunit/test.h;
> > > doing this allows us to build kunit and test_kasan as a
> > > module while supporting the builtin functionality required to
> > > retrieve and use kunit resources within KASAN itself.
> > >
> > Okay, great!
> >
> > > The impact of this amounts to a few functions, but it would
> > > require a rebase of your changes. I'll send out a  v3 of the
> > > resources patches shortly; I just want to do some additional
> > > testing on them. I can also send you the modified versions of
> > > your patches that I used to test with.
> > >
> > That sounds good.
> >
> > > With these changes I can run the tests on baremetal
> > > x86_64 by modprobe'ing test_kasan. However I see a few failures:
> > >
> > > [   87.577012]  # kasan_memchr: EXPECTATION FAILED at lib/test_kasan.c:509
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.577104]  not ok 30 - kasan_memchr
> > > [   87.603823]  # kasan_memcmp: EXPECTATION FAILED at lib/test_kasan.c:523
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.603929]  not ok 31 - kasan_memcmp
> > > [   87.630644]  # kasan_strings: EXPECTATION FAILED at
> > > lib/test_kasan.c:544
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.630910]  # kasan_strings: EXPECTATION FAILED at
> > > lib/test_kasan.c:546
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.654037]  # kasan_strings: EXPECTATION FAILED at
> > > lib/test_kasan.c:548
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.677179]  # kasan_strings: EXPECTATION FAILED at
> > > lib/test_kasan.c:550
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.700242]  # kasan_strings: EXPECTATION FAILED at
> > > lib/test_kasan.c:552
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.723336]  # kasan_strings: EXPECTATION FAILED at
> > > lib/test_kasan.c:554
> > >         Expected kasan_data->report_expected == kasan_data->report_found,
> > > but
> > >                 kasan_data->report_expected == 1
> > >                 kasan_data->report_found == 0
> > > [   87.746304]  not ok 32 - kasan_strings
> > >
> > > The above three tests consistently fail while everything
> > > else passes, and happen irrespective of whether kunit
> > > is built as a module or built-in.  Let me know if you
> > > need any more info to debug (I built the kernel with
> > > CONFIG_SLUB=y if that matters).
> > >
> > Unfortunately, I have not been able to replicate this issue and I
> > don't have a clue why these specific tests would fail with a different
> > configuration. I've tried running these tests on UML with KUnit
> > built-in with SLUB=y and SLAB=y, and I've done the same in x86_64. Let
> > me know if there's anything else that could help me debug this myself.
> >
> Alan sent me the .config and I was able to replicate the test failures
> found above. I traced the problem config to CONFIG_AMD_MEM_ENCRYPT=y.
> The interesting part is that I ran the original test module with this
> config enabled and the same tests failed there too. I wonder if this
> is an expected failure or something in the test that is causing this
> problem?

This is:
https://bugzilla.kernel.org/show_bug.cgi?id=206337

I think we should add:

// See https://bugzilla.kernel.org/show_bug.cgi?id=206337
if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT))
    return;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYtpOUHBrdd5n2ajueMreh4Bz8uvR9NXU50%3DmNQD9-OEw%40mail.gmail.com.
