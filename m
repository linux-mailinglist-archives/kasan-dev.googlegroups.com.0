Return-Path: <kasan-dev+bncBDK3TPOVRULBBLGD5DZQKGQEZ5IQISI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 944471913D4
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 16:05:16 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id b7sf15133185edz.9
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 08:05:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585062316; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0KkSvWPaWr6rzM+oSZdC9P+zZD66aSS9RPd4FMjoxz8GY2JkrKnZPpW7H0lVfuZkT
         ncEWkhpcMyGR2DHGKcL0pDuxVHxDvS7vae/+M8O8JE9JN2mo/EEkK4GO2UHMGsUmgQya
         siVvpJHqblashUoZlKCIWMqQkc1C9hf0rh4YILTQDzQUBSU7QIago6c1gx48LGWp8aRe
         ApUQEx+1JG1tzKDaDuusSTXTML43wHvlo5fdynG40z3UVEs2iACxXGtDllNaDg9atnKr
         hpGtbTMxhXtHMjQiW2+gIa7wthlR8frkgk8JQn04iWZOCYe6Rm44axXucOrEJZ6ibCpn
         tP/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zJDH4VzG5Jc1MMOUPxiwJYPQ0rdanV8qI/9JdT/iH0E=;
        b=GRgLZoxAZ4OHd0v8kvEez72fDk3A5x06jKh5ILpIivU4buMR7gJ+M+vB7Ksdl5yao8
         x43w03zhsrCmsWfVCI8m0ofqsg/HRuZV6imox8NUMZl5b9e4LWgZ8n4NTbPf+mljGpZa
         LvvkGIzvL/LDJBK2XONXZp31N9KdgTUAQE1MnJrYzWM2DwT6561coYPc6lR0ORrkYGP0
         WBilW4mb+LkvHmMy4cDjA/tskif/X3Ex4/kLPQ8pNpgQloptiXkS22lfVSwR45z0w1nx
         2WgwywSwRQM+qGbF0rYmh2AmIimfhnbnruEXRDCT+xlisglMf2gF9pvo2WuwwCM6AN8+
         DSKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=koZzPW8O;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJDH4VzG5Jc1MMOUPxiwJYPQ0rdanV8qI/9JdT/iH0E=;
        b=m01wnQvQ9cqNMDlAjmWnLPTBbs4UHQbsEbhBecA6zsm1rr+qFFsm3AZHwMAMbfatps
         Dtr+eolAw4pnJbHObZNoyen3oskF5GlttKjOMtA54KbbtYrkGnBJ4wbunN9SNi5C6Jsv
         baKE/OPJ+wGMEIjMlfHiQFFoKUKZQzYgXv4DDKiZDAPeF+YSsE05GQHUyA/BnsPdpNHG
         nHNb5bK7pilDKoaCm+yt85MqhRFMQ3BNsld5XwdGE4ss/jFZMS9AqWwXCburz4ZLapRt
         Oaetkm0IBTLa16uB1tOS/zsdPpYfrc2jqOEYpY0YfvPvLIxuYDqJd4m1eF6pLjtG2vBd
         l2gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJDH4VzG5Jc1MMOUPxiwJYPQ0rdanV8qI/9JdT/iH0E=;
        b=FpxCLMjLhb0nY0mq5/a37wC6Ktdcf3R055Q6zBdMBlIEl7uRmkik9JJ2Fs9RAVLVAB
         U7df9EU1rGKJRXeoSusA3aqlK0+0uE0I0uJSaVuxtdyiLbO1mRThQHKUMnhRcXlC1Rip
         8kkXZReZsvssEGCupQgqpCIu7P6TbSkfnIDrNtu0Zy2Rw+0y/Sabr13Qtv3T+iVfh4pK
         N4O9dUmesUnoSjLrfHf8JOgxBQ3CtL7iv4LilnW10IO7Gcs4l77N1gLGC69it80wxitd
         E7nLcOlCqMyOiISof76GfqUvf3s3r1+d76lBe3fRuOa6qWEYfjgv4E2knFR+LyjkLPTo
         UiKw==
X-Gm-Message-State: ANhLgQ3Ec7aakjm4CVr78o5tNvBjvwDxO87S2JBzq/9vW83rXk0Gy3h9
	fTWD2RCNxJ7zzdYiXGjwDKI=
X-Google-Smtp-Source: ADFU+vsNmaQ5rdKRCd6gkSy0/nwfig/NFpIgBgU8PQF9yZvHtN0g6WFGDXMqOAoijxF3/mclVKcwBw==
X-Received: by 2002:a05:6402:cc:: with SMTP id i12mr26772209edu.270.1585062316236;
        Tue, 24 Mar 2020 08:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7da:: with SMTP id m26ls1257042ejc.8.gmail; Tue, 24
 Mar 2020 08:05:15 -0700 (PDT)
X-Received: by 2002:a17:906:fc01:: with SMTP id ov1mr24722182ejb.65.1585062315502;
        Tue, 24 Mar 2020 08:05:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585062315; cv=none;
        d=google.com; s=arc-20160816;
        b=WYSpY5v78geLgCMcStMxUz5VYohGti3VGC0S5lt63/x0tPk3YEt1IRAsOdGeb38ORE
         nIsXIWmjTXOcZ6fAzEWGjIjuR0nef+mYu/rW24lXy5R23uUJBcooeFqOeWtyFSNf/tHY
         dj7PeoVDbZrrTnfgtNCaJQbyLhtfz5Bb3Kzo1Uxq30AzW60v8B33fDwKeuJUaDRizEIR
         3V95L/O9qbSJo1JkN0VrgfMmFhxoOaP/2gSN4sioLsDAuvCMU/97OgtmECXpveeas2AH
         NPEPqi70toM6lqAnTHtnmNDJILk+Qf20HjQm55ne1DWB5A/NwiCf9qjYk9P+eQuYqCmp
         dX+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z37whwAEqv2UhQ238liZabu95DixugSK+aNM/HESChs=;
        b=N5LNLPCjDQ9s7MFG9d3UNh3/MdcooeI07BQsgpAn3iER0yYybEswlGOlnkEe8nR8hQ
         lCtGojZszuUavJ4j8VHx3LbutX2cbJh4mV4wOdoLAn5bzj6YnqxRxobRF7hv9TBjSr69
         kYnAEt2k0LURkSWQ6/mBetRt5wABS+Uamb2l3Xn4snOppos3nUhSHLAL2fTCWAo6PBu5
         OBtHkC33V3UiwKF23D593l/Zz+Qxj6IuqcYFs90Zgm327nzLu+TAbDwKioS53khzLLxX
         Ff3zzhXHJHfbgdTEyIdPMhHQOUKqn8hh4bI67/SOR3FnSGF8PUYho7wos0dczuU5OFWd
         RwRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=koZzPW8O;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id be1si114502edb.3.2020.03.24.08.05.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 08:05:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id w10so21912020wrm.4
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 08:05:15 -0700 (PDT)
X-Received: by 2002:adf:efc9:: with SMTP id i9mr16611416wrp.23.1585062314941;
 Tue, 24 Mar 2020 08:05:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
In-Reply-To: <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 08:05:03 -0700
Message-ID: <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com>
Subject: Re: [RFC PATCH v2 3/3] KASAN: Port KASAN Tests to KUnit
To: Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=koZzPW8O;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444
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

On Tue, Mar 24, 2020 at 4:25 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Mar 19, 2020 at 5:42 PM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Transfer all previous tests for KASAN to KUnit so they can be run
> > more easily. Using kunit_tool, developers can run these tests with their
> > other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> > report instead of needing to parse each KASAN report to test KASAN
> > functionalities. All KASAN reports are still printed to dmesg.
> >
> > Stack tests do not work in UML so those tests are protected inside an
> > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> > instrumentation is enabled.
> >
> > copy_user_test cannot be run in KUnit so there is a separate test file
> > for those tests, which can be run as before as a module.
>
> Hi Patricia,
>
> FWIW I've got some conflicts applying this patch on latest linux-next
> next-20200324. There are some changes to the tests in mm tree I think.
>
> Which tree will this go through? I would be nice to resolve these
> conflicts somehow, but I am not sure how. Maybe the kasan tests
> changes are merged upstream next windows, and then rebase this?
>
> Also, how can I apply this for testing? I assume this is based on some
> kunit branch? which one?
>
Hmm... okay, that sounds like a problem. I will have to look into the
conflicts. I'm not sure which tree this will go through upstream; I
expect someone will tell me which is best when the time comes. This is
based on the kunit branch in the kunit documentation here:
https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/log/?h=kunit

> Why the copy_from_user tests can't be converted?
> It would be very nice to get rid of the modules entirely, rather than
> having 2 different test procedures because of 2 tests.
> Or, alternatively can there be other tests in future that can't be
> converted? Naming it "KASAN_USER" looks somewhat overspecialized. Say
> tomorrow we have another test that can't run under Kunit, but is not
> related to copt_from_user, should we create yet another module for it?
> I think the crux of that is that's a module, so a better name may be
> "KASAN_TEST_MODULE". Currently all tests that need to run as module
> are related to copy_from_user, but that's just an implementation
> detail.
>
When I converted the copy_user_tests into KUnit, I was getting a
kernel panic with a "Segfault with no mm." According to Brendan, since
KUnit starts a new kthread and is not invoked via a syscall, things
like copy_to_user won't work in the KUnit framework.

I agree that the naming is too specific, but is KASAN_TEST_MODULE too
generic since the current KASAN_TEST can be built as a module? Maybe
TEST_KASAN can be KUNIT_TEST_KASAN and TEST_KASAN_USER can be
TEST_KASAN_MODULE...

-- 
Best,
Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvU%2BN%3D8%3DVmKVdNdf6os26z%2BvVD%3DvR%3DTL5GJtLQhR9FxOJUQ%40mail.gmail.com.
