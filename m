Return-Path: <kasan-dev+bncBCA2BG6MWAHBBDMV63ZAKGQEDSQHJDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BACB176781
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 23:37:02 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id fc5sf838267qvb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 14:37:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583188621; cv=pass;
        d=google.com; s=arc-20160816;
        b=cf2dKmm8t7Q6NH2VpMdTomWWcqo75hArqI39cbzkW5xMM/yvMHIPIAjilOMZgxDoae
         2X4iC5R8Qr9rg2YfsgrUCZ/AyRuc2aYvOBubhMjTbNT0MhAtLl/MUOgSnUYTOoe72YDu
         9pkN1PK7HJ7ONDelNCxFNzq2Ws3ADtdQzd8m7QZgwGgCRBW842Kvji+7eJ1f8E11YyK6
         2BmSZIEsK20VKfPiHm3+cnMXPU1FmWdljdpfEkBJwFGNu7jYSq4w6IsYGpRpPOgbN9qx
         BVeN41bZpT9IZEdq0E9S++B+x9oCI8eiXxUHxRZ9vvMfvqfarhP0nzNEYWamVRdLgLvp
         q6rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uRfV7l6LeH17s8NgpdFeT1jwHwsvoVoMYBADLmVrkGA=;
        b=sxq5FGuBMk04gfeMv67m78rSOJPUsnfAFUaptkONf5aqHGPx3SccKAEyKaHeZ8vXuh
         nX989YBmSMLSXkUFoXDPG1skqlVQ8TkILuagrx4naWSPJ4tzrQP4e3nkbBVtf00nmyju
         RgfpoVvgbdskFZghvp0huwbhonDlhCXjmSpwubYcYfIYpeewchlSlCdwbDn5vuvoUZSE
         ZsWEzokqQ0/NVsOuL22KcCSt5c9yMK2LJCxWp9j41C5ci8UKI4+CzqlpPL6llDhto2Lq
         XPWEyo6JJ2kKKt1EjU1lqQOOB3xko/MOzPfZZBwMSV/ECuU0OcuKG3gJZk2QHx2tBjHg
         WOHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gzCkLslX;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uRfV7l6LeH17s8NgpdFeT1jwHwsvoVoMYBADLmVrkGA=;
        b=b5fk17Z+JYvB8xnjwIIJKOrbhL50GVB4GJ5M5t2NH4qOLU2cuXa1eWhI/xQR2siyjY
         inAUIrXGlSHvt3ROUWJ7WsRvxsW9CGNrcd7kIdqfQe81GaUlpATNT2Ye9tpYiIky6/7B
         L8EjnE+BdtzKKyS0ZrsdLI5+xdea8ADRNUEbsIHVj610z8xPWEug5be6DDB2SZtbQ2BK
         D6IpAUnISwBIiYRy5O8oMfATIAkjsP1YXbYIEr1kvDdTWREF9B3g+tb+mAqbEdQZP4jr
         qmscrdtlY4+tiNB2MLAGvYge3f/OaKEwMJn2LHEfMBWerbXG+nt/TcHVm4oIwRxEz3+K
         OXtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uRfV7l6LeH17s8NgpdFeT1jwHwsvoVoMYBADLmVrkGA=;
        b=AwlWBvyGeTSDUT09qV6duEGnqlTj9QklbqAlh+4IfExgvM5kf4WDQqZbLeFDcSHvDz
         p5ReppCtxrLu3tfrj8TL1lWXoDpnZ97wFTKMeVAgkJOM5hBbEVET0mJMx9udpxdAG1wv
         d/LW7vPdYClfyZuDjltvn+bVuFZVB+L8EzKx+OVbZWhcqy9tEwJfeFwThb23ZKdGrQze
         Wxla1dlaJ9/hAMCK7/EqYuQhDwPRlT2f6Wrhco5NTBQZ/qgpfcpuZTD8rblCpVsgeWzW
         UyveAeKUfHM1Hgp4osirYXJMRTrZzi3aLSZIYVltFFm3rQbyAUCSBQi0L7qNNE/uiqDt
         nVDA==
X-Gm-Message-State: ANhLgQ2QHresanGn/6vB/PxMGWPmXEnPHm4d4pIloExr+ZOyQrgC9WEs
	Vwi0DpF2HoF47we6tHvrHr8=
X-Google-Smtp-Source: ADFU+vu3UANVafZ4K+yZDd222Rvcbm4aFkOJCjqz8JFQiIqka0qx8sXvzGvKGcOjcJVfrg5QL1rWkQ==
X-Received: by 2002:a37:387:: with SMTP id 129mr1445320qkd.293.1583188621414;
        Mon, 02 Mar 2020 14:37:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:514c:: with SMTP id g12ls286371qvq.7.gmail; Mon, 02 Mar
 2020 14:37:01 -0800 (PST)
X-Received: by 2002:a0c:e58e:: with SMTP id t14mr1493971qvm.131.1583188621029;
        Mon, 02 Mar 2020 14:37:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583188621; cv=none;
        d=google.com; s=arc-20160816;
        b=dtiHzFOVSj8MPWXmQGQgn7XyYiRpJz1AJHLCqAIeoh2Qs41OdrS6b3TmJBWbb75U0L
         ZPwJMuImyb0GDpB3k24WKCmUMmaqX8vbshvHu9Ri8N58pWREdKIs7iCBBUag4PMNvlnN
         MN4qq0jp+UjBwORwBHPLPA951qU5z6TkWrZVFWV+6SKYaGcxeTTOMAXcRQtCYySEqMqi
         IrJhD2JC7uBMMWwuECDBIIP4sHesVsqFPA9AjDZxbO9W2VVwwfs/x90Yk2pIrlDxB2qO
         tTGZKUHJGBUNPXGnPDdjEtPUay+WfVkbxfULFd0+ppoYgav85FZ31246dVlKm9K3fo4j
         70dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w4Md8j8zd2YWszLJ5ilbEdqON4mnmjdfj7ZdSWk0uFA=;
        b=fs7U7q+SET0LwLlP4snmN77disy3i1DkBfv3qcvXlDw8uoCth0xa71MjFEOgEPIjcE
         +q8EnNB4bp9BkXyYJjJsy65Ku5OQyVO2uAbwXyQs0jKKPfxipfudHel0SOIwJSY5Ld7P
         XZq9VtLZ2Ih8/UN271PvOWCLTdlxYRQxmSTu7HEf/LBqCIiObZYYUwRLFe5Cqfk8fZ5S
         edzfWEg8jvxwokPuJ0Z6URPXdY3YDbPmDs2V6IGphUEjTR6Tdnmqja7pn+TzutwoJ1Dn
         Y6vIb9Wa6qVsX/5wAhLiX4XFMwQADx9gy67G401PhicODMeb7Zf+dI/9ZSkqg+CK+pV9
         cGbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gzCkLslX;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id s202si520536qke.3.2020.03.02.14.37.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 14:37:01 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id y1so378085plp.7
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 14:37:00 -0800 (PST)
X-Received: by 2002:a17:90a:3a90:: with SMTP id b16mr184340pjc.29.1583188619857;
 Mon, 02 Mar 2020 14:36:59 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <CACT4Y+Z_fGz2zVpco4kuGOVeCK=jv4zH0q9Uj5Hv5TAFxY3yRg@mail.gmail.com>
 <CAKFsvULZqJT3-NxYLsCaHpxemBCdyZN7nFTuQM40096UGqVzgQ@mail.gmail.com>
 <CACT4Y+YTNZRfKLH1=FibrtGj34MY=naDJY6GWVnpMvgShSLFhg@mail.gmail.com> <CAGXu5jKbpbH4sm4sv-74iHa+VzWuvF5v3ci7R-KVt+StRpMESg@mail.gmail.com>
In-Reply-To: <CAGXu5jKbpbH4sm4sv-74iHa+VzWuvF5v3ci7R-KVt+StRpMESg@mail.gmail.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Mar 2020 14:36:48 -0800
Message-ID: <CAFd5g47OHZ-6Fao+JOMES+aPd2vyWXSS0zKCkSwL6XczN4R7aQ@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
To: Kees Cook <keescook@chromium.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Patricia Alfonso <trishalfonso@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gzCkLslX;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Mon, Mar 2, 2020 at 9:52 AM Kees Cook <keescook@chromium.org> wrote:
>
> On Sat, Feb 29, 2020 at 10:39 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Sat, Feb 29, 2020 at 2:56 AM Patricia Alfonso
> > <trishalfonso@google.com> wrote:
> > > On Thu, Feb 27, 2020 at 6:19 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > .On Thu, Feb 27, 2020 at 3:44 AM Patricia Alfonso
> > > > > -       pr_info("out-of-bounds in copy_from_user()\n");
> > > > > -       unused = copy_from_user(kmem, usermem, size + 1);
> > > >
> > > > Why is all of this removed?
> > > > Most of these tests are hard earned and test some special corner cases.
> > > >
> > > I just moved it inside IS_MODULE(CONFIG_TEST_KASAN) instead because I
> > > don't think there is a way to rewrite this without it being a module.
> >
> > You mean these are unconditionally crashing the machine? If yes,
> > please add a comment about this.
> >
> > Theoretically we could have a notion of "death tests" similar to gunit:
> > https://stackoverflow.com/questions/3698718/what-are-google-test-death-tests
> > KUnit test runner wrapper would need to spawn a separete process per
> > each such test. Under non-KUnit test runner these should probably be
> > disabled by default and only run if specifically requested (a-la
> > --gunit_filter/--gunit_also_run_disabled_tests).
> > Could also be used to test other things that unconditionally panic,
> > e.g. +Kees may be happy for unit tests for some of the
> > hardening/fortification features.
> > I am not asking to bundle this with this change of course.
>
> A bunch of LKDTM tests can kill the system too. I collected the list
> when building the selftest script for LKDTM:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/lkdtm/tests.txt
>
> I'm all for unittests (I have earlier kind-of-unit-tests in
> lib/test_user_copy.c lib/test_overflow.c etc), but most of LKDTM is

<Minor tangent (sorry)>

I took a brief look at lib/test_user_copy.c, it looks like it doesn't
use TAP formatted output. How do you feel about someone converting
them over to use KUnit? If nothing else, it would be good getting all
the unit-ish tests to output in the same format.

I proposed converting over some of the runtime tests over to KUnit as
a LKMP project (Linux Kernel Mentorship Program) here:

https://wiki.linuxfoundation.org/lkmp/lkmp_project_list#convert_runtime_tests_to_kunit_tests

I am curious what you think about this.

</Minor tangent>

> designed to be full system-behavior testing ("does the system correct
> BUG the current thread, when some deeper system state is violated?")

Makes sense.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g47OHZ-6Fao%2BJOMES%2BaPd2vyWXSS0zKCkSwL6XczN4R7aQ%40mail.gmail.com.
