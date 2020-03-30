Return-Path: <kasan-dev+bncBDK3TPOVRULBBMMCRH2AKGQERNXPCZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A33231983CD
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 20:57:54 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id l17sf11811940wro.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 11:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585594674; cv=pass;
        d=google.com; s=arc-20160816;
        b=fMDklg+Jn44dTYkLnPmn1NfcedbUeprnLguD8gKHpEadOp/MUZv74QuBZOIUiFfj4o
         DLv81ChQ25NV6difM4eFdTOhEdWjEULhnxrzGWT3eYfQPV9P/mJQWfo+8DV/mi/eGHjl
         oXcHDtDetrAxX6Te0wmOuPjJs4Ts41LOA05e0BMVaIi18Z6fi3vRFnVcdfI4OFt9Gq3t
         1A00Xhe8uVVozkAD1XrvRIlpC3hRuhFrnR4qGa56Hygu/m7Qd9QyTr0XY77OWo46QewX
         Jgl/V5ZotGibihWPMlFy4yqtCBdwcYg+vAnlBllsCSs1e8UlGbB+Kq7+eoLCPqSJAgGg
         XQAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XjpiFe0ZML1ILMXKrThCUbWPpuE307Wr/UaSRV3gWnY=;
        b=fEqaqNTyGGtkTsvPRWIgLUSApQq6z8MwQWsNAaa461/QNI/+SBRLTBBdEh+Hjbneft
         Ryhmraa/SF5dDU+rx9YlbMrNL8Q1XA4r+OlhYLU7dpUQiBV9EAd8HancMO/ocRdncvOe
         wpJS0xvsrB1ACFv8FD1a9VWZYAbBe8ED2KbkE3+z1EHzl4TdyRqRps/rTAmo4BmVCL8d
         3wWKlcHWlKM3ZZpFGZH+ysrj9m+1+rCRrH6tNfHNBHm4w8QQPoRfrD7+q8Q6I53JL+2z
         f6YfLhTxcq3E9dpozTSlz7z7PBVPtCRJve3/tnqh5eCCgYIGvNqk+K9IA3YA9VuDZa/9
         RUSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kB2HLnpA;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XjpiFe0ZML1ILMXKrThCUbWPpuE307Wr/UaSRV3gWnY=;
        b=RiH1GgecuPll5Pm1NROM4cGtKHOoICtb72YJcMfH32oB2LTG1GghQxHbfT1yMb6yBJ
         34GOPi+e0c6aoombGXPIw+OMLaIc2Dn7rsN1qnOCRWH3hEyhODH4A+XBYYEvfQW7thRc
         P7vaAr4i5yTTni0JJsmkht/hRDuX7HW+dDVeepMOTfTGDkd5tPb23EZnbcwMVlRkaE9d
         DCNX+hMQvuAsl4V6kAdZp37+Tz3gjxfjnxRqf3cUfZrgR9IaDVLG23uYT1BXZDn6U3cq
         BeYvGcYEzvY9wwrR9SdsO6FsxdAWmkjQBtJZA/lC8lrHQ6BtHAYdjxj9Pl4zzA99tb2c
         5UzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XjpiFe0ZML1ILMXKrThCUbWPpuE307Wr/UaSRV3gWnY=;
        b=N2ocomFGA99hVG7hq+kd//mACWmabr+/uNvVMWoAlarK+zkTRxBDv+UmmwoO4T89mi
         O/0XVOI77j6UakyEORoZHOVrCVl3iPHYdxX1kVETY+zMfpPYiHrdgUumKHdlaX+CL+Wm
         OiY91A3Ks5u6dZNEENEz2grSwkjOZP9VGF73cgbaGIZ/7Ex3wzXjyaS3jlK6QS1WDzUl
         rIzafwPStJUDiBbBJC2W5PprPS9GhK8d56tnMLyUBwnXKJDjwTGYjsqfHFp9RkdlsztX
         wiOxes/nTOPp987nRgT33MNf7vOoji2ymUcbI14lrhngEYYgYOwUbe9SOV5oI0SyRZgr
         555Q==
X-Gm-Message-State: ANhLgQ1j2b6atfAa90N0Hc0ukdAPac7yWSg/CeAvEA1/t2EvOQM29Uqr
	COeuXfe/ax9gxA4ZtrPfzjA=
X-Google-Smtp-Source: ADFU+vvPWKgZwfXUhvyuTtJ0tet6uz03zWWRRWAhmPbUCB7QcyADSSEgpV6Bsb3ekK128HZuEK6xCQ==
X-Received: by 2002:a05:6000:1212:: with SMTP id e18mr17515577wrx.0.1585594673347;
        Mon, 30 Mar 2020 11:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:104d:: with SMTP id 13ls239379wmx.1.gmail; Mon, 30
 Mar 2020 11:57:52 -0700 (PDT)
X-Received: by 2002:a05:600c:2611:: with SMTP id h17mr682176wma.183.1585594672782;
        Mon, 30 Mar 2020 11:57:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585594672; cv=none;
        d=google.com; s=arc-20160816;
        b=iLNXHsxamOVOuwcaEy65MHt0F3odlg+davGNunDIAvggfhaCebxdti4XmjMSLj9ViX
         BRcFnee7mKuAypJflUhC4FPrjSZP9X3QV8dbefaUghlKBExx7xYvJhjy8Oki6KpO212o
         jh9sIPJJJiVpmeSn+vVNU0fQmGAGGLskTxyqEmmEIziqM8m/2MV/C0G/5eP3qQIc9g9A
         hws5kWiCBUSQNRPJLIdjSbtD4qDuDBh8XD81MyaATtE+k2U0LykrotzT3J12jpyqEKlC
         bibfkbXPYQeMYnxlxH6lSUME6IHEhTdLJZWdpqIr1DCKhkM4S638bpWPJTkTfhz3bQYG
         otEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jpXPPGv1foHbi5ckVrxl/EHcxYcDyUhafMePdQC+Tic=;
        b=YMa99AGQqdK1Zv5mIA56lXXmTkvb3U2mQdmkU85WTTj/IGXS1xTHFadezVM8sd2kIu
         1VXQYmgPhFWmUBNGt5HsxAa19PJz6BoXkJarIS5qJndNMYvrjxFZ2nNrGChZnh+MS0UA
         PhY81IXi8LxlsUw0AiktsqGokqUGlnbEYbeCEU0TQTjDaKlStYHXNd/83eT8jIP/9FSz
         0PolUtzZTp4TVOwGOJdUeHtPwThJrYlTrQWbE9Owq/TA+sdLxRbFVfZ3gsd1Sb7uKNFh
         r/81xzDZnbiezI7euOdluE50m/dxd6Pm5utdd3TqyDlCaWpEr2ZBsVF6uIf7XT2WsSee
         Q1jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kB2HLnpA;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id y201si37258wmc.0.2020.03.30.11.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Mar 2020 11:57:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id u10so23008388wro.7
        for <kasan-dev@googlegroups.com>; Mon, 30 Mar 2020 11:57:52 -0700 (PDT)
X-Received: by 2002:a5d:46ca:: with SMTP id g10mr15797736wrs.290.1585594672130;
 Mon, 30 Mar 2020 11:57:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
 <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com>
 <CACT4Y+ZGcZhbkcAVVfKP1gUs7mg=LrSwBqhqpUozSX8Fof6ANA@mail.gmail.com>
 <CAKFsvUK-9QU7SfKLoL0w75VgSOneO8DWciHTDYMfU8aD98Unbw@mail.gmail.com> <CACT4Y+ZhraraMNC+uvD9O7h3wMQntiEu5zSmVd_UYEaqvdxTaA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZhraraMNC+uvD9O7h3wMQntiEu5zSmVd_UYEaqvdxTaA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Mar 2020 11:57:39 -0700
Message-ID: <CAKFsvUKaeHnHp0Y9BUiB=RRHLd0TNoEA99VaUZVyfrQy8ptTqA@mail.gmail.com>
Subject: Re: [RFC PATCH v2 3/3] KASAN: Port KASAN Tests to KUnit
To: Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kB2HLnpA;       spf=pass
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

On Thu, Mar 26, 2020 at 10:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Mar 26, 2020 at 4:15 PM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> > > > > <kasan-dev@googlegroups.com> wrote:
> > > > > >
> > > > > > Transfer all previous tests for KASAN to KUnit so they can be r=
un
> > > > > > more easily. Using kunit_tool, developers can run these tests w=
ith their
> > > > > > other KUnit tests and see "pass" or "fail" with the appropriate=
 KASAN
> > > > > > report instead of needing to parse each KASAN report to test KA=
SAN
> > > > > > functionalities. All KASAN reports are still printed to dmesg.
> > > > > >
> > > > > > Stack tests do not work in UML so those tests are protected ins=
ide an
> > > > > > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> > > > > > instrumentation is enabled.
> > > > > >
> > > > > > copy_user_test cannot be run in KUnit so there is a separate te=
st file
> > > > > > for those tests, which can be run as before as a module.
> > > > >
> > > > > Hi Patricia,
> > > > >
> > > > > FWIW I've got some conflicts applying this patch on latest linux-=
next
> > > > > next-20200324. There are some changes to the tests in mm tree I t=
hink.
> > > > >
> > > > > Which tree will this go through? I would be nice to resolve these
> > > > > conflicts somehow, but I am not sure how. Maybe the kasan tests
> > > > > changes are merged upstream next windows, and then rebase this?
> > > > >
> > > > > Also, how can I apply this for testing? I assume this is based on=
 some
> > > > > kunit branch? which one?
> > > > >
> > > > Hmm... okay, that sounds like a problem. I will have to look into t=
he
> > > > conflicts. I'm not sure which tree this will go through upstream; I
> > > > expect someone will tell me which is best when the time comes. This=
 is
> > > > based on the kunit branch in the kunit documentation here:
> > > > https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselfte=
st.git/log/?h=3Dkunit
> > >
> > > I've checked out:
> > >
> > > commit 0476e69f39377192d638c459d11400c6e9a6ffb0 (HEAD, kselftest/kuni=
t)
> > > Date:   Mon Mar 23 12:04:59 2020 -0700
> > >
> > > But the build still fails for me:
> > >
> > > mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=E2=
=80=99:
> > > mm/kasan/report.c:466:6: error: implicit declaration of function
> > > =E2=80=98kunit_find_named_resource=E2=80=99 [-Werror=3Dimplicit-funct=
ion-declar]
> > >   466 |  if (kunit_find_named_resource(cur_test, "kasan_data")) {
> > >       |      ^~~~~~~~~~~~~~~~~~~~~~~~~
> > > mm/kasan/report.c:467:12: warning: assignment to =E2=80=98struct
> > > kunit_resource *=E2=80=99 from =E2=80=98int=E2=80=99 makes pointer fr=
om integer without a cas]
> > >   467 |   resource =3D kunit_find_named_resource(cur_test, "kasan_dat=
a");
> > >       |            ^
> > > mm/kasan/report.c:468:24: error: =E2=80=98struct kunit_resource=E2=80=
=99 has no member
> > > named =E2=80=98data=E2=80=99
> > >   468 |   kasan_data =3D resource->data;
> > >       |                        ^~
> > >
> > > What am I doing wrong?
> >
> > This patchset relies on another RFC patchset from Alan:
> > https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-ema=
il-alan.maguire@oracle.com/T/#t
> >
> > I thought I linked it in the commit message but it may only be in the
> > commit message for part 2/3. It should work with Alan's patchset, but
> > let me know if you have any trouble.
>
> Please push your state of code to some git repository, so that I can
> pull it. Github or gerrit or whatever.

Here's a Gerrit link: https://kunit-review.googlesource.com/c/linux/+/3513

--=20
Best,
Patricia Alfonso

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKFsvUKaeHnHp0Y9BUiB%3DRRHLd0TNoEA99VaUZVyfrQy8ptTqA%40mail.gmai=
l.com.
