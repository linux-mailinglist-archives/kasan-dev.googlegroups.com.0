Return-Path: <kasan-dev+bncBCMIZB7QWENRBDPE6HZQKGQE6XYNMFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C45D193B89
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Mar 2020 10:12:46 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id 11sf4203113oii.8
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Mar 2020 02:12:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585213965; cv=pass;
        d=google.com; s=arc-20160816;
        b=AHchQg+/ZNxsdxL7tXLA2f24uR7nWWAg7B4MLw6b82aLlyLuFTfbNE9KI8aZCbcPb4
         GWtfspiECzkixOw2+J/fu/xRc9azS2zxsQ9BEtMhNc9P8tlejXEJCA3PJksBcixwdTkl
         jRPS2DqS8Nd0iexTIXz/ia/nNXjasAPBNo3MIgJvmxwb4K4G2FV81bNXlNvggTGGublc
         /PgEVbE+zcZn/toyfFIPruL8YpkyZQusuLP3jDEVswTYL4eqwc0+Bk2bN0fKdLSWua9C
         xDZ8RYQOC5rf9Yg8VBtr2VzHRLyCtFePD2AX2w7eqqemF3jy+aT5V6nBDrBnQ/ENRSMy
         Fxfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MzvtyGqfiq22pUYr+dPFBEbzYO+ebhmx6J4Z7Ch10Rg=;
        b=AKPrsJXPMXcPqfwLAARRrMYNwXiIosxN40eX0qkg9RWv9LY188GKqVs+pOZ685LgMj
         RmWHh9mjf0TAhHl0cvd8Rnzqtlm1+AZUhszQje/xh6Ye0uoFJKdxikmbqcwZya/NhyQw
         cvl5SX5KKHhlO/YWtSrEtOmbQOA6k8zPHSa4r4VWWL7plaNvcKrtoJzwZLMpMfRI68zo
         beZRGZspJomzMowx/8/joj2na/miIlH07meghK+hTqBJQ5FywdUz0QyreWgGLPhdX+Qc
         /cubN0Y1s8kgUSDrHv51r5DBU5iG/kq0jJt1TkXbwuMRjIzrqyy2gd2JBN7aKG3S7ZIp
         h8PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gv9m6hr2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MzvtyGqfiq22pUYr+dPFBEbzYO+ebhmx6J4Z7Ch10Rg=;
        b=aLfrXwEZHy+7FKK+27Wf22jpBDTePg85RbqfqY4LJ4VHp9IQ1xpc9o6vT5M3YwTM3i
         4MD4VErJqOh16KGdqBdjXoC8+wjTI+Algx67b7kxlZetnehJUTNP3o/fROx2mp5tUEd6
         E6THDN3+SGxLx8PS+NheLX8Vck1MfsP1vD8ROChw1KjOTtUbmzCxh/HQwNrKA6Mp9SiS
         Ls7BN+aHlafkUg5zVq1RCUXEGDKU583rTON5Bl6SkZar2Rs84M6iJKMU495zMKUyVl3X
         zK2wTof5gvMxFKyGmSvRnSBaTQKCcAfHFgJEjKmZ804/Hfx+Bf5wFzEQ17epiLR0FJXl
         Wm7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MzvtyGqfiq22pUYr+dPFBEbzYO+ebhmx6J4Z7Ch10Rg=;
        b=uiN6SVAMDNRgCDETCQOXTpA43Z/Mrak2dQesLk5mxg2Aq21itvcuZeh9kaoh6Znll6
         h+xTRJx8mB8yTQP5WV88PuEwRF2S9UW9QbR+YKUwJV3xv4Bp3rghaFZw7zgbuxDoxfYX
         6QIPW4AwItquVZoebwYSb+HqSWSFo6FY6+OgADtxOAKViQ8lk6QkU57H2CmzEUBjRax5
         IJ/8hrz8Ef8dOR9aPAP6Mteplq6wDkn6Hb/JWdDnsLnj6sicxKyt1Tyj//LvzU8xgVmk
         H3AtKj5reSt92ezST9eZkiaSQiEvecIsp8rt1NECZxZWoG8zDAGp/cdC/v++s9A7siI2
         yl7Q==
X-Gm-Message-State: ANhLgQ1DGxwjj11CwI6zEuxm18i7OfEHyWfap7Eyy/0jjBdqw4Smm/aL
	4pPzlRmId/6cv+3uD5+6yGY=
X-Google-Smtp-Source: ADFU+vuBt18b7ABpiatfmQ7Q7fP3uMeFpLULmhelugllXJdE8KwoA6B7yt+vI15kaLGm05gOwjt5Rw==
X-Received: by 2002:aca:4fc3:: with SMTP id d186mr1027663oib.171.1585213965313;
        Thu, 26 Mar 2020 02:12:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9643:: with SMTP id r3ls405368ooi.10.gmail; Thu, 26 Mar
 2020 02:12:44 -0700 (PDT)
X-Received: by 2002:a4a:6841:: with SMTP id a1mr4488362oof.18.1585213964898;
        Thu, 26 Mar 2020 02:12:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585213964; cv=none;
        d=google.com; s=arc-20160816;
        b=oOvWWze3FNRX4a+Kq6YiD6SmPKSjsOrMLK1jZY21V92HAF5ubl93jjan/YdeP1Nyuw
         62Wj4Nw16/YXne5U7Zoa0YyCPMqFcrMpdJ5R6iBozhAjvdbGZdDv7s2opptuC2xzU/DL
         r85pc3OXupNwaBSYNa96Pgby2thiEMt3zKeRHd55iqW3bYbeqltc/g15yTwux7MazvsJ
         4VjyBEEQO4pfENJ45rOq0zn/sBHulbbxVNTa49czeKwxIrS6kpwjlKq2k7Mn0EemqpHE
         vrQc++KZP5zrUlhYD8iHbvJE0Ghc9i6Ys5h/VkCpU/U2zAaB79opNijAV5MXO7ZqrqNQ
         25OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h+0dBf2eFnAW/4J/Q/Labg8qpjK7rs2ogArALHG5odA=;
        b=hnHems98OigZls4SXIaE8fiqg8TTXHNTc8Yi+HTL+OS4EhlZ+1n7cXa3WVI7PjucEP
         vwlpxDdj67S8mR+RepjJNC6IKCaWxgr/Y+CYzX7qINX3olyKJaaOerl+hvhm5yczubmn
         Ajn26+uhqE0/ks+f4DZovV252TzpqhAdw9QHRiWz3UlH2nnAINYeZTlCiFMYaRiKYchM
         Sp3rtKHmZSJ85i3ue/zaFp+6JQm64fxr5K/EwgfuvC5L+A2C5LD+SbWAheO9ysdMk4D8
         OaiRswIsjphLPgXWWOypAC1oOLD81ntNw0Z0PvDBXtiWloYJ7F0S6IBcren9zqwaRgPI
         rr0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gv9m6hr2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id d16si159607otp.0.2020.03.26.02.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Mar 2020 02:12:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id m2so2513725qvu.13
        for <kasan-dev@googlegroups.com>; Thu, 26 Mar 2020 02:12:44 -0700 (PDT)
X-Received: by 2002:a0c:a8e2:: with SMTP id h34mr6828428qvc.22.1585213964095;
 Thu, 26 Mar 2020 02:12:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
 <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com>
In-Reply-To: <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Mar 2020 10:12:33 +0100
Message-ID: <CACT4Y+ZGcZhbkcAVVfKP1gUs7mg=LrSwBqhqpUozSX8Fof6ANA@mail.gmail.com>
Subject: Re: [RFC PATCH v2 3/3] KASAN: Port KASAN Tests to KUnit
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gv9m6hr2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Tue, Mar 24, 2020 at 4:05 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> On Tue, Mar 24, 2020 at 4:25 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Mar 19, 2020 at 5:42 PM 'Patricia Alfonso' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Transfer all previous tests for KASAN to KUnit so they can be run
> > > more easily. Using kunit_tool, developers can run these tests with th=
eir
> > > other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> > > report instead of needing to parse each KASAN report to test KASAN
> > > functionalities. All KASAN reports are still printed to dmesg.
> > >
> > > Stack tests do not work in UML so those tests are protected inside an
> > > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> > > instrumentation is enabled.
> > >
> > > copy_user_test cannot be run in KUnit so there is a separate test fil=
e
> > > for those tests, which can be run as before as a module.
> >
> > Hi Patricia,
> >
> > FWIW I've got some conflicts applying this patch on latest linux-next
> > next-20200324. There are some changes to the tests in mm tree I think.
> >
> > Which tree will this go through? I would be nice to resolve these
> > conflicts somehow, but I am not sure how. Maybe the kasan tests
> > changes are merged upstream next windows, and then rebase this?
> >
> > Also, how can I apply this for testing? I assume this is based on some
> > kunit branch? which one?
> >
> Hmm... okay, that sounds like a problem. I will have to look into the
> conflicts. I'm not sure which tree this will go through upstream; I
> expect someone will tell me which is best when the time comes. This is
> based on the kunit branch in the kunit documentation here:
> https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git=
/log/?h=3Dkunit

I've checked out:

commit 0476e69f39377192d638c459d11400c6e9a6ffb0 (HEAD, kselftest/kunit)
Date:   Mon Mar 23 12:04:59 2020 -0700

But the build still fails for me:

mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=E2=80=99:
mm/kasan/report.c:466:6: error: implicit declaration of function
=E2=80=98kunit_find_named_resource=E2=80=99 [-Werror=3Dimplicit-function-de=
clar]
  466 |  if (kunit_find_named_resource(cur_test, "kasan_data")) {
      |      ^~~~~~~~~~~~~~~~~~~~~~~~~
mm/kasan/report.c:467:12: warning: assignment to =E2=80=98struct
kunit_resource *=E2=80=99 from =E2=80=98int=E2=80=99 makes pointer from int=
eger without a cas]
  467 |   resource =3D kunit_find_named_resource(cur_test, "kasan_data");
      |            ^
mm/kasan/report.c:468:24: error: =E2=80=98struct kunit_resource=E2=80=99 ha=
s no member
named =E2=80=98data=E2=80=99
  468 |   kasan_data =3D resource->data;
      |                        ^~

What am I doing wrong?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZGcZhbkcAVVfKP1gUs7mg%3DLrSwBqhqpUozSX8Fof6ANA%40mail.gm=
ail.com.
