Return-Path: <kasan-dev+bncBCMIZB7QWENRBMU763ZQKGQEYRAPPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A0451950A8
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Mar 2020 06:31:32 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id w1sf7291860qte.6
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Mar 2020 22:31:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585287091; cv=pass;
        d=google.com; s=arc-20160816;
        b=nmAA9Kg7fatF2as/JFQFzxX49iYgc7cjalC2WAiIlxkvFe8LEAO8f6KMMhN+LqTFZd
         VxDrRCs71vX4rS7O1ggl4qOEpkDwpp/PsRgcalDgRJpCb55OmN5Dge3S37vuv14F3brF
         YGUW6/CcgJvF1Hq0kNRP2IhbAXGMpKd9FXXQDcOBjB9upAsBMWnT+xX7q+/YBhNA+lxF
         x/gP2aS5Deo7YoW02jod3/GhtYTI+BBSRKx5mvrcWB0LZthJWj7wwbenCslsIspir5oQ
         ++UTOFeM4nnvfDjcBc93eZvagVEhmMJCY5+W5d4oyDXwV+graahFGQR5CnqvMt85pdhC
         If3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cXBP1rTVfw6NO2NiSdo0oVNEzeUtXHJrSExbzHeSZ7Y=;
        b=w5pa22+tO8D+M1m65R7+JXvUnPdkZrcOLCFccrrh3rGhZShId7YDPQAs86MHioO9a2
         xqmPzO6lD7T00hlV6w3+YtKycug40Ew/xMANkSDGWMFqB8F4BDtHLuW2L7vkfSo6AG1r
         q/0gsIKYBUlhROn4X4vmyI0xfFThZ11eGzpdjugHNopUM5b+OV0Zb1S3HNVxMhxbSIYS
         Dv4jHYTjkYazeAoAyMTyug/+q/QmzsEqreE9Mf8jSJZGpQ+wbIrDPpY8wvj1iOVC+xMT
         fAk5HEiFdJ2FI7L65mrpBjgz0YgF/yxGiWbEPGOgOFm4HamSWTnG82JaRNdIyZLkn3L3
         Y9/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F8D9FdaZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cXBP1rTVfw6NO2NiSdo0oVNEzeUtXHJrSExbzHeSZ7Y=;
        b=Y64RSEDQHxit5xJ6G9fgX3RaXKRcTayIURdkmmQulBW8wOt/HcpodBy7gbJ2c+MGP0
         EHQCMPWMmAt/aaP8kooNYJyjbYs1K9mwm5xCQDFk/gh5H/eGadZf4Cu1+xKGFDcFBKCC
         05vmWocCz5Bp4kgBUodwWsH8K2X+Yip2pzpXMDJ8o5fURFZgRNGnw+9SkVG1/hi1l81V
         +2CQYtMzLWF3lo/iFrp3li4SrE5++WbcSEdOoIIjBBjZ4GzbI7CS9Gzdt94tjMoZJPlb
         BOB1xzR1G/dUSz8sm1T967ylWf5zNJ2U2pOyargqmSU5BCpkJYZ/kDkAt8kW8Xbkzkql
         sabA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cXBP1rTVfw6NO2NiSdo0oVNEzeUtXHJrSExbzHeSZ7Y=;
        b=MmOQIQsxypRQL85ZcTvNDKDcfKF7N3fhVCc9/rRtMqz7PSYJEtCfXCEStdjvOUuiIJ
         XUjnkRVWUkOekAEhGwQZtfQHiK5x0ZiniGAdZf3RhypQOCVSL5SyZQaDbBRa+al6VfCz
         cs09sacnuuAD2Z/fTUwPt6/vZW/g+TauTXJ0aTCxyZzDfAIm+wGN8hYaxoCxBcpN83wv
         gnoTZNUk/bQKt2rUqqqU0wQ3mHi8cfQ9WNL2dzsV8oJ4c3jNXdB8hPkzUsfp6lNgXlQn
         jaZJZMq5yc8edDLkX5cXshWo82DzlYnYX5e7Uc/LrmF2ORTp9OsRLK+NMpgBndTMUg62
         gXhg==
X-Gm-Message-State: ANhLgQ0oGIPaa8VXmFcSxNyeTGVECCGuohk+dEXGCXAhzutLDHvHO81W
	vfxrn/+p5zOejtKLy39Kux4=
X-Google-Smtp-Source: ADFU+vtpQAxMoxRAA7iMbIg4j2LCBrkknju0HnXpvzeacSkuYDOImqNMRHVZtLIzFSi7M5FbjycD/w==
X-Received: by 2002:a05:620a:84d:: with SMTP id u13mr12404560qku.94.1585287090960;
        Thu, 26 Mar 2020 22:31:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e815:: with SMTP id a21ls3910820qkg.0.gmail; Thu, 26 Mar
 2020 22:31:30 -0700 (PDT)
X-Received: by 2002:a37:a281:: with SMTP id l123mr4041591qke.438.1585287090552;
        Thu, 26 Mar 2020 22:31:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585287090; cv=none;
        d=google.com; s=arc-20160816;
        b=q1mYbzUc4SgZse/V8IdUhs88WbULvi8wEZkyRF0EgR/uAi5vj22IQJjf7uRZo4T1E/
         fk1qbWM1cp2rAUKGc00DE69hzYbjU7gm1p3SfMLejYAnIc8XAXStmX0lnM94Xol2uScQ
         xqgZah4jeC7BFM5F8FWnoHOpIhYkvGXSBpcKW2foYDj2MASON3DD3VXpcESNcnztSEot
         +ku6KH+X9CkiHqBCkfbdVwL+JfJqHy+0cHBjBH1zD0owNpRp30FlJZD5oTTbJ565Hef3
         u/jErAzuaGdIUh3SRuiRLbLApjHIwswgUb5yjVXCsr7GHvFZq+axmma7av941WnmVarj
         czzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0aSGmCSFNaK2u76JjA7BVQB1O79rv1aQ7YCzvcBdSxY=;
        b=b56bsInSAcBlA568lNG4qtMvzdLD/cNz4QoOKmcojf5U8he3GOXsCcBc+qOIYT1o3b
         R8fCv0JpTLK/PcNhQ5bBsbbedE6WHT5Uf5rUuDSZeOGsJyljL8JZEMvqxlycoTVdGNt9
         9R7rMIF3ktCCzmg1M30AoZfMzBdrrs5SpGtBFLvkc9SdoDryRcrONi9BJaQBNqQg5ZZs
         +dS5Oue6zEMTlq05sTvvYVxwe38gMN+9GmsCqQn3pBgxbmMPqou/FyBs+nzjB/50tjX9
         /Lm+fTYrPLXn7vvsKDdK4M+YTdmF9Qv27x6DnhUCy3I7zyN3YIgKnL7sXufesK2EvI/t
         SwsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F8D9FdaZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id x11si267007qka.4.2020.03.26.22.31.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Mar 2020 22:31:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id g4so4332149qvo.12
        for <kasan-dev@googlegroups.com>; Thu, 26 Mar 2020 22:31:30 -0700 (PDT)
X-Received: by 2002:ad4:4088:: with SMTP id l8mr9904318qvp.34.1585287089966;
 Thu, 26 Mar 2020 22:31:29 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
 <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com>
 <CACT4Y+ZGcZhbkcAVVfKP1gUs7mg=LrSwBqhqpUozSX8Fof6ANA@mail.gmail.com> <CAKFsvUK-9QU7SfKLoL0w75VgSOneO8DWciHTDYMfU8aD98Unbw@mail.gmail.com>
In-Reply-To: <CAKFsvUK-9QU7SfKLoL0w75VgSOneO8DWciHTDYMfU8aD98Unbw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Mar 2020 06:31:18 +0100
Message-ID: <CACT4Y+ZhraraMNC+uvD9O7h3wMQntiEu5zSmVd_UYEaqvdxTaA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=F8D9FdaZ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Thu, Mar 26, 2020 at 4:15 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
> > > > <kasan-dev@googlegroups.com> wrote:
> > > > >
> > > > > Transfer all previous tests for KASAN to KUnit so they can be run
> > > > > more easily. Using kunit_tool, developers can run these tests wit=
h their
> > > > > other KUnit tests and see "pass" or "fail" with the appropriate K=
ASAN
> > > > > report instead of needing to parse each KASAN report to test KASA=
N
> > > > > functionalities. All KASAN reports are still printed to dmesg.
> > > > >
> > > > > Stack tests do not work in UML so those tests are protected insid=
e an
> > > > > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> > > > > instrumentation is enabled.
> > > > >
> > > > > copy_user_test cannot be run in KUnit so there is a separate test=
 file
> > > > > for those tests, which can be run as before as a module.
> > > >
> > > > Hi Patricia,
> > > >
> > > > FWIW I've got some conflicts applying this patch on latest linux-ne=
xt
> > > > next-20200324. There are some changes to the tests in mm tree I thi=
nk.
> > > >
> > > > Which tree will this go through? I would be nice to resolve these
> > > > conflicts somehow, but I am not sure how. Maybe the kasan tests
> > > > changes are merged upstream next windows, and then rebase this?
> > > >
> > > > Also, how can I apply this for testing? I assume this is based on s=
ome
> > > > kunit branch? which one?
> > > >
> > > Hmm... okay, that sounds like a problem. I will have to look into the
> > > conflicts. I'm not sure which tree this will go through upstream; I
> > > expect someone will tell me which is best when the time comes. This i=
s
> > > based on the kunit branch in the kunit documentation here:
> > > https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest=
.git/log/?h=3Dkunit
> >
> > I've checked out:
> >
> > commit 0476e69f39377192d638c459d11400c6e9a6ffb0 (HEAD, kselftest/kunit)
> > Date:   Mon Mar 23 12:04:59 2020 -0700
> >
> > But the build still fails for me:
> >
> > mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=E2=80=
=99:
> > mm/kasan/report.c:466:6: error: implicit declaration of function
> > =E2=80=98kunit_find_named_resource=E2=80=99 [-Werror=3Dimplicit-functio=
n-declar]
> >   466 |  if (kunit_find_named_resource(cur_test, "kasan_data")) {
> >       |      ^~~~~~~~~~~~~~~~~~~~~~~~~
> > mm/kasan/report.c:467:12: warning: assignment to =E2=80=98struct
> > kunit_resource *=E2=80=99 from =E2=80=98int=E2=80=99 makes pointer from=
 integer without a cas]
> >   467 |   resource =3D kunit_find_named_resource(cur_test, "kasan_data"=
);
> >       |            ^
> > mm/kasan/report.c:468:24: error: =E2=80=98struct kunit_resource=E2=80=
=99 has no member
> > named =E2=80=98data=E2=80=99
> >   468 |   kasan_data =3D resource->data;
> >       |                        ^~
> >
> > What am I doing wrong?
>
> This patchset relies on another RFC patchset from Alan:
> https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email=
-alan.maguire@oracle.com/T/#t
>
> I thought I linked it in the commit message but it may only be in the
> commit message for part 2/3. It should work with Alan's patchset, but
> let me know if you have any trouble.

Please push your state of code to some git repository, so that I can
pull it. Github or gerrit or whatever.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZhraraMNC%2BuvD9O7h3wMQntiEu5zSmVd_UYEaqvdxTaA%40mail.gm=
ail.com.
