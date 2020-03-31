Return-Path: <kasan-dev+bncBCMIZB7QWENRBC5PRT2AKGQEAPW7L5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DD44D199332
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 12:12:28 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id t7sf22051955ybj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 03:12:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585649548; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThGoDgfeASvgB2Nve5kA/eTQ0J9nSp+3iXam7hv29aajWrYzLA0q+Y5KWLmzqdDDdo
         YuVuH8xQ9ALaDwRCyx2KsQVwOnNnQFkh3ODhVEWYkTOcSDtLcTBV+YJvTSWHQ1BjTDC1
         /JInI36fiwtAZAR+jyrlMrBldcV4fCCVt7DoJs6o9APRDsrBHiMHdcNSZlr3esvILXV4
         rTukbWrBMcEukHB3ef+MBwhaNNQq9Q+pD0nvgVetLxfOzHVbhI5Ob00L3PXt2M/pcEp+
         8Bg3+cWLeFcgIy/rNIBYZxXRGCQla3y0YE3hh7KQpdPoc423Mu1oV34SSdn/3e9s+1ij
         t0og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pGpBrnzy85hQm++YxyNi1Ek79tD3x0/5dXbR6F8ii/k=;
        b=qYCy0pbh7SBl73LZ8HmozfaXCT9JTMZo6qQiBfxsXMgotNb0fgszrBPn2glCTsqFQl
         taa5GL7dSnvZk5B3jeEhEp/5A7xrBE0aNBOuSyFLmPtku78qwF1aeeh+kZY2HHGznzMq
         H5AxnWjkjloxq0kBs0uZctx5QxmLEpuQbJqXxF7HJgGBIm1jY/3oYGT20teEf4ZNJPta
         7vfryHIU853cifUpwEn7d3w9GddqQWXMUW1SprkZKhY2f0nqceP6QD6LD97jA8+bREBI
         EuUC4DV6XpV97xib5o99Hdaqt9XY+UmDEbE5U4S2YcfX1r7P/DltzmAaSHE02zeLzZbr
         T9WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QmT8jZjq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pGpBrnzy85hQm++YxyNi1Ek79tD3x0/5dXbR6F8ii/k=;
        b=LzDurK66HvShPKlaOc6IgeoiBMQZsz3BqkSlmtQPb0X6PgSkEVWk2lGK9qkDox96QA
         XrbeEgpauX8kDMe7IdzFABJPRlBvUKmcz8Hz2uHPLH55ubP45/qafvkNBY8A0yov7bnx
         wfoAStCovzevNDQ/a8kjlNDqNy/66Ao4CMOAjEFWpcUdoaONwQ+fhHD7K6pzsDYc8HZF
         ibYiUxDhgtNcXc6H3uJKkE6Yib1djFONBYFUhlUJOdQYPtPykVKJsWP79fGyGhW4MRa/
         2mQ5F+gy/t/7wHTwsRmgdIWJLi14ERoihD7WoleqYw7hqR/2MvuIwbc7bOTEQDc9gsCE
         XVSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pGpBrnzy85hQm++YxyNi1Ek79tD3x0/5dXbR6F8ii/k=;
        b=VMrPvjycosq7MAbiLeahtZCuFX+KgXgUScDLdUKwQ6YAGFIewPE6N1jpDtNkFGQvjH
         7AmmpuX6f4RyoNzzu5X2hBnWs+I16Tz5dCs1ycNe8vfRQhXq1GOj6hTjYv9dZQbaZSR6
         LjTfCEsqFnT6eo+KsngZn0VR81fvxpJ161/uO7BeoVJIXYAg+XKPjBndnxJeRa45oGzN
         XHPod796hxHJRRwfaa5oXNSwjPb2HdlkUoRrRFWE73gmNs50JZ3VCf9Kqxjyb5v4xtK5
         kIsDwJdVzYScteQduBmCAjCG+BQvqrdO5vpl/924uS2O1p/jRuen8RmqXqTRKnnWHXPs
         J7cg==
X-Gm-Message-State: ANhLgQ1CeI0gg3+XocC+O6LvbWT5gPmzHKieNT9l24OhVEKUMDYARLRH
	lBMFhHr/UlWlrpI9Spn6rqk=
X-Google-Smtp-Source: ADFU+vuY3tsQG2hJ04nLqsyVFu8DWqJM7b8LyW3PToDlOxo4/UiazzGUiL2ghSmzcm92R0xYm0EoLg==
X-Received: by 2002:a25:7502:: with SMTP id q2mr26753354ybc.276.1585649547867;
        Tue, 31 Mar 2020 03:12:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e00d:: with SMTP id x13ls7060109ybg.7.gmail; Tue, 31 Mar
 2020 03:12:27 -0700 (PDT)
X-Received: by 2002:a25:6a8a:: with SMTP id f132mr8811436ybc.322.1585649547428;
        Tue, 31 Mar 2020 03:12:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585649547; cv=none;
        d=google.com; s=arc-20160816;
        b=wBBjOWM5OHwt3nxkBHZyBL9SpAQGV2EfZOpCoq0fdTfjt2Y5rboEGWzRKNmDoAmmmR
         +svS5xgm3xue8vQZxojVl4b0rkvimHeqOzi6HDqUtEmip0bfk7jKEaEVhoXn3UxKm51e
         qFIBaHG7a0Xv/dxOK+eb+2++ljAJmFzoHoTj2/PN26BzOE750IHY+mJm1vXC8d8TcuR5
         yymgy+tCz2+wLXJ4Rg3Vp8L1xXjtIZZqVx12znTkYV5UfylKi89sK7of10F6pR43kUI1
         Bw7U57ME/5/yY7AsFwMud9MVUpbL5JFkHwXaJ7c1VcM6VXmQ15UEGSMOG/i5jnXfL2p3
         5rkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PpCiJ4Lui2bH+hihck/1M29XXQzUL8SEpkRFBSZWS3E=;
        b=iXbTqKP4kM3dIj2Zpw4uGHEtynZXSiHs5MNJbs6etrCgavEpCGdx2hQkx8qvhcnQBy
         cvon3L1lCcxMeGDwMLAlgtzIsrCqnW+MLf+cNDZe82f8N1+NMJVUenYflpRInC1gz5yr
         QSduqFn2oylMFE37XDPkNFops++wXeIB6jCw0ipzw0fyV34CiCMcaWfmxkI9fkMd3z3L
         sR0Qt+FgzDbG4tBBvY/emOBMXBbdOKb0gibA6LNdASRyzF3rzUWWR2T4F6B4gw6Z8D5/
         RoC+69qUsEKxTaH9FJhlzF+kj4Rbv+3faVVeTML2GMTTEDR0772IuFa5WPgY6vWHOSwM
         lSiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QmT8jZjq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id d72si720472ybh.5.2020.03.31.03.12.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Mar 2020 03:12:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id p60so10542329qva.5
        for <kasan-dev@googlegroups.com>; Tue, 31 Mar 2020 03:12:27 -0700 (PDT)
X-Received: by 2002:ad4:49d1:: with SMTP id j17mr16149922qvy.80.1585649546681;
 Tue, 31 Mar 2020 03:12:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
 <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com>
 <CACT4Y+ZGcZhbkcAVVfKP1gUs7mg=LrSwBqhqpUozSX8Fof6ANA@mail.gmail.com>
 <CAKFsvUK-9QU7SfKLoL0w75VgSOneO8DWciHTDYMfU8aD98Unbw@mail.gmail.com>
 <CACT4Y+ZhraraMNC+uvD9O7h3wMQntiEu5zSmVd_UYEaqvdxTaA@mail.gmail.com> <CAKFsvUKaeHnHp0Y9BUiB=RRHLd0TNoEA99VaUZVyfrQy8ptTqA@mail.gmail.com>
In-Reply-To: <CAKFsvUKaeHnHp0Y9BUiB=RRHLd0TNoEA99VaUZVyfrQy8ptTqA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Mar 2020 12:12:15 +0200
Message-ID: <CACT4Y+Y_zQPispr5FgW1VWr0Kpc3Z-6AR3TxEFJN1zKB72C2XQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=QmT8jZjq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Mon, Mar 30, 2020 at 8:57 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
> > On Thu, Mar 26, 2020 at 4:15 PM Patricia Alfonso
> > <trishalfonso@google.com> wrote:
> > > > > > <kasan-dev@googlegroups.com> wrote:
> > > > > > >
> > > > > > > Transfer all previous tests for KASAN to KUnit so they can be=
 run
> > > > > > > more easily. Using kunit_tool, developers can run these tests=
 with their
> > > > > > > other KUnit tests and see "pass" or "fail" with the appropria=
te KASAN
> > > > > > > report instead of needing to parse each KASAN report to test =
KASAN
> > > > > > > functionalities. All KASAN reports are still printed to dmesg=
.
> > > > > > >
> > > > > > > Stack tests do not work in UML so those tests are protected i=
nside an
> > > > > > > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if sta=
ck
> > > > > > > instrumentation is enabled.
> > > > > > >
> > > > > > > copy_user_test cannot be run in KUnit so there is a separate =
test file
> > > > > > > for those tests, which can be run as before as a module.
> > > > > >
> > > > > > Hi Patricia,
> > > > > >
> > > > > > FWIW I've got some conflicts applying this patch on latest linu=
x-next
> > > > > > next-20200324. There are some changes to the tests in mm tree I=
 think.
> > > > > >
> > > > > > Which tree will this go through? I would be nice to resolve the=
se
> > > > > > conflicts somehow, but I am not sure how. Maybe the kasan tests
> > > > > > changes are merged upstream next windows, and then rebase this?
> > > > > >
> > > > > > Also, how can I apply this for testing? I assume this is based =
on some
> > > > > > kunit branch? which one?
> > > > > >
> > > > > Hmm... okay, that sounds like a problem. I will have to look into=
 the
> > > > > conflicts. I'm not sure which tree this will go through upstream;=
 I
> > > > > expect someone will tell me which is best when the time comes. Th=
is is
> > > > > based on the kunit branch in the kunit documentation here:
> > > > > https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kself=
test.git/log/?h=3Dkunit
> > > >
> > > > I've checked out:
> > > >
> > > > commit 0476e69f39377192d638c459d11400c6e9a6ffb0 (HEAD, kselftest/ku=
nit)
> > > > Date:   Mon Mar 23 12:04:59 2020 -0700
> > > >
> > > > But the build still fails for me:
> > > >
> > > > mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=
=E2=80=99:
> > > > mm/kasan/report.c:466:6: error: implicit declaration of function
> > > > =E2=80=98kunit_find_named_resource=E2=80=99 [-Werror=3Dimplicit-fun=
ction-declar]
> > > >   466 |  if (kunit_find_named_resource(cur_test, "kasan_data")) {
> > > >       |      ^~~~~~~~~~~~~~~~~~~~~~~~~
> > > > mm/kasan/report.c:467:12: warning: assignment to =E2=80=98struct
> > > > kunit_resource *=E2=80=99 from =E2=80=98int=E2=80=99 makes pointer =
from integer without a cas]
> > > >   467 |   resource =3D kunit_find_named_resource(cur_test, "kasan_d=
ata");
> > > >       |            ^
> > > > mm/kasan/report.c:468:24: error: =E2=80=98struct kunit_resource=E2=
=80=99 has no member
> > > > named =E2=80=98data=E2=80=99
> > > >   468 |   kasan_data =3D resource->data;
> > > >       |                        ^~
> > > >
> > > > What am I doing wrong?
> > >
> > > This patchset relies on another RFC patchset from Alan:
> > > https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-e=
mail-alan.maguire@oracle.com/T/#t
> > >
> > > I thought I linked it in the commit message but it may only be in the
> > > commit message for part 2/3. It should work with Alan's patchset, but
> > > let me know if you have any trouble.
> >
> > Please push your state of code to some git repository, so that I can
> > pull it. Github or gerrit or whatever.
>
> Here's a Gerrit link: https://kunit-review.googlesource.com/c/linux/+/351=
3

This worked well for me! Thanks!

The first thing I hit is that my default config has panic_on_warn=3D1
set, which has the same effect as the "multi shot" setting.
I think we need to save/restore panic_on_warn the same way we do for
multi shot (+rename kasan_multi_shot_init/exit to something more
generic).

After removing panic_on_warn=3D1 I was able to run the tests
successfully on x86_64.

And after injecting some simple bugs, I got expected test failures:

[    3.191793] # kasan_memchr: EXPECTATION FAILED at lib/test_kasan.c:509
[    3.191793] Expected kasan_data->report_expected =3D=3D
kasan_data->report_found, but
[    3.191793] kasan_data->report_expected =3D=3D 1
[    3.191793] kasan_data->report_found =3D=3D 0
[    3.191852] not ok 30 - kasan_memchr
[    3.195588] # kasan_memcmp: EXPECTATION FAILED at lib/test_kasan.c:523
[    3.195588] Expected kasan_data->report_expected =3D=3D
kasan_data->report_found, but
[    3.195588] kasan_data->report_expected =3D=3D 1
[    3.195588] kasan_data->report_found =3D=3D 0
[    3.195659] not ok 31 - kasan_memcmp


All of these should be static:

struct kunit_resource resource;
struct kunit_kasan_expectation fail_data;
bool multishot;
int kasan_multi_shot_init(struct kunit *test)
void kasan_multi_shot_exit(struct kunit *test)

With the comments in the previous emails, this looks good to me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BY_zQPispr5FgW1VWr0Kpc3Z-6AR3TxEFJN1zKB72C2XQ%40mail.gmai=
l.com.
