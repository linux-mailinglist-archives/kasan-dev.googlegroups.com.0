Return-Path: <kasan-dev+bncBDK3TPOVRULBBD4O6PZQKGQEYTLMJAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E27641942CC
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Mar 2020 16:15:27 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id o18sf3189859wrx.9
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Mar 2020 08:15:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585235727; cv=pass;
        d=google.com; s=arc-20160816;
        b=pdvW6Eo4p4cUUbUW0vnOYGnfGbwrlnqNYnA0dvs8BY1cFLdjrfT0nt+qyfjxTpJEs8
         4qRryMj6vTbaVsTBOh/dP37NfCV2HtrRNpp7WoOAIzJHSe9OD0F+cjBVd5u+p8RuuV0L
         kmnPl/vC+9a96a8fxMwKSP/wTznye2Nfl7wgwFn2jYpYrn1KkRLpLTSdalqI9Ls9uvOk
         /YrFwbDMykTgoKIeqFyKYL5759RrjyLvj/Hm8/ORUxA0IQbU7EkTaTmLQF3dftuyMMK6
         bp/ubjM2PaTb98L8QlNCw3+2cVApabekuUrlNq72m+i0a57j9zdBGXIlIe8xMv/eP+2A
         4TCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bz8iK242dOoNLMRrg/9Bxo/6r6oaGvUIgJyW30XN+zw=;
        b=DahqwJOXdM31wdP60VXzLBSRTTrLzrRCeZi8nB4d57Y44Y7xO72+vMGGRD6siAoSMd
         yKwBBbpNjhGc16BN9HgVO2zvVi1vCjq3tu3/xDI9+qPXA7dMOZFPKXWz1AnIvAeMzaoi
         2IrNGa6LFL6QFCTjAPOEKtOJUvblv495DvMnMt6FzooQKWsMX5Y9mLKSOuicFUWRKnqe
         ru1bCks1vUbmz1ujBcwhlJD/QGLjq2RnVIJ2KQN4kyvceAWuIsxfffakYjMDnd2HjIwe
         aV80zUBzpibU+kNjQKH2+tTcBF+ZR7QotBrFfYYIYoqVsl9HFUiw6T0032pV2Ecy5+aZ
         HEag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JS+pLv9f;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bz8iK242dOoNLMRrg/9Bxo/6r6oaGvUIgJyW30XN+zw=;
        b=dVKoZ0AeF45VM8yK3R7/o/hkIP5PAvC9F49H7FCKKu8VV8efsvxc7M0yWFJqdAqBGM
         3FOml0+SQehoTtdXT5rV0ZqlDZk1fSb5VUYw/Vsn/suIDhA4fw1HaB3jjBay5XQ0545+
         U5XQCoD0Nm7iJcbi7/kZ5g2Qng8rOO+e3OXtlCHekTXZD8Q0P/g6fOYMO6+4+XVI/FfL
         cMxka4aXyyHq05UjE2wWmUv+EMPVP437Ydk/nj5NjUpu2qdAmvKkkeeM/272Zy4/Jo4g
         slBdNgN3AQdcq1eG+s0ytFJJESsNQF1H4B7KudZkai6k4vEaab13ItY0skVd/XIVYOXD
         pXCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bz8iK242dOoNLMRrg/9Bxo/6r6oaGvUIgJyW30XN+zw=;
        b=o/zZOqcm49TpbKwoh3lUPjcScIiJ9lHDH+AyEax1Dqx/8HzDfcVt6kQ2te9TYLJGR+
         ht5rb47xQo/DGWA5xlWHEx7QvUPTIGKEpMeeZ3Xw/0eRaF9BmLveN0lAt9uXai3Q0Knu
         kf8zrdV0GbfUnKrhebP+xy45wQZ8zk7JFQ4ugHgalNJ2QWCiwAAWXgONd/EWpArpgAp/
         0Sko79eFsUyTW+2fsLieIRoBl/qficNxDmeDjJE0kq5UDG3HK9WtefbdZGR/EbSUEpk3
         CKW4EBX4FUHeGQHhzserLskuFik4I+aHPIz8BVfTA48gh3BootubmdzQFfhgYztcH05F
         boaA==
X-Gm-Message-State: ANhLgQ0bUgTnC9ckpnQHHiFzlSzoVOyR2/Dp8KwjGhrt7W2nurnaDKZ9
	9HTdN8QysZg97SPEIQAjvOE=
X-Google-Smtp-Source: ADFU+vtrBimoCiobOD2JlfB8bRApFVdSutVLrpzOX2xSNGjBRsie3SukQLX76unVGPwbHVw4EmGPCg==
X-Received: by 2002:adf:fd44:: with SMTP id h4mr7534110wrs.177.1585235727587;
        Thu, 26 Mar 2020 08:15:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4441:: with SMTP id x1ls2933938wrr.4.gmail; Thu, 26 Mar
 2020 08:15:27 -0700 (PDT)
X-Received: by 2002:a5d:464e:: with SMTP id j14mr9917131wrs.339.1585235726983;
        Thu, 26 Mar 2020 08:15:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585235726; cv=none;
        d=google.com; s=arc-20160816;
        b=QZf0IG1ra8wCyPPrWmlS1LWksHR8QrlCUSJMcSFkfKE05wGkowZmBWFdH9ELW8UoKH
         UUlfbUIrtrfw8mLuairu60W899irrkFDzlvhwdHxJTLNrvEykvepQftx/o4pbTtRyjXC
         ilk/LCzy6oJBsuTg2WSk3Tjx8WhgSo/4o0ywT+xveofDNJLOgC/DWIn/SQ1A4/LU7TtF
         QdLWrmTkcTmcuD9yx3KH/l/b2lX94kDfW3daf7Vw0aoW8DDyCmyTLimgAQNbli04SM8w
         aDEwC0GjsgxbCDh6Oc/kpNgYgfqoebOV21n7af9EJUNhQlZBsbsFCl+CiQZ9xy7ILdJb
         8Z5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h4U844jPltBTNlYGJyCJI7cYyBDxAP1w1W8i3jCDF+o=;
        b=Pz0Q2KY2GxAljp18UQmbyABCehtqAlf17QuABN4pTQilj1g4DwdPrU7RkvVWyc1r/3
         15Nj63R7vAjVxRyLT+yjs3mcyp+5BMDmSEUIW95relDGnyMO6BweoaLWjENstE20Ybvh
         dnqGTfsSmHYf0cP34+4r+cnbiXd++krPN6eQFHU9JuhffQzkRgwl+gv/GshwLT1m/QsR
         a2w3OPFHgj/7M7ddiifzRZ5rfSQE+uW9DkgIAYkKI48dRQcz3znUiYYf4OK13cicawbm
         biBsG1KSag1rnQ6Wgby6atqv8LqNtVWNuTYIZoIIsJRIbLbs8ikll7yRodo1OmIAkaqh
         X1rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JS+pLv9f;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id i18si671349wml.1.2020.03.26.08.15.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Mar 2020 08:15:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id s1so8267204wrv.5
        for <kasan-dev@googlegroups.com>; Thu, 26 Mar 2020 08:15:26 -0700 (PDT)
X-Received: by 2002:adf:efc9:: with SMTP id i9mr9415479wrp.23.1585235726390;
 Thu, 26 Mar 2020 08:15:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <CACT4Y+YHPfP3LP04=Zc4NgyhH8FMJ9m-eU_VPjmk5SmGWo_fTg@mail.gmail.com>
 <CAKFsvU+N=8=VmKVdNdf6os26z+vVD=vR=TL5GJtLQhR9FxOJUQ@mail.gmail.com> <CACT4Y+ZGcZhbkcAVVfKP1gUs7mg=LrSwBqhqpUozSX8Fof6ANA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZGcZhbkcAVVfKP1gUs7mg=LrSwBqhqpUozSX8Fof6ANA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Mar 2020 08:15:14 -0700
Message-ID: <CAKFsvUK-9QU7SfKLoL0w75VgSOneO8DWciHTDYMfU8aD98Unbw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=JS+pLv9f;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442
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

On Thu, Mar 26, 2020 at 2:12 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Mar 24, 2020 at 4:05 PM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> >
> > On Tue, Mar 24, 2020 at 4:25 AM Dmitry Vyukov <dvyukov@google.com> wrot=
e:
> > >
> > > On Thu, Mar 19, 2020 at 5:42 PM 'Patricia Alfonso' via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > >
> > > > Transfer all previous tests for KASAN to KUnit so they can be run
> > > > more easily. Using kunit_tool, developers can run these tests with =
their
> > > > other KUnit tests and see "pass" or "fail" with the appropriate KAS=
AN
> > > > report instead of needing to parse each KASAN report to test KASAN
> > > > functionalities. All KASAN reports are still printed to dmesg.
> > > >
> > > > Stack tests do not work in UML so those tests are protected inside =
an
> > > > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> > > > instrumentation is enabled.
> > > >
> > > > copy_user_test cannot be run in KUnit so there is a separate test f=
ile
> > > > for those tests, which can be run as before as a module.
> > >
> > > Hi Patricia,
> > >
> > > FWIW I've got some conflicts applying this patch on latest linux-next
> > > next-20200324. There are some changes to the tests in mm tree I think=
.
> > >
> > > Which tree will this go through? I would be nice to resolve these
> > > conflicts somehow, but I am not sure how. Maybe the kasan tests
> > > changes are merged upstream next windows, and then rebase this?
> > >
> > > Also, how can I apply this for testing? I assume this is based on som=
e
> > > kunit branch? which one?
> > >
> > Hmm... okay, that sounds like a problem. I will have to look into the
> > conflicts. I'm not sure which tree this will go through upstream; I
> > expect someone will tell me which is best when the time comes. This is
> > based on the kunit branch in the kunit documentation here:
> > https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.g=
it/log/?h=3Dkunit
>
> I've checked out:
>
> commit 0476e69f39377192d638c459d11400c6e9a6ffb0 (HEAD, kselftest/kunit)
> Date:   Mon Mar 23 12:04:59 2020 -0700
>
> But the build still fails for me:
>
> mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=E2=80=
=99:
> mm/kasan/report.c:466:6: error: implicit declaration of function
> =E2=80=98kunit_find_named_resource=E2=80=99 [-Werror=3Dimplicit-function-=
declar]
>   466 |  if (kunit_find_named_resource(cur_test, "kasan_data")) {
>       |      ^~~~~~~~~~~~~~~~~~~~~~~~~
> mm/kasan/report.c:467:12: warning: assignment to =E2=80=98struct
> kunit_resource *=E2=80=99 from =E2=80=98int=E2=80=99 makes pointer from i=
nteger without a cas]
>   467 |   resource =3D kunit_find_named_resource(cur_test, "kasan_data");
>       |            ^
> mm/kasan/report.c:468:24: error: =E2=80=98struct kunit_resource=E2=80=99 =
has no member
> named =E2=80=98data=E2=80=99
>   468 |   kasan_data =3D resource->data;
>       |                        ^~
>
> What am I doing wrong?

This patchset relies on another RFC patchset from Alan:
https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-a=
lan.maguire@oracle.com/T/#t

I thought I linked it in the commit message but it may only be in the
commit message for part 2/3. It should work with Alan's patchset, but
let me know if you have any trouble.

--
Best,
Patricia

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKFsvUK-9QU7SfKLoL0w75VgSOneO8DWciHTDYMfU8aD98Unbw%40mail.gmail.=
com.
