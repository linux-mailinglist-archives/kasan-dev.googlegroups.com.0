Return-Path: <kasan-dev+bncBC6OLHHDVUOBBMFNXWCQMGQEDQ3KMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B977839296C
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 10:22:09 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id m17-20020a1943510000b0290240943e037bsf1802327lfj.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 01:22:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622103729; cv=pass;
        d=google.com; s=arc-20160816;
        b=si/pf+qi6jnbM2yfllRRyAUSAPJqdYucWMtyw1k/9nBLe28pdUVo12bPylPPAvg7FO
         N09h0phZT+nKvPRFGpfJ5Ulx+luqXhWqMW9XPQ9d0wOdMPxZWmFWvSo8kpTkpy1Byg89
         BhzQcnpjUu12k0UooBAxte2sYXQILU5LkUY9e3QqF0AYQlzJbSYMXAomSMTaq+ZSBH5Q
         cupEUVg3pvUvRq2Dr5gjAg7qtRSBAJPxVh8aadjT0JHUzCA3sp2zDrMaVY+j+cjS7zMk
         LO0ANPGR05sAUKDQkTQolbsqQRKc27aSbI/32mWZzpy8EFhUJ2/bnnlNmU/t58U/O+H1
         kOng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wf2mvN0qvJXOuZwKgInVzPyzCX8PA2OyS2J9VlDnamE=;
        b=P0akr3blDzLhpJuto3rLKgbgWvsQTaDkXEk1/Cc1gQHGpLObjpOio/fcYETccBdiur
         1LCZjTfftMAF37/YwbIVjYtCAP1SBO6RWM6k+ChXL36+psbJKKKl0sm7sXqHsmhzno7I
         9RUeR07wjTNcHH97ttemvjO6YUUPMzejejlRNypyXsXulQMloHpBsX7U5Jp2rGKxy2NT
         19o+bPicZtky4YJStGrY2s+Z3vr1p7PogWX1rYiRFJ24rlNZZKQQL8BrsX0+KqMJlt48
         KRG6I6uHySiV7mTdj/BHc5lWCa8dfBggs9JDx38u8KnV7bLLfvhBG+TWpZAa7Pi3cl9n
         oZXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=luW6ubII;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wf2mvN0qvJXOuZwKgInVzPyzCX8PA2OyS2J9VlDnamE=;
        b=jX868KeqxniuxbDA7bgvEDIhSZmkTdZ4P10HhTaZIr/auqq1xhmz9SDXNfxydzLo5w
         PlYMPQirv2yLi/RrGjWdMxYZFwOK3q3fp1wqhz4e3uZ+pJ8lE46FdJN1/s71pRvxsA+J
         G7xBW3VWCvK+o7AaNd3GTOKpyr8c10+mw9KDGk4r1TLOfWvE6vBUf3QImNsSEQcf928+
         wI0S2o5Y+lq+zpwcD4LDiz1IpEN9VMyIoyd46rj6dqhFsNR+H4QyDryvP3JW9RB9rpoO
         I7S2oLGCtPCkKyWRUFncQ8p1BvpzOgsrZI+H5io03F9uOX2yZPjLt6rIvMRurfzSqlwh
         sOag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wf2mvN0qvJXOuZwKgInVzPyzCX8PA2OyS2J9VlDnamE=;
        b=jt/+7D/dvqkMCYED65xMmTdS0+A6j19kYTbM7+lSXYSo75aYwolh5MyWmZkIY005b2
         OvMVIld0RlH2blAIXg5w/fGNglC6gJU06JPMvGwfZ0Om+mDXAXoAofiCKPGHvgh34kN0
         Yn5yuvqalyCs6De+kHFLASldRpvz3KRdBiDFrSQXWeyC+niSyxU2ojFQEswUCpZDuYAN
         KDUHo0OQn60qDyhdj1Ep3TwScniXj+ZkVwoTCxxI5W8c3hGBWIoR0sP5GxZfIx+L0mDw
         b7sXE1qRA0yyVYBOL5u+c+VjIw9fbDM60Gg5VPp53EUzHr/stF1dkaBnudKKkxC3khOu
         RhiQ==
X-Gm-Message-State: AOAM53042bDg5CUh/lZi2LHEzY2h/9B5xXeUOC3YAj1V0xP99Lc/3M1P
	ZsgkvO/j5fpatMVDfWV123A=
X-Google-Smtp-Source: ABdhPJxxUfxvVjtvGmV98V7NPrvqFVD2ORkURz8lSAYV4ixfVfLp39hJMiKHd8VqXghYV2WVnP1/1w==
X-Received: by 2002:ac2:53a5:: with SMTP id j5mr1605541lfh.618.1622103729209;
        Thu, 27 May 2021 01:22:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:230f:: with SMTP id o15ls1640414lfu.1.gmail; Thu,
 27 May 2021 01:22:08 -0700 (PDT)
X-Received: by 2002:a05:6512:3094:: with SMTP id z20mr1651177lfd.551.1622103728016;
        Thu, 27 May 2021 01:22:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622103728; cv=none;
        d=google.com; s=arc-20160816;
        b=K0nRIcyeCrSqf3ZQc5EHPa0HTMBHGUwTOg5V5z6o6PmiUtRc+4t1kPS8sKeSlOMCIL
         J3M0HXShDbgwsuERlSpsFR0FYWT7o3UaNQf9JFZ2ob1k87Q8YBuQgobkE7F7RieZ2Mm1
         vNaC09As3ZIZIpiGGt9S7o2278CFMxpidgEU4/aTQntoVUCDYVZ/75NFxoFpCY+pYQSD
         vvMKS0kB04asgZu+zIIqWmSwjAd1sdDgg6d0H/qxa6autZB33bq7VCtH2Zf1OFBQYcTw
         Zr8pDGI03ZOurvivaCQgP5Sz4nZKse7HIYZUjRVdJZ9/Q+uO3bUitlDH4gUiU5ZcHaOv
         eutA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7AhqvpsgmWy2utZlqk5NzWiQ2z3M3gpksG7TnXtqeGI=;
        b=q3RK3mcu7eD4QRsoqXwnP3jDMBsUlmNDka+EqpnlGTmY8ZXCaPe6WgCXlNvTOKYkiW
         J3+f/+sqbhfta2fiI+/6Sd/xgZlBFytQBQJvX+VPSfSaAewMvjyJY4bH7kLG4unPd2cf
         vfnc67wVnGjuiV330xM/KzaVe0TcuJKAVsiPt8tDTOy+AmlsnVfYhxEIqjY77GDBgrGg
         Szj62TElSGUuuACG3DG5xPeK89LXEKCy4j99AgFgDfaiSbKusmS6/KBb28HdDpTVafAe
         9149d4lr17hxJ0siROkiIHHWgOJMC+I3jzmUK30ueaAxM+wnRysqX8Z+1cM0+ljFnTNT
         S8RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=luW6ubII;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id w11si65139lfl.0.2021.05.27.01.22.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 01:22:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id m18so3818997wrv.2
        for <kasan-dev@googlegroups.com>; Thu, 27 May 2021 01:22:07 -0700 (PDT)
X-Received: by 2002:a05:6000:1147:: with SMTP id d7mr2067742wrx.302.1622103727662;
 Thu, 27 May 2021 01:22:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210526081112.3652290-1-davidgow@google.com> <YK4O1DkP1/DKzVU5@elver.google.com>
In-Reply-To: <YK4O1DkP1/DKzVU5@elver.google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 May 2021 16:21:56 +0800
Message-ID: <CABVgOS=Tw1NkUfh1pDfo-3stAKqg_Pt0EtM7+rH2Qk6EUw2+Vw@mail.gmail.com>
Subject: Re: [PATCH 1/3] kunit: Support skipped tests
To: Marco Elver <elver@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Alan Maguire <alan.maguire@oracle.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=luW6ubII;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Wed, May 26, 2021 at 5:03 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, May 26, 2021 at 01:11AM -0700, David Gow wrote:
> > The kunit_mark_skipped() macro marks the current test as "skipped", with
> > the provided reason. The kunit_skip() macro will mark the test as
> > skipped, and abort the test.
> >
> > The TAP specification supports this "SKIP directive" as a comment after
> > the "ok" / "not ok" for a test. See the "Directives" section of the TAP
> > spec for details:
> > https://testanything.org/tap-specification.html#directives
> >
> > The 'success' field for KUnit tests is replaced with a kunit_status
> > enum, which can be SUCCESS, FAILURE, or SKIPPED, combined with a
> > 'status_comment' containing information on why a test was skipped.
> >
> > A new 'kunit_status' test suite is added to test this.
> >
> > Signed-off-by: David Gow <davidgow@google.com>
> [...]
> >  include/kunit/test.h   | 68 ++++++++++++++++++++++++++++++++++++++----
> >  lib/kunit/kunit-test.c | 42 +++++++++++++++++++++++++-
> >  lib/kunit/test.c       | 51 ++++++++++++++++++-------------
> >  3 files changed, 134 insertions(+), 27 deletions(-)
>
> Very nice, thank you.
>
>         Tested-by: Marco Elver <elver@google.com>
>
> , with the below changes to test_kasan.c. If you would like an immediate
> user of kunit_skip(), please feel free to add the below patch to your
> series.
>
> Thanks,
> -- Marco
>

Thanks! I'll add this to the next version.

Cheers,
-- David

> ------ >8 ------
>
> From: Marco Elver <elver@google.com>
> Date: Wed, 26 May 2021 10:43:12 +0200
> Subject: [PATCH] kasan: test: make use of kunit_skip()
>
> Make use of the recently added kunit_skip() to skip tests, as it permits
> TAP parsers to recognize if a test was deliberately skipped.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/test_kasan.c | 12 ++++--------
>  1 file changed, 4 insertions(+), 8 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index cacbbbdef768..0a2029d14c91 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> -       if (!IS_ENABLED(config)) {                                      \
> -               kunit_info((test), "skipping, " #config " required");   \
> -               return;                                                 \
> -       }                                                               \
> +       if (!IS_ENABLED(config))                                        \
> +               kunit_skip((test), "Test requires " #config "=y");      \
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {                 \
> -       if (IS_ENABLED(config)) {                                       \
> -               kunit_info((test), "skipping, " #config " enabled");    \
> -               return;                                                 \
> -       }                                                               \
> +       if (IS_ENABLED(config))                                         \
> +               kunit_skip((test), "Test requires " #config "=n");      \
>  } while (0)
>
>  static void kmalloc_oob_right(struct kunit *test)
> --
> 2.31.1.818.g46aad6cb9e-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DTw1NkUfh1pDfo-3stAKqg_Pt0EtM7%2BrH2Qk6EUw2%2BVw%40mail.gmail.com.
