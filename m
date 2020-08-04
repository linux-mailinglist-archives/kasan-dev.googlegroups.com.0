Return-Path: <kasan-dev+bncBC6OLHHDVUOBBA6YU74QKGQE6YCVXRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8243A23C219
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 01:15:16 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id v17sf3964312ljk.20
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 16:15:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596582916; cv=pass;
        d=google.com; s=arc-20160816;
        b=o0TzTYcvkYeEoy/IBabt78QGPdAFcjIHhrGwEqcujnam5oy9Ro2guoKQIb/ITPdJHD
         BB5g+H1RXDEQcm7id6Fm+AWeyaC0CaPtzGJ+/FbhkFVsg03SjXbp2mK0b7w+1eIq158C
         FIkOIa7ABi3WPRs9qR16YXlg31BqtMvYZFP+0YApBszNIc6aaAiXxT15Z2MvOZjll1+4
         yHy+gNmka/As2l80By7aLJbx3jCTLORqfmxR6bMQOVF+4X09HFtFSY+at8lFGPB/7sP9
         AfdjnBuzEorlLiuNW8OHutO1O36ezAdMzEyhNSsFf1rwm92yrAaTkuZKS8yJfAZMpmpV
         bHiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=au/D0PdsuVtmXDTHOvkTupaJHg2K1MewOLr+5lO4Nws=;
        b=ZNhLSvaliHgkJEgYUGXl6r40n3bKiJ6fb2rp8eT7CMm9wk19YXnuhMEnXzoJRDqsKg
         EyZGdLl6FWnNewmm3eiaBUZ6+ZThDKzV2QnQxsUs1UGW/a963UXy5oyOeNy+1eZyHlQG
         3tAAQiMJ62dmyOqafx91NPdYIFMXiBo8tWbRKzUm1gNU2xaC2FVhSyP79nb8G5Uh3d1G
         hcoSV6wEWhd1n0JqctxLJNt7Kq+mF/kDXFPNArTcjGQ9livJkO1Bc7ZGi5zEDcuSdqkm
         OLffNgbCGlD3r2eSDQlrhte6sjwuz8ykD2tURKKrH6af3ut1jmgXdGeKr0hMEfOwwH9D
         6/EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vKJZJB4t;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=au/D0PdsuVtmXDTHOvkTupaJHg2K1MewOLr+5lO4Nws=;
        b=iQvgGrG1Rk4qoe2jx45/KHSxL0oHW0Frz7JEhJfgncFu5/2uXqZeeXJjphfPhumh3D
         3DEKqtteaT941LR4U3VcD0jn2WUit5nTTZj/fbt98FcH+IqebfBaCKetL4IULGn00fS9
         I8OOgKBTQaeoXuFCDYcB9X2ISPc1bvS/tzfHpB3zShPsJXW7G+149e0mHU+pyxWBAiT9
         7bhpSB4I4vop/FzlijV/e4spMAGdnomSzXNSUbvz2bUMRSiScrBQFF9dKRpymYiGH+TL
         8pffDtuK+4z8nkwp32DxIhxq4kZKYJDfG/1jMs8N4NhIMr/ez7q70/P7x6+9ob9DoTdY
         qQzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=au/D0PdsuVtmXDTHOvkTupaJHg2K1MewOLr+5lO4Nws=;
        b=qAgdeop28dQKYac7NMoUmBrJKKFbpC0/l/SyG6bYzJnQudurwcxxXE6d99P7d6GJtL
         T3yLuSZbaBjP1t3C/uU/jx1cUZNvGppmGN7+PO1ve0fe9900qLjyURPj0LCPXkaHeX7C
         MaqAJ24zJbn3nZzkCYcZltDV1J3Q3ylRoGrjdpkBJ76TgXWDsTq+yl17TM6uZjoQhwuk
         8FsMCoMUkponbxHiOLMFMbed8W/5rjqFZFxSK39s+P5g8mdo3PfWakqkGtUbtxROd1mK
         Emf+XvPSeOqeoUGYJzNq1YoGfts7gbX/Rmz5w07niJ+WR1sUzERtTET+H0fX/Vl5FGzo
         0aEA==
X-Gm-Message-State: AOAM530S1eTXX8EG3b+XBvBQvP1/3eZgvcYplNZJd+2SC3puJv29exRj
	OOK9geHgLFLEpvZknBGpTnQ=
X-Google-Smtp-Source: ABdhPJwugeyVNOlflUcCYMsdgdPKnhQpxJVK+grgUjYwPBhhApon9uxOGO5n6Vo9T/9Kh96nh/hAdw==
X-Received: by 2002:a2e:a370:: with SMTP id i16mr82202ljn.22.1596582915935;
        Tue, 04 Aug 2020 16:15:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6c18:: with SMTP id h24ls28660ljc.6.gmail; Tue, 04 Aug
 2020 16:15:15 -0700 (PDT)
X-Received: by 2002:a2e:7e0b:: with SMTP id z11mr61200ljc.133.1596582915134;
        Tue, 04 Aug 2020 16:15:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596582915; cv=none;
        d=google.com; s=arc-20160816;
        b=hWGPIKo/jyctj9ZDxCP0bQGZNyPsoDnTbWwu51fQBxGGKgyaRTQsiV3bjzH2J1tYfE
         hlmwMqhR7VbtQlMZUnn06OkBLu02i7njCs+k+aVGs5uFhz6OhdWTCmc/eLgwI5AQdqnz
         cYZyAUlqUdjz1T2eu2S3GJPd+4YhG8O3ooQb0ZMx27ruAV3bsSmdtdlYFflkG0h2wZNF
         D96A426P3Cb/2nCZE00oJyaZz3rp30q6ef8fGzysZP0QgIkAsr5HcIo4rbciCq8dVrqR
         fCIErr7TdZe2yP81S/CjX95Wo3BZDHhAbpK/qVtgmiCYFKP5/QohQbae9JMGVwfY5Vaq
         +6Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K9gpV2EukdQDh4ZPc/03X4i9rg/1FfiYZWy/TtTUyw8=;
        b=Ph3zKhnB/64SZACWkQKM5mVunSp9RIqfKyNfsm/0TLBE7vv7wC6YlN1D71b2Z/hknX
         0UA4egqUOxeAWfUzBC75SM6n+KFHlcVVI3/gT7HC2SeJN7ELfiPBbPRiqMRvtIvO0k5J
         a062PmKBxOcB71z/5G4oFmVwmUp69Pg8L0RCm4f37i6S+n2leaUI/VCWFrOxL71ghG9n
         hP57BXFripVyhQnrQx4zI7iWlcsK2f2oQt2hjLCVNBzOuc/4vL3SgTUep1S+LMJULqru
         m1qfrTDWIfyNGh4ML+fwUjCLbuKDpyNs83uwowMZvklVxItO9piQQO5wbnf/MxUnSpuG
         YI2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vKJZJB4t;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id z26si22231lfe.5.2020.08.04.16.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 16:15:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id a14so38922276wra.5
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 16:15:15 -0700 (PDT)
X-Received: by 2002:a5d:4e8c:: with SMTP id e12mr191888wru.19.1596582914310;
 Tue, 04 Aug 2020 16:15:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com> <20200801070924.1786166-4-davidgow@google.com>
 <CABVgOSnpsnYw=0mAks4Xr2rGe07ER1041TKCCY1izeCfT8TcBQ@mail.gmail.com> <CAAeHK+y5KBuAfpeO90X0rxyZmPj4OQGUF=L-q3GAgQUTFNxdsQ@mail.gmail.com>
In-Reply-To: <CAAeHK+y5KBuAfpeO90X0rxyZmPj4OQGUF=L-q3GAgQUTFNxdsQ@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Aug 2020 07:15:02 +0800
Message-ID: <CABVgOS=fOj++o2sBbOAwnKJSC+2s4dE6pDuuZNHYq+u_ayPiAw@mail.gmail.com>
Subject: Re: [PATCH v10 3/5] KASAN: Port KASAN Tests to KUnit
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vKJZJB4t;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442
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

On Tue, Aug 4, 2020 at 6:15 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Tue, Aug 4, 2020 at 12:59 AM David Gow <davidgow@google.com> wrote:
> >
> > On Sat, Aug 1, 2020 at 3:10 PM David Gow <davidgow@google.com> wrote:
> > >
> > > From: Patricia Alfonso <trishalfonso@google.com>
> > >
> > > Transfer all previous tests for KASAN to KUnit so they can be run
> > > more easily. Using kunit_tool, developers can run these tests with their
> > > other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> > > report instead of needing to parse each KASAN report to test KASAN
> > > functionalities. All KASAN reports are still printed to dmesg.
> > >
> > > Stack tests do not work properly when KASAN_STACK is enabled so
> > > those tests use a check for "if IS_ENABLED(CONFIG_KASAN_STACK)" so they
> > > only run if stack instrumentation is enabled. If KASAN_STACK is not
> > > enabled, KUnit will print a statement to let the user know this test
> > > was not run with KASAN_STACK enabled.
> > >
> > > copy_user_test and kasan_rcu_uaf cannot be run in KUnit so there is a
> > > separate test file for those tests, which can be run as before as a
> > > module.
> > >
> > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > Signed-off-by: David Gow <davidgow@google.com>
> > > Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
> > > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > ---
> > >  lib/Kconfig.kasan       |  22 +-
> > >  lib/Makefile            |   7 +-
> > >  lib/kasan_kunit.c       | 770 ++++++++++++++++++++++++++++++++
> > >  lib/test_kasan.c        | 946 ----------------------------------------
> > >  lib/test_kasan_module.c | 111 +++++
> > >  5 files changed, 902 insertions(+), 954 deletions(-)
> > >  create mode 100644 lib/kasan_kunit.c
> > >  delete mode 100644 lib/test_kasan.c
> > >  create mode 100644 lib/test_kasan_module.c
> >
> > Whoops -- this patch had a few nasty whitespace issues make it
> > through. I'll send out a new version with those fixed.
> >
> > I'm pondering splitting it up to do the file rename
> > (test_kasan.c->kasan_kunit.c) separately as well, as git's rename
> > detection is not particularly happy with it.
>
> Maybe also name it kunit_kasan.c? Probably in the future we'll have
> kunit_kmsan.c, etc.

The name here uses _kunit as a suffix as part of a plan to standardise
that for all KUnit tests.
There's some draft documentation for the proposed naming guidelines here:
https://lore.kernel.org/linux-kselftest/20200702071416.1780522-1-davidgow@google.com/

(The idea here was for kunit tests for modules to nicely sort next to
the corresponding modules, which is why _kunit is a suffix, but that
doesn't really apply for something built-in like KASAN.)

-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DfOj%2B%2Bo2sBbOAwnKJSC%2B2s4dE6pDuuZNHYq%2Bu_ayPiAw%40mail.gmail.com.
