Return-Path: <kasan-dev+bncBC6OLHHDVUOBBGVLW73AKGQERPPOY7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E16011E35E5
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 04:51:07 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id i199sf4966930lfi.8
        for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 19:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590547867; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPzCgrsd/PnGjJMjcuaezCuSWeBdBl3+YNd7bmBZmKt0rPhFMAgdxwrcJEjx5vFur7
         Tree+lvbrdSyQ+fHgieNbPpHPXUORDljAOwqhR5uQzEKu3DcsuyLkFjuroshk8rzFjCV
         P4luUDPaCNxEK5qWa7QUrp1StApwa/WomfcdHA1dzxR7pmT5CFWfxsihgEuClxPk4sND
         0VcMNTkRAIsrX0Cqrtl6Y61UhXxUtvAPTBFgGwOnWdD3ccIG7Rs6VlgzuKVN7IdOkBKm
         +5JZUtx2K4uqqaeytJk1v4BX8gmF+2lbqGdBbgw9X4BbtovZuCHmTyxPycJ9JKmT1vst
         slfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=12AKo0PW+G4I4hSk9P/P8qJJrgp6GaIqGW4MiGn7wEY=;
        b=VTmYOpdMvtSv640YYKahOcCAJnd8Z7aAF578G8Vb525HBf93kCXcm1fgMkuXOVUhcN
         yzNFfB5TgAte37RWrVYyBS4Dht8RVrSDkLDgW2AVL4Jn/Zg16FOBBoHDDJgbWd5Tz/gv
         qDoMmc/tZP1KFb4PcA1NOWm/x9gGCJK4Qu2XJfkDvt/3Fx53MIfYX5peTm1lZRTk+CwU
         KFUpLijt/Ln73sMbdEhe8rGTGpE8EHigns/abeRiYR04HN05AwN+vT5HArJ+ylM9kj4l
         okOBKeES0iNtPbvZ9CSkvy234sF+roHmBw4mbPFyfKNLeEMBVcSPrAPQgc0zbCjk2JhQ
         5McQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="taXQRZ/f";
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=12AKo0PW+G4I4hSk9P/P8qJJrgp6GaIqGW4MiGn7wEY=;
        b=mTNJO9APdV/OTA5JQAJPsanLGUOYRpgvWtqX7mP5tw/5crbDqrYvhX7lwa+BAjNLr2
         DJ/cTMDCishGtrGz0LdYd5J4r9UBFF/nl9PGlsqjpWyT2Cqns/P03fTJf0IZzI69/+QP
         xJCW6oZzQu3EUrwCoKlIlu0TTMfKui0GXdl/D14JVyic5VK5kLGXEavnvTrbGJ13IaRV
         ZLgxzEIlU9CrsjUrFEJFJq78ZivS1nUgeq5Bjnxa4754b9PI2vuUnWXTzJXDynoT7Tto
         4Au1wvvHelnFtH9wIJaPlzc2JzG31zpViObE3ZvbtZoRjedi9y1HCR0WSo8kH8TT+6W/
         V6EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=12AKo0PW+G4I4hSk9P/P8qJJrgp6GaIqGW4MiGn7wEY=;
        b=Yt+1Bq1Yf1m4J8hnVbEglE0vf2edG/M7Mymbgd0GKLo3mUw+hyyWtHd/qF5uzuC7sc
         zzdL3m74c0kpm5sbrvFQ8gjMDW7urif44zGrJi5RwmvzVybrCxQZIjlrPljeYrAk1ncL
         z5bBvFeGcbz3NeKp7mtdPOwLhIYmFu4Pq89+N/dggO3IxzqUAnwK5S5Ani2iGFQ72tAa
         xOQbVfhhpReNZzv1TlMHyX+0VXrmmFwsCmJgJznnCw5gnkiCZXt3EzmzzG1s1yAZj/nY
         FNoATdc72Zg0A7P70sjqXpO7/5ZtuzKHzz6pTCTWSJgtY19Cwevkgpu6ILw7FnnW6vcw
         LrFg==
X-Gm-Message-State: AOAM533V4fXrNSTNM0ZNk8nmSl8gEnCkjeEXleeZrClGOO7Bm4pQ22Dq
	UNZXKtFMocDGwM2pD+qGMCo=
X-Google-Smtp-Source: ABdhPJyNm/jg1aaWwIYICSo3qbS0zlMfMIdXs+qOmAa5t5EbMfljsqb1GlmZ1JMXHrJAdA2TYGFjEA==
X-Received: by 2002:a05:651c:1035:: with SMTP id w21mr1944250ljm.278.1590547867046;
        Tue, 26 May 2020 19:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:43bb:: with SMTP id t27ls3753231lfl.3.gmail; Tue, 26 May
 2020 19:51:06 -0700 (PDT)
X-Received: by 2002:a19:e049:: with SMTP id g9mr1919111lfj.198.1590547866299;
        Tue, 26 May 2020 19:51:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590547866; cv=none;
        d=google.com; s=arc-20160816;
        b=dDaxarNBGv0n5tGgEbtodorqsCj2OmSJx73JREjLn5EgqQbhy0zZ785IMXKqFG5P1I
         Q4W4tPNftO65a7p39K/ALVzTFAwdbogHd05QIey9nZx2rmTHdpE7JdTU4owqcafr3YNC
         8uh7Gz0u2j4WEUByGr0vGZZgmTvEgVhyp0KS1Cukd4jQIdBG0DO4jxNUDrvCiF3pbbjM
         SSPNFRQyv4uDfq1ibtdWwrTad50A4knQzc0xRTbxBDAOQFXpBc58eUybTIpRP4n4pTT7
         CK6VVz2G65sJOkp1oXl9Tpyk5cV8tsn+fXqytGuCdAxt62zCkqzCcsLc7lMCNc9cgezv
         gVsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LaRXr+sBaHv3EXaCNPBVevZdSo0W53kZX/a6MHQcNAw=;
        b=KXf7XaX6frKHo5E8OjovBR0rLeZRjmyykDQhDodq9X2ACxMn3ZTtcEhkwZRol75FFS
         TQAyuWyKcPxEGneUfOqoBtxvzDJpVZNRbv6Rtb66ELhRc65Qwf3eeiU8UeJ4ubiSLqXI
         Mab6A5SfJhqc3blDDwOIOOxxSbLDPRhjGq3sWm5luCtbWm+lsiAWhHHemGzZSVgUwfsN
         nlYfvPW+6dAAI6AjEWbvbnCX/XtccT6rt+0l9RlII9VQfmLX+/ORV7urFSrvR2CdBlye
         onxOQ7rHvj8WF8HwdEIku3omQqDt15AXICNeMuokVZH730dqAVhTYv6PnUapgqwLiktx
         YIow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="taXQRZ/f";
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id r21si106353ljp.0.2020.05.26.19.51.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 May 2020 19:51:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id j198so1263906wmj.0
        for <kasan-dev@googlegroups.com>; Tue, 26 May 2020 19:51:06 -0700 (PDT)
X-Received: by 2002:a05:600c:34e:: with SMTP id u14mr2056425wmd.16.1590547865534;
 Tue, 26 May 2020 19:51:05 -0700 (PDT)
MIME-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com> <alpine.LRH.2.21.2005031101130.20090@localhost>
 <26d96fb9-392b-3b20-b689-7bc2c6819e7b@kernel.org>
In-Reply-To: <26d96fb9-392b-3b20-b689-7bc2c6819e7b@kernel.org>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 May 2020 10:50:53 +0800
Message-ID: <CABVgOS=MueiJ6AHH6QUSWjipSezi1AvggxBCrh0Q9P_wa55XZQ@mail.gmail.com>
Subject: Re: [PATCH v7 0/5] KUnit-KASAN Integration
To: shuah <shuah@kernel.org>
Cc: Alan Maguire <alan.maguire@oracle.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="taXQRZ/f";       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::341
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

On Sat, May 23, 2020 at 6:30 AM shuah <shuah@kernel.org> wrote:
>
> On 5/3/20 4:09 AM, Alan Maguire wrote:
> > On Thu, 23 Apr 2020, David Gow wrote:
> >
> >> This patchset contains everything needed to integrate KASAN and KUnit.
> >>
> >> KUnit will be able to:
> >> (1) Fail tests when an unexpected KASAN error occurs
> >> (2) Pass tests when an expected KASAN error occurs
> >>
> >> Convert KASAN tests to KUnit with the exception of copy_user_test
> >> because KUnit is unable to test those.
> >>
> >> Add documentation on how to run the KASAN tests with KUnit and what to
> >> expect when running these tests.
> >>
> >> This patchset depends on:
> >> - "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources API" [1]
> >> - "[PATCH v3 0/3] Fix some incompatibilites between KASAN and
> >>    FORTIFY_SOURCE" [2]
> >>
> >> Changes from v6:
> >>   - Rebased on top of kselftest/kunit
> >>   - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
> >>     incompatibilites [2]
> >>   - Removed a redundant report_enabled() check.
> >>   - Fixed some places with out of date Kconfig names in the
> >>     documentation.
> >>
> >
> > Sorry for the delay in getting to this; I retested the
> > series with the above patchsets pre-applied; all looks
> > good now, thanks!  Looks like Daniel's patchset has a v4
> > so I'm not sure if that will have implications for applying
> > your changes on top of it (haven't tested it yet myself).
> >
> > For the series feel free to add
> >
> > Tested-by: Alan Maguire <alan.maguire@oracle.com>
> >
> > I'll try and take some time to review v7 shortly, but I wanted
> > to confirm the issues I saw went away first in case you're
> > blocked.  The only remaining issue I see is that we'd need the
> > named resource patchset to land first; it would be good
> > to ensure the API it provides is solid so you won't need to
> > respin.
> >
> > Thanks!
> >
> > Alan
> >
> >> Changes from v5:
> >>   - Split out the panic_on_warn changes to a separate patch.
> >>   - Fix documentation to fewer to the new Kconfig names.
> >>   - Fix some changes which were in the wrong patch.
> >>   - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
> >>
> >
>
> Hi Brendan,
>
> Is this series ready to go inot Linux 5.8-rc1? Let me know.
> Probably needs rebase on top of kselftest/kunit. I applied
> patches from David and Vitor
>
> thanks,
> -- Shuah
>

Hi Shuah,

I think the only things holding this up are the missing dependencies:
the "extend kunit resources API" patches[1] for KUnit (which look
ready to me), and the "Fix some incompatibilities between KASAN and
FORTIFY_SOURCE" changes[2] on the KASAN side (which also seem ready).

This patchset may need a (likely rather trivial) rebase on top of
whatever versions of those end up merged: I'm happy to do that if
necessary.

Cheers,
-- David

[1]: https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
[2]: http://lkml.iu.edu/hypermail/linux/kernel/2004.3/00735.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DMueiJ6AHH6QUSWjipSezi1AvggxBCrh0Q9P_wa55XZQ%40mail.gmail.com.
