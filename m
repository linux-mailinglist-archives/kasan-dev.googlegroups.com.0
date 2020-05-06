Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXNBZL2QKGQEFTEXUQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id AD1631C6E55
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 12:26:38 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id k3sf372670vkb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 03:26:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588760797; cv=pass;
        d=google.com; s=arc-20160816;
        b=K4DA392ZeTkQOVBOPCMc0auBTG56H4s3Bbf4htmNV2ntckiWK54gHCoRe4SmnjvUCn
         vfr0ooBWKBhfWm12cFsJWs91whFpuaef2QfBHYrJQMvWEjt8D3wvTixUaZBKauMK+IGD
         HFsgMwxYsfDTQW/sd4/FhBzTBXNGqpoXro+ZmhYup49VCTgaO4I1PnC//8xiUFyxdWm3
         Zna2c7gbouMhAImB4GW4eDN6tztIxViVPdh1CwZwm0J1CC1L0Wlf3ev6ovAgw4qAMJSa
         HT49rD5mjDJNninp2LaA+FqpppzSMW6lQsWIB2nsjVBqs8vo1EULxKTVjoL6yH7dNc+r
         1aoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wl6XRmBSOIBs51TUEZ15NEJnYP/vHErNTwWg9moSES0=;
        b=ue6Ro51+H2Ouevq51OqJQMmGSris79l95huwSyaj4rUQPrRS65i47GP0gyobq9gKIQ
         HtZLc3BXua9IUTArqzakxdxFoWnN896Q1BU4EOvXo9cFEpQNcynR/fQ2EeoYDSICHpbu
         VC9i0YqZw+859YX8KzoNMIJ7kvmrIQgPZVvbb4DbUDYss91Gzb45Dr8k9d6My8+1ovDw
         c9EIaMJTTaAkpw16ZKkRHtlBYIIDRQiKyUVWu36QOTKY9hyAgeTYPg/5ArP6tWILmc9T
         p1OjakpahrOF0yq0Ne+BkXy15I0YRD6aDtFBNc3W0giEU5cnJabj55t8mkkJ6+PafzL/
         f3EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SekfQuef;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Wl6XRmBSOIBs51TUEZ15NEJnYP/vHErNTwWg9moSES0=;
        b=fU/sVqhyMWniXV8uvZQDUpPIwP0qsuaAb+FVnlR1kqgnXsELj+wWHpwFi5AGCKCGfr
         t7GnQSXRyHd6vDNktlkPRO7dNoZB0NgRnPod1XczYK5RVZi2otewV9mfA/wG7NfVyyQM
         H6MhqciWibfakl1rOA8hzcACzmpKkADuciRMDN0p1uT+CHOK3zc3ndyQhu1RMg5DxShi
         OtU9TqCxHcqsT2at30IodL8shRwLudCqRjVfd70BtoJo+mLbWr0oclU/hrhUcqcwVsL8
         SRWcArS1FZRjNTr/knNXAX434gH5mem2PJvKwCjCbzHsxrgE/yURGnqINrD5Ne+7CLI2
         pRnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wl6XRmBSOIBs51TUEZ15NEJnYP/vHErNTwWg9moSES0=;
        b=PZHafPwTzPBmmxa9zK77quc7c6Z/rLPLHjQmAQ6I/HNPP7HGsSs3xWJGokQAgPjIKv
         LVZG4iIdblH2YY8HMtilJCmynyGxI4VkGDFzJuYbWHpGFrXwviJJZhjkBZ6Ac/X41lan
         UaFSLnMPDAsQ0ZJkpgFOvJ9PQ8YyJY8Me6V1lOZYoGWPV0T9NfLrlPVDJMF8OwYiIlNX
         7uWOjY61qcrvPmEtWOcKsfCk4Tns+2FhkaN/eWmF44DcAUHCJe1EGK+qaljPuRD12Q1u
         nzZuL+C9JETHcAG7x00Xzi1vQ7p/zJeiMeqs7TRZ3Y1op28rfumnluTJJic6Y2FheKg7
         oo0w==
X-Gm-Message-State: AGi0PuaYpiWoaLLj0zUWbxnR0DRcZBpthYCdky2p+A1vlBooSwmhgvNK
	cPLbnDwYsjSKdglAxhlx90M=
X-Google-Smtp-Source: APiQypIsdaLq8U7RxEuABtJY4WUbX0KpFGT3WvGxdUJsFGq7O6yhtGPp640m1QCgdGRik6JooxLtmQ==
X-Received: by 2002:a67:fb4c:: with SMTP id e12mr6269721vsr.79.1588760797701;
        Wed, 06 May 2020 03:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3184:: with SMTP id x126ls194317vsx.11.gmail; Wed, 06
 May 2020 03:26:37 -0700 (PDT)
X-Received: by 2002:a67:7784:: with SMTP id s126mr6733153vsc.223.1588760797330;
        Wed, 06 May 2020 03:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588760797; cv=none;
        d=google.com; s=arc-20160816;
        b=LpeoaYzMgLfJ29QBC/9m1Lk476+0/Y5Hx3AJpGpvQ7CGIrQDX64fAWQK6lJke2blBd
         XrEtq7oPTzkGVDpTKFELCQtJGf4AlbL2hAMoGe+QErfFdP6th/rwSrZ5GH6eHw+MCnnW
         JAY8Tc2AEBpkKxjHbdhxV6CigFacvNFvkfmPoV7GQY0eYXbYiuSWNbM0Uxa/mTdfYpRU
         K2mVPZdAKEUomLKjONRBGq/1PJmBLsj/wR4uGxxfsSzIrJTNrDwfPyVi0DCEOZaT4Ce5
         sbWqsFXukJBUVbZcC3LxDxpUgnIZ+U/D12IPTNVnhWXavtPef8Mjwr9zWRUyUFUQY0wB
         68sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JJrxKPKyOXug7kU6AgNPvK7plqXWXoHNTpGsuarqFzQ=;
        b=hqUtiVh6bIbVfczTtb6kyiatjyu4YwQmNUgX9gDEqNdRNi9erHXctHa5ZOamjA3OWj
         ZiFiGW5j9x1Ml3+jhvFtG2b1zA1GKsBuA81Rwzw/05adZ0znaZ+R67JSFKK2UXqCCEwk
         +2m5/dzjd0riFZ7wHCJ2zmm3IDJvB6y6ItSn0e0hEFs06zTnd1zPzKSwLEKfXOdP3oDy
         sDGcy6nEPNHrwJLYmmudZ9yFrTJHDxArRkfVujFGbYYEk4TsEmLrHUWdNovulZImw0Ee
         JYDlQsOUJYwmeOVJBWQVhMIb/SdAgJNjkgGMwyDOo4jWa+SOgQmIuP+MwrDfKzqgniIJ
         b43A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SekfQuef;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id a205si100739vsd.2.2020.05.06.03.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 03:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id e20so896143otk.12
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 03:26:37 -0700 (PDT)
X-Received: by 2002:a9d:68c5:: with SMTP id i5mr474295oto.251.1588760796552;
 Wed, 06 May 2020 03:26:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200505182821.47708-1-elver@google.com> <CABVgOSmg8z1TpMh7NPy0M+9Gs2JT097-j_XGBRGhKk_3y2J-oA@mail.gmail.com>
In-Reply-To: <CABVgOSmg8z1TpMh7NPy0M+9Gs2JT097-j_XGBRGhKk_3y2J-oA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 12:26:25 +0200
Message-ID: <CANpmjNOF5mPzU+TT+LftpfLFEhWUy1s1To1rsPXZBORTgfM_fw@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: Add test suite
To: David Gow <davidgow@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SekfQuef;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 6 May 2020 at 06:45, David Gow <davidgow@google.com> wrote:
>
> On Wed, May 6, 2020 at 2:30 AM Marco Elver <elver@google.com> wrote:
> >
> > This adds KCSAN test focusing on behaviour of the integrated runtime.
> > Tests various race scenarios, and verifies the reports generated to
> > console. Makes use of KUnit for test organization, and the Torture
> > framework for test thread control.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Thanks, this works much better on my setup: having an explicit error
> for there not being enough CPUs is a lot better than hanging. It'd
> still be nice to have these be "skipped" rather than "failed" at some
> stage, but that's a nice-to-have for the future once we've implemented
> such a thing in KUnit.

Will keep an eye on KUnit adding support for this, and in future we
can change it. Although I'd argue that these tests failing is a signal
that a particular KCSAN based CI setup isn't terribly useful at
finding data races, which can still be a valuable signal to have.

> I'm still a little hesitant about non-deterministic tests in general =E2=
=80=94
> even if they're only run when CONFIG_KCSAN is enabled, it's possible
> that a future CI system could run under KCSAN and report false
> breakages on unrelated patches. Given no such setup exists yet,
> though, I think it's probably a problem for the future rather than a
> blocker at the moment.

True. But as noted above, it might also highlight an issue with the CI
system's ability to detect data races if KCSAN is enabled, which is
the whole point of having a KCSAN test setup. But yes, let's cross
that bridge when such a system actually exists.

> Regardless, I hit no unexpected issues in my testing, so,
>
> Tested-by: David Gow <davidgow@google.com>

Thank you for testing!

-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOF5mPzU%2BTT%2BLftpfLFEhWUy1s1To1rsPXZBORTgfM_fw%40mail.gm=
ail.com.
