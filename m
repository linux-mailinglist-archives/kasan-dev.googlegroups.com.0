Return-Path: <kasan-dev+bncBDK3TPOVRULBBCH243ZAKGQEA34IDAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E513B174421
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 02:23:25 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id w3sf1148713wmg.4
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 17:23:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582939400; cv=pass;
        d=google.com; s=arc-20160816;
        b=l3Jw0mB4KjC/FzWCYA2QvomMpPlw0+WMQDGdQYSto1oU+U8Qccvcsz0d87X/aUiS2p
         iMz6HDUUR73s41u3thafiiblINWMJD14uzLPHR+zhsOCCKzGO7NBXDgkpPrfUuIgYIO8
         NSpY0i+tpZYDchIOEwTMRZ0mO8XQiNc78bUpGaHOTBmdzFy3nv/yJEWymGNofaSX7LL9
         2dtud6G41EJ9o//8LmmC1HhecMR0lQmrImi2YNxC9AzYoNJ4ZS+gr1opaBGR60otWCWF
         mxHeqbHVLvmU+TWb0EHqO+TPJePHCE5qeWq8kKH3ylMlhTkINWiFPFv7z7Wws2Xk3Gw1
         vVOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Hui8SHrPQbuHgII4UFt7OxBpXvPUkRVonrtlbeZusuw=;
        b=roMA8Q+5fef0GJWeaJQVMyN4HOlMFDAF9lAn6UNJiW8TK6LgbYdeT0h++3SLyqetYF
         DY5I4zmswig+JAcgzVy94z/AwZ/Pl0T6kszzEkdUGwbyAl/0qvJdjnJ7oWeGNGU5rqeO
         Arex6bIHAKoHapBlHco+HX4n5pTFDx6ZZUJVa/wDl8DwXtKPuKcLUJ3SwApsMOW3o84o
         RBC7O0lTESarH38yOC8hqB03Q9z3UwHijPeJJPoFGh+DeKUTsEJifyYjRxcpl7kBkWok
         G6r1dMRWK5+fGOzBJ6QjEhGrEYd9TM/r53liPMPab2rtOpjuKDRJctou05ri58q7aPwM
         Pe5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Irm3kkRL;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hui8SHrPQbuHgII4UFt7OxBpXvPUkRVonrtlbeZusuw=;
        b=bOrh+LwsbF77+aAlDD8O8p9a4iVA9sxhucSB14qouvbwBAQy9AZkoF2KMme3gv0FME
         IgM/rosRaWH/B4N8UGzDYDun9RVYtKhQQ20USuVowBk5RGZbBMu64a/HAq+Bq43A0GYB
         IWtIcipjil9E8UWMCfAHk2tldrv1plCsjegZkmxzYJ4FGQen5FfU21IWzHYRJ2rLQOc/
         EJsUSdSsrm5sNarBYPyruAxuec+Qb/k8oprYWO6o+NwQuT2rne86L5Uh/UeiDwObtodx
         hPluAR58plstNOixUVTLvDMAMKRY5xhT/10uu+G3jFkkOoPWsIV7wM7OWey7J8XzMZtj
         AtUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hui8SHrPQbuHgII4UFt7OxBpXvPUkRVonrtlbeZusuw=;
        b=UFQflj3MABVHHbjmQ0qscnQqX0Te4BDAltp6nbD2PuJBs06zI1AtwTAZ7ybFipadne
         ucBWluD5vdrut+ZS/d1Vra9fAa0qvsNcqXzLx1xcbE+umLkjOyQc8W7jpju/VeuUcnT5
         vXIB2M9ECD1Nz1EfOVqk7Rj7/OXSu2awrhprFX+MpBLpXHYjiH0qrQkjtL8pAUo1wm/M
         sfY6U6rFS7q44spZGy3xAahxLPCrv/jQq8pLB0+UJiAVq6ARf3WlLzcry7NfnXGDsE1C
         jFrnkcZ0r7E329jf7h94pGu8p+0XYE8IvLEim7Vxcg6a9NQd7qm3vtONaZJl35woTA0P
         v9uw==
X-Gm-Message-State: APjAAAUhFDhkO7CmTyzD9nt/qIIPIiWyA4Eqh6w8U2uIkmoS2KY2w8o8
	KDyWRLGAzC1T/c461pW6PQo=
X-Google-Smtp-Source: APXvYqxPjttSVhltcAIeDTn0vLG0TVoJpQVeLvH7i6ThtzyHe0UxBPoik4MBc038N2q557FdZN5cHw==
X-Received: by 2002:a7b:c395:: with SMTP id s21mr7707950wmj.121.1582939400421;
        Fri, 28 Feb 2020 17:23:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:100e:: with SMTP id a14ls2085003wrx.2.gmail; Fri,
 28 Feb 2020 17:23:19 -0800 (PST)
X-Received: by 2002:a5d:488c:: with SMTP id g12mr7566348wrq.67.1582939399917;
        Fri, 28 Feb 2020 17:23:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582939399; cv=none;
        d=google.com; s=arc-20160816;
        b=0XEq74clJJaz5iJfGFiy5F0naMvSZYJ+GnBlJkkNxm1C4IBmRtopRfvsW4inoTdf2C
         wr78R+ZXe7G50iUS4M5DLNpvGkHMI4OTBoFZJyXYKSQDHKNr0Tb9k6N3xOeaf/LOH+4E
         QQfkmsSda6/ln2dfbcYwq5qHBn5n7MHLm1C4XJq2absO/kbPEe+3gKVBvzX49E/5MTSw
         54BUKyrNMqU7K8j5WRvLMKlddN64rXSsosjhUsHkcpRC4on3kpQ6MDrteqwTwTzcmtii
         AcK/KVfIEchPUBf3oeHV0hot+WdJto37LDNmqVC7okDfhNZWR95DZs/kA5uLLzXaxg78
         LPzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i/7YNCxPMBaPfRc0r6hwDsD4AYhHuz/+hoGyVq9vhR0=;
        b=W6JCLH2kqS39Rem/s/TviHOiA6YsKguKbJN0hudCiGTEmHs/nSUlgBRNsCEs87yegd
         i9m50EEjJBE3iZ0UVwVHiyRypm2KhYT16lt+tsBVI8d7tYae6BBiWpwg82YqFUavHu7p
         tGi0N2pmvfqfAabufxHr0g1UYK2ovYyIA3RMScDvrStrNGiq2ClhN5cJUSZIMJOPSdr9
         e7EoBgt6pKgCqLhYO8qqXGO451ykyQkwWPNwWUfEnOvDhgZ/ccoLIY9i7iuFUdeGijSn
         AKwTCbTgQYo51zIA/FA7zgW/OmphaH4ZSmeOPM4ws3QmmK4/s/YrIZQPit58JFFtR1rM
         zp4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Irm3kkRL;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id h15si261655wml.4.2020.02.28.17.23.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 17:23:19 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id p9so5404764wmc.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 17:23:19 -0800 (PST)
X-Received: by 2002:a1c:3204:: with SMTP id y4mr7078376wmy.166.1582939398894;
 Fri, 28 Feb 2020 17:23:18 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
In-Reply-To: <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 17:23:07 -0800
Message-ID: <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Irm3kkRL;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::343
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

On Thu, Feb 27, 2020 at 6:43 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Integrate KASAN into KUnit testing framework.
> >  - Fail tests when KASAN reports an error that is not expected
> >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> >  - KUnit struct added to current task to keep track of the current test
> > from KASAN code
> >  - Booleans representing if a KASAN report is expected and if a KASAN
> >  report is found added to kunit struct
> >  - This prints "line# has passed" or "line# has failed"
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> > If anyone has any suggestions on how best to print the failure
> > messages, please share!
> >
> > One issue I have found while testing this is the allocation fails in
> > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > does cause the test to fail on the KUnit side, as expected, but it
> > seems to skip all the tests before this one because the output starts
> > with this failure instead of with the first test, kmalloc_oob_right().
>
> I don't follow this... we don't check output in any way, so how does
> output affect execution?...
>
I'm sorry. I think I was just reading the results wrong before - no
wonder I was confused!

I just recreated the error and it does work as expected.

>
> > --- a/tools/testing/kunit/kunit_kernel.py
> > +++ b/tools/testing/kunit/kunit_kernel.py
> > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> >                 return True
> >
> >         def run_kernel(self, args=[], timeout=None, build_dir=''):
> > -               args.extend(['mem=256M'])
> > +               args.extend(['mem=256M', 'kasan_multi_shot'])
>
> This is better done somewhere else (different default value if
> KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
> Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
> to be a mandatory part now. This means people will always hit this, be
> confused, figure out they need to flip the value, and only then be
> able to run kunit+kasan.
>
I agree. Is the best way to do this with "bool multishot =
kasan_save_enable_multi_shot();"  and
"kasan_restore_multi_shot(multishot);" inside test_kasan.c like what
was done in the tests before?

-- 
Thank you,
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUJFovti%3DenpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg%40mail.gmail.com.
