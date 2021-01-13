Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRF77T7QKGQETIVTG7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CCF352F4FF4
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:28:53 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id w3sf1340381oov.16
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:28:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555332; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rx2Epclb6w1ORONyzzUsXITjfKvDYyqwgVeeuItDzUE7ZqRBTH3dxqSxVi/WGg7Ii8
         /Gjd3DYMTeoduRCIK90fxYnqc/9EdPSiWSpkQwFT6W23Ol8/zi323HAuVGAKee6P4KkK
         rcQ0GNcgKZ4WIHrEeqK9hmB8f/+71A80cqrQtCo+/u6xZbtv4ZpL5AjJocKCTnSH8hCF
         gnsr0iYIj8czuQmtXhzWzEboIGc4pxFmCRq6yxAoJask1VosHDVSft0d0+RLqVX+BT7i
         SQ+o2vji84S1FZ7CyuYTZ9mp+ktWT00IfWDy4/uWH/bQnfeGbe7sF9vjricEXWSbft+3
         0RYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WLAQ/xLvwaK9Csas5aSkKzQIWUSa5AEIGe7AgJxrNDo=;
        b=OeSIMlEelnYaKw5yp4+P6//xa7L+4a0JDPCzWgIpKFZ9un3LTdTlcL90NnhnuQSPe0
         N9esX0CvE6gKO4MxrFow5/6z0pA0FEQ88Zp4Awz1F+w/Gb5UeeVjqx3FI4u71wkDRAJy
         44VcApQYM+9og4gNxJCH4JDpegBwRYPpwVOyyogN+Vt80+ZrVqIWSKhyo6LViLeJuxsk
         5HvFs94L6bfVSXGRLBrKhcFR52BdC34VEm8u+/mlAp2qGnpTZo+yMCp+iwjIdLRZ8sXL
         ZQPsmQeqafvL8/prvOCS7vPLeHyLNJBb6gStg6ilccdvzla0eINSoo+bVoah4KFKfg4h
         8MLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sI9xRXQ7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WLAQ/xLvwaK9Csas5aSkKzQIWUSa5AEIGe7AgJxrNDo=;
        b=ncRMrUgaPTU5afAERIL5CSY5wmRIifEuRDl0g0ml+s137F3JsAU5332qPZ+FsYCkfV
         xBcCWkt34EsH1gJGmDn6xcuQMRbB8WSiCWdJkSHTn4UQwVlePuE0ekM2uEg79oKoEnW3
         QRr9AVKK/a9VNBVKGyqGeNW8Z/uE9N35uCwQOeGt2PIMjlCIBuLbowwYOJJex81o0ev4
         5ggOVaGN3jjnZjE0f+CsWlf3/IaHHLjdSmX8s7wYciJHc4Cettwa57DUrmweMghDmteT
         ws3kcSO1bfc31I0ev82zZITx/QcH9OusHxSjBrk74UQ2JnuV2O/KiTS6hPSioC7ELjbq
         eekw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WLAQ/xLvwaK9Csas5aSkKzQIWUSa5AEIGe7AgJxrNDo=;
        b=XIz151+/SpBHNmKcoATobJzLVmADwUTRjZCkOO6AZwWozSLjTzBlhONmocBTco8TOZ
         G5c3O+sI3eclBrzFBdfEcyTfup6XC7szaCXpJzueFF/96t2Ph+f6gIw8HXTfNQr80N4S
         bA03ma/9xuTJDxYNFA8KNmG3Kfzva8hywTZRl9LMUn3AaP74maCYnEawUu53lZb6CDZQ
         r+qzsnfZrFbSgboDgS/mk6M6muLxi8A3hHVRHK78zyZF76pIMpUoroIqVNmdkBKopCIF
         We5F3ODKHwe2dmACBbW4rxw8voWFhDWSmxDQagm1X7alS5U2/N/+M0ITsjKhV7ukLFSc
         TURw==
X-Gm-Message-State: AOAM533C1C1oYGaIQzZw+e6jVaja8/vTHcHbHQyUrlQCNdnfvPz8n5l9
	Qvx4HXDH0n2u+UaIbizECOc=
X-Google-Smtp-Source: ABdhPJxvzU6GB3plPXC0aDf2PRSPfAIyGmd4JqaibiaLpk7fCoIDlP21cvaRhip+B9e6Zb4q0VhWNg==
X-Received: by 2002:aca:ec43:: with SMTP id k64mr36350oih.43.1610555332655;
        Wed, 13 Jan 2021 08:28:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60cc:: with SMTP id b12ls668937otk.0.gmail; Wed, 13 Jan
 2021 08:28:52 -0800 (PST)
X-Received: by 2002:a05:6830:2363:: with SMTP id r3mr1781688oth.282.1610555332361;
        Wed, 13 Jan 2021 08:28:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555332; cv=none;
        d=google.com; s=arc-20160816;
        b=rFoZNM3q2e35RJlCs03973YzfEEmnEGMHfItA6lApJrCiqH0Knp2nUMTNsSQr/RToq
         Db1ZWPIGcY4dDTCVgG5oCUxtIxyQyatJzcCSRojwvgUXCvk1iRky9A9KufBl0Yxk5a2W
         yIslXo0BkREfyaU1FsaWH0OQW1annK3iWb7HO17QxGdR3fFIyTWVv9T4TRR7mNibMOjX
         fSlpI2ESUcf2wwA/2iFMXhr9CCs7ENCAqqY2P2VpqjHh5lhfGQ/NELSM0A0g09ubmBzI
         TSHw94U+ffVJ/TZikfrQohWGHtEhTIZ1X0BvEQInWhfzwi/ilxYt/pvmW3cOXudFYbf3
         bMWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dtGuPSqxThBxFFND3TAs3eyezmIFF8iGuQhEPWlxFw4=;
        b=0qt4PKJcr6b+IgO6ytiEkl9g3656ppZ40sT+CK4ZQuxQ84tP3a/C5AgbLoyGoAz158
         gSWaJqcHH7TxnN/tJ2UM4hCgbLsgWugjEn56aG60bJ4nf6brnARy5vxvldgK5l2t7Hgi
         ZUzb9xTdVgk2RJk6DTcL9wcRpBComgg39ntj40UuF/GyJkOcW973pyvKlBEc/vfIzo+7
         73jYkLM3JP92yl361HujUDBWx4u8hoQyrOfztSJx/Z7+DS8YinMArjplEZ6MpbXoWnPj
         MoXNiJGhMX3kfvNNyyhNgs0m45aIegLqIBBYz/gIq18a7eSISDw8bQ/hcf6qMYMwiw3E
         ELIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sI9xRXQ7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id s126si200702ooa.0.2021.01.13.08.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:28:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id q25so2686220oij.10
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:28:52 -0800 (PST)
X-Received: by 2002:aca:58d6:: with SMTP id m205mr23481oib.121.1610555331853;
 Wed, 13 Jan 2021 08:28:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <e75010281350ff3a4380006218f81e1233fa4e6b.1610554432.git.andreyknvl@google.com>
In-Reply-To: <e75010281350ff3a4380006218f81e1233fa4e6b.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:28:40 +0100
Message-ID: <CANpmjNPYKzY+xPAddAjsry1RC2Y84pSCFZ0VuVMMEu+LN3A0EQ@mail.gmail.com>
Subject: Re: [PATCH v2 08/14] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sI9xRXQ7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Wed, 13 Jan 2021 at 17:22, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> It might not be obvious to the compiler that the expression must be
> executed between writing and reading to fail_data. In this case, the
> compiler might reorder or optimize away some of the accesses, and
> the tests will fail.
>
> Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL
> and use READ/WRITE_ONCE() for accessing fail_data fields.
>
> Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c  | 17 ++++++++++++-----
>  mm/kasan/report.c |  2 +-
>  2 files changed, 13 insertions(+), 6 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 5c8aa3a5ce93..283feda9882a 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -68,23 +68,30 @@ static void kasan_test_exit(struct kunit *test)
>   * normally auto-disabled. When this happens, this test handler reenables
>   * tag checking. As tag checking can be only disabled or enabled per CPU, this
>   * handler disables migration (preemption).
> + *
> + * Since the compiler doesn't see that the expression can change the fail_data
> + * fields, it can reorder or optimize away the accesses to those fields.
> + * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
> + * expression to prevent that.
>   */
>  #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {         \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))                   \
>                 migrate_disable();                              \
> -       fail_data.report_expected = true;                       \
> -       fail_data.report_found = false;                         \
> +       WRITE_ONCE(fail_data.report_expected, true);            \
> +       WRITE_ONCE(fail_data.report_found, false);              \
>         kunit_add_named_resource(test,                          \
>                                 NULL,                           \
>                                 NULL,                           \
>                                 &resource,                      \
>                                 "kasan_data", &fail_data);      \
> +       barrier();                                              \
>         expression;                                             \
> +       barrier();                                              \
>         KUNIT_EXPECT_EQ(test,                                   \
> -                       fail_data.report_expected,              \
> -                       fail_data.report_found);                \
> +                       READ_ONCE(fail_data.report_expected),   \
> +                       READ_ONCE(fail_data.report_found));     \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                 \
> -               if (fail_data.report_found)                     \
> +               if (READ_ONCE(fail_data.report_found))          \
>                         hw_enable_tagging();                    \
>                 migrate_enable();                               \
>         }                                                       \
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e93d7973792e..234f35a84f19 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -331,7 +331,7 @@ static void kasan_update_kunit_status(struct kunit *cur_test)
>         }
>
>         kasan_data = (struct kunit_kasan_expectation *)resource->data;
> -       kasan_data->report_found = true;
> +       WRITE_ONCE(kasan_data->report_found, true);
>         kunit_put_resource(resource);
>  }
>  #endif /* IS_ENABLED(CONFIG_KUNIT) */
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYKzY%2BxPAddAjsry1RC2Y84pSCFZ0VuVMMEu%2BLN3A0EQ%40mail.gmail.com.
