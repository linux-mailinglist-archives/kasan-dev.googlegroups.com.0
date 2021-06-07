Return-Path: <kasan-dev+bncBCA2BG6MWAHBB27W7GCQMGQENZ5WVXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C9D139E7FB
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 22:02:52 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id n16-20020a0568200550b029020b438b2591sf11709573ooj.19
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 13:02:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623096171; cv=pass;
        d=google.com; s=arc-20160816;
        b=dt28AualmLIC6RbFBh9w/BPwD5UaZ2jkjYHP9x5+3Y4EWFNU8GRWhEK2xn+09QCJLX
         brITE8Yk3p/EYkBkXQAl1A/aGDQYgcOtqiAtCcq6pR8nvlk5+efaVwVRrc69k8mSIrJc
         r5xtWVci5ReMgF40ZVxRn9vEzRnCQcBffdIPSSGvPxwHF9txQ3rGqt0wTEwHDmM1im7O
         FpplXytFZoEP/IUVkbdVyC3uOUA2slTXI3Vpai8T1CNgpIPHRmTShEz3GGhKXgpE2ECt
         iK4npTOhearXKNz3f4wUzgBS4eLrh0bIIwHidfHvnrPt4WzefygIFmbpRE+5u+hb5zqK
         yv4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HDN7Ge6YRvgQp54Ezs+3IBRgwKx0rvNETyDaQa4SQ/s=;
        b=R/dH2osD62bpXRFcuikJnS9qFN7M+npW8JbuHYBjZy1eJaPQmP22E79GoHCI/E+Wlo
         VJBVrtOx4DgNSDiUa9oL0DBDOPJ61cYPeTQnBKffjOppfOeD8yQmU8WGnbd4fuwRrWyM
         F/e2BYIqevepSex9+edx3HLYkquY0wy2aAva6IlLUmWJcjwqMiKXCJl6LP+oej9QD2gr
         7YpCmn4PJhC+bRqCLXq6EtjLCXZPNfSN9JVqbi8aOWeOA9O2a5Z3djXhWHKscY0Ehh1T
         oIOj9kSsl+VOJNo2Eq+0nQmwhZEJAQMrtwZWDhhgLUWpyIrVLzcYF+jcXFaG2bOjxN0A
         q5uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FUJQObTw;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HDN7Ge6YRvgQp54Ezs+3IBRgwKx0rvNETyDaQa4SQ/s=;
        b=exGIiLQgjZxftdDD3xOuGesQDDMO9hqBwnpxKrbDXLda3F2UvGiokhIa3GeTOnUbpR
         zHwLaf7HUsuap9QPWT2wcmfirhqBfSKpvPopJ9c9+0sApI/OJ28viu31jK7FXsCpA68R
         uO4nUrgSdU/m/PKoaDmdblUtVQk5t8bpdreb3764OYFOvdQNuNK0Cx8PHTqjY6kmh5wd
         Bw3thlTGaWHlEg1tlwokFW09ZwoCYphELfBFV7SjJDNSsRnydn7FU1W0wFk8ZJmBNtym
         jxG7ZbR82MmJps8PAopGR7mCt5GVHRckW6w4rhytGsJYWM2qaDMG6fEbJDYLMficwtVq
         pD1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HDN7Ge6YRvgQp54Ezs+3IBRgwKx0rvNETyDaQa4SQ/s=;
        b=Ju8MjyVdG2m6QwDVE/CjndgZJZagGiuVrEW5VX+8f+aU7gFMZ7kjSxLoSdRqW+PRzh
         C7o8kV/oPqiFvmb/+EaoNhJiovj0erlGWfDqRbnRPLLyo/cSo8AvpDMRrv9hz6HIMs67
         FPQv0/4Jl3RSgBxbr5QiIlZfGF0YbnSh+mPh6xA//XU75DtQ8ipeesLnJikXE3nDC++l
         WC8rHzt3At+Ts+PtWdRH1zsHjIyaJ6xITXgauH1xRagF1AhnxncmwZDpFFQ9AQ7Zdwx7
         vnlNXjK2kB3A4GaB/eMVa6yfod5lRSQJfM6raI111L6J/4ObipGAxXJyHAk9XM8qqU1B
         CPgw==
X-Gm-Message-State: AOAM530ilIkdg+gTziyrnH0IMIoAwrfGccgjtOLaOn83l8sIOoJt46BY
	TOCTulLe+IEL1ttshueNVKU=
X-Google-Smtp-Source: ABdhPJzv34BNQ6aeBNXlNvVZd4XQ7OSzicwehV4YbjmmpH+fgQBQWXk4NeJiFn0T2myUAz/tBGPd9A==
X-Received: by 2002:a9d:6255:: with SMTP id i21mr15354165otk.284.1623096171187;
        Mon, 07 Jun 2021 13:02:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7c1:: with SMTP id 59ls5350762oto.8.gmail; Mon, 07 Jun
 2021 13:02:50 -0700 (PDT)
X-Received: by 2002:a05:6830:1342:: with SMTP id r2mr6821870otq.136.1623096170838;
        Mon, 07 Jun 2021 13:02:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623096170; cv=none;
        d=google.com; s=arc-20160816;
        b=XAr+h6HMJn1zdGP5I/yv46LWT1uER26h0/6CE9au0So8iV0h50JX/tEfNRdsM0BTI7
         7gfVFAovfIt9V1NKNjNUpkspePERN/upxDyMqjB3cEpPANECBDx3SAfA9bIpACXcgpUa
         RgUdlVHlmzLOx25tX7XOl6PsDlEJardk1FGfifjLHRSXR2k7ka6jPSGFWdfQR81v57yc
         9vUgmGvLGgqT2sGdOlZyk5e0gVfHwG8uNfWiWKYNIvuRyO6sv+lqb3xcz/iL4FrnYnZ2
         CWUtcjZBtbk+7kk/hXRSnwjI6Ozv+HPVwJxU8QdX5KpKDhiMwHOtrkf87WTwEhPop6Ld
         0UbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X2XQQivzvNRkfVR3uSuxxvXJvrtUp9ycHqIQW57PEVc=;
        b=ch2Ikp9oL6p1+XcA+6MzQKOc/uYd4gP/KLrqUt61w2hR2q6BSPpPTtbPulebUE2Sb+
         QfBXq1DTiknU3/sfJ69Kz3YE6yQE4Q2jLobUe+26dOl9UGPXqZJcpe9l1+laOSOw7h+7
         cIb7mMx2C7noGPB8t4V/OUYAgLpW6+CVYs2B5MqztuXqukjZyF0SbaND2p8Vj4c6mtRm
         1DtRcoWohnNjMDtQmM3c8zGOeK4gdY8LVPIrhFjdDgwudEhBvlNef8wLsd/LV5ATYk8t
         mYeKcSlFrVpTTxQo1PFoDJWLm/JsFPrt1W0+lB4k8fJhJuX16QQfglxxz1/Tc7WL2l8c
         xakQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FUJQObTw;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id b17si1259161ooq.2.2021.06.07.13.02.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 13:02:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id pi6-20020a17090b1e46b029015cec51d7cdso746990pjb.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 13:02:50 -0700 (PDT)
X-Received: by 2002:a17:90a:b28d:: with SMTP id c13mr854921pjr.80.1623096169879;
 Mon, 07 Jun 2021 13:02:49 -0700 (PDT)
MIME-Version: 1.0
References: <20210606005531.165954-1-davidgow@google.com>
In-Reply-To: <20210606005531.165954-1-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jun 2021 13:02:38 -0700
Message-ID: <CAFd5g44YH5P=4U34kTnWwgTKQbT6toLtEfDNHw3bHLHqiyj8QQ@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
To: David Gow <davidgow@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Jonathan Corbet <corbet@lwn.net>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FUJQObTw;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Sat, Jun 5, 2021 at 5:55 PM David Gow <davidgow@google.com> wrote:
>
> The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
> compare fail_data.report_expected and fail_data.report_found. This
> always gave a somewhat useless error message on failure, but the
> addition of extra compile-time checking with READ_ONCE() has caused it
> to get much longer, and be truncated before anything useful is displayed.
>
> Instead, just check fail_data.report_found by hand (we've just set
> report_expected to 'true'), and print a better failure message with
> KUNIT_FAIL(). Because of this, report_expected is no longer used
> anywhere, and can be removed.
>
> Beforehand, a failure in:
> KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
> would have looked like:
> [22:00:34] [FAILED] vmalloc_oob
> [22:00:34]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:991
> [22:00:34]     Expected ({ do { extern void __compiletime_assert_705(void) __attribute__((__error__("Unsupported access size for {READ,WRITE}_ONCE()."))); if (!((sizeof(fail_data.report_expected) == sizeof(char) || sizeof(fail_data.repp
> [22:00:34]     not ok 45 - vmalloc_oob
>
> With this change, it instead looks like:
> [22:04:04] [FAILED] vmalloc_oob
> [22:04:04]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:993
> [22:04:04]     KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
> [22:04:04]     not ok 45 - vmalloc_oob
>
> Also update the example failure in the documentation to reflect this.
>
> Signed-off-by: David Gow <davidgow@google.com>

Nice work!

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44YH5P%3D4U34kTnWwgTKQbT6toLtEfDNHw3bHLHqiyj8QQ%40mail.gmail.com.
