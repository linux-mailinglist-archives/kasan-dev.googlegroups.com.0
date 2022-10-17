Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3OGWONAMGQEL6DJ64Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B2660061F
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 07:09:03 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-3538689fc60sf100641907b3.3
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Oct 2022 22:09:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665983342; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBGhUMXyfbtssXi7SFPJ3eANe9rGMZskCqW7EMWBXYy4+dAWz8Sw9gjpPGHdA7z8Bw
         AGEQae1HDavy+Cf1gx9qiwL7KC4BhdCFui2iHP0f3Oa1xjBaDANy7NsZFr9nF22zI8u1
         XH7nGcuuw0N2mJ5DsE8DacNKoaB9b38JHB7omS+FYPqWc47FomnERuoctzELKFcifeZb
         qre5yIh5zvE8B9wRITRgwPfUcpE9C/K4NS6Q95b6Aqa8OU7XiVVMMWLLEMa4fuY9/DRs
         iC/YT1wowGeQFL15xaiWQqmxIBOtYDY0UPN0jBgkBanGzpVmd4QxHyLGtaw0jrGUAfer
         IfEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zV6/yYkOLZCctlzgQKc0oYw3udya6686PqNqvf+6ZGI=;
        b=ensNJ3DyjC0T6Ithdya3YI+F2MvNRJ9m6NyljjiRBhFL4jYvFXyr8xly/LH0ddo1Yd
         vPXUlBSkFxKmZJVWjzpcagt5XoVSnUPsn1laS479njCAK3IWH9CAUWJ3yDltuX7nygvX
         KbhWw+Na8LwI1U0dAFBf+kWnzFUa0FkW1bjcl1xh0iCMi8qzTGT9KPb7lbnNtCXQt9/A
         QI63dNErNRVsVjz9QTN/y5wOx3txIbPXkA7Za1qQmqsMiu0NheTyaARYZg+nqaF5/39k
         oIpZ6ENxLnBZTrAePv2mENMh1Xjcr43cve+dHpyKqs5okXFAVXn5tvDol8duAaJLCooE
         FWVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T8eEgfyL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zV6/yYkOLZCctlzgQKc0oYw3udya6686PqNqvf+6ZGI=;
        b=boA1st23WkT1dWzqTcx/xYXzOmqSuGFc1vMHBDAX1IwKvaqRQOpqcAgHR2GzmXxZWD
         kw7uZ6gSU/+38gl+H+/FFgj0onIY1rAk2lz4sGSF1t1D+KrzA78BpJxNdU0dtO/yT4uK
         1Ild62R0Bh+fInrhlayv4d7THQXzrKEh9zy0fYLykOuNIk4Ux66s0LghToTBjCk5fYBx
         bXwe89mQdCFf7sGOkyHDQkW5RgbQ1WYXfdOIsIc195c6uS7ItNM65l1RuFYlg25l00zz
         wi0VvdkiJ7MozjAOEykNJvqWUDRs/wWH8ff9vdIDdkGKBN8x61kaO9RCq1D1SERInRw1
         KyAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=zV6/yYkOLZCctlzgQKc0oYw3udya6686PqNqvf+6ZGI=;
        b=BslmYVkHs+JTZqrOORnCiTgfYXcEWjBM3g4rM6aJCmzisuunplXP7XkXcW1ECiU/Ru
         9V2J85AUggfMz5H0XQwOjHNImiejCnuNCQFNBs58cN0/aRmO/o8LZeOWldHQZS1mZiO8
         K6MszCuDuc474K9je+Ly8QH2NUJoF7fvv9whytn8LmitYZWu9PxaIUAj/o2jkGpX+zJF
         oCD6E7Xfp43u+YtBCp2MmMPMjLvdsrGfhvGcvrZh0l/+mQGQ4l9jAdVsnHOZU0jb50CD
         eL509Do1+ILtF5gMGzxq92O9rWEADA/jBKqjvYyh8B49DkeKYVLy6mZ48jqyoOntG7AA
         PWGA==
X-Gm-Message-State: ACrzQf3HVVwdHcSXOiyxwI3n3cEmiuaIhM8lHXl+xejgIkSsTT7VJ/aS
	5ZFVlk/TJvu1pNfBdueOYQ0=
X-Google-Smtp-Source: AMsMyM5fcV0jC7xh43O6zP42UAT6FC4ZqgVK+AGp3+uNiMuvImbvldvLfPEB+t5h5CCNqdH8SEjSCw==
X-Received: by 2002:a81:5444:0:b0:361:ccf:84bc with SMTP id i65-20020a815444000000b003610ccf84bcmr8001211ywb.77.1665983341954;
        Sun, 16 Oct 2022 22:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:62c2:0:b0:346:9a19:8dcc with SMTP id w185-20020a8162c2000000b003469a198dccls3961592ywb.5.-pod-prod-gmail;
 Sun, 16 Oct 2022 22:09:01 -0700 (PDT)
X-Received: by 2002:a0d:d8d2:0:b0:356:642b:53ed with SMTP id a201-20020a0dd8d2000000b00356642b53edmr7853343ywe.88.1665983341284;
        Sun, 16 Oct 2022 22:09:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665983341; cv=none;
        d=google.com; s=arc-20160816;
        b=Vz4YFOouJjWluW494ekiZ6Qnmz3voPXjQFjmc4aJlwXi9lFflu/VljDQ1IZR5iHrWo
         dqfWfvQmzZ/mXkagGH1B39m0rnenH1GteRsowqyGw13JXCL0sj8Kt2dmEciBmKjylDZ0
         R5r8SqAY67UQn/jqVSlsHy4O7B9NSszX1IKIPJ/uQ4B1fYSiRUQhNJHQQ48pLVc1rbsj
         8DFDVSfvfAuLYA43tD0AofbWU9AKEFjpyGXNHX4hSvdmvR4JXI6IQnDtWZI0ynpKkLwU
         d7ZH1J448ZoJIllsY4fmBgBhE/quaGizQt5xCmoaRrJj1CPDfslzMFLr7qy5NBdi3oU0
         AzNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VEzm5h9OntgxbzEjmOZCMD/M7H/7hxbpoHa7ynBSAfU=;
        b=r0EClP7NYEAe9kWKznFgRv0h+AKLmDL9aqbtehSD3eZ6Ws6A30/xPAIZ91YWhiitfS
         RnAKAIIE5tGwNWNqkJVwzK99T5rEZcygz49yGo+fNe0ybV9q9SbNL1jJmWTT81+cQdRE
         WMun0zvTNFqfkqVIRXUH2+qMSjIo82ZZ9evTQUd1CxHg1ByrFGET/7A9DGFmO5X+RhDZ
         2qBtIS40lYBibC1gr/6mW15Oypwkci1FNSVfjRmpemjR/abfj9zKn3zlWvan4sGtjkKn
         44LkNxD3jGZrkth+t7brB1ygcXwJ8/OH1eIERjuZaZzo2xTjB5ioUZNT2dZfYdNepzYa
         QQGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T8eEgfyL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id a124-20020a816682000000b0035e0f02f094si836871ywc.2.2022.10.16.22.09.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 Oct 2022 22:09:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id j7so12001776ybb.8
        for <kasan-dev@googlegroups.com>; Sun, 16 Oct 2022 22:09:01 -0700 (PDT)
X-Received: by 2002:a25:c102:0:b0:6c4:c94:2842 with SMTP id
 r2-20020a25c102000000b006c40c942842mr922664ybf.611.1665983340924; Sun, 16 Oct
 2022 22:09:00 -0700 (PDT)
MIME-Version: 1.0
References: <20221017044345.15496-1-Jason@zx2c4.com> <CANpmjNM7Sca3YJQ7RK14e_pzB5Wq3_-VokLum6MpqKXq7ixzSQ@mail.gmail.com>
In-Reply-To: <CANpmjNM7Sca3YJQ7RK14e_pzB5Wq3_-VokLum6MpqKXq7ixzSQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 16 Oct 2022 22:08:24 -0700
Message-ID: <CANpmjNO0hu7OHmckU7kAVu+C6Jy_M_yMxe41YmcF2oePxh7Rnw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: remove rng selftest
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=T8eEgfyL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Sun, 16 Oct 2022 at 22:07, Marco Elver <elver@google.com> wrote:
>
> On Sun, 16 Oct 2022 at 21:43, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> >
> > The first test of the kcsan selftest appears to test if get_random_u32()
> > returns two zeros in a row, and requires that it doesn't. This seems
> > like a bogus critera. Remove it.
> >
> > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>
> Acked-by: Marco Elver <elver@google.com>
>
> Looks pretty redundant at this point (I think some early version had
> it because somehow I managed to run the test too early and wanted to
> avoid that accidentally happening again).
>

And kindly queue it in your tree with all the rng related changes. Thanks!

> > ---
> >  kernel/kcsan/selftest.c | 8 --------
> >  1 file changed, 8 deletions(-)
> >
> > diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
> > index 00cdf8fa5693..1740ce389e7f 100644
> > --- a/kernel/kcsan/selftest.c
> > +++ b/kernel/kcsan/selftest.c
> > @@ -22,13 +22,6 @@
> >
> >  #define ITERS_PER_TEST 2000
> >
> > -/* Test requirements. */
> > -static bool __init test_requires(void)
> > -{
> > -       /* random should be initialized for the below tests */
> > -       return get_random_u32() + get_random_u32() != 0;
> > -}
> > -
> >  /*
> >   * Test watchpoint encode and decode: check that encoding some access's info,
> >   * and then subsequent decode preserves the access's info.
> > @@ -259,7 +252,6 @@ static int __init kcsan_selftest(void)
> >                         pr_err("selftest: " #do_test " failed");               \
> >         } while (0)
> >
> > -       RUN_TEST(test_requires);
> >         RUN_TEST(test_encode_decode);
> >         RUN_TEST(test_matching_access);
> >         RUN_TEST(test_barrier);
> > --
> > 2.37.3
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0hu7OHmckU7kAVu%2BC6Jy_M_yMxe41YmcF2oePxh7Rnw%40mail.gmail.com.
