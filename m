Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ554WNAMGQEE5EBZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4038E60E564
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 18:22:01 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id y44-20020ab048ef000000b003cd69b6e479sf6968386uac.9
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 09:22:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666801320; cv=pass;
        d=google.com; s=arc-20160816;
        b=lvkumeiK6tdobBBUJ6f3RMD8mDRLQFAS1cavTWlm7XiqaBXhaoxXWzq01XgSNpcgDC
         6qCRuK5Tu5oSfyYwzfPlz7x3tkgjbtGAEGS1oggNI70N5ksoHrUU8T9Pk2IDoeyG2cdJ
         D3JtIfl9EWbluGZrlXptty0czQp0x8vN35wU/myKv/0KLQJWa91zXMr0O0v/Hh5j3BG9
         8wXiwSxDtl1w4kcTRnfdBqQVFaLzXV477OGiI0Al1EW0VgFVj0Do/7gioo9WgK+8RYlk
         AQTLgnSUQIpx6BLqBQxB4TF7bKEo8npttIoDYrng9Y4py99lVWnxl2MtIDKvwL7RhNW9
         1cdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jnZFZfuDugKbRWH1DWHPJikYrJkoxLPXOeRF0Mb8kBE=;
        b=XFykh/Qqx1XVbtm3AFgxza+icKY7ilw9kVzJsQb7hfEOZqWSGFj4dnuFJJ6Mq4q4mP
         prEBZXjDLdu8PMXuV6O/MieZiEUVFdrEzW+1AkkjVWbeiUkaQ1mUbu1s1Nu9Ba+yxJ92
         HvYACvJLocM1tsoCImY7RBHrLzCWI417yHmahqOqlruAb05N80cZE/ACWKOyzzmfVbD1
         pz/7/7LySM+rs/GBxlU/dHkJlJdchd1ZQFF7Ek0MMykZqO/5a8pWzqVTNjR5Tp039TXy
         rM1ZbTqtRhdMLWX2Ee9aX3A85ohRpdJQGXavTZNjVSXxzgcrW7nUpre9aefox6IKhgoC
         Bz6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="MBEkyQ/u";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jnZFZfuDugKbRWH1DWHPJikYrJkoxLPXOeRF0Mb8kBE=;
        b=aFMxEb/vEE8pSIKbRi6XNV9aP9kKp9AmiOIm6rZVlqxIMYnMcPwqMjoftnJYdGTon6
         OLZqzppu2pPkNUe/KT6dYwKID8yxqTK09epyIKOkwaik9NVIPPN4kIrMwiF6MGjVJKSB
         m+eYaI9lFg59wNNWbkXSUrqTsjnoao6J7ExGztCLB97bu4R5BUpGnt9uNK8KgcuBZxxE
         yM2gu4K/9DKTnvSJLDmG03n+WlBNKxyitkFEIxKfyvvBY21B2zwHKyc+pXI1uxAJusGm
         XfyIWJ010OC+9NMvdtwtsu82g/oCRA+PXs4snIUqW7CAMnxXVLgIctymqlIk9Bj4Go4A
         JCWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=jnZFZfuDugKbRWH1DWHPJikYrJkoxLPXOeRF0Mb8kBE=;
        b=LdnwgblgG02G7geLjTaryB+RIDQzx8kXKOK5b73OpE450i+wi4XZmfOIh3s4WyVsFB
         arzZcQuIZDSuzn2G8fTBjeaYblE/3kxk9MleQ2I3pIDdRtq3jRDiImOccY75x4CElcF6
         kobowGI6s5o07AOhaeeO+DMmb6bTtG5qlR/BDdzUkOhhQiwPrP4jNgW7jbdeomfYkGHQ
         M8p4+mrSCwQZx+5fpyrUN038m8W6tZCNQIJsTek9/oDOgT/ScJc/14wL1FtRdG349uwv
         Dg4KnlPlDDP8P+WrXzS+y5Zg4/LcO6CxCWUXHQFR8RbTlDP8u7hvixC1xVoa53W0OrCh
         vYXw==
X-Gm-Message-State: ACrzQf2UEx7vFm59qwBjrepAXkhlamFEpocIScVgT7b4+nCMfLLLpeEP
	Ur7ysdG1dC86kaOERjoSDVs=
X-Google-Smtp-Source: AMsMyM428y0gfrGW6yLF7s87wS+9e0mkUmGheM6n7CD3ESVMhTHGxeDZRQrMGE1nhMTIgIMujSRczg==
X-Received: by 2002:ab0:e05:0:b0:3bf:2088:64e1 with SMTP id g5-20020ab00e05000000b003bf208864e1mr25192593uak.118.1666801320076;
        Wed, 26 Oct 2022 09:22:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:30c9:0:b0:3aa:ea29:71a5 with SMTP id w192-20020a1f30c9000000b003aaea2971a5ls1587304vkw.8.-pod-prod-gmail;
 Wed, 26 Oct 2022 09:21:59 -0700 (PDT)
X-Received: by 2002:a1f:130b:0:b0:3b7:a58a:e1f8 with SMTP id 11-20020a1f130b000000b003b7a58ae1f8mr2531404vkt.41.1666801319341;
        Wed, 26 Oct 2022 09:21:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666801319; cv=none;
        d=google.com; s=arc-20160816;
        b=RfVnob5sn0aCsXfgqUWxczyTQPd9nEbeWB8Edqw90LZk0dWYcyELoUOo1US7N/Bg4+
         3pffCua5s8wUW7wk2RI7vUs41HS27Yrh9Q6+mEU+woXlDOn4YJ7LSXzdVKF78+n4N8MY
         G8Yj1e8LNsqDH2jF14HudNUY3skQF9hRPrGSio3emy+9YJhU80I6McIrMQ7eWaMjz4N7
         6XKPDy4R+T1VaQZRZEKmoXQbiJ2Hthd4lGbzSnUW/WJvCtjQSrehO9/wueheQk3qr7DT
         THmEvvMyyVYcGDkvanQxNMLoAU6r7hETINkEeEWDTnjYY/UyP/shLUPQs63HLsyY+bi7
         Sqmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dyd6cIxqMoiV31eHklrQhs9akoYIl7JR8zcy+9Yf9Ek=;
        b=ZaU1LtBv/OJwntRsa34I1WHkU/HWQeYg48H40ng82NCWT2bz10vUHJ+FLkfCCI8GNY
         +yQO0aEQlHUNfAZpXiGHPCYuI9BviD4Iqx8LI7lXGi8rapdpbjKDSAJPUV727Z2rg+UR
         NQywMdz//cuDl6+Fg82hiO/S6gyf4EP9jcpw2E/ZGoHZWOgZKczMzXczXxF+zpA3G/NN
         jdb6mIzWsISO8rUxJPFFOx0N5pJBKOBKBOyghnvmVTgXIZE+7YR/iboKyNP3kJRpdXPe
         wG9JmsuvkTqODe/WGsxwwflYOZEUAiAYvXJU4hDhdXxREsPuU+Tw4/22aZjDrk4dQGaZ
         gZVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="MBEkyQ/u";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id p197-20020a1f29ce000000b003aa19e4feecsi300755vkp.0.2022.10.26.09.21.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Oct 2022 09:21:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id o70so19553736yba.7
        for <kasan-dev@googlegroups.com>; Wed, 26 Oct 2022 09:21:59 -0700 (PDT)
X-Received: by 2002:a25:c102:0:b0:6c4:c94:2842 with SMTP id
 r2-20020a25c102000000b006c40c942842mr41389384ybf.611.1666801318874; Wed, 26
 Oct 2022 09:21:58 -0700 (PDT)
MIME-Version: 1.0
References: <20221026141040.1609203-1-davidgow@google.com>
In-Reply-To: <20221026141040.1609203-1-davidgow@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Oct 2022 09:21:22 -0700
Message-ID: <CANpmjNMLuep71fz2P=9ZrYSaD_GwE6XDf69+auf=2G7FYqu4sw@mail.gmail.com>
Subject: Re: [PATCH] perf/hw_breakpoint: test: Skip the test if dependencies unmet
To: David Gow <davidgow@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="MBEkyQ/u";       spf=pass
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

On Wed, 26 Oct 2022 at 07:10, David Gow <davidgow@google.com> wrote:
>
> Running the test currently fails on non-SMP systems, despite being
> enabled by default. This means that running the test with:
>
>  ./tools/testing/kunit/kunit.py run --arch x86_64 hw_breakpoint
>
> results in every hw_breakpoint test failing with:
>
>  # test_one_cpu: failed to initialize: -22
>  not ok 1 - test_one_cpu
>
> Instead, use kunit_skip(), which will mark the test as skipped, and give
> a more comprehensible message:
>
>  ok 1 - test_one_cpu # SKIP not enough cpus
>
> This makes it more obvious that the test is not suited to the test
> environment, and so wasn't run, rather than having run and failed.
>
> Signed-off-by: David Gow <davidgow@google.com>

Acked-by: Marco Elver <elver@google.com>

Although I still get confused by the fact that skipped tests say "ok"
and then need to double check the log that tests weren't skipped.

> ---
>  kernel/events/hw_breakpoint_test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
> index 5ced822df788..c57610f52bb4 100644
> --- a/kernel/events/hw_breakpoint_test.c
> +++ b/kernel/events/hw_breakpoint_test.c
> @@ -295,11 +295,11 @@ static int test_init(struct kunit *test)
>  {
>         /* Most test cases want 2 distinct CPUs. */
>         if (num_online_cpus() < 2)
> -               return -EINVAL;
> +               kunit_skip(test, "not enough cpus");
>
>         /* Want the system to not use breakpoints elsewhere. */
>         if (hw_breakpoint_is_used())
> -               return -EBUSY;
> +               kunit_skip(test, "hw breakpoint already in use");
>
>         return 0;
>  }
> --
> 2.38.0.135.g90850a2211-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMLuep71fz2P%3D9ZrYSaD_GwE6XDf69%2Bauf%3D2G7FYqu4sw%40mail.gmail.com.
