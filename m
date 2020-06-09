Return-Path: <kasan-dev+bncBCA2BG6MWAHBBROC773AKGQEH4627QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 40A761F46FA
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 21:21:42 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id 5sf13684992iou.6
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 12:21:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591730501; cv=pass;
        d=google.com; s=arc-20160816;
        b=Om0n9ZCxHPY3wi9SLfRxpBXlcz/Xvdlk4AiGh86uGF5u0T6Z0u3FT2lBvUgiyPs1C6
         H4La+iVB4LCdbZlDq/SRnoOViuMIDxYpMchXlNVmo+FdUfl7rfscT2Vz5M53IqVa/Ztt
         Zq9nmqDFcYvp4GixmKyM7A5IhDuXPoHiqIeuwLwMy9gkeIaWJyqy+J1d/NoZYYIhvEhH
         KIlI2nAQS8ifF5l1MMjQRGU0YuLdNU77XCaRSMzbBM941JqikRx31ut2PrucAKHi5duA
         4Qgk3UvKYuk3pl2GQwLQJYR6ln9vwEKRXJ7OmSrUpERm+y2lhveipaY8H3iKTfeozZIG
         +9KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gLvEnrD4Q5ypcsd16Ft+WxwlNI1wWYtU4dn8j9f1gKk=;
        b=NETm6j0k9mUckRlshX0a5a5ODhaI0CN0eixzHO1hOZnNsVAmKHzEWqqJ5h2tjg/BQo
         1xIOoQVLepbLE8hYNqwMHoZnl2Nh0cfNyZg8D6bsT12N2K8NcN86PChlMZoIqiClvr95
         MTCwvlFXxsranwWA1IKGjulnMv9SLJGRpp+OWAcA0yPSbyW1vh9zegecY4WDiFjUekGw
         e5aljAJuZj/B/ZQ5jgwuDGG+0PTCn4mTPLygQhfCrAj0+9ar0MlzRcQooI+4/GY8DnCb
         nGGTVR9BDPh7rS/ouB3f4+gBxG/ITqpIzPwjDMmbgWb8ZS2XNRDQ+2V5b2B0N3Yu1CZz
         E2Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qkWSINAK;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gLvEnrD4Q5ypcsd16Ft+WxwlNI1wWYtU4dn8j9f1gKk=;
        b=TD7ckHvIrDCSx6UP6xA/7BxIwV4pqykkep+qSgILA5KM7g9zOUcRI/fdOSSZKV+7Up
         q8BQx9Pwh09WV1z8C0014pTKf4AB/WrAgsrm6afj8jt6UamW9S2OK0VVroOwy0iHf1Lc
         udKL31sSrOlPqawopGVH3YGgvf+FA8CsYKOmegzGApweYz8KrRhH5EbZwDRFkQr8eq6I
         7WUXa7rTh6nrFHK5M/Xvs2nWnB3kugz08zIwmjVI+5Pwl4OjzIE3OWjVU0xKGCsYIsMK
         4oWF9jaJI5WkKvS/FQhsfd0Mx0BfN0uwZKsTq/2er5h0Uctb4GTNnPI5Dm5okIxscgNd
         S1zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gLvEnrD4Q5ypcsd16Ft+WxwlNI1wWYtU4dn8j9f1gKk=;
        b=ufn/WfuoW5bwm83e1ecc05D1ZW/MdlmwTcuVAYZD4VIJUtJSwkRgHId5NXRZdKx/XC
         jypkMzte/EZeKxTcxcjRbK7WyQ5U1NDBvJ/JFN3lzF0Ag+SsxySPtLHmCxeN/APM55ft
         bjFgZkmgUrn/W8yO5St0gHdfzr2H8L7qJ90/pZbVGb8njg2w3L5NQqUHbjQnH7LS8b8Y
         92+UiHNw6tPyAR+qrhfUsw0Aa2dxz0JeXeK2Iz9/TSF4S6v09KqBSsMEoJjveXqhzFK0
         s8hXvMjRqW2fz405vkmzPlma+4LBAsq6XLl7ISx2/7GOSP6bnIDHSqr1l63NSMwODUb3
         CDxA==
X-Gm-Message-State: AOAM530KOUD1Yi3GhPsfqO6bQuMIyuArjyLDMZOn+wm//8SVWK0/5Utw
	SrTS5VlV79JZls6HX/TuSnI=
X-Google-Smtp-Source: ABdhPJwfIT0zyB8NaClf4R3q3SZVaeQtsNPVZLbDn7jmZTlEOBg5+Axa54rVBxoSIkPmhktfIjF0AQ==
X-Received: by 2002:a02:23cb:: with SMTP id u194mr28733818jau.63.1591730501084;
        Tue, 09 Jun 2020 12:21:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:113:: with SMTP id x19ls717477jao.0.gmail; Tue, 09
 Jun 2020 12:21:40 -0700 (PDT)
X-Received: by 2002:a02:dc8:: with SMTP id 191mr28423080jax.95.1591730500735;
        Tue, 09 Jun 2020 12:21:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591730500; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/dIprLxWWeIYZzsF4qvFhmq8579kUuhAwqKUs59HNgxJL3Y2CCadLqug4S5YW/i0V
         uIKVdZkyej3yXMDQQREiU5fXwCSPByA1Z2GiRi/VgVbxmqVYxQeS8ti+Lcst+q/E0KQL
         zAVDR9eIqSAhh/H+xlOvC74SNNpkzzMnuYCmQIBlHHwiXMFUb/ZhKzJSceB4mO2RqYla
         rjJe7NK+xVjPZoY+3UfKrHNAwBYzPc/XGZ6v0A37SaMvAdW/cGIj9X+pnw2J8Ss74bbT
         PlVk4u142j25pTTsk8t7NjtTqtu1D9L+CnxQXJwno075ped3gi5OClU/ydXh1K4R/FYT
         lioQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v8Y+QEIY0T38+LyOkVjhLl2iDQvo9/HQ1D/xWJhCBjs=;
        b=JyNW3Vi7WIFP2fURG63GsVgUmLZxxwNgTygxHYthW09Elj1VNmv0qMzjqsw3xl1iTP
         BeJs71Mm9AhfRNFEEqalqXZrycivL1xZO4dByCF75YSHw5CNHX5mtpAGdZkxQ+GGcVrD
         Sc8CbuMLSNe53arQynAgW7xk0qwpnWk9gnKt0DARxALC83EGJA3IA3daPBQDy8pTeWJs
         LoX12rq3onIed4kksd4wNJO/7cVaC5X6GPfYxRLsh0ynxvaXdCll0l1duq4wdzq7IjgL
         g2qUIx5xDXP0A9FbboHW8ZRl9PLtksDincdHD7tRpsRZ+0QT3s2VINUm4W3jYWi3nW1R
         O2tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qkWSINAK;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id x10si1041739ila.3.2020.06.09.12.21.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 12:21:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id y18so8420188plr.4
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 12:21:40 -0700 (PDT)
X-Received: by 2002:a17:90a:df82:: with SMTP id p2mr6537329pjv.217.1591730499841;
 Tue, 09 Jun 2020 12:21:39 -0700 (PDT)
MIME-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com> <20200606040349.246780-3-davidgow@google.com>
In-Reply-To: <20200606040349.246780-3-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jun 2020 12:21:28 -0700
Message-ID: <CAFd5g45zNikNb6wEa1UWDS_ZtxOVrUt006s_cMqM7ZCTMjfSYA@mail.gmail.com>
Subject: Re: [PATCH v8 2/5] KUnit: KASAN Integration
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, andreyknvl@google.com, 
	shuah <shuah@kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qkWSINAK;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
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

On Fri, Jun 5, 2020 at 9:03 PM David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Integrate KASAN into KUnit testing framework.
>         - Fail tests when KASAN reports an error that is not expected
>         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN
>         tests
>         - Expected KASAN reports pass tests and are still printed when run
>         without kunit_tool (kunit_tool still bypasses the report due to the
>         test passing)
>         - KUnit struct in current task used to keep track of the current
>         test from KASAN code
>
> This patch makes use of "kunit: generalize kunit_resource API beyond
> allocated resources" and "kunit: add support for named resources" from
> Alan Maguire [1]
>         - A named resource is added to a test when a KASAN report is
>         expected
>         - This resource contains a struct for kasan_data containing
>         booleans representing if a KASAN report is expected and if a KASAN
>         report is found
>
> [1] https://lore.kernel.org/linux-kselftest/CAFd5g46Uu_5TG89uOm0Dj5CMq+11cwjBnsd-k_CVy6bQUeU4Jw@mail.gmail.com/T/#t
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g45zNikNb6wEa1UWDS_ZtxOVrUt006s_cMqM7ZCTMjfSYA%40mail.gmail.com.
