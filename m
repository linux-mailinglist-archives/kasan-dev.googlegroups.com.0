Return-Path: <kasan-dev+bncBDAZZCVNSYPBBH6T5GLAMGQEKBVWGBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 99B5C57DD60
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 11:10:56 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id o15-20020a05651c050f00b0025d7ab3943dsf858489ljp.14
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 02:10:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658481055; cv=pass;
        d=google.com; s=arc-20160816;
        b=selKxnJbxPgdzhp0DSbhtdZGgs8KDp8NV1KVII7ag6m9iwNLuXgVcJtSxSujFYsWZV
         ICSXwjlv6TmrXqarDZuxriA/PZjZHBBxokqluXzBv4l1TEGmhUmEJnPVVW42A1Cpg1oj
         zQgREDwV7enDLpwWfBFvtgKMTavl0aSfxskSMexCQO6Dk2N+IXmphragP9lHvFf78STN
         DoNad5E2VXmUX9gReLG7UsZ6GUHdwPYZul4w5oC49lJz8knnfPOXlDSppzGGtiQ2e9Ty
         GxzEh+b1ficafLfYHC6GaFcQEb6wEA/oKXIp9bW0Ga0sBXML98kwzvB65rEmhv6h9RLc
         +amw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2aNCSYktEtlgyr+DW+BGXTdrelXUgrSp7A4RoSvUu8g=;
        b=s9bwi1tbV70A8LdYhx2cD5SzfiR2KVUpecK66n2vJJxp9AYw3e0bfWU44iJpIYee8y
         4Qr84npBHAsSs4iaDmQnF/ygsodmEbexcPeYqubUHddyyQyS4Ntoj5O7RpFl4Rl4eylF
         MsxGNGGegEcSKQkEuPiyDnpGRhXidw8TmzaMWu4eJSNLjk3TZ8ef0AdhrtsdcD2ejlqK
         en1ZLSVXDHLs30LNfKVpe7y8x3B8J1Tn1ZG0tSXQfKZMzvo4Z64+0reW84cuxqXoJ9vy
         qVktprofhBBsKDF367YR89jAFoNVeAn4uvOb6QHrKaOWmlYMDvsBF14IL9VM/OkqRYxB
         fRYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O6jq7Tg0;
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2aNCSYktEtlgyr+DW+BGXTdrelXUgrSp7A4RoSvUu8g=;
        b=JVQcpUTWv4QntlJZb/rmlxqHAUkSjuPpxTbquvJR7JBvU3Pj1XqhOa1wO10JU3CrLP
         /BpaAfTnQqdPJOwpR2U2B36vcNxUolcEqH+/DkwXuvMs+TdlArCIv1hMiiYW8OfQ8Eau
         YmMbCBqYshuXNyw3wrLi14By8E9VXU4RHzGsky7bQDb8aAJj3gRwKs9U5HFcHmOGLeMb
         ntPSyA1puDpzGm1C3UdAER8174CXYu4zJEQ6cYmL9/dMke3uaGYOIdvZKo2TnyFxCKg+
         qc2cOO5CaxVsqHSIkrZ0YbFEZVvJnV0PAyto1h8wo0h71ERau5XM2n+3jP+FUcnDzlZI
         KZgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2aNCSYktEtlgyr+DW+BGXTdrelXUgrSp7A4RoSvUu8g=;
        b=HlQ4lkX3vRvgJ6RlND2nyXPd0/XyIbAEUiVUSg+lReyhBv3Wa6/LX99XDUHwvnE1oL
         dypQvm55o16tzoRVGQlq30zg2jV6sx0DVV+ythuMraJNGJswTsqF08NlYsxq7h7hSOYO
         /CMOVE8FxtzLIG8IOjeN80YuXZ//ONFC0A4i+E1nQwFcEoZVVKlkMD9fckWoVitxU13R
         JkxAB1gdj+qK2ZoxE6uYin1AgRn2+1csMQ2cJWRib45oA8jv/3tajykQYi/i8Qni5z0g
         UweNm+9ou8J4/9MRrfCfxXbKxayJWWGYcPIm19NhhdzchcKf6Y3ma0fTNv0gBeL/6HU3
         YGrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+93O0Gucccjb6gMCWu106MHVitTkKhSsKYkDfdbKey1ist4gh9
	wzX/NHI/aGICrk9CgQzl8d8=
X-Google-Smtp-Source: AGRyM1vYnGeOHUu3Df5xdbhV1kAs/KAzh1TXGfQO5EhMbSOiXwCvXXFCxUzSTmUaqSybRisA4SpMcA==
X-Received: by 2002:a05:6512:6c7:b0:489:fd5d:c87c with SMTP id u7-20020a05651206c700b00489fd5dc87cmr913420lff.421.1658481055415;
        Fri, 22 Jul 2022 02:10:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:834f:0:b0:25d:762d:6e56 with SMTP id l15-20020a2e834f000000b0025d762d6e56ls834854ljh.0.-pod-prod-gmail;
 Fri, 22 Jul 2022 02:10:54 -0700 (PDT)
X-Received: by 2002:a2e:9015:0:b0:25d:e2af:4e9a with SMTP id h21-20020a2e9015000000b0025de2af4e9amr835355ljg.106.1658481054298;
        Fri, 22 Jul 2022 02:10:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658481054; cv=none;
        d=google.com; s=arc-20160816;
        b=SETWV3nuh4caaDOHXpM50+41D174IbGxowWpRePPuWXsP1SB2+AwZJ49vGuvyDukv6
         +RFg3COGN5FtMIqjLdpH+cicRvscHrGdHhGI+2EapS8/NQ2gExzlimTjJVJhHwJ41hWd
         7fQ6VqacEW1l1PJE9qNCU2KxWfZZve9zGcFY3tFQtb7b4daAkPywOQ2/IljZ+YNVwH3S
         0eURNdBTwtYpZtPfQRwaRxyo5TgnDa1ao9ob9SBwV7LR3uRY7VOIhmRAx4lETfbyfyUo
         fpSyHVDfUcg9bGI8Lx6AoXTIfqpj1h6RSwHUIM1+ncZzqiIXGp6zSZV+cOA3FUVs8Lg8
         I1zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wb8DNu2REjAOwbASgbT4WC/2UYmsBEeIsxT77AReJgU=;
        b=eW3GNV7vR11hlxeIcBGs3V20ZSN9Qo45VGROvzuLMIjLGxuP+aU7fEXWqSTXhKj6nM
         I2fyntjM4VlMM3U7JvDIHKsJdYjUVR7VWdw1tv/oqzTQQz3UC2dxyLNsFqRqQeBN2moh
         RVxzyOZXjZTx6B8danqDv1bFt/OAl6xMovyfK8fJf0YWqYbOMuLdcDsf6aKGBcdiolVj
         +vdYwgC9UiBThIHsNvHNDYoJUglmX/yxn/KgBwoMgXx1vV5PBukTYtv0+I7XYU6HG8kJ
         MoVLTuL3SjLqkmq4PqDzjbSIwCoIuwiK68B71mkLoyM5eaOe9odggz/ZcdGcvyChwaUA
         OA7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O6jq7Tg0;
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id k28-20020a2ea27c000000b0025ddee0cad4si156544ljm.7.2022.07.22.02.10.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jul 2022 02:10:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8D767B827BC;
	Fri, 22 Jul 2022 09:10:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D77DEC341C6;
	Fri, 22 Jul 2022 09:10:48 +0000 (UTC)
Date: Fri, 22 Jul 2022 10:10:45 +0100
From: Will Deacon <will@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
Message-ID: <20220722091044.GC18125@willie-the-truck>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=O6jq7Tg0;       spf=pass
 (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Jul 21, 2022 at 05:22:07PM +0100, Mark Rutland wrote:
> Hi Marco,
> 
> [adding Will]
> 
> On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> > Add KUnit test for hw_breakpoint constraints accounting, with various
> > interesting mixes of breakpoint targets (some care was taken to catch
> > interesting corner cases via bug-injection).
> > 
> > The test cannot be built as a module because it requires access to
> > hw_breakpoint_slots(), which is not inlinable or exported on all
> > architectures.
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> As mentioned on IRC, I'm seeing these tests fail on arm64 when applied atop
> v5.19-rc7:
> 
> | TAP version 14
> | 1..1
> |     # Subtest: hw_breakpoint
> |     1..9
> |     ok 1 - test_one_cpu
> |     ok 2 - test_many_cpus
> |     # test_one_task_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 3 - test_one_task_on_all_cpus
> |     # test_two_tasks_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 4 - test_two_tasks_on_all_cpus
> |     # test_one_task_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 5 - test_one_task_on_one_cpu
> |     # test_one_task_mixed: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 6 - test_one_task_mixed
> |     # test_two_tasks_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 7 - test_two_tasks_on_one_cpu
> |     # test_two_tasks_on_one_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 8 - test_two_tasks_on_one_all_cpus
> |     # test_task_on_all_and_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> |     Expected IS_ERR(bp) to be false, but is true
> |     not ok 9 - test_task_on_all_and_one_cpu
> | # hw_breakpoint: pass:2 fail:7 skip:0 total:9
> | # Totals: pass:2 fail:7 skip:0 total:9
> 
> ... which seems to be becasue arm64 currently forbids per-task
> breakpoints/watchpoints in hw_breakpoint_arch_parse(), where we have:
> 
>         /*
>          * Disallow per-task kernel breakpoints since these would
>          * complicate the stepping code.
>          */
>         if (hw->ctrl.privilege == AARCH64_BREAKPOINT_EL1 && bp->hw.target)
>                 return -EINVAL;
> 
> ... which has been the case since day one in commit:
> 
>   478fcb2cdb2351dc ("arm64: Debugging support")
> 
> I'm not immediately sure what would be necessary to support per-task kernel
> breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
> invasive.

I would actually like to remove HW_BREAKPOINT completely for arm64 as it
doesn't really work and causes problems for other interfaces such as ptrace
and kgdb.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220722091044.GC18125%40willie-the-truck.
