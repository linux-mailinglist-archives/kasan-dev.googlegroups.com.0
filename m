Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXQ7GLAMGQEE7DM7EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 201FF57FDFD
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jul 2022 13:01:28 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id l18-20020a6bd112000000b0067cb64ad9b2sf41323iob.20
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jul 2022 04:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658746887; cv=pass;
        d=google.com; s=arc-20160816;
        b=ygH4m2a/B6CBd4JH07S6sVkvGKahYf5KHCdUftx3jh/V7nEWF42myK/+R1YwbTSW93
         Ioim03McFviZQub5msN/Q9cpNOecqzm1GbStw+NuwsgUjOVcG7G71oxuXD2Io4lnOfZY
         r5l1wbViU10mbFqQ3jzqfywKgfEt6V5yVUmgcNXJubnw0zpLdFvrk8h03F/WK9nNHu7E
         xBiwwNpoYn0g1rnm5AHpwVPS/+Hp8sP/lHCA4caXzs8dm1BcIBbK4rBdwjHqsmsXe0yd
         Czo9XwQpx3krbTktPi3DqhRDvF7s2sqrz83LbgNdPDa/gkpnrXMx4WUW00ErBqqPXR+c
         VW7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=F8eed+AFz36Juji/g+73XTRTym5qCUYS9L5SlXt20FY=;
        b=rEiNcn+H5b7rdPyVJyn0/FKX+vyavODGAqw6T+q8P1iPsq7zAaNky0tR17pb6J1ody
         ni+vpMlWNrZbR346aWrFKXEXrP10RaspB88fuEcS3y7I191coMXRbIo2BJvsiEbLKIBy
         ZKY7btKBt0CuZ5AYFqqscCP1gPByu/KvQLg2eqxCp59JXAxy9km+3sK3mrKM7K2Iei8b
         5r2eBtrKX5UU3dKH8/Lv/5XYdb0kSeDvtmLBo0owGjgR3/OT49f208wKhx/xph/tae3v
         SjrSMmHioBBNOl39O2emB0hax5liFlAQoZN3Na8zxW1hzg9KQQyOGT3UptTN/IEN/FL4
         xpSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E3q3Uy+K;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F8eed+AFz36Juji/g+73XTRTym5qCUYS9L5SlXt20FY=;
        b=eSoJGqRW+WnGVUHDInmGaRufL2EBxOm9ZIfqJ67ipZQrOGtNWOToWdfVnasVZ36ZME
         3izysJdShjRDiKY5K9aqU2Ih1ZLkR6alcAN3rb/1sO/XycEOlbZP0gMw/AvTBAL+gkap
         MzEXlYHXZpNbJp9y100n+ICorsvB1UcOy4955gOTh/iETNq+ao/0C+a+B4rCRzucWya6
         tU0fynTrtfFRSDVBc6Xi3inhIJfSNdgXZEboPrG28vp3ItFtJyGZOfxLvzN2jpzD3fG6
         h4hR7QnaR7FOLG0wbqa+fid+RPdtBCNbLgEezHTtn0YnwixaH3eFPSML+9AQx2m0kZXq
         M0wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F8eed+AFz36Juji/g+73XTRTym5qCUYS9L5SlXt20FY=;
        b=zy8uQGj6K52qyULB7255Idw5Fu217GtpXRMBB7v0iM+en3brCM7mWrkVuPtjdrpmm4
         0qRwvro2nwBKf4mNehWWvUuApEdXAMFf+lHRrzKL7EpkoMSG04f3YkztQAPOigXJUSuH
         NgRMGiVEFu7Km7zjdVt0jxle4KJjKgQt9MyCKauA72i0KBcdUKqU4vGvnQ4ltU9yrJVN
         aYtY+Oz1SEgO0VRNLtQiUWXhXAK7GjP4UDKZqNrBS2z8DBdJilsLopVZemna0Ieym33S
         6V7uekCNsC2YYV4D1GBietAmKwXcxqitK3r0EcUXNrtWrppHAQUS723uyKhN8jHZ5ZpU
         50Yg==
X-Gm-Message-State: AJIora9hfyBroVd0z41CW7pzkeatVO8U4uFsAdreOZkRWZiCduj8oCNk
	+JFrMO1wHsTWVW+tuZWp/qA=
X-Google-Smtp-Source: AGRyM1vV4fM0KZsTPkJUOL9G0fgVC7KvYg8JRzljY9ZIZ14ZPX49wpoiJ67TgyHnKIuHbrmO++HW4g==
X-Received: by 2002:a05:6638:4094:b0:341:5ecd:365a with SMTP id m20-20020a056638409400b003415ecd365amr4749306jam.221.1658746886797;
        Mon, 25 Jul 2022 04:01:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8e04:0:b0:67c:56d:eadd with SMTP id e4-20020a5d8e04000000b0067c056deaddls381131iod.8.-pod-prod-gmail;
 Mon, 25 Jul 2022 04:01:26 -0700 (PDT)
X-Received: by 2002:a6b:3ed7:0:b0:67b:d012:b72a with SMTP id l206-20020a6b3ed7000000b0067bd012b72amr4128361ioa.149.1658746886131;
        Mon, 25 Jul 2022 04:01:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658746886; cv=none;
        d=google.com; s=arc-20160816;
        b=RF4WRuKcsVLy/mxHspZDMOZcecvQRdlz0wS6rlgMYA/M7yN08ipl1V66Gx69jE9BeR
         vGrTpgu2sfsMGXlLfbXudPi57quPA/U0LySJfeM0aBSSopoUk2flBwHaK36huvbNiNtv
         jTynxWgL/quPTpXQonIfeELPs6K8ZU+UmGPWj/BPM+GLIZZ7hCB3xhqV9nlcSxZTZKH5
         pYTKq2kaWUG52ffabRBQWcrT8F9H/bx6Tn2R0JXBxLCCyLMOfWiM/icXrXmD1eJS4t27
         5G7FOX+3vQ5ioPP5nRCHyLpYipugOdnNnfzsJjL4L/9/apBhlssptF/pEmiYGmG0bLwJ
         wcKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hnm/5jPi/oqeCaQaqiY7o9Mgs5EnAdp5rIAWl4CX1kc=;
        b=R8FJ71n/w3Jmn+svo9pQI+v9+vnQuiO33mGd9xElFhgTLZ0vF1tCy+ScMP6khtOFFS
         7tvyY1svWBljLCMfVSzDVOlsk3MrdjrgR90qbBD7Q/potznhK/t+ome01E4oqYTY7Ikz
         wSxMbhbd22iSgHiQ7ILu4p97hICr4Eqca1rlFgUKQDraEyAG2vxlo9bZAvMhHJ/BTbX+
         lv3afnb8O9lbiUdeQPShCeliUlk6l7HTvOaiKeCPhEgIpJ60sxtibXz4DSpAegqEUR3Y
         7BWlD9IS+WTCxUAW5UIJnGZ+XZIt/G/BzdSxQoptGZ7y4ItD/MOzKhsAAN9quyUXVj+l
         Kw+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E3q3Uy+K;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id m11-20020a056e02158b00b002dad0373761si556618ilu.0.2022.07.25.04.01.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Jul 2022 04:01:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id d124so1947505ybb.5
        for <kasan-dev@googlegroups.com>; Mon, 25 Jul 2022 04:01:26 -0700 (PDT)
X-Received: by 2002:a25:c602:0:b0:670:90ba:98fb with SMTP id
 k2-20020a25c602000000b0067090ba98fbmr8445943ybf.143.1658746885541; Mon, 25
 Jul 2022 04:01:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
In-Reply-To: <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Jul 2022 13:00:48 +0200
Message-ID: <CANpmjNMk+p1bAEKe6Em6n0_6_1O2Aco7g9v1hcVj54hKdGJ4ug@mail.gmail.com>
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
To: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E3q3Uy+K;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Thu, 21 Jul 2022 at 18:22, Mark Rutland <mark.rutland@arm.com> wrote:
>
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

Thanks for investigating - so the test is working as intended. ;-)

However it's a shame that arm64's support is limited. And what Will
said about possible removal/rework of arm64 hw_breakpoint support
doesn't sound too reassuring.

We will definitely want to revisit arm64's hw_breakpoint support in future.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMk%2Bp1bAEKe6Em6n0_6_1O2Aco7g9v1hcVj54hKdGJ4ug%40mail.gmail.com.
