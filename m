Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE6MUGIQMGQE2PM3MPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E9274D2AAB
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 09:32:21 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id p69-20020a257448000000b006295d07115bsf1188147ybc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 00:32:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646814740; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2VaWpkRw4An3f3pLorVnMmh7Iatw4GxahiCqVNfLep7xMaK5jeYnnskTORdAgjb5K
         tG+eMHBXLCnHFC+60WQd1y+A6kKIlYWmTTNQeXWLSjzSp6aiD90aIMA5Zz5pzheUX5R+
         QdqQdpR2se7uCn0IxgBT5OwtIcA+nHcX1UjIYKcV4qtbSNVY3fii0KHdk+NY+EXmZ9uC
         GOfHRapc3+GkZDFtzspvu+vfD8aLqFiwOdywEGgK9yxlvVSHryq1LEhDd0azW2ukxyX3
         lCll0HQnn1o6Wt86WK8pfEsJbTzXFlE0H9xtxyLegICKMcyG5BU/2vDiFYBovLjVOqWR
         LIEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Eht8e4mA9UVSxPp3jtvW14kqbEboRvisD0dqKMGUmmA=;
        b=Jxv/9O8BC3b40DdzikLoml9I5hKeGjUBtauAblF47dG1GaulbZW95TVR8qlXNeqjUB
         ImlbLTtsClcqmKhOIvehqE05rrd3E8cL4wgBVFoMgn99iAFxIs65e0/xC7UbQ5iBYMzP
         5qo+Urzriju25I/OFjV9lxkh8eJVb060+JeqXonj8qQYvQprZKOPKESYMmiiwP+eowyL
         E+3B5fZSM6Ln45gvz7bqQlNWTS3ZE7vE9nxX+7CfR+xCxZvsgNb/16YV7LC1n8lBVHO8
         bjMO+LxgOOk7wgBsumfMWL3k27dhuITop4MUJJTALgSDvyamFPGcQsfV9b6Hlqcf9k2D
         I67w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BYKNESOG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Eht8e4mA9UVSxPp3jtvW14kqbEboRvisD0dqKMGUmmA=;
        b=mAkwkzgmliHvRUQowHuYxxhuwliF1OYVQCM4pa4TbRevlSXSDsWCvqc/xRCqjRkha1
         WIzsej3eux0Jtj4YhPoHymR6IjMy8kH7JaQfXqVpAK91vz3I550idMrRpSPje7/oDs5m
         XtF0M497ULKi8Pi1OeMbyOOjBac4ID/VyyC2rZCaK1GJQEHclaDNKjJNSVvkybM6bt4H
         ewrXAxulWDZztohM74COv8rGu95W/3beZa4Kr89tfTWPtTQyzQqnZXzDZ3V/RFcM1T90
         ooVFWRi+xnD6qfeGzopfWM7vUYPeMh+tH+ZiUli14X2IQaGwo7TpPMvV1apF9Pm/zj3d
         6LFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Eht8e4mA9UVSxPp3jtvW14kqbEboRvisD0dqKMGUmmA=;
        b=6jL8ZlrQ/YSwP+IZjfQan+0rCm1FukKyJjO64ymB9zkW5pU4gomphLfOz3hmMbUMnE
         NbFtbIExPpHbA8xjQJ5Xd+X7h2PCBOFQpR/SaiAOWRV8lmU+i2173qNGLOStxZM2b7Wd
         m43EKmoBf1fNZKn1RIvVZL+31XIqSqYRKktfVG6WhKDlMW2G9VVxOOVsxyZIwDt36wFI
         qrq3nSO5oE4adME9fF6wsvNlGv5g/7jxE14ndKJ+3+th8WyItwxtBgsVMXI6tn0ylITF
         sBDmH9qd66HQDbTrBZyzwDBDA5cR0ih5zmD42Cc7thPaFF0SCzHdVmtWKwPv4fDlcuaW
         1oFg==
X-Gm-Message-State: AOAM530ADVwlBurcXWRWf+yYAc3r7zY0EQY1WsR/rPKCt4NpC/ITYehn
	mmjFiFum1JKeJeoYo+5iw2A=
X-Google-Smtp-Source: ABdhPJwcimv10JUJO3vHKd4A/W23fAL6Zptwev8MH5YsLklj3utjNKP5edo9qAW7cbjsLWkFgcqP0Q==
X-Received: by 2002:a81:493:0:b0:2dc:a1c3:5e13 with SMTP id 141-20020a810493000000b002dca1c35e13mr14391905ywe.381.1646814739985;
        Wed, 09 Mar 2022 00:32:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:13c8:b0:624:97df:9f91 with SMTP id
 y8-20020a05690213c800b0062497df9f91ls795245ybu.11.gmail; Wed, 09 Mar 2022
 00:32:19 -0800 (PST)
X-Received: by 2002:a25:c241:0:b0:61d:8fd1:2954 with SMTP id s62-20020a25c241000000b0061d8fd12954mr15015356ybf.584.1646814739443;
        Wed, 09 Mar 2022 00:32:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646814739; cv=none;
        d=google.com; s=arc-20160816;
        b=Ph7LbuM3kdt6cSAuZTuZJRWqT0ZqvpVX4nb6XOuhERuOrcECgYoLyaAPuuxZv2w7O1
         Plidtz9RITofz06pqMqOPCkN+dTLuj9v/co4WL2quarz1t/RRgR7UkZ9C1tL9/0tntMP
         MNUBYsjC6mXtkV/UZvAer3YDIhiwcX8/IGqx63ljkzx4dO54aHhxPweAms7a8v/5Sesf
         C/P4cY4LEGesulxFEWLp1o7lJ8EAXk/kIKFvbt+IvRAuDOGQBtHuQOY7ZQl/78BPSTh+
         vvO8aoajzKTXWi+rNkyGSbvq/aCU2sh6B/0wYywkG7rSQ2TaUnctWLRgdc4pg1M4iVJH
         G2xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fXNP/dUkerz8xKSj4rusJS07a77a18F1+lKC1sYQrwk=;
        b=Wr6VRM4gVWDZ980ZogfZIMB1gix4OUa4UJZvRG3kNsFtuhTTed5UrH4Fv8fSrOjTyo
         k5eSiNRMpv2evnUcULgA4snaym1qpH/XtUI1UTzVjdliJ58aUrIT3JO/OWKFiQGYcZHu
         M/30d/9h1fyo1EKDeiP95o0kdencSHcy2bQchgsHPry4BmKtxWkvzO/VazE4BiD2onFj
         os4BaaCq7tuIFYNe14m2sUFY9Xkjp7BYsMb+IdzPJpDA476mAhdcCkoj572fVbyGnkz4
         O+zoJuN5JIMOAEIhi+Q3+pNPAM2+GWTkRptZzJk6GTNZuer3y2Z+2OnsfNN9rJKgIBlB
         ZZIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BYKNESOG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id q131-20020a819989000000b002d128e6be04si64780ywg.3.2022.03.09.00.32.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 00:32:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id l2so2778694ybe.8
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 00:32:19 -0800 (PST)
X-Received: by 2002:a05:6902:184:b0:628:233e:31fe with SMTP id
 t4-20020a056902018400b00628233e31femr14839424ybh.609.1646814738911; Wed, 09
 Mar 2022 00:32:18 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com> <20220309083753.1561921-4-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-4-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 09:31:42 +0100
Message-ID: <CANpmjNN6iRS1xfXq6_dKQaHJ83zrU7heZCWL2odauc=_zkmQog@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] kfence: test: try to avoid test_gfpzero trigger rcu_stall
To: Peng Liu <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BYKNESOG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Wed, 9 Mar 2022 at 09:19, 'Peng Liu' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> When CONFIG_KFENCE_NUM_OBJECTS is set to a big number, kfence
> kunit-test-case test_gfpzero will eat up nearly all the CPU's
> resources and rcu_stall is reported as the following log which
> is cut from a physical server.
>
>   rcu: INFO: rcu_sched self-detected stall on CPU
>   rcu:  68-....: (14422 ticks this GP) idle=6ce/1/0x4000000000000002
>   softirq=592/592 fqs=7500 (t=15004 jiffies g=10677 q=20019)
>   Task dump for CPU 68:
>   task:kunit_try_catch state:R  running task
>   stack:    0 pid: 9728 ppid:     2 flags:0x0000020a
>   Call trace:
>    dump_backtrace+0x0/0x1e4
>    show_stack+0x20/0x2c
>    sched_show_task+0x148/0x170
>    ...
>    rcu_sched_clock_irq+0x70/0x180
>    update_process_times+0x68/0xb0
>    tick_sched_handle+0x38/0x74
>    ...
>    gic_handle_irq+0x78/0x2c0
>    el1_irq+0xb8/0x140
>    kfree+0xd8/0x53c
>    test_alloc+0x264/0x310 [kfence_test]
>    test_gfpzero+0xf4/0x840 [kfence_test]
>    kunit_try_run_case+0x48/0x20c
>    kunit_generic_run_threadfn_adapter+0x28/0x34
>    kthread+0x108/0x13c
>    ret_from_fork+0x10/0x18
>
> To avoid rcu_stall and unacceptable latency, a schedule point is
> added to test_gfpzero.
>
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kfence/kfence_test.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index caed6b4eba94..1b50f70a4c0f 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -627,6 +627,7 @@ static void test_gfpzero(struct kunit *test)
>                         kunit_warn(test, "giving up ... cannot get same object back\n");
>                         return;
>                 }
> +               cond_resched();
>         }
>
>         for (i = 0; i < size; i++)
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-4-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN6iRS1xfXq6_dKQaHJ83zrU7heZCWL2odauc%3D_zkmQog%40mail.gmail.com.
