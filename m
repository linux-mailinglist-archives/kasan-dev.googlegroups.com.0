Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF7XUGIQMGQEWIH7VVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FDB44D2CBC
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 11:04:09 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id z10-20020a634c0a000000b0036c5eb39076sf1020475pga.18
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 02:04:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646820247; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpsAOA4I/y7mRZFn9DPFcJGGhnRx6vvUWo6Zh6tM56gZo3+wB5kIDR+ikGrtyI3MeJ
         KNFQ8cC5t67brul+lYcqW0+YW7UTdCeCYs+x2qvxIQLQYmJlC42Yu7AXBYYPd9jUm7sp
         PZ6h30v+0FluEY2fnkVvwXJIHKZRrGWHiXgSRFgqdXDP9iI0kjMsy82i4UJgWXlg9qC0
         +yyG6i0iWMEkHUcWUqrGo8r4Mslt392SkS9vqHRkapSA8sCa4bEr6Lf95cepPyIsqh6v
         x53Ityo76W4PRo4BaGZnE+sleVLA+fRvdgKZe/ageko/yQKVCJ4u0dku8tj+LhuuX2R7
         EoTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5gJ/7lBjrq9aUyScquK86movumZSJfqo5Elx5EUZdug=;
        b=Vi9mAD+9pD+qvFo56x88/tWDAYyWepFpLNBlZCiBowlYhpyeB1JrNScKj+M7yj7bJK
         p6huU4VL/ZtMuYq/GeQdxI6pTwxOCcgfvNXnr0ERcprN3Ota1CgVM5QSELh+y8mqXNko
         1sYl87Dx0kUEnd3j0baxwZa2CEmAptfIZO3U1dNWUd8XGvs6Rg4JxsrXXzBZL/Nc2X5N
         EibNuiMyK/gUhLGCe9jPxCA7bzcmIEthQKsaMCZQGHeK89Mc3AaBK5kGc85W+ybkKvoB
         N94A//j2CO9/xa4vHCYXtdJ2mAU++5gjxoxfWPFMTVEFTqaX/C5awFFvJEjnsQQ9wKJd
         a9yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZoGSXpWH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gJ/7lBjrq9aUyScquK86movumZSJfqo5Elx5EUZdug=;
        b=Y4SE2muCwl8PSizN6rTETYAmDO03hPtQXWtzXfhIM8cR9kZaCIFwFl8cF7Zurnew3j
         y8XwxIjFlRvYTVII0F2lDkqQaDVhIfCbB8ywAGFThyAOgG5XVNLFMkvtZ7qLfCMPbmPE
         swnROofpDa7FxVXUqGd+Ktgot/UHXn6HOt/av0DuJ2SoiCJ0rGmvbIrFrnlg9tkYbDZ6
         2PauO/yxIijjeKPZfnVURCjGga/PiZ4a6wCMC1W4/8DYjeaMn9GwCGmfM8HS0M2v6mHp
         ccXy1Ct6gCodQBZBQ6+0HrYPoGqPFckLF4qV38f/X5tskTI5basP6qVYrsuNYErSPFq0
         eFkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gJ/7lBjrq9aUyScquK86movumZSJfqo5Elx5EUZdug=;
        b=7oPnUaBLkfcyXqSWpS2fJdiPvQAw9az0M9XOeghHr7QnfsyeEjEUOKHWYK4pVSqUju
         HuWrcwORyoWKKe4Cqhi0x6vRJ9e4UJg6ht/uDw+T9roeo2pmV/7JmB+EOgTqlNxqXVzn
         qCeJ7o7lYmZkm5kHgrkP/SwuDRTVc9Ti695ltN6OCqpJKAFUD6V4gWNMqLN1UXdlopW6
         w8WDR3KybEp+bgldVax4yAn3gcUIukjB94zf6/0eCHUKISr+xN0G9YJv2bhPP0ASjvHF
         dNEB3MryxF2tByYsa918CmXJWmjWschhXic3OQ668NblIcqn/QsiV5kSN0FL1KRBG24n
         FtjA==
X-Gm-Message-State: AOAM533J/FntzKSYoUwkKRuPJ3m7pHVxj5NpYA+O9rW4sPZwfplcFHD/
	SDrRHaMmB6tntXQ80CBx1/Q=
X-Google-Smtp-Source: ABdhPJx+Q4NXjIega+D0DEYZkk4NR9nMtxFrWU2EYU7CQAO5+OXuFyA4VTAY7S3WZNetASYAsp4i+g==
X-Received: by 2002:a05:6a00:a23:b0:4f6:72a8:20c7 with SMTP id p35-20020a056a000a2300b004f672a820c7mr22764793pfh.12.1646820247696;
        Wed, 09 Mar 2022 02:04:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b8c:b0:151:eadc:9992 with SMTP id
 y12-20020a1709029b8c00b00151eadc9992ls1307533plp.8.gmail; Wed, 09 Mar 2022
 02:04:07 -0800 (PST)
X-Received: by 2002:a17:902:ec8f:b0:151:a28a:943b with SMTP id x15-20020a170902ec8f00b00151a28a943bmr22625141plg.56.1646820246949;
        Wed, 09 Mar 2022 02:04:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646820246; cv=none;
        d=google.com; s=arc-20160816;
        b=I20EZVOHMxZi11AaDE00sYX7k0BGZa+TLl28AykkO3W6c7QneIfPJaVvpP3CklLnrr
         sNrKvd0jcDeucnX4n+t1wmdFe8Gt9b/AFD3DkWrld00lHfGiLFc2ygFpvtZyiOvRuzq4
         TfWCpGUxk1tdTPM+SiJTqbL1GwWIzgt8bd8bJDiwmTA6dO5ljFvCK/tdzBnJRjHD1FV0
         YdHt/KoN5j1C7jjzBZqWph9K/lL9dHUPaNVDM6Kdw9ELSZXAVLLt9FbkWYgMJiE9uCVZ
         lxy9TZJghnLYfhystEdKzNoId1ihVeAtXLLtFFVkQ2pwc3RDxPohqmfBrk8HuBTa9kti
         tHLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Snnx2gCzpEJKOVry4K+to5AuKutoJTTCZRIqxcxA9Nk=;
        b=GyXI+0lENC8WDqvM8lxx1XxRyJWIRRLcrhKoPfPNiw57o1B+siDKXV+yv1GM8ZF1+8
         gAhxW6ZpIUi/yBtvZhK9bRvTLsDxDGU+lH0TU5jeRZ+tGnjnjuVlF1uStOtbyEcTmuw+
         ypfZB8llKMHPyVHdRSdPZOQAtK8pcFUVzJzs1v/hePWcfdUJpWWfQF9eaxDTy0FhVTbA
         uErH7Tb8yexBbON2c5noYkOW1fqf5xqi/z8oLR1qGXCrKY5V7WnVR2bEVmXpFlM3f72q
         hRgbudHuPMlOVHdpqb/EdUA9cex66760mBZhLLj2+IhkreeZH0nycYc5N3jVCziZBbSB
         PEoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZoGSXpWH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id ge24-20020a17090b0e1800b001bf6ac2c31bsi73894pjb.1.2022.03.09.02.04.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 02:04:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-2dbfe58670cso16946587b3.3
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 02:04:06 -0800 (PST)
X-Received: by 2002:a81:8985:0:b0:2dc:472:ff3f with SMTP id
 z127-20020a818985000000b002dc0472ff3fmr16171043ywf.333.1646820245970; Wed, 09
 Mar 2022 02:04:05 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com> <20220309083753.1561921-2-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-2-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 11:03:28 +0100
Message-ID: <CANpmjNPkewkNv32+LFA8bHixL8E=Cm_deVttoqTeTMO5aeOtSQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] kunit: fix UAF when run kfence test case test_gfpzero
To: Peng Liu <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com, 
	Daniel Latypov <dlatypov@google.com>, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZoGSXpWH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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
> Kunit will create a new thread to run an actual test case, and the
> main process will wait for the completion of the actual test thread
> until overtime. The variable "struct kunit test" has local property
> in function kunit_try_catch_run, and will be used in the test case
> thread. Task kunit_try_catch_run will free "struct kunit test" when
> kunit runs overtime, but the actual test case is still run and an
> UAF bug will be triggered.
>
> The above problem has been both observed in a physical machine and
> qemu platform when running kfence kunit tests. The problem can be
> triggered when setting CONFIG_KFENCE_NUM_OBJECTS = 65535. Under
> this setting, the test case test_gfpzero will cost hours and kunit
> will run to overtime. The follows show the panic log.
>
>   BUG: unable to handle page fault for address: ffffffff82d882e9
>
>   Call Trace:
>    kunit_log_append+0x58/0xd0
>    ...
>    test_alloc.constprop.0.cold+0x6b/0x8a [kfence_test]
>    test_gfpzero.cold+0x61/0x8ab [kfence_test]
>    kunit_try_run_case+0x4c/0x70
>    kunit_generic_run_threadfn_adapter+0x11/0x20
>    kthread+0x166/0x190
>    ret_from_fork+0x22/0x30
>   Kernel panic - not syncing: Fatal exception
>   Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
>   Ubuntu-1.8.2-1ubuntu1 04/01/2014
>
> To solve this problem, the test case thread should be stopped when
> the kunit frame runs overtime. The stop signal will send in function
> kunit_try_catch_run, and test_gfpzero will handle it.
>
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>

Also Cc'ing more KUnit folks to double-check this is the right solution.

> ---
>  lib/kunit/try-catch.c   | 1 +
>  mm/kfence/kfence_test.c | 2 +-
>  2 files changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
> index be38a2c5ecc2..6b3d4db94077 100644
> --- a/lib/kunit/try-catch.c
> +++ b/lib/kunit/try-catch.c
> @@ -78,6 +78,7 @@ void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
>         if (time_remaining == 0) {
>                 kunit_err(test, "try timed out\n");
>                 try_catch->try_result = -ETIMEDOUT;
> +               kthread_stop(task_struct);
>         }
>
>         exit_code = try_catch->try_result;
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 50dbb815a2a8..caed6b4eba94 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -623,7 +623,7 @@ static void test_gfpzero(struct kunit *test)
>                         break;
>                 test_free(buf2);
>
> -               if (i == CONFIG_KFENCE_NUM_OBJECTS) {
> +               if (kthread_should_stop() || (i == CONFIG_KFENCE_NUM_OBJECTS)) {
>                         kunit_warn(test, "giving up ... cannot get same object back\n");
>                         return;
>                 }
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309083753.1561921-2-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPkewkNv32%2BLFA8bHixL8E%3DCm_deVttoqTeTMO5aeOtSQ%40mail.gmail.com.
