Return-Path: <kasan-dev+bncBCA2BG6MWAHBBKPEU2IQMGQEXIFNCYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A40E4D4237
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 09:09:14 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id d40-20020a0565123d2800b004482625da41sf1511024lfv.20
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 00:09:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646899754; cv=pass;
        d=google.com; s=arc-20160816;
        b=urMQkmS58H+fuMHKP2fGrx9hZcv+9Ny81osf9gdX5Ys0KMAk/hcIw0zzm4OpRf9AY+
         opjWKQEXrgHv3PGIAhffxQ/nhHXsphuziqHYTRYTgoJ6vlJAzPGC3Wn15umEP5ZUIDOy
         ljjwIa8X+b1Iw4YvX2oxlDamDD3wGM7e0T6s7J5OppjmEKcwynyB7Xj0GI+3WOuEQmWO
         z8Jk51/TmqvDzY9DYNGIoJxHc5SkAStFaSXxN2dOoQl0DM0Y8maCXVjfUvz9fAUjU4C2
         zS1qNHG12MIf4W6mPPw/tqeJ5JRe2ph3l3+DWSO+ij2bEm/eftLpJLiJ57dQuZe+brVh
         AV0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0i4s35WUAvnhft1nFlVthTeskgL94o3MF33L9NER8yw=;
        b=uQ4RbfBBDMpPHt6pa/ZMzaJn7xnj/693j5+WrKCCpeU3F2CxXCrGY6Mdk/bfV0YQiS
         QrY2OfyLQtZWeCAUqGZzODLrRmBUCXwX9O2rLascgU2k+QRE2+qUzcrXBzmKCV7Jq3/l
         /B+SkSCNFGojDhxXm+67W0v6qhi7u0l1RLOJMw/4phXvUdFmnoOUvhKngb5lfpWIEze8
         zgMt1FJqe/1EcJHfOlytl+oHq9OZk0EloGCgqM5gP0sl2R+Sw2toIgjIq2kdPSTOUP/Q
         vV+XYSnJUpW9i/nDSOqYmGNyQ47xma42XswHcS9wVn/1MhnVEUrFbMcbeTG+wMQb/Mko
         m4MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="r6m/oi9H";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0i4s35WUAvnhft1nFlVthTeskgL94o3MF33L9NER8yw=;
        b=I9UV8lq4wroNz/5zZUcaHF9tsb9fumiujVvAccI7F714ABw8zvVAO0AsWs9L9V8tc1
         RoVgzvgf9uS0JjucnYxjV/54gXYySRgevdMnaUMp920TS8TtMYz8xU8HRqNAeqS2rttW
         rEGs/TJ4yzRaLHf3cBySMfOeDgVEOoha5Sls7A4lbItUYQ7zVs9WZ7mNZi4r2sleTPlz
         06B0lis4mJJFys8hLd2LkQRnn6KG+7/UqqJIp8XUcWrXjgDgKL5EA6F5UUwSu7mxIsh/
         aqtVSvhZtNIhpBOAZCz0+XuwpI4ryE0KQUfs+6DffXLH8x41AJhxrPpfDY0bBiPTWGnH
         +TWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0i4s35WUAvnhft1nFlVthTeskgL94o3MF33L9NER8yw=;
        b=hzirQd8iQs6RtxGH3MHFLPRlSGXlF8j+6YmledJ7arBdydQ1BhVGabC91rSJO6suG+
         6MznTULOdKuXO1hRs0lU9P6xGIEljZ2dPP725FV8uouP0R/KxT5U1FCUW8yUkxdqG1yJ
         1YLsKzBb9+XNM+Id+rdpkzsjrN/OD0PKDSUCP7S6ZBUFMyHms7AjlBxXu6ysfrEwE7yZ
         vBRiBQWJBqEfrOFEu3lu532nIEnuK+ADmxFLztEWmUhsdrctocgyfwwKw6A/1YSN8UOP
         Lu2PUmIS994goSuXij0F6oAbpNm3245F63ywBQm8+iebLy95wF8728VcRwy3tjPBb/dm
         489Q==
X-Gm-Message-State: AOAM533Oy5kTdPdXTquhUkiRNvmDX/t2Kn3ZjWndHcyIAviWmyHwlZiX
	Y69urIO+0ZBObhWMUlQc+MM=
X-Google-Smtp-Source: ABdhPJzSJocx8h+E7S1OMml1GhIiaFD/Fpgpgj7DgGC5QpUBtdxhobbUhAWsDpGPDyfe1bMu31r7/g==
X-Received: by 2002:a05:651c:543:b0:247:eb38:14f3 with SMTP id q3-20020a05651c054300b00247eb3814f3mr2283517ljp.526.1646899753991;
        Thu, 10 Mar 2022 00:09:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf20:0:b0:246:801e:c87 with SMTP id c32-20020a2ebf20000000b00246801e0c87ls923944ljr.1.gmail;
 Thu, 10 Mar 2022 00:09:13 -0800 (PST)
X-Received: by 2002:a05:651c:511:b0:247:f8f0:e0be with SMTP id o17-20020a05651c051100b00247f8f0e0bemr2307157ljp.474.1646899752926;
        Thu, 10 Mar 2022 00:09:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646899752; cv=none;
        d=google.com; s=arc-20160816;
        b=JSyggpGMyxamtaNmjFww5Vg4bW/kgqSBwvrMMiGW7lZsmQCYYWg5yyMRG5ZHuhVmOR
         IBQEQU97kr08iDxY9HAy6h7P50knleATVmchkx/6NDfeE+K1M04Khz8SV9nHTtWcjUJ7
         AfTqbZOWqo/6cdV0BPm4cfAsk+rCf8mIBBi8r6N0uUrBwGW9MHKi8PeUcM7Ho6bV0Q+d
         63ld8z0Aw6q81c6qh/YdDm6v2k823HqBH442i71JWVIF7bcJoSz0MkRI7QAyc4Ij/R6g
         qR1NNiqXrVim/0RWf9FLonY8FICA/kIUX6GvtMjxoJ49qmE3A4oWT5CRiWgNW6iliQA0
         h/5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YWbAcZy/i8HBYK2+LI1DmtpGjLhVyIVjDAmA+olRSX0=;
        b=QGal9jxwh4CBrb08EIr3UmYD3wtAkBf6Wld//3sn7in83TEABoS1m155slwvM9jQrw
         EBlhGQoodicnsL5vPU4SDOf6MmwEGE9nCvZFhiAVQ9f0TqYV5Bvj8bXE1sGwgUw+vG76
         wol736lBf2GJNE4nTqYyOLW9Fw0yJKjvpKrx4AeS2obzSrPmE7sxIfFOfhoBgcg7eJHD
         sWgAcOHJM6bTm+DZBBgPciBQRo3yuc/N+QyrS9lP4qEpDftT69ImjWNapCyClM+CG6Dc
         HBdWFTlSWEjc3HjiHktnVCnH3s0JQQgYGIUvxvg644La+4vT5+ZV/uy4vbbLrXys3mDY
         ed4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="r6m/oi9H";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id g6-20020a0565123b8600b0044835aa8864si250043lfv.0.2022.03.10.00.09.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Mar 2022 00:09:12 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id b24so5886618edu.10
        for <kasan-dev@googlegroups.com>; Thu, 10 Mar 2022 00:09:12 -0800 (PST)
X-Received: by 2002:a05:6402:26d3:b0:416:4186:6d7d with SMTP id
 x19-20020a05640226d300b0041641866d7dmr3159206edd.129.1646899752425; Thu, 10
 Mar 2022 00:09:12 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com> <20220309083753.1561921-2-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-2-liupeng256@huawei.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Mar 2022 03:08:59 -0500
Message-ID: <CAFd5g466XMWRszdn=Wdg4GXNv=KR-CZmWYZ0j0bG7_1QXtu-LQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] kunit: fix UAF when run kfence test case test_gfpzero
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="r6m/oi9H";       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
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

On Wed, Mar 9, 2022 at 3:19 AM 'Peng Liu' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
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

Thanks for taking care of this.

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g466XMWRszdn%3DWdg4GXNv%3DKR-CZmWYZ0j0bG7_1QXtu-LQ%40mail.gmail.com.
