Return-Path: <kasan-dev+bncBCYPXT7N6MFRBT4ZQGJQMGQEVQGA73Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E91F508F1F
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 20:11:27 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id r9-20020a1c4409000000b0038ff033b654sf1230744wma.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 11:11:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650478287; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cs4O9bhzic0j1RGYVgYKmQZv8gxOM9atbe0OQzfzocDo6UM6KPpTLvHI7vdIiQrDVc
         0X9Fi3FnacsApMjcsulmucmrBTl5MksgYhnZeEHgfyBbjnecILinOUUXeof/j4KPufE8
         U99tuwAdbucQ53zgtckn1Jc1+M3yiw8vTuNgPnvcZk0SwC6eKGSydFGC20DDpH+ps76l
         FuA5Mm0UhW30TBofTbnClSYzkSLEOgl4UFD3yTLMu3ORZ5CSZeTXpGcGnwjmpILNCvKo
         G0NO83e3xpgN8GUxavnGHuNMUqa9GPQPOlXlpN3GeMZeB+MQ9ZHBikGRa/WGZx95ZeNT
         nOlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=o8jI8sAuAnbzTCzFzmc01dWYTa40kZoJl2ScPvV2KdY=;
        b=yWzL8GXYII5r2GG3qCu4R7d78qrawh+dRCXHxreCSsIDYlJIEM14Ac1xpTcn1SULI6
         L3N4EU7301JqxZjn19aE0q+mV3nSAl+syJHlVcMVjz3Wtxyqf/Vh8ywN0pzRnLdOAQK/
         0reRLHE3BgBJ8RaJ0NsKANEkaVzyx/t/JarLH6sz0CIrEu+bWL7Rk/Xul5oiFfxuuziN
         nDEU8gjoP9HEDvqPd92xNqJNMZrXWMkibh/D4rcStM6V/g9UgUdkoZ9xyWOe+p9W9oxI
         ehRe5Ktc0Cz+9g05mmDK6G8mxgTBARKqGJcoZ0/WWLPGCfkyzMIGLpRrb6U5wLc3z2N3
         9Qaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=H82Ttv0f;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o8jI8sAuAnbzTCzFzmc01dWYTa40kZoJl2ScPvV2KdY=;
        b=WZHY+YzXV3x0D6VRZIz7IVIX776Hix943OmGFqvxLzTLgoiDN7vQIuqwaPs+xWfnJQ
         rME5zE2CkU8ehkEHGnMSrNtO68rrE9ZdVOVTrwLPjqNMNxFtWNP3QFT0vMAbnuMj5C7U
         WngXbm063cN5RFAheybdKhICKXw+IER/I+1UpScD5ECkIT+DHXq91ZYHIBeJKAQ/iq8v
         Cr9G6LGs1263bVFvi9K8eY4Oifg0TjAQMty1LlYgUNjj903JRctQvxMz/o/Cns/UXOkf
         zjpsm/J6bv4XNmfP+1GYHfkOBtNKuwWOBofyjwLu6aJl+oD7KEEPRw5DxC2WUjLtbzs5
         14pA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o8jI8sAuAnbzTCzFzmc01dWYTa40kZoJl2ScPvV2KdY=;
        b=L/HXYRwa2/DK6WgurxWl0gO+GF7szHQoIM20enTDOh9RbAz0G7XtTOTL7ebLJVljYf
         doVV+ijVBeMGLu6JMgM/fKiVT/CQVr7Oyy8YKowyxtDeDCscp0CZIGjkwNaCn+xainrG
         YeE2ABzpuOxEdMpI6dCI0/wla4NRhP2uUSTG8G/5dqz90GYca7/y2p3Af5ZRtjJQ4mM8
         TxQtJdoSgdItLwnpDLtZgV9oeEIZ9lBFDXCCnjaWppfQSXHWh9fSs+Wmksl78w0Y+72/
         Yr1l7efJgfVAoryBJNVoKzdBJmmLe2UTwiN8ReexHhywb5d+GhaRPvJeP+Z32f5HnInF
         x9lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o8jI8sAuAnbzTCzFzmc01dWYTa40kZoJl2ScPvV2KdY=;
        b=ABOrRIXn/7UXXylueU3dX3ttwPuF0Kslh9h+v91m55ruSzcB3HD234Qe9SeBxc4zV5
         9LZhKQgVhh1WKo0jZQubveNnx6WrzrK5A1LKFBNQSb8WIf7AiJPRCWaAzZ+3AlA7AWgP
         hC/BVFYRhsqyD4wEb76AhxjEsWh12R9o1fQ3vaaqEee3z2K+AsOy4GtGl1lxTJc2I1YK
         6GvK5XLM3idk2/B+T0q3SbNcrCHPwasrZGjLWbPCgotMXDbJUZhHrBEMJAfSJj7n5Nqp
         MD5meH8qiUTX1eODf1m/Ep1a3/FFOC3iqqyK7b7AiGKdf9F9MSvt8nyDIaN7WGP7V6iR
         Gd6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kRvYdA7BEy690SgZh7wqEHBEucpKr1iF47YUKDh9xrM+0Yg+b
	PLSszUoVVYwtO8+tbP2ey8c=
X-Google-Smtp-Source: ABdhPJxQVttxd1C27vC8Ax41Ev0WJeOmEh/baRcU4gM/dwiPehipPmY1Wx8+FHtOKWpUQuOk1S0Dxg==
X-Received: by 2002:a7b:cb83:0:b0:37e:bc50:3c6b with SMTP id m3-20020a7bcb83000000b0037ebc503c6bmr4991566wmi.67.1650478287249;
        Wed, 20 Apr 2022 11:11:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47a7:0:b0:20a:a30e:f9ec with SMTP id 7-20020a5d47a7000000b0020aa30ef9ecls3235327wrb.3.gmail;
 Wed, 20 Apr 2022 11:11:26 -0700 (PDT)
X-Received: by 2002:adf:f2cb:0:b0:20a:77c2:3958 with SMTP id d11-20020adff2cb000000b0020a77c23958mr16106530wrp.589.1650478286339;
        Wed, 20 Apr 2022 11:11:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650478286; cv=none;
        d=google.com; s=arc-20160816;
        b=Fh+gzASnpB2gWCIGgGxWCbMUQPNVYuRbaiakXMLPCjyTWiBkIPahU5OGqSMU3alY6F
         9fvC5CHWJBbtDN2MYtlYdeGeQX2+XKmrmXhQ6Rl3QvSmGf10Po/fD2eYA4XE6xiVmeng
         W2BjAJtaT4fktM6Gh+cqKh1WudBOpFRyYR3YfZYLS5fzic7zoFux3XaH17CeZshUqiEh
         arCxFdfRseg3rg+Fdde7W1ynuFKhA6opcqBYZ84k6A9GgZmH05JiT6O4vODmBk9zHRBx
         5RD+qsE4Oe5NL1N+NE3zHuZ0kF6ml3oTDzqtF+f0eOtJDSv01pzhxG5Wgtrc2DbzqPJt
         G0DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gxAOnHHQAuaDftNo97RhXRpBzyhCyWX+rYpgSqBanog=;
        b=SYwo8GrJJtURt500OFB1L5JVbNJc/gKE+2+eFY/nK8e4wsAJY3KO922XlK9uF7JnV5
         NkXU/SW6oREyXhOjMN1dq7+AwXQ+qNd3IwZDZ69FymAPKqudTrKHWmPLCvSvei1nTKU2
         PCr3mY5lvZ2f644UeWEX2D4CGN87tRda2o6nye6vBmVNwGbbIYIe/DLXgDHdU9XBSpI2
         K1ollq6aNhJZAksWiFDDU8wfXdAdcWWadC0uOwANNyMNf7P5/buyVy8yn8mbPX4Btcfu
         Cja7lvDstWzL6HojzifndGGBW8XsQ7sKhGd4gsM4BQOIMDILlYacP/jDPFNxmGR/6AdT
         PAhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=H82Ttv0f;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id y19-20020a1c4b13000000b0038e70fa4e56si26368wma.3.2022.04.20.11.11.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Apr 2022 11:11:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id r13so5203378ejd.5
        for <kasan-dev@googlegroups.com>; Wed, 20 Apr 2022 11:11:26 -0700 (PDT)
X-Received: by 2002:a17:907:8a26:b0:6e1:2646:ef23 with SMTP id
 sc38-20020a1709078a2600b006e12646ef23mr20364325ejc.109.1650478285979; Wed, 20
 Apr 2022 11:11:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220416081355.2155050-1-jcmvbkbc@gmail.com> <CANpmjNNW0kLf2Ou6i_dNeRLO=Qrru4bOEfJ=be=Dfig4wnQ67g@mail.gmail.com>
 <CAMo8BfJM0JHqh8Nz3LuK7Ccu7WB1Cup0mX+RYvO1yft_K4hyLQ@mail.gmail.com> <Yl/Mh4gjG1hYW2nA@elver.google.com>
In-Reply-To: <Yl/Mh4gjG1hYW2nA@elver.google.com>
From: Max Filippov <jcmvbkbc@gmail.com>
Date: Wed, 20 Apr 2022 11:11:14 -0700
Message-ID: <CAMo8BfLANCoLa4zXO4aYmX0Wk7fV7_wei04MveLHu=d2RDZ77w@mail.gmail.com>
Subject: Re: [PATCH] xtensa: enable KCSAN
To: Marco Elver <elver@google.com>
Cc: "open list:TENSILICA XTENSA PORT (xtensa)" <linux-xtensa@linux-xtensa.org>, Chris Zankel <chris@zankel.net>, 
	LKML <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=H82Ttv0f;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::634
 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Apr 20, 2022 at 2:04 AM Marco Elver <elver@google.com> wrote:
> So the right thing to do might be to implement the builtin atomics using
> the kernel's atomic64_* primitives. However, granted, the builtin
> atomics might not be needed on xtensa (depending on configuration).
> Their existence is due to some compiler instrumentation emitting
> builtin-atomics (Clang's GCOV), folks using them accidentally and
> blaming KCSAN (also https://paulmck.livejournal.com/64970.html).
>
> So I think it's fair to leave them to BUG() until somebody complains (at
> which point they need to be implemented). I leave it to you.

Sure, that was my plan.

> > > Did the kcsan_test pass?
> >
> > current results are the following on QEMU:
> >
> >      # test_missing_barrier: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:1313
> >      Expected match_expect to be true, but is false
> >      # test_atomic_builtins_missing_barrier: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:1356
> >      Expected match_expect to be true, but is false
> >  # kcsan: pass:27 fail:2 skip:0 total:29
> >  # Totals: pass:193 fail:4 skip:0 total:197
> >
> > and the following on the real hardware:
> >
> >     # test_concurrent_races: EXPECTATION FAILED at kernel/kcsan/kcsan_test.c:762
> >     Expected match_expect to be true, but is false
> >     # test_write_write_struct_part: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:910
> >     Expected match_expect to be true, but is false
> >     # test_assert_exclusive_access_writer: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:1077
> >     Expected match_expect_access_writer to be true, but is false
> >     # test_assert_exclusive_bits_change: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:1098
> >     Expected match_expect to be true, but is false
> >     # test_assert_exclusive_writer_scoped: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:1136
> >     Expected match_expect_start to be true, but is false
> >     # test_missing_barrier: EXPECTATION FAILED at kernel/kcsan/kcsan_test.c:1313
> >     Expected match_expect to be true, but is false
> >     # test_atomic_builtins_missing_barrier: EXPECTATION FAILED at
> > kernel/kcsan/kcsan_test.c:1356
> >     Expected match_expect to be true, but is false
> > # kcsan: pass:22 fail:7 skip:0 total:29
> > # Totals: pass:177 fail:20 skip:0 total:197
>
> Each test case is run with varying number of threads - am I correctly
> inferring that out of all test cases, usually only one such run failed,
> and runs with different number of threads (of the same test case)
> succeeded?

For most of the failures -- yes.
For the test_missing_barrier and test_atomic_builtins_missing_barrier
on the hardware it was the opposite: only one subtest succeeded while
all others failed. Does it mean that the xtensa memory model is
insufficiently weak?

> If that's the case, I think we can say that it works, and the failures
> are due to flakiness with either higher or lower threads counts. I know
> that some test cases might still be flaky under QEMU TCG because of how
> it does concurrent execution of different CPU cores.

Thanks for taking a look.
I'll post v2 with a couple additional minor changes.

-- 
Thanks.
-- Max

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMo8BfLANCoLa4zXO4aYmX0Wk7fV7_wei04MveLHu%3Dd2RDZ77w%40mail.gmail.com.
