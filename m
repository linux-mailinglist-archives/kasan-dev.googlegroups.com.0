Return-Path: <kasan-dev+bncBCYPXT7N6MFRBAPO7WJAMGQETFZ5UKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7DDA507F43
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 04:59:14 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id u17-20020a2e9f11000000b0024db4b08035sf65893ljk.13
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Apr 2022 19:59:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650423554; cv=pass;
        d=google.com; s=arc-20160816;
        b=HGxBAbk0wHpH+4jG+m9Gw8ZIkp/X1mXbyc9190B13pyI55sI15fuO0ltg83Wj0zHc1
         weedbn9koL809FxOJTk45E8IGUaU8Y/zXunNiGLakD7DOG96kLX9kZxRjp/xYmJOAjip
         ylNM3/CEj6GzzmrWoJA7QnEvqyNeCoRsm8/LnoaZNM+g9KuF/fZmfneInBK4HfWSfpJ7
         F/oKKyRBxpMpN4eiL2Q1P3vMPmghgMjh0SJ+y+zaynlQpMk1P0zGjKfm0EkTLuTD6sGC
         q7NVcluTEKVQqyNqFYhnAD7WU0o2uX7Nz/aqIafk0cCaaUT+NVcFlEUq/OftFp/9MBiu
         rg4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/VHRRb+CiXvpLJuC9jRwmQ0CWaOpTVKaZ2QmP8rlfEg=;
        b=f/ntdIj7LZs/GjTriEp5DHlTCaW5OF4Rc7LR4FA2MNBHkgUAxs1RkXBQFPQtVdyYuR
         5NdzLLu7yyDu46d01sNAZM+uWZ3AaxyBqviv47GTj7sCVNFopFSKnnt09dO4Fr5M8NWA
         yQ6gUwCOJhNvWgqFQXH/khDc4IYcWEeQOfzyFaSSS9imTS0/klM1UZeIwx7pjZp2hkpy
         NgQcwj3aqwjGxJ6/ITe8PIzD7p6tC9vNhoKsfoLkry7yPjKpluhylap7tkwBohY6LFy/
         SlFbQzHeKWvGxDJZDyo7ZvpRVzsJwuZRxLee1I9BD30VL+fy2kqPGojeBpRuUOpxnFm3
         Fzgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=VLMO61q8;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/VHRRb+CiXvpLJuC9jRwmQ0CWaOpTVKaZ2QmP8rlfEg=;
        b=gLvnWX8X69rjeQf0IFWNXGqTyGFZOogjsiQpphYUyAtcVXzxD0FGy5KHISim1YPcUm
         ou3mIX14VSyhTRmb5e/iijwlCSzOEHSYwihlz3xAj4Yfghb7WcafnhhoRyHl8/nI2DOG
         KXmcHtz134JgfNbn0hcgKPC6QJujRvsQoo06DkMz9rC8VLOl+HQqZPlK2+YIdIIt8hmb
         +3BhB0lYBRcF8r/HM24/1JCkCOEfNJF2RHQdNU8IJ+0EueshZPXffiXIQE00k1rcbtrf
         DTbdWV+ya5JLPshlOrbwsbqXPlwGWiR5OIKSqjmpb1kpvbaGNks+Ru8Qilo6v2m9358K
         81BQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/VHRRb+CiXvpLJuC9jRwmQ0CWaOpTVKaZ2QmP8rlfEg=;
        b=TIOg3IqXod4mXdMCZL/BemaAxtv36gsnxboKEHA88zNhlRlhxa1qCAWWYowQ01TAhW
         /seMLGU6C44TYXJktYwdCvxjCHVrs+7QKkjcHj8IO9CSIewijfJwz4QkT5UzgrjikuWX
         kZhcjCksgOSxVQWugQq+0cUIQdZHbXfvfuan0pMFZ1ICreFIPSkIzoEIvdzuRs0E4DH7
         iBBN1mSz7Qr9caCdyqlCrs8VeydS7hlXnX61W7+ci9Z46gwGeHhlXtTpZBYBnPHYUdpy
         cS4ZEK7rcUY2ETrDj61SXFacRh/2yRq66/JNd0nTjFGcM/u15TLmPOJyWN9HeVdB3mXW
         vOlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/VHRRb+CiXvpLJuC9jRwmQ0CWaOpTVKaZ2QmP8rlfEg=;
        b=k3TlOJ5VkkOsu+nd/+yFcMcP587jXvwt5gOU9mWrmoVdlaaxtxCj5FcU3lCO1rHY6d
         LdgRpB6+gXh01/Frw7idUUqNyisQOJnJEq4kF9varD7tFJFiJAXpP9rkNnPMup1Pa6tO
         TbgO8BcIIuDCXlJ6QRMqN5BSFAEWjS3z6XHqY0mTn1zg2qvFIZqCjpQHgQDoC5PNiv99
         D4ADv2sv2u2nqviH1ribE3TXJjaHp050wxptlioIkwJOu2qFTzjuNXND4tIFXWDxptUq
         O51/LKEIdarJH5uhdZrh7X07eRfqgYjsmACygbxcPon+QGhSjHMfWtX3fYhn3Mt+NEJH
         l9Mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530K9X45vtNLnxLrW7nx4OakT/4X4/c1kRVXjAudfuB8q6JeEG0G
	gGKYmNTKrqNm//bTb/1Jsho=
X-Google-Smtp-Source: ABdhPJzbvXOiY2xa5AvVLrXg+YfgcBlifYh4pDBdI1oW8Bi6g2G9J6xuiXB177JmvsdtEp7sz3JGZw==
X-Received: by 2002:ac2:4554:0:b0:471:8d27:ec33 with SMTP id j20-20020ac24554000000b004718d27ec33mr9607029lfm.683.1650423553708;
        Tue, 19 Apr 2022 19:59:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c3:0:b0:24a:fddc:ed41 with SMTP id x3-20020a2ea7c3000000b0024afddced41ls163853ljp.9.gmail;
 Tue, 19 Apr 2022 19:59:12 -0700 (PDT)
X-Received: by 2002:a2e:8512:0:b0:24e:16c2:c976 with SMTP id j18-20020a2e8512000000b0024e16c2c976mr380880lji.349.1650423552407;
        Tue, 19 Apr 2022 19:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650423552; cv=none;
        d=google.com; s=arc-20160816;
        b=FkKuK3ivqHimOIM3mCek4Xzsgl6H+don3ZPNgx4bwx+QZgUqX9mkEcwfDxtBeYhVFG
         bLoO8gIVi0ZNDm29KPuR0YqI4OTDxBk8TaRrS6KFfvksW2nQ5jWSX4Kr8IEkfq1j3A/t
         y+vkIgi7S5SiFOZUP0nBZ/nJ+kdPnnik6Aua6DBUQFMNNOJ5SPQZCNB/PBuTXtgNnmew
         iYg7vtfHLtPf5R79bI51rLQX81ZN2+OOtfNgBWzQFQuPswfzWiIWB6oPTmfh5OFwSjMM
         k52URTe3p9LTUNjk4YLrc6du1pq8jYo6gw8mEbX+0x2mL5kZewkRowPeN3Cfa1RQqKsy
         KyNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fCO4DZsrcFJvW/h/KDtAy5sw4iMAoyjRegeBhEbbGME=;
        b=EWYqFa53P5fEILVZhYs40/j7ln4RrIH6IR7mRYfKVQKKLk5G/UI+nc87QNaTVi3X94
         kijminZ4OB9+lo6Ff11j4ZvMWyPTF5KucZs2X0GTsjDQX+8gVqCLWPM0n0O+tZ23tEIW
         t9PcCCejzX8sG4Z7BDpDgoba/3En0SRQLrkEIxS9UJqUiYFuNnVwqr/oS/snuWpA6tNc
         JM7Iy30dSmj69mqBQvRZavFnW/sO+hv6M3S/lO4JHjfezodvcgE9sl/L9cYf56VRNzOO
         bJ0E0J+SL43EpOYb3RKUnrFlle9219u6in57wJ+D55pkeNu5lJOWLXNT1gB1OpVe1l9J
         mMCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=VLMO61q8;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id o3-20020a056512230300b00471902f5be2si31558lfu.3.2022.04.19.19.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Apr 2022 19:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id g20so559018edw.6
        for <kasan-dev@googlegroups.com>; Tue, 19 Apr 2022 19:59:12 -0700 (PDT)
X-Received: by 2002:a05:6402:350a:b0:423:e41e:75cb with SMTP id
 b10-20020a056402350a00b00423e41e75cbmr14422528edd.178.1650423551851; Tue, 19
 Apr 2022 19:59:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220416081355.2155050-1-jcmvbkbc@gmail.com> <CANpmjNNW0kLf2Ou6i_dNeRLO=Qrru4bOEfJ=be=Dfig4wnQ67g@mail.gmail.com>
In-Reply-To: <CANpmjNNW0kLf2Ou6i_dNeRLO=Qrru4bOEfJ=be=Dfig4wnQ67g@mail.gmail.com>
From: Max Filippov <jcmvbkbc@gmail.com>
Date: Tue, 19 Apr 2022 19:59:00 -0700
Message-ID: <CAMo8BfJM0JHqh8Nz3LuK7Ccu7WB1Cup0mX+RYvO1yft_K4hyLQ@mail.gmail.com>
Subject: Re: [PATCH] xtensa: enable KCSAN
To: Marco Elver <elver@google.com>
Cc: "open list:TENSILICA XTENSA PORT (xtensa)" <linux-xtensa@linux-xtensa.org>, Chris Zankel <chris@zankel.net>, 
	LKML <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=VLMO61q8;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2a00:1450:4864:20::530
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

Hi Marco,

On Tue, Apr 19, 2022 at 3:16 AM Marco Elver <elver@google.com> wrote:
>
> Nice to see this happen!
>
> On Sat, 16 Apr 2022 at 10:14, Max Filippov <jcmvbkbc@gmail.com> wrote:
> > Provide stubs for 64-bit atomics when building with KCSAN.
>
> The stubs are the only thing I don't understand. More elaboration on
> why this is required would be useful (maybe there's another way to
> solve?).

It doesn't build without it, because the compiler left function calls
in the code:

xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic32_compare_exchange_val':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_load_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_load':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_load_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_store_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_store':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_store_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_exchange_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_exchange':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_exchange_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_fetch_add_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_fetch_add':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_fetch_add_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_fetch_sub_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_fetch_sub':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_fetch_sub_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_fetch_and_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_fetch_and':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_fetch_and_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_fetch_or_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_fetch_or':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_fetch_or_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_fetch_xor_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_fetch_xor':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_fetch_xor_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_fetch_nand_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_fetch_nand':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_fetch_nand_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_compare_exchange_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_compare_exchange_strong':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_compare_exchange_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_compare_exchange_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
`__tsan_atomic64_compare_exchange_weak':
kernel/kcsan/core.c:1262: undefined reference to `__atomic_compare_exchange_8'
xtensa-de233_fpu-elf-ld: kernel/kcsan/core.c:1262: undefined reference
to `__atomic_compare_exchange_8'

None of these functions are called because xtensa doesn't have
64-bit atomic ops.

I guess that another way to fix it would be making
DEFINE_TSAN_ATOMIC_OPS(64);
conditional and not enabling it when building for xtensa.

> > Disable KCSAN instrumentation in arch/xtensa/boot.
>
> Given you went for barrier instrumentation, I assume you tested with a
> CONFIG_KCSAN_STRICT=y config?

Yes.

> Did the kcsan_test pass?

current results are the following on QEMU:

     # test_missing_barrier: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:1313
     Expected match_expect to be true, but is false
     # test_atomic_builtins_missing_barrier: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:1356
     Expected match_expect to be true, but is false
 # kcsan: pass:27 fail:2 skip:0 total:29
 # Totals: pass:193 fail:4 skip:0 total:197

and the following on the real hardware:

    # test_concurrent_races: EXPECTATION FAILED at kernel/kcsan/kcsan_test.c:762
    Expected match_expect to be true, but is false
    # test_write_write_struct_part: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:910
    Expected match_expect to be true, but is false
    # test_assert_exclusive_access_writer: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:1077
    Expected match_expect_access_writer to be true, but is false
    # test_assert_exclusive_bits_change: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:1098
    Expected match_expect to be true, but is false
    # test_assert_exclusive_writer_scoped: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:1136
    Expected match_expect_start to be true, but is false
    # test_missing_barrier: EXPECTATION FAILED at kernel/kcsan/kcsan_test.c:1313
    Expected match_expect to be true, but is false
    # test_atomic_builtins_missing_barrier: EXPECTATION FAILED at
kernel/kcsan/kcsan_test.c:1356
    Expected match_expect to be true, but is false
# kcsan: pass:22 fail:7 skip:0 total:29
# Totals: pass:177 fail:20 skip:0 total:197

-- 
Thanks.
-- Max

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMo8BfJM0JHqh8Nz3LuK7Ccu7WB1Cup0mX%2BRYvO1yft_K4hyLQ%40mail.gmail.com.
