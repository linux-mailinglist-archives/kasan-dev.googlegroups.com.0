Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT732PWAKGQEV2DWWTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86851C9290
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 21:43:12 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id w5sf29156uan.19
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 12:43:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570045391; cv=pass;
        d=google.com; s=arc-20160816;
        b=gfoOhgdyqaU6dFZVJQkg6/ld0DfezxognsjDp5rcYkah0wlmtdfoMKOsLguKDWoTke
         xdjPg5oXr44bSeIfRFILjQmJJ1WEAtyjloflcXul3AJNhYLKq6Ueelp5R8jGFCt1Ufub
         oRCARRVauMr0wlizry8TUs2TmnyAf5UazCk18K48cTR/XDEv8BgIrUhUYKI+74IukeMw
         aYUrC2oXsl97YcttTg2mE7ihV3UxgIPACaKwW9avOkhOtksxhC3/3JtTEPcsEf45kaQG
         +gx/uWPPV9PBZK/Vybj5UGDl1ItJJx0vUGsmz1PaPptoM6FTbiPcpnalmFFNBe599h8q
         PKzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mIaqpuUSiRFge1o/EuSrXMlwNit+SM2bKL/ymoGrADU=;
        b=QFg0IoBd9jMfR3FM2/2Tm9TKMbf9xuiCCvgtgMyZGbP6t8Kt66DvWekMg/i3rcHm+5
         PLRaWXRv9dToiWpSz4B9Oil1Svqq7Ptm3JOKZ3GdfFiVqEDYBOzmmLHWtwjrKy4UY2ak
         V5K4yvbfqgOwYtMVYrKnQZmpzfjofi/1TqzJvDmiq9b1FKR287za44T1xn3E032Fdfo4
         1+Y/Vku+Dl14kO7uc9YMhgQtkiBhWFxSZ8YUXcp+c50bBDZaj17K6Ox+xlJ4TSO8Yv54
         2Fn/mUmsWQp5WFoioQLH0pnv5dzOwI4UDPZ6fGnbNkZh2j72hPYTZU0r4dsAgSzmIkIV
         hODA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f24UR+aS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mIaqpuUSiRFge1o/EuSrXMlwNit+SM2bKL/ymoGrADU=;
        b=GBLQ8Vx3j9cI9ORo2rT4T6VdDPmXCFxozG2lT2D8FBAg/EJYGZdJVa8/6athyy3/YX
         v+LmWjJqZ8wN5Lcky421Rit7H7ECu4I0Y1q3IZdaxHpxU2ghT9iNCnlp+0u7zYu/vN+P
         EavY/EUa6LberbgWW/Qkeqq08aNaWUFuIpgkIJSoIMTcWX9cxaMrbmY8uj4sGty2rAKJ
         Dc8tucUa32XyMxrK7mjsmskbA0t5wm/ODrsMDTIcGBBJ+fP/kcdv2f80oAlQV+DX4Jyc
         SqIrFB8kEIWTQwN90L+PfNINsgPe1rFdD74fsj4Ooj3xjovSt2fNXNztyMhytf0/AbZq
         enPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mIaqpuUSiRFge1o/EuSrXMlwNit+SM2bKL/ymoGrADU=;
        b=HIR8N1Pdlbgeag52B3t+uWg0Z711ZJa0Wko0WlHLqC2wdxzeUR6vnlLZu138Cz7Xl7
         sJPvP+8AzVzTBQCr82XH/gsyA+RNiNBd1vo9RnZ0+N8PcKWxy0wXd7f5Xu+NVpmVDa5P
         /YZBQDkR370cWJCymRgItYVt3RwtR3MPcQ3itA7FRiRjUwTlrC7lFNNVXAm0m/eR3aq4
         RwVZxWM+2Ed+cgXekbIuIWCMwP3MG3lh/1iG9NuRwsp/fL2/l6eSW+YxOAXrDlDpayxK
         dpOG1QhkCacrskloHxdEhKBSisGzxZjrpRE4awFYesjKPjRmIH8n/PkYGqK3KGGdHoF/
         zzrA==
X-Gm-Message-State: APjAAAUJdnnHVqHd0XXZtiwgEgD5qWyPGrZjblBABZnFwyxsw6UmRRbf
	T7y9Wv5i6D1Qg8v0+LGTOww=
X-Google-Smtp-Source: APXvYqxL4TLEQMqWq3M/EBYs0RcRGxpyYQUKhrhsWW6AU9dAab9y9uwSc3Ab0siAwhxgG4TqxYOxWA==
X-Received: by 2002:a67:5f45:: with SMTP id t66mr2878157vsb.204.1570045391488;
        Wed, 02 Oct 2019 12:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f68c:: with SMTP id n12ls368045vso.14.gmail; Wed, 02 Oct
 2019 12:43:11 -0700 (PDT)
X-Received: by 2002:a67:d706:: with SMTP id p6mr2981654vsj.56.1570045391169;
        Wed, 02 Oct 2019 12:43:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570045391; cv=none;
        d=google.com; s=arc-20160816;
        b=uZkBMTqAuA1ADt7fEZhm//k5TyXItsVxVRjDukhk3JXeDzG62Hut51ZXqyPDoOOx5K
         CNhyGZVSKz4PI2vPiKBLLWtgSo80u8DMwvbf5HM7+z7VRHvpx7UrWZXSnMEwEkDz3qiS
         3vwLUBl/OocREWyy/ZZ7nSsvrFMWVk/RnqspzW7DQDARQXs8ixPk5mNcPqYinG5HTQH5
         3farYzpD4pFB3+lTYHYA7PQtnjKV1BoWrfUxVDJt8PhffrJpd+bEwoMPS7TIwGxf5OpW
         ENQfMNaBBWRmtDUP0cphpMpcEK8+oadi4M2/35iIQ2Gwa6VORuafVpMWkSRD367FFMM9
         aGSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OOyld7LsE/8SoNryaMxnr2dK1DwxpSS1XhCCKoKRX5s=;
        b=DP1kEd3/4bqObWK2QAI+uEZUNhU98ozoEil49E7kTDwGzqp9BJE/MPtq3Q5BxIhltT
         pvMFwdzh1OkhHSKu8DWl8uZtWGMvRZ2as3K/5FceEX4qQqbzmCBySjy/5IipK8rrRkUd
         E4Fxqm0enlc0lG0J6Zo7WyutsKqQWv87tygobrsDdif8UC5ubu+g35rzIBY8TMt9L7+l
         gmlx/OXB+jwLQJYauxLQwTfUzc2MVSc9bblIUTX5NNLNwEPSOOdmkhwtYJ1d9KFubuJf
         vpZOZYSi1vC3VO+OljgElPls0B56jaEHgywZmIFjjRehwU6UvRbCarSB/cGqQHCwRVu4
         UCUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f24UR+aS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id h184si21954vka.3.2019.10.02.12.43.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 12:43:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id g13so220899otp.8
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 12:43:11 -0700 (PDT)
X-Received: by 2002:a05:6830:101:: with SMTP id i1mr4042375otp.233.1570045390142;
 Wed, 02 Oct 2019 12:43:10 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <8736gc4j1g.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <8736gc4j1g.fsf@dja-thinkpad.axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Oct 2019 21:42:58 +0200
Message-ID: <CANpmjNPh656M2-1J6v5AO1eDL-SShjZwa-wvGOfEdKbKCh-ZJw@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f24UR+aS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

Hi Daniel,

On Tue, 1 Oct 2019 at 16:50, Daniel Axtens <dja@axtens.net> wrote:
>
> Hi Marco,
>
> > We would like to share a new data-race detector for the Linux kernel:
> > Kernel Concurrency Sanitizer (KCSAN) --
> > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
>
> This builds and begins to boot on powerpc, which is fantastic.
>
> I'm seeing a lot of reports for locks are changed while being watched by
> kcsan, so many that it floods the console and stalls the boot.
>
> I think, if I've understood correctly, that this is because powerpc
> doesn't use the queued lock implementation for its spinlock but rather
> its own assembler locking code. This means the writes aren't
> instrumented by the compiler, while some reads are. (see
> __arch_spin_trylock in e.g. arch/powerpc/include/asm/spinlock.h)
>
> Would the correct way to deal with this be for the powerpc code to call
> out to __tsan_readN/__tsan_writeN before invoking the assembler that
> reads and writes the lock?

This should not be the issue, because with KCSAN, not instrumenting
something does not lead to false positives. If two accesses are
involved in a race, and neither of them are instrumented, KCSAN will
not report a race; if however, 1 of them is instrumented (and the
uninstrumented access is a write), KCSAN will infer a race due to the
data value changed ("race at unknown origin").

Rather, if there is spinlock code causing data-races, then there are 2 options:
1) Actually missing READ_ONCE/WRITE_ONCE somewhere.
2) You need to disable instrumentation for an entire function with
__no_sanitize_thread or __no_kcsan_or_inline (for inline functions).
This should only be needed for arch-specific code (e.g. see the
changes we made to arch/x86).

Note: you can explicitly add instrumentation to uninstrumented
accesses with the API in <linux/kcsan-checks.h>, but this shouldn't be
the issue here.

It would be good to symbolize the stack-traces, as otherwise it's hard
to say exactly what needs to be done.

Best,
-- Marco

> Regards,
> Daniel
>
>
> [   24.612864] ==================================================================
> [   24.614188] BUG: KCSAN: racing read in __spin_yield+0xa8/0x180
> [   24.614669]
> [   24.614799] race at unknown origin, with read to 0xc00000003fff9d00 of 4 bytes by task 449 on cpu 11:
> [   24.616024]  __spin_yield+0xa8/0x180
> [   24.616377]  _raw_spin_lock_irqsave+0x1a8/0x1b0
> [   24.616850]  release_pages+0x3a0/0x880
> [   24.617203]  free_pages_and_swap_cache+0x13c/0x220
> [   24.622548]  tlb_flush_mmu+0x210/0x2f0
> [   24.622979]  tlb_finish_mmu+0x12c/0x240
> [   24.623286]  exit_mmap+0x138/0x2c0
> [   24.623779]  mmput+0xe0/0x330
> [   24.624504]  do_exit+0x65c/0x1050
> [   24.624835]  do_group_exit+0xb4/0x210
> [   24.625458]  __wake_up_parent+0x0/0x80
> [   24.625985]  system_call+0x5c/0x70
> [   24.626415]
> [   24.626651] Reported by Kernel Concurrency Sanitizer on:
> [   24.628329] CPU: 11 PID: 449 Comm: systemd-bless-b Not tainted 5.3.0-00007-gad29ff6c190d-dirty #9
> [   24.629508] ==================================================================
>
> [   24.672860] ==================================================================
> [   24.675901] BUG: KCSAN: data-race in _raw_spin_lock_irqsave+0x13c/0x1b0 and _raw_spin_unlock_irqrestore+0x94/0x100
> [   24.680847]
> [   24.682743] write to 0xc0000001ffeefe00 of 4 bytes by task 455 on cpu 5:
> [   24.683402]  _raw_spin_unlock_irqrestore+0x94/0x100
> [   24.684593]  release_pages+0x250/0x880
> [   24.685148]  free_pages_and_swap_cache+0x13c/0x220
> [   24.686068]  tlb_flush_mmu+0x210/0x2f0
> [   24.690190]  tlb_finish_mmu+0x12c/0x240
> [   24.691082]  exit_mmap+0x138/0x2c0
> [   24.693216]  mmput+0xe0/0x330
> [   24.693597]  do_exit+0x65c/0x1050
> [   24.694170]  do_group_exit+0xb4/0x210
> [   24.694658]  __wake_up_parent+0x0/0x80
> [   24.696230]  system_call+0x5c/0x70
> [   24.700414]
> [   24.712991] read to 0xc0000001ffeefe00 of 4 bytes by task 454 on cpu 20:
> [   24.714419]  _raw_spin_lock_irqsave+0x13c/0x1b0
> [   24.715018]  pagevec_lru_move_fn+0xfc/0x1d0
> [   24.715527]  __lru_cache_add+0x124/0x1a0
> [   24.716072]  lru_cache_add+0x30/0x50
> [   24.716411]  add_to_page_cache_lru+0x134/0x250
> [   24.717938]  mpage_readpages+0x220/0x3f0
> [   24.719737]  blkdev_readpages+0x50/0x80
> [   24.721891]  read_pages+0xb4/0x340
> [   24.722834]  __do_page_cache_readahead+0x318/0x350
> [   24.723290]  force_page_cache_readahead+0x150/0x280
> [   24.724391]  page_cache_sync_readahead+0xe4/0x110
> [   24.725087]  generic_file_buffered_read+0xa20/0xdf0
> [   24.727003]  generic_file_read_iter+0x220/0x310
> [   24.728906]
> [   24.730044] Reported by Kernel Concurrency Sanitizer on:
> [   24.732185] CPU: 20 PID: 454 Comm: systemd-gpt-aut Not tainted 5.3.0-00007-gad29ff6c190d-dirty #9
> [   24.734317] ==================================================================
>
>
> >
> > Thanks,
> > -- Marco
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8736gc4j1g.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPh656M2-1J6v5AO1eDL-SShjZwa-wvGOfEdKbKCh-ZJw%40mail.gmail.com.
