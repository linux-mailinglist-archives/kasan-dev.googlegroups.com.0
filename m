Return-Path: <kasan-dev+bncBDQ27FVWWUFRB77V77WAKGQEH3FGYVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id F0E7BD37F4
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2019 05:46:08 +0200 (CEST)
Received: by mail-yw1-xc40.google.com with SMTP id o14sf6372413ywa.9
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2019 20:46:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570765567; cv=pass;
        d=google.com; s=arc-20160816;
        b=GR0mKx+lziBxYXZc9C8W/zQOOgIPlA1abiooQjF5TdjBFiwuoPcrru5maltNh5D0QJ
         IgJSjBTtlpUbRxx3XfaFuFHtC3S20UzQghzoV0nZb4Y2YzsEf2MbJagbIbx5u5B1oQIg
         OAdUdLZGaTf/wudmktqtW7zccz/BVPXiluG6tsAPTpzJrdxAspjqa7h3RkB+uge9R+d0
         lGg2kQ3c+Pydr3prILw3OEGPzeFzv2SqDoA6CUUUJespFX9kLVwE0GTdDXIpHDjmG5bx
         9CikoaWfxo/9nT08q41QADkQHlYCdVUnkAWcsgiS4Whl1mnjIuOIcS63PtSC49lDazb9
         GuCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=+WtuzRwXEmAe50YA88p4Q1ubVhfWazVfvbPjg1UjAM4=;
        b=a9EGPsxNuFM7dn+mxPNlE67OKKDUbcApkGDCd3Y1o6i537i9HGu+g/CJF8aXa0MvnW
         udiT9Av8Bm5X2js06tJyjMCRFVF8o0LquAgNMaEVU8BZIWkCijo1NosZyM2E9BBGVEWr
         zxRRfIQFtMA7xn6b015zeB2hvzItLoPBwEvZ9VeF70XktO2vPnXrhn1UFsKS8VJ+rNd4
         BydvMjKDAXXK5Q8bFSze18STiBi/KAmIoQL0hG09iU6LK/gnH6d8mHBXjTMUUbc0VTvm
         AKKXi6K/oWSGJ3+RVUOLGXD0CvSH2fBlNtck79eElDlGxLUvp7H+cAK+TJH2V2lEaK6i
         JD9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=SF9vd87t;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+WtuzRwXEmAe50YA88p4Q1ubVhfWazVfvbPjg1UjAM4=;
        b=EIrq/8qjoasoromb7Bd6BZ9I3xlOSiZW7VfhAnVNt0zrBoeEkL0ZmtTT6D2sA/2Dkr
         SJ+wFniupibmiYBUJ4KyXZpv58yemmW+ltlwTgmVocGCikARcpD7aoTIibWDerUIZQSM
         Hpx5U/0Q8dvAIahHdTvT/vHIkwTXfiBcguQkhsTPFDcuxqSQ3EI0uXXF/2I8bL6ayKz9
         Palk5oFAMEfLIAzjarmLjFG62e8vRb0i6RS6MhoqlDnWR0/S30Nf17a9111Q4ZmahYgO
         yQFLfx/vcSTC9wou8Rkx+eQE9h6yMAJCuvYxtvVpx9+BczIdPbuQ7Q6d2wsSRNU/O0Gz
         rsOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+WtuzRwXEmAe50YA88p4Q1ubVhfWazVfvbPjg1UjAM4=;
        b=og+nwFrNc2Si6ePD1uY+j2ECyxL4zNgPpKsU8PMqSZJeFDNFsb8JYZhgFl8glfV0hj
         MRNn5m9/YG+V0ibWFujGvUGNJkMUmOVRirw5y1YjCDAwZPS3+IL7XMTo/cIGkwlgKZgz
         k3EdegMmNl1YBM/vPiEcZ2r9utTZ7pS/h3kY6Xkg+5Usi6vDQvoyfrfLRzbbyCYTeP8J
         a49Ytf9c+wVAexiSjbJ9AQLJuJHhTZbyCpn1Eo4x/WiNCfxi7FEFUxKYLXFlipMFTgaT
         ELopLEek1r75Wz45SfrYK4euM2gsNlgoUjV/n6Pnr0fLByz1S3SkQm1qmPVGxIAO2bob
         y27g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFiGpGGzq0Jq1evWE4OjJiyUeMqkYQQC0N5IKmCy8Mey5c03PA
	4X3WOgI2EgZYlyNKIvlKxFA=
X-Google-Smtp-Source: APXvYqy7LbQOFSZVhoIzW/dQnFxMVf2yFO1V3dxauHoNlloH8+sSuOGBLwuSGvAOAFTD7CZOiMIqMw==
X-Received: by 2002:a25:cfc4:: with SMTP id f187mr8985799ybg.496.1570765567589;
        Thu, 10 Oct 2019 20:46:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8109:: with SMTP id o9ls975865ybk.3.gmail; Thu, 10 Oct
 2019 20:46:07 -0700 (PDT)
X-Received: by 2002:a25:bad0:: with SMTP id a16mr8708681ybk.399.1570765567071;
        Thu, 10 Oct 2019 20:46:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570765567; cv=none;
        d=google.com; s=arc-20160816;
        b=xVLljcFYsqQtJ5u/lq1SuUyvTmUlID7ueKsupW5vuVVJcVqXFCqb6CVrWkjHsOpQeD
         VIIO8zUHkqEdeZbN6BbYsqKCNlx9LhXdYkFlEQ2h+5WKDzyNYqQAGeXech8WZ1awMpDU
         MxgpciY9HBoheysbHqQh7fl2fuuQmpFRF45ErmcnnqSHimDFlrZnAzubLqjnNBA4dS1z
         clTCxt800gquLb5CG9xs7ketCMjcby0wjdPJO8lidA/bpofN+8ileHl79zExBpUFcLYN
         0JL9RClFlU4nyuB+cHjERoRnZIQc6SyAwjJ9+4+20wqIKEe2HAJtrbcEE5/VsEec3SVr
         BDAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=ORx0rqQt8UStlqtrKikOMAgWlRFsyx371vf3MywmV+c=;
        b=HUoNqntPfLcAzyH7rHDx5RhsS6/T53gDJ0ShOvenRVY+VpPpELFnQrobXTSU9ZwFVU
         qLJUS9msSff1backA6vZuKtjQJdlLNRA0G2BhmSKGRGq4rlO+U1n1tc0BGsDliEc5VTQ
         42VDanrkdFZJXZnZfsykcjE4CYRBEXJM31bHSZULU16LCeLRVCYCOcOtpu0NRgnFhuq5
         UCtvz1veHMokMyBIgLNQa+HCpKxwIh74YPakioZoDpskk/p2EpmO4QzORaNfzud7FWBF
         SMwiCkcEKMgbUd+QXRfHmTFgDSTHpDdT9tcoIb5YB2hrGy/L/O1JyyQoWzUL+cv12nKM
         lXVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=SF9vd87t;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id u8si332222ybc.2.2019.10.10.20.46.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2019 20:46:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id u12so3787282pls.12
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2019 20:46:06 -0700 (PDT)
X-Received: by 2002:a17:902:8d98:: with SMTP id v24mr12781851plo.265.1570765565945;
        Thu, 10 Oct 2019 20:46:05 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id w189sm7985769pfw.101.2019.10.10.20.46.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2019 20:46:04 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
In-Reply-To: <CANpmjNPh656M2-1J6v5AO1eDL-SShjZwa-wvGOfEdKbKCh-ZJw@mail.gmail.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com> <8736gc4j1g.fsf@dja-thinkpad.axtens.net> <CANpmjNPh656M2-1J6v5AO1eDL-SShjZwa-wvGOfEdKbKCh-ZJw@mail.gmail.com>
Date: Fri, 11 Oct 2019 14:45:59 +1100
Message-ID: <87v9swt05k.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=SF9vd87t;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Marco Elver <elver@google.com> writes:

> Hi Daniel,
>
> On Tue, 1 Oct 2019 at 16:50, Daniel Axtens <dja@axtens.net> wrote:
>>
>> Hi Marco,
>>
>> > We would like to share a new data-race detector for the Linux kernel:
>> > Kernel Concurrency Sanitizer (KCSAN) --
>> > https://github.com/google/ktsan/wiki/KCSAN  (Details:
>> > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
>>
>> This builds and begins to boot on powerpc, which is fantastic.
>>
>> I'm seeing a lot of reports for locks are changed while being watched by
>> kcsan, so many that it floods the console and stalls the boot.
>>
>> I think, if I've understood correctly, that this is because powerpc
>> doesn't use the queued lock implementation for its spinlock but rather
>> its own assembler locking code. This means the writes aren't
>> instrumented by the compiler, while some reads are. (see
>> __arch_spin_trylock in e.g. arch/powerpc/include/asm/spinlock.h)
>>
>> Would the correct way to deal with this be for the powerpc code to call
>> out to __tsan_readN/__tsan_writeN before invoking the assembler that
>> reads and writes the lock?
>
> This should not be the issue, because with KCSAN, not instrumenting
> something does not lead to false positives. If two accesses are
> involved in a race, and neither of them are instrumented, KCSAN will
> not report a race; if however, 1 of them is instrumented (and the
> uninstrumented access is a write), KCSAN will infer a race due to the
> data value changed ("race at unknown origin").
>
> Rather, if there is spinlock code causing data-races, then there are 2 options:
> 1) Actually missing READ_ONCE/WRITE_ONCE somewhere.
> 2) You need to disable instrumentation for an entire function with
> __no_sanitize_thread or __no_kcsan_or_inline (for inline functions).
> This should only be needed for arch-specific code (e.g. see the
> changes we made to arch/x86).

Thanks, that was what I needed. I can now get it to boot Ubuntu on
ppc64le. Still hitting a lot of things, but we'll poke and prod it a bit
internally and let you know how we get on!

Regards,
Daniel

>
> Note: you can explicitly add instrumentation to uninstrumented
> accesses with the API in <linux/kcsan-checks.h>, but this shouldn't be
> the issue here.
>
> It would be good to symbolize the stack-traces, as otherwise it's hard
> to say exactly what needs to be done.
>
> Best,
> -- Marco
>
>> Regards,
>> Daniel
>>
>>
>> [   24.612864] ==================================================================
>> [   24.614188] BUG: KCSAN: racing read in __spin_yield+0xa8/0x180
>> [   24.614669]
>> [   24.614799] race at unknown origin, with read to 0xc00000003fff9d00 of 4 bytes by task 449 on cpu 11:
>> [   24.616024]  __spin_yield+0xa8/0x180
>> [   24.616377]  _raw_spin_lock_irqsave+0x1a8/0x1b0
>> [   24.616850]  release_pages+0x3a0/0x880
>> [   24.617203]  free_pages_and_swap_cache+0x13c/0x220
>> [   24.622548]  tlb_flush_mmu+0x210/0x2f0
>> [   24.622979]  tlb_finish_mmu+0x12c/0x240
>> [   24.623286]  exit_mmap+0x138/0x2c0
>> [   24.623779]  mmput+0xe0/0x330
>> [   24.624504]  do_exit+0x65c/0x1050
>> [   24.624835]  do_group_exit+0xb4/0x210
>> [   24.625458]  __wake_up_parent+0x0/0x80
>> [   24.625985]  system_call+0x5c/0x70
>> [   24.626415]
>> [   24.626651] Reported by Kernel Concurrency Sanitizer on:
>> [   24.628329] CPU: 11 PID: 449 Comm: systemd-bless-b Not tainted 5.3.0-00007-gad29ff6c190d-dirty #9
>> [   24.629508] ==================================================================
>>
>> [   24.672860] ==================================================================
>> [   24.675901] BUG: KCSAN: data-race in _raw_spin_lock_irqsave+0x13c/0x1b0 and _raw_spin_unlock_irqrestore+0x94/0x100
>> [   24.680847]
>> [   24.682743] write to 0xc0000001ffeefe00 of 4 bytes by task 455 on cpu 5:
>> [   24.683402]  _raw_spin_unlock_irqrestore+0x94/0x100
>> [   24.684593]  release_pages+0x250/0x880
>> [   24.685148]  free_pages_and_swap_cache+0x13c/0x220
>> [   24.686068]  tlb_flush_mmu+0x210/0x2f0
>> [   24.690190]  tlb_finish_mmu+0x12c/0x240
>> [   24.691082]  exit_mmap+0x138/0x2c0
>> [   24.693216]  mmput+0xe0/0x330
>> [   24.693597]  do_exit+0x65c/0x1050
>> [   24.694170]  do_group_exit+0xb4/0x210
>> [   24.694658]  __wake_up_parent+0x0/0x80
>> [   24.696230]  system_call+0x5c/0x70
>> [   24.700414]
>> [   24.712991] read to 0xc0000001ffeefe00 of 4 bytes by task 454 on cpu 20:
>> [   24.714419]  _raw_spin_lock_irqsave+0x13c/0x1b0
>> [   24.715018]  pagevec_lru_move_fn+0xfc/0x1d0
>> [   24.715527]  __lru_cache_add+0x124/0x1a0
>> [   24.716072]  lru_cache_add+0x30/0x50
>> [   24.716411]  add_to_page_cache_lru+0x134/0x250
>> [   24.717938]  mpage_readpages+0x220/0x3f0
>> [   24.719737]  blkdev_readpages+0x50/0x80
>> [   24.721891]  read_pages+0xb4/0x340
>> [   24.722834]  __do_page_cache_readahead+0x318/0x350
>> [   24.723290]  force_page_cache_readahead+0x150/0x280
>> [   24.724391]  page_cache_sync_readahead+0xe4/0x110
>> [   24.725087]  generic_file_buffered_read+0xa20/0xdf0
>> [   24.727003]  generic_file_read_iter+0x220/0x310
>> [   24.728906]
>> [   24.730044] Reported by Kernel Concurrency Sanitizer on:
>> [   24.732185] CPU: 20 PID: 454 Comm: systemd-gpt-aut Not tainted 5.3.0-00007-gad29ff6c190d-dirty #9
>> [   24.734317] ==================================================================
>>
>>
>> >
>> > Thanks,
>> > -- Marco
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8736gc4j1g.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87v9swt05k.fsf%40dja-thinkpad.axtens.net.
