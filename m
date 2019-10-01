Return-Path: <kasan-dev+bncBDQ27FVWWUFRBIWPZXWAKGQEIERHGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F35EC3808
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 16:50:11 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id m20sf17740975qtq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 07:50:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569941410; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oc+DrJeVFYAe1Ujh9sq/cPe9Dm3692m3HqQEIwW/ugX16/kxDiH0Jl6Rwtp8xh4nB9
         6XONBjTS3qcimpFIZ7l20cQXZvTzaa/pttkclM98Cqhwe2VtOqMehQTvaPLHNIKqpA7O
         cQzJ0T+9i2uXGVL7RCEiBZTSXj0XMo5hm1wlGOj/QzrupAkTW4Ynr7ZZZ3jgtxIJD1r9
         UStIPqPZhNRN263k+0JCZWS5PtTWCI63f6FLme5JQ77bVgkJ4vYKWZpE53mn3iMylfIt
         xhOOiXE2lmb3YQZuUNn67yMcS5fR8SOYVMRSxREGQ1aT7AtppQELGr8qB/+zJ4EaVxlO
         WAvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=gUIV1Ofb13jTnDIAJ/966546uapLTOHJtc/FtoWbCFU=;
        b=RK0tRGKQHRSdmtAdHFOM3+swmQ8VQ0LNOkFlHjsHOkKnkptyJ5S0hWRPNNszPeBL/v
         xq/tiDAmdtBzEM06Tdgesz6WVDmpXb4qO/MXRPuAbnI+r7jFYo50u15RKIQlbegX4Px6
         wH/hF7XePlLDyvwTkL+VUgrlqvjn2cQLnPNwrUlDa9exnVArnGl/ae3FcyEi8OQeUJ+6
         2aMC8rpVCs4dfsnM3un4lzPX/DREsbbda0yjhZ4TBmbvQFrARx5U7Vl1YRexO0lDVkey
         ttOM6FsWmRrz1zWbmS4x0G/oUB6P6vuZaX7jCBpUJwVxgRnbV/J6BLutLdbOy8kGw+Cn
         SaaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bfOoqcSO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gUIV1Ofb13jTnDIAJ/966546uapLTOHJtc/FtoWbCFU=;
        b=iLVJ/r86d673dt0epX6GSZ3tpqHIcnaDCrBRHvadHH1nm36HH5mOhTVTPJgZ0N8bNt
         XQ24F6mN9N61ltEosMjDqoT2SZ7mwh67W7sjiJBZEPUNu0QeTEb4fxEqnl1MIYHUhNrz
         VE+lCwJsaJyfTTidl6MhpCWTzORYnsy27Hnn/fAfcRTGSUPfgcMWCfb1usjMb/BRfAk3
         f3X5T6kduZ4euRudW9SOlcJCDRF8H3SdHezgJGQ8ugnC8xbtRlgmixzLTGpWMb/uyheX
         ahPzwMvznFprweh5yZqY+ctCPMOJ11hTfLCvWJwoAZ9pj4l4K5h+dYhtRXF0duWYDaD8
         eoFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gUIV1Ofb13jTnDIAJ/966546uapLTOHJtc/FtoWbCFU=;
        b=F72I5hzxmBhmzYRzBXW1bvg8on0FaGPMOiERyVZDtU3MMVvTCZjHV0sTDecnfLZlqc
         wYk4MYVIaQrWq1lMTmZSQLZ4qjAFIUPCTklDxp36ydUWL5ohk9ZyVyABqxQ/fyGEahgs
         iDXPPQebQ5NzZjgonILHLirGVrCkXuO0e7luKWuYeXDdC1dF4yOmNl8y8psZ/rKBPSwn
         zbPR1eE3IIItcyxGlqNR/ENrjp52xU4UPrEl39fjaSFzvJuP0Zhk8KD9Tt9FXuhTeOEi
         K18VIQHaQSUAO6M5K1s4RD9nIWheg4psLYeSrBAA0hHnvMVjJyxLr2akAsFiGo/ThA0o
         O/eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWScjCQE2kwVg256+PgT1Y85Dmo+DCg4re4sVad5G/wsRhnx9VB
	IS/PTZM0FYJsMpy6ljp9cg4=
X-Google-Smtp-Source: APXvYqygKweP2gUPeWs6tBxB27s0pKrvVwLmIIkXfQjR1fgMtFtnvSQsG0mRqQuMHWkvUsbWUsWByw==
X-Received: by 2002:a37:6292:: with SMTP id w140mr6321303qkb.24.1569941410151;
        Tue, 01 Oct 2019 07:50:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:19c7:: with SMTP id s7ls5753653qtk.10.gmail; Tue, 01 Oct
 2019 07:50:09 -0700 (PDT)
X-Received: by 2002:ac8:611b:: with SMTP id a27mr30959741qtm.390.1569941409835;
        Tue, 01 Oct 2019 07:50:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569941409; cv=none;
        d=google.com; s=arc-20160816;
        b=sg8wo7H6L3568DbDWG/ivJvoXaNz3Gc/gEcp9TB2YhWjCdm+DqnWJcjJfqjNFezAgY
         FRegAZLjPo8hoGyr/o00WEodBtPSqTPuUPoWCmkPWfZbmab1oc1Mtz8JpLcz7cymP2a6
         DdExJbVCJap35cLdXpzVbGJExFYJUt2Y62f2WP0DmonSLORHwV1bZJA+J0pFvW6ZVIja
         roCX6w1LsoY9Ilgrec/+qzUaa3QbtA/cU2HuXMMMXYmvCeHvMPM4F1wPV4eZvREf7rae
         v/4u9aGdfDLChZo3wxdiDsp2qE6erN/B8OEWJh4NW2XKra6cutLjTOsvo4pjb3IMFvNF
         HuSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=s4336hjcbyIRnMmYze0B4CZtiLvT/avtj/eCRfHbhfU=;
        b=unap8QnvUmps6uEqpj4jjx9pblTdRlsr9KPu20BLDhJ9JAlyfpn/ctL+gnWjC3SMf0
         JEOngFm/Uz9iPyhxI/Q1s8IS5L4Dum3gy5+0PJ1Arh6oFxS51YjxH3T8lT2AoP7i8cDN
         ACqPS1NWbzgQ5S4lTeNFwRHtKyRhkip1csswgcPPsKShkmo71LHbkdelpuBMbia9Aa+U
         l2kzFubpL52MTFuGBphUdcxPu3cywAcjiunPLlxC84GULK6pA1I0dhYzgsXWRL0LK3FO
         yLTB/8MR4jqmCWUq96XqbGpSwaET3K631UqhOkvMIrCNtLFYShWXiZXCF6XmNcyidcbr
         xHNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bfOoqcSO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id o13si680325qkj.4.2019.10.01.07.50.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 07:50:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id q12so8166982pff.9
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 07:50:09 -0700 (PDT)
X-Received: by 2002:a63:475d:: with SMTP id w29mr30514631pgk.46.1569941408673;
        Tue, 01 Oct 2019 07:50:08 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id k15sm14647466pfa.65.2019.10.01.07.50.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2019 07:50:07 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com, Paul Turner <pjt@google.com>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu, akiyks@gmail.com, npiggin@gmail.com, boqun.feng@gmail.com, dlustig@nvidia.com, j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
In-Reply-To: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
Date: Wed, 02 Oct 2019 00:50:03 +1000
Message-ID: <8736gc4j1g.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=bfOoqcSO;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
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

Hi Marco,

> We would like to share a new data-race detector for the Linux kernel:
> Kernel Concurrency Sanitizer (KCSAN) --
> https://github.com/google/ktsan/wiki/KCSAN  (Details:
> https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)

This builds and begins to boot on powerpc, which is fantastic.

I'm seeing a lot of reports for locks are changed while being watched by
kcsan, so many that it floods the console and stalls the boot.

I think, if I've understood correctly, that this is because powerpc
doesn't use the queued lock implementation for its spinlock but rather
its own assembler locking code. This means the writes aren't
instrumented by the compiler, while some reads are. (see
__arch_spin_trylock in e.g. arch/powerpc/include/asm/spinlock.h)

Would the correct way to deal with this be for the powerpc code to call
out to __tsan_readN/__tsan_writeN before invoking the assembler that
reads and writes the lock?

Regards,
Daniel


[   24.612864] ==================================================================
[   24.614188] BUG: KCSAN: racing read in __spin_yield+0xa8/0x180
[   24.614669] 
[   24.614799] race at unknown origin, with read to 0xc00000003fff9d00 of 4 bytes by task 449 on cpu 11:
[   24.616024]  __spin_yield+0xa8/0x180
[   24.616377]  _raw_spin_lock_irqsave+0x1a8/0x1b0
[   24.616850]  release_pages+0x3a0/0x880
[   24.617203]  free_pages_and_swap_cache+0x13c/0x220
[   24.622548]  tlb_flush_mmu+0x210/0x2f0
[   24.622979]  tlb_finish_mmu+0x12c/0x240
[   24.623286]  exit_mmap+0x138/0x2c0
[   24.623779]  mmput+0xe0/0x330
[   24.624504]  do_exit+0x65c/0x1050
[   24.624835]  do_group_exit+0xb4/0x210
[   24.625458]  __wake_up_parent+0x0/0x80
[   24.625985]  system_call+0x5c/0x70
[   24.626415] 
[   24.626651] Reported by Kernel Concurrency Sanitizer on:
[   24.628329] CPU: 11 PID: 449 Comm: systemd-bless-b Not tainted 5.3.0-00007-gad29ff6c190d-dirty #9
[   24.629508] ==================================================================

[   24.672860] ==================================================================
[   24.675901] BUG: KCSAN: data-race in _raw_spin_lock_irqsave+0x13c/0x1b0 and _raw_spin_unlock_irqrestore+0x94/0x100
[   24.680847] 
[   24.682743] write to 0xc0000001ffeefe00 of 4 bytes by task 455 on cpu 5:
[   24.683402]  _raw_spin_unlock_irqrestore+0x94/0x100
[   24.684593]  release_pages+0x250/0x880
[   24.685148]  free_pages_and_swap_cache+0x13c/0x220
[   24.686068]  tlb_flush_mmu+0x210/0x2f0
[   24.690190]  tlb_finish_mmu+0x12c/0x240
[   24.691082]  exit_mmap+0x138/0x2c0
[   24.693216]  mmput+0xe0/0x330
[   24.693597]  do_exit+0x65c/0x1050
[   24.694170]  do_group_exit+0xb4/0x210
[   24.694658]  __wake_up_parent+0x0/0x80
[   24.696230]  system_call+0x5c/0x70
[   24.700414] 
[   24.712991] read to 0xc0000001ffeefe00 of 4 bytes by task 454 on cpu 20:
[   24.714419]  _raw_spin_lock_irqsave+0x13c/0x1b0
[   24.715018]  pagevec_lru_move_fn+0xfc/0x1d0
[   24.715527]  __lru_cache_add+0x124/0x1a0
[   24.716072]  lru_cache_add+0x30/0x50
[   24.716411]  add_to_page_cache_lru+0x134/0x250
[   24.717938]  mpage_readpages+0x220/0x3f0
[   24.719737]  blkdev_readpages+0x50/0x80
[   24.721891]  read_pages+0xb4/0x340
[   24.722834]  __do_page_cache_readahead+0x318/0x350
[   24.723290]  force_page_cache_readahead+0x150/0x280
[   24.724391]  page_cache_sync_readahead+0xe4/0x110
[   24.725087]  generic_file_buffered_read+0xa20/0xdf0
[   24.727003]  generic_file_read_iter+0x220/0x310
[   24.728906] 
[   24.730044] Reported by Kernel Concurrency Sanitizer on:
[   24.732185] CPU: 20 PID: 454 Comm: systemd-gpt-aut Not tainted 5.3.0-00007-gad29ff6c190d-dirty #9
[   24.734317] ==================================================================


>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8736gc4j1g.fsf%40dja-thinkpad.axtens.net.
