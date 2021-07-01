Return-Path: <kasan-dev+bncBCP7VQF36ABBBJWV6SDAMGQE7HDVG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DAD13B8C62
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 04:38:31 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id g3-20020a67fac30000b0290279c2771f64sf1651344vsq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 19:38:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625107110; cv=pass;
        d=google.com; s=arc-20160816;
        b=bvXyttIQ21/Mx8UKCLMkuxpjeCl9ukTPUeA09am6N1Pp2Oq7MR3tQxOOsoawdTND18
         VcLK5qCs373JGCxqtTTnbKnWfllrxQrucyVi+ueV2UOdhM3sNswQKzsKZA31uRuYvHpO
         HE9+lTk07F/1vzFHe6CDVpalTSKPjqCCNDuKUY3csXgJtsl0J/NhinanVFotgTHlLOXA
         Rx/4UJhwsWXpuFScQrmUGWytt+5pdthsw28HEiAT2UR7DoW0SQCi63SUvRY57QH55zjO
         QTJ78xL3qP6t9vzc8X7sf8lK0PjRffGbp6dZeEuHPMnOUQ4r7ll87TFLGrc+pq+rkJnq
         aE3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id:to
         :from:cc:in-reply-to:subject:date:dkim-signature;
        bh=wbSzQ4hKJelLrQ0BeZXv0QFAuKmZ9ci6QsKIIsyZAI4=;
        b=B3srE+5jjIwwGx1brh04qhGbDCsDPmG//r/M9rnMvXV2fZCaaFJl0cH5c9upKXW8kP
         tVUdktCAI12POnrPCWsKH2yJxRgF0XqOibRuH1RYxle9YcLumwFKe742QisOXRHozPQh
         CjUY76yKZh5GOdNFjPT5NaCPcX78JEpjpXDiVNpmtGLRzM9hM6XhwAYK2Kd+k3+RBec9
         +q96ZXSZV3mAe/Y7bNsJDXpFkDTzFIY5Jhq8XM+DNvn3EQd1vFvqDuwa9znEwF1dIfBe
         OrNybrIGBKU6ECJw9Pzv2euGr5Dl1iWijtsSE17shHpCeHWoQMsJgUt+4RdqVcYNy0Cv
         NQcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="KZPgT5/A";
       spf=pass (google.com: domain of palmerdabbelt@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=palmerdabbelt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wbSzQ4hKJelLrQ0BeZXv0QFAuKmZ9ci6QsKIIsyZAI4=;
        b=a1RvzeIDGDwcQ0Jr8cmoGIrjx07ktm8mVTrQDtpu4KRBjf9LFdiR1QaK327CC6pVlU
         VkHj58OQw0I7A0shaYRJLj6aJte/gPkE1jpbEMb0JKKPBnyOutRDju1/UoOevYyx2tps
         Fb2Sy9MAOEN0rhhv4vV1T8Mqycwl26XQyCUO8uaQ1CuFa6Nqj+L2Fyc0e72xHC4X9opj
         ulPUJZkJonKfWp+HF2hVjDCESq4SeUIZMcyCsTCz+bTElHI8UxE0PaMv0KFdyrncbnwi
         6urVgve7Yg1GRKMXzroR3B7/ELSpGO478w54/1MDQ4V2kdTwJVZe8pa5mQLVA47CX5+B
         peoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:subject:in-reply-to:cc:from:to:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wbSzQ4hKJelLrQ0BeZXv0QFAuKmZ9ci6QsKIIsyZAI4=;
        b=ruK+nX+itbwSxoGByF8/oXBs14eyjliQ94b3V7qsaTpf/DmMAhFlGp6UyFt3Z3XljN
         4DBM6eM3Z0sj2QVFTVPXjrZyeZNshmQUXVBm+2bTcE9qMLtz1WymE/0RUNGKftq5yVfn
         3K0pLAYcRw1jOF7lp5jNsHbgjVuJJGncurdFPb2mPTkBemZmpFMfvfNYRftg0wXjuW48
         4EPaEI87HgZdA85CAMlWc5evCldkTBV0G9XF26ONJK9Iiu9KjNTtpSbnBNEOwcIaeFVD
         Tqe/8P78/teS0xlkgzrHyxR+5WK5w6DSsGPGq1qU22i4A1SAbtRb48gW97to82Y38YXW
         wIBw==
X-Gm-Message-State: AOAM531CTwDC9cQpuCsQKqeUJFVpi7VOTZUMi1xjQMectk2BAokc9Own
	rAO0tS3Y/NObO+ddnMpL8Rc=
X-Google-Smtp-Source: ABdhPJyFIWCR6YLNqBAyU7o2EQbgDwqIqa0RycEBS69e6w7eNOYiJQROIcR0Jb0uFfme8wkGIlCg4Q==
X-Received: by 2002:a1f:9950:: with SMTP id b77mr30799558vke.25.1625107110393;
        Wed, 30 Jun 2021 19:38:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:405:: with SMTP id 5ls1384336vse.6.gmail; Wed, 30 Jun
 2021 19:38:29 -0700 (PDT)
X-Received: by 2002:a67:b10a:: with SMTP id w10mr35531330vsl.1.1625107109804;
        Wed, 30 Jun 2021 19:38:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625107109; cv=none;
        d=google.com; s=arc-20160816;
        b=CsfsEwmPBLZjJmMxPpRc/g0fvQyQ5Zdiww9fxhK+cqO01RSNzqLr2XVKe6539QQiJm
         rwhNhzuA4JzS/kMEkY+y76ZWf5SAZjoCgMWuRnoy4m/B+mLNN/lIjpscal24j6ttyrqQ
         bHWNTZQ2btsUW2HG6TUq4QY4pL5wfJ2Bl5BjfxAPLw0qRcjJEGvnwPrTDGB7+r60wbRw
         sDIQXc9kSOXUsacopVFpFd9dOlpiA5pCXI5SZwsrFOSulr86cbJHSjNEKHEHmesfoNXA
         25gh0+EOWg6qGyHdszYZJTFNWD55VgFv6IXoaH/HBF2BJa4pBbDxugSVBPKYZ7lsy1t7
         TnkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=DuvFY1gPxxozd7qXy5qfSaZHOIKcOMsMpJnnW/JJ+sI=;
        b=Fi9g0d6aGfpa5ryuUj7CFzYpq4SBQFt14KHP+Z0MPOgdCSqkNapcGRC/e8E7vpogdL
         w93A0K+dGojFk05UplqXBmS/B+XhPiFJ4qrRttkn93TGPSxc5l0N/9KIrKxWF9nXEWVg
         hzmEu6OKYUb4xtcI6xgo+HxFzpyMEY2KakNCgQd/KI2U4gZHJ1l4wWfphicLUW0IwW6J
         wxOP/IXOSrb3ttFPZL5KoJ/fGH/esfILsX91Mwgqc0M9jEUEk9Tj2hir51jOJDCwUm1C
         plz2jJLMKzgB6zytO6nTNNXUuxgQFfxUuCCzFngmeeYwK4FlrM1YXRa1d+YVpajAv8EH
         1a5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="KZPgT5/A";
       spf=pass (google.com: domain of palmerdabbelt@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=palmerdabbelt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id d66si932542vkg.3.2021.06.30.19.38.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 19:38:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmerdabbelt@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id i13so2769506plb.10
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 19:38:29 -0700 (PDT)
X-Received: by 2002:a17:90a:6605:: with SMTP id l5mr42070512pjj.168.1625107108942;
        Wed, 30 Jun 2021 19:38:28 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id g4sm23225456pfu.134.2021.06.30.19.38.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jun 2021 19:38:28 -0700 (PDT)
Date: Wed, 30 Jun 2021 19:38:28 -0700 (PDT)
Subject: Re: [PATCH -next v2] riscv: Enable KFENCE for riscv64
In-Reply-To: <CANpmjNMh9ef30N6LfTrKaAVFR5iKPt_pkKr9p4Ly=-BD7GbTQQ@mail.gmail.com>
CC: liushixin2@huawei.com, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, glider@google.com, dvyukov@google.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
From: "'Palmer Dabbelt' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Message-ID: <mhng-d63a7488-73a5-451e-9bf8-52ded7f2e15c@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmerdabbelt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="KZPgT5/A";       spf=pass
 (google.com: domain of palmerdabbelt@google.com designates
 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=palmerdabbelt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Palmer Dabbelt <palmerdabbelt@google.com>
Reply-To: Palmer Dabbelt <palmerdabbelt@google.com>
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

On Wed, 16 Jun 2021 02:11:53 PDT (-0700), elver@google.com wrote:
> On Tue, 15 Jun 2021 at 04:35, Liu Shixin <liushixin2@huawei.com> wrote:
>> Add architecture specific implementation details for KFENCE and enable
>> KFENCE for the riscv64 architecture. In particular, this implements the
>> required interface in <asm/kfence.h>.
>>
>> KFENCE requires that attributes for pages from its memory pool can
>> individually be set. Therefore, force the kfence pool to be mapped at
>> page granularity.
>>
>> Testing this patch using the testcases in kfence_test.c and all passed.
>>
>> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
>> Acked-by: Marco Elver <elver@google.com>
>> Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>
> I can't see this in -next yet. It would be nice if riscv64 could get
> KFENCE support.

Thanks, this is on for-next.  I'm just doing a boot test with 
CONFIG_KFENCE=y (and whatever that turns on for defconfig), let me know 
if there's anything more interesting to test on the KFENCE side of 
things.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-d63a7488-73a5-451e-9bf8-52ded7f2e15c%40palmerdabbelt-glaptop.
