Return-Path: <kasan-dev+bncBDR5N7WPRQGRB2GEX2CQMGQEAGFV7LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF368392FFF
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 15:45:13 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id b3-20020a4ab4830000b029020d5d68e38dsf311993ooo.21
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 06:45:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622123112; cv=pass;
        d=google.com; s=arc-20160816;
        b=uCfLf5VuFcCBhmrelUd+Mq5RhboUDk8y0KO8N38n58ocBre746IhhGxAVipwmZXGvz
         D5zho6ATeDHpoUKB6rIfTcPZCpcHoemCssnflO7jEKsF0pQlOlsVybqiT6yNUq8isUoD
         J52iKIoMPC7SMsp0znSn6Re2v7fvDuLSCj9yYr43yiqPtC3aSpb0oeqk+Wj24gDIoKW3
         nBE36fCE++oWcrOiYrziUqEbc2LRHloAuM8rOoyLz/BCBOlKLgKi8jSQl8faLaEruBjQ
         bKuvEDqmoqf0DBzWW4LciRKNYKs8xhHh1RgKorD/SmXIRPaJjblAQOC7Zf2CUsEsmmVu
         O/ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=HgMylvbhfmoxDZysvlUhnq4SZSptkAXr+hDEipNR930=;
        b=M7Nl/E5BbvvXM442NvNmdQXrrNRYmni77CCYeqgRTgqt3VKWQ0SP8yqeNSnaADW1oK
         fivxXn2cDGWxPc++s3zIxf2SM2k9HIfrk69RywCI2WB+Q7tLU1/0f8qljLHx/0gOtS3J
         3IdiPiohXAJHPs6YymthaMCY6R5cls7liZMAslHIwjpwltgI2ZAGALswkggwIcAmpmbm
         SWqShSzyoqYxqjR4UOVyB+TKXyZhT65CkWJuYVrAUWjn3jy9lXKRUY1ntUjyLtE7XcyT
         kqSTXprF64zSxmJMyadjBOgQgfgmtpteDB5A952slBlyIPU8Rln7x5xy5uAAQBm0MLMS
         19wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20150623.gappssmtp.com header.s=20150623 header.b=gbRqGxkt;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HgMylvbhfmoxDZysvlUhnq4SZSptkAXr+hDEipNR930=;
        b=GhIPbijstFXRSmtdhOqrBoeEjdR8gTb1o0JdhScu+GpFTgfwQhi/l2RnuwS2t+resF
         +kijQ3f4TGbyOs0MPwqNfm39sJPrLP6t5pML7O8QJjX3M4G+CWFF5VApDUT51xP417wg
         cxaYZfX3qM82bQO+SBrCDzbk+9G2Mq46PB19ptt4lwLacvce/g30I2y9iM1x/GU5/hGU
         zv7t6vpCeX1KEVrFSp+/eiot9sVAyb51GjjLp1e3XUAnCpWU94o+95lcx+TZOJa4ravo
         Ey1e1wVxLRx4HgHDwEyp8PzcCxkmiK0e3s0zv1cmr1f4p7CTNgRBCT0x2q9c1UoqGuYK
         hAvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HgMylvbhfmoxDZysvlUhnq4SZSptkAXr+hDEipNR930=;
        b=X40O8wInapuNnLAtFWJRojEUe1U43k1IP0b+j0Q4hGp2VWUS/xn1UBmPv24/civ2Gq
         96SbW9UQrr6PQFG56DhN+mPQR4S7WKdvqAiA4ysdkMAfpIyS9juBla6MQnukXbc9myJm
         iZQxdNB+2a80AzYjamCDL4lieeeg+MTfen4aCPu8T2tiqAkfklYbPY/smiodfHYhYUlU
         reJ28WI04ItCOZ0XPCYf7nfuHLg24wAGz++qPOjcRoe0Cue/PmYmjdk2wL6xmLhuv/9V
         d+lVMjH1lF8ygFHOTJtl45zWv9viaacXXUnUEzYhmfk0uJ3tQ12BNTmwUSW20ODetl5G
         Ml/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319LlHUJ+TAi9wYQUUDZ5SrRGbQW7grA6elUs6VBwVxB1XL5PgT
	LyVRaYTSUIfjvlZKExRUcsw=
X-Google-Smtp-Source: ABdhPJyG88U4EY+EVlNWhHIZ5dC8r7CIcPQpQNZmptJWnj9aXbljurDM963VEGzYXhvrgSplGHpbng==
X-Received: by 2002:aca:bed4:: with SMTP id o203mr5414829oif.102.1622123112404;
        Thu, 27 May 2021 06:45:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d11:: with SMTP id o17ls939556otp.11.gmail; Thu, 27 May
 2021 06:45:11 -0700 (PDT)
X-Received: by 2002:a05:6830:10c9:: with SMTP id z9mr2914350oto.275.1622123111816;
        Thu, 27 May 2021 06:45:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622123111; cv=none;
        d=google.com; s=arc-20160816;
        b=AEKNb/iWeR2vOWaEtyiSj2M/oMdElj+SIbG65T4i8bc1nTCg7qSPziOON6ZDl6tuyK
         EkKgJnoQaAgCeuVqHzs95hLcgfdbRDr+yyTO0vxzfKcY0dy2f6WKdWXOoscsIsT3mJk+
         +j5sNRPuHlIj0ZxmeEst6VqiufvgBf9Lr+MNExziB+VlCIVE3VU2dLtglXaJqLVo8yDp
         1qOWa/SodNrY7bPcDKrGGZR8sNw8YLVVAbPTbUCP+nN850CPNL33Ck3spszKR2alo7l/
         xWWz58TsM0DE4D0PMzSGeaXimyvzkFWVlK2OKubRPZy/NVRAIecEStGvPP0z0kpU9MMj
         tggg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=zZ100OgAiDnND5MKuUNcSvGRwi3n6jrkgirwTZqtvBg=;
        b=TYpKSaNQdoUAnmre6DY3JszxYa2wEwnFNpKZSrgGT06QfhG7mJaypTkCZxuRDqgtnw
         ww9lMqxVyVD7sqwXWfmghD5HM7EHDLurCm9Kr+xkpo+M8eJ4lIRTDLChVQH3HUChSsqW
         vBAGwvQlmKGRm4BtLREYLV/fvt6tzim89iaPQoqFH1/vXTSpJTtBVZ1OrXGw/4flnlYE
         yqSw79cuE8vTXPCErd3M7wOF0h80ti2dfCNEYNGQYdSCipXMNxRtFK3noZuVxOjMC1vw
         kSPR4tBf6qwFX4SKbj8RW8Cq+NAIkEPVSZzw5I7UY+NPLx7jTMpfDTzfaqEuZjAp0Vu+
         8b8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20150623.gappssmtp.com header.s=20150623 header.b=gbRqGxkt;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id c4si382344oto.0.2021.05.27.06.45.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 06:45:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id i12-20020a05683033ecb02903346fa0f74dso222680otu.10
        for <kasan-dev@googlegroups.com>; Thu, 27 May 2021 06:45:11 -0700 (PDT)
X-Received: by 2002:a9d:5c08:: with SMTP id o8mr2856752otk.261.1622123111562;
        Thu, 27 May 2021 06:45:11 -0700 (PDT)
Received: from [192.168.1.30] ([207.135.233.147])
        by smtp.gmail.com with ESMTPSA id k18sm515360otj.42.2021.05.27.06.45.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 06:45:11 -0700 (PDT)
Subject: Re: [PATCH] io_uring: fix data race to avoid potential NULL-deref
To: Marco Elver <elver@google.com>, asml.silence@gmail.com,
 io-uring@vger.kernel.org, linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, dvyukov@google.com,
 syzbot+bf2b3d0435b9b728946c@syzkaller.appspotmail.com
References: <20210527092547.2656514-1-elver@google.com>
From: Jens Axboe <axboe@kernel.dk>
Message-ID: <893559c1-4510-3f7d-7c7f-82eb2468a5d5@kernel.dk>
Date: Thu, 27 May 2021 07:45:13 -0600
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210527092547.2656514-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20150623.gappssmtp.com header.s=20150623
 header.b=gbRqGxkt;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 5/27/21 3:25 AM, Marco Elver wrote:
> Commit ba5ef6dc8a82 ("io_uring: fortify tctx/io_wq cleanup") introduced
> setting tctx->io_wq to NULL a bit earlier. This has caused KCSAN to
> detect a data race between accesses to tctx->io_wq:
> 
>   write to 0xffff88811d8df330 of 8 bytes by task 3709 on cpu 1:
>    io_uring_clean_tctx                  fs/io_uring.c:9042 [inline]
>    __io_uring_cancel                    fs/io_uring.c:9136
>    io_uring_files_cancel                include/linux/io_uring.h:16 [inline]
>    do_exit                              kernel/exit.c:781
>    do_group_exit                        kernel/exit.c:923
>    get_signal                           kernel/signal.c:2835
>    arch_do_signal_or_restart            arch/x86/kernel/signal.c:789
>    handle_signal_work                   kernel/entry/common.c:147 [inline]
>    exit_to_user_mode_loop               kernel/entry/common.c:171 [inline]
>    ...
>   read to 0xffff88811d8df330 of 8 bytes by task 6412 on cpu 0:
>    io_uring_try_cancel_iowq             fs/io_uring.c:8911 [inline]
>    io_uring_try_cancel_requests         fs/io_uring.c:8933
>    io_ring_exit_work                    fs/io_uring.c:8736
>    process_one_work                     kernel/workqueue.c:2276
>    ...
> 
> With the config used, KCSAN only reports data races with value changes:
> this implies that in the case here we also know that tctx->io_wq was
> non-NULL. Therefore, depending on interleaving, we may end up with:
> 
>               [CPU 0]                 |        [CPU 1]
>   io_uring_try_cancel_iowq()          | io_uring_clean_tctx()
>     if (!tctx->io_wq) // false        |   ...
>     ...                               |   tctx->io_wq = NULL
>     io_wq_cancel_cb(tctx->io_wq, ...) |   ...
>       -> NULL-deref                   |
> 
> Note: It is likely that thus far we've gotten lucky and the compiler
> optimizes the double-read into a single read into a register -- but this
> is never guaranteed, and can easily change with a different config!
> 
> Fix the data race by restoring the previous behaviour, where both
> setting io_wq to NULL and put of the wq are _serialized_ after
> concurrent io_uring_try_cancel_iowq() via acquisition of the uring_lock
> and removal of the node in io_uring_del_task_file().

Applied, thanks.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/893559c1-4510-3f7d-7c7f-82eb2468a5d5%40kernel.dk.
