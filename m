Return-Path: <kasan-dev+bncBCMIZB7QWENRBOEDY2CAMGQEZGZSZQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C1E7372E9B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 19:17:45 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id m4-20020a9287040000b0290166e96ff634sf7625295ild.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 10:17:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620148664; cv=pass;
        d=google.com; s=arc-20160816;
        b=ByvM2Cc7svL5FH6eGkWT1xmPw7zqdKEJ+m9rwt85SbqTP3gLivPN08MlzCOJ1wr80Q
         do9swKLIhzuDabTwL+wD0CEuBPxbrE5yivIZc816vezK0IUuX2kVkpmDjaQhaYjAEj9k
         nLvdvw+IK7wsb+orHWVtGNRxPQ/TcaD77m7Pbr3U29rpDeqQYOh4L62OPLbQMP5zTcN5
         WkOnU5X60V7Amo/znIHvIuoBpyaXjurBqJJZdnwm1o6QY8TXnOQPyQbpwvCmGb1NMJHk
         xro4KF7YgUOvu90ZrkuwNVtJOafYxc4Pb62KVCFExsLxp2e9KLoGOpTSwVjl8QSB/qJM
         V2wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gwYwXyhPAy2Uw1w5htuRfCYXcTUBqqWnuU9JDge8+YI=;
        b=gGLZOiUWM9zMI+1gFKNvUmsFV29PBxRdXYqqLqq9g+IxPEpGGC44i2r88UsA6G5QSP
         L5VOMKIDunLDB85m6sPE6K2mTQCflbrMjIuM2BXPDDVKu8+ovPSgmVKqqsIebYZGNRE0
         doV3KykePI8w7SKzh/YGT4aEt7rohyH8q8krqmf6tdv0DUKg3704bLzC9kb2C3qINrex
         PiIlxJjYVHi6J3LDaAiui8MBDu01STEt38j+McQxNTGd+SkDAyofhkOwxcv4qs6KCCW3
         lJFbcU1v2+fcidaUxbiMZ0jh0FgZIgIXewuCGMuS3QW5igKJuq/6xZH8Vf1tkaur2UTV
         QbtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lV9pNu1A;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gwYwXyhPAy2Uw1w5htuRfCYXcTUBqqWnuU9JDge8+YI=;
        b=nmN+JN2oXYr+BKJLlvzK94HMoQIoI5Rq1e6T/MNiTl3L+PmX/cNscETa4EfC4mTjaw
         kp2jaDOs0bYcPcMIDlwtZoaHmgg4/4Krja1XZpLekIYzi6z6AysPmd95zJ+TLT7MGZb7
         EssR2XoHd8RksFV3IyRBgS04/PmhehsZffInQbPiSTxMEwH+E+N5vRrwpMmkP/grS/qG
         S1TY3Zy0m17vuHoJovLncSjusk24vircqLJ/c+HrjZkxCRjFqvbpX5/B4j7eYVFma67T
         croJ4oM3ARBgzXlP9No+btSTNg+m6xZ1TIzFprI+T82ofp/r+vYE9T9zxn9FaEfPnwPu
         bawg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gwYwXyhPAy2Uw1w5htuRfCYXcTUBqqWnuU9JDge8+YI=;
        b=Etb8OR3G6I2EW2q47+aD+wvKxvv6wX4LpYMfBXngqb+VuhuU5d2+5UqYGKtnlCjnjm
         YkPLrHKMniNQkHZvIqG298oM5I7Reo515bA8zA74Ba9DSeVCx6YJEXxx6V8rYOSUCSL9
         ymz0ZLn+1ovcxC082cGykmbTmip4b9iacmuNY0i7VXeD1li5fs6+klJl+Gt9SYrgezRq
         Qmz7qiFxcRiAHx4CFGrGcyhIfQ1EKhe+zL7L9dF2r3Utal5vF2hwY57EV9sgrqoM2DDR
         qfnf0CT67HymcSamOP3QGn6CZYLOu9bnP6pzh15DAsOiYJpMvP2joDKZ9cLLzYMs1fCE
         v22g==
X-Gm-Message-State: AOAM5302M85Nk7nY584g4sUt3I53l1/1kd1odHhxRYy67IBjeoiLfGjA
	CsL5p6SGQRvDlhCS3KQyl+E=
X-Google-Smtp-Source: ABdhPJzhTRtZj3wYtg1Dh67+fwxQokm/BLNdzGQdrhi/KBMKo1PUpBtSohZXlg1RBhlqE9iDGLZHKg==
X-Received: by 2002:a5d:8147:: with SMTP id f7mr19777041ioo.135.1620148664522;
        Tue, 04 May 2021 10:17:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1455:: with SMTP id l21ls2253838jad.11.gmail; Tue,
 04 May 2021 10:17:44 -0700 (PDT)
X-Received: by 2002:a05:6638:1a9:: with SMTP id b9mr24191509jaq.97.1620148664182;
        Tue, 04 May 2021 10:17:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620148664; cv=none;
        d=google.com; s=arc-20160816;
        b=yElvDLC7DrqlG3s0LDkd3nLOI4R3tD749HTCSMav/dfmICQce9kZH1pGZY0duGoSzR
         oOiQiwod11WjCmLTlY/35dYq1C2GmToYRSyhjNoF9sK9YjlaDvgf5FQVZbkhhLmO1Y9f
         4xI+dFGcoiU04KD3iYkctaUwVdRGWJtt/gm3YRi+m0u3VRJ1xSukO9unsKlsljtgKpnl
         3CtOKHo6ipwEhaOBzeyQBAowug5vpR7PXICFQVxblh7zTbIHHA8z8AHENUM1ah2Jx4SD
         sy9KxJtbecciaz3IDS5+dcRq0DBo8gHxiObmR4Z1y/tDSpsqPuiVbq/a3xKyTx5xzCl7
         aMwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4RwyehG38JsKD/EL1cHF9aUCKECHFf4iXyx7IfSeRco=;
        b=k7yUYeBPUI5fsTKyqerDHG5Ks/IFSuV+40ya3TZhW93OVP+OtBesS68XPezQ4xCnVr
         M29RPeQnUo+HdlE7ZqVLe/h2fu/6jle7LFMMPEpjiqB3zNhRVXYZwNc9mUB9PDhPzhCY
         0ehjoPvU9U2/86VQ5IViXsRDnAbXDfNXX+bN3cMNpQXJ5AAGpGZJFnmaAe2h0p+rm418
         C4rupLrN+2OYKSGo6UuPnBpb96YCUTEVLZUsz6npqJoncpLkLjOg79Zl6Uc4w6cI9lKX
         fIZQurdDh4I6BKvyH2GvToN0LZtQ8IUce5oxOxVV0+BfLMoWoCtpc2Y9Tl+tQ8MEJ/96
         Ging==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lV9pNu1A;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id o3si453444ilt.5.2021.05.04.10.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 May 2021 10:17:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id i17so9318418qki.3
        for <kasan-dev@googlegroups.com>; Tue, 04 May 2021 10:17:44 -0700 (PDT)
X-Received: by 2002:a05:620a:89d:: with SMTP id b29mr27216870qka.231.1620148663606;
 Tue, 04 May 2021 10:17:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210504024358.894950-1-ak@linux.intel.com> <CACT4Y+a5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA@mail.gmail.com>
 <77634a8e-74ab-4e95-530e-c2c46db8baa7@linux.intel.com>
In-Reply-To: <77634a8e-74ab-4e95-530e-c2c46db8baa7@linux.intel.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 May 2021 19:17:31 +0200
Message-ID: <CACT4Y+a1mjOfiud=WBVaP-96rovKQmW9_AaV+y=NFAKQJy_Kwg@mail.gmail.com>
Subject: Re: [PATCH] stackdepot: Use a raw spinlock in stack depot
To: Andi Kleen <ak@linux.intel.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lV9pNu1A;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, May 4, 2021 at 5:34 PM Andi Kleen <ak@linux.intel.com> wrote:
> > So why is this a false positive that we just need to silence?
> > I see LOCKDEP is saying we are doing something wrong, and your
> > description just describes how we are doing something wrong :)
> > If this is a special false positive case, it would be good to have a
> > comment on DEFINE_RAW_SPINLOCK explaining why we are using it.
> >
> > I wonder why we never saw this on syzbot. Is it an RT kernel or some
> > other special config?
>
> This happened in a special configuration that triggered ACPI errors at
> boot time.
>
> It's probably not something that is normally executed, as well as syzbot is
>
> probably not exercising bootup anyways.
>
> > A similar issue was discussed recently for RT kernel:
> > https://groups.google.com/g/kasan-dev/c/MyHh8ov-ciU/m/nahiuqFLAQAJ
> > And I think it may be fixable in the same way -- make stackdepot not
> > allocate in contexts where it's not OK to allocate.
>
>
> Yes that's a good idea. I've seen also other errors about the allocator
> triggered
>
> by stack depot being in the wrong context. Probably doing that would be
> the right
>
> fix. But I actually tried to switch depot to GFP_ATOMIC allocations
> (from GFP_NOWAIT),
>
> but it didn't help, so I'm not fully sure what needs to be changed.

We may not allocate at all, see may_prealloc idea here:
https://groups.google.com/g/kasan-dev/c/MyHh8ov-ciU/m/k1LXBmonAQAJ

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba1mjOfiud%3DWBVaP-96rovKQmW9_AaV%2By%3DNFAKQJy_Kwg%40mail.gmail.com.
