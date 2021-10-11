Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRNGR6FQMGQE2YVRNOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F2C4428690
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 08:01:43 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id f9-20020a056a001ac900b0044c4f04a6b1sf6870277pfv.23
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 23:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633932102; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQOhGZbDcSOCPhVfenAxmaf52/Mxqlm6JchC464kUqmBSOiNoLZAAx1y6YDys0W5tC
         l5FNQBgZQ7ANQMqYbTQYLmA6GEl2AmQsIm5ycXXh0/KZCi1/0M//Tr3U5homWxVrnfFb
         QEMTzCOq3EOQ2dKbCDjsrVzpHJ86nTso0mITTIDRbDTuUuSF2LISRvRFTFoBeenWLSyG
         +ShUlgac6yrLFzSsZAlqzJon3jG9vXcOkSusWO4UAlvBaRnGPp8mjp2OFz1SgxVOdvKM
         MVCXW4P0Wp6c5/CxotLaRyfOd4JBaVxxDEwXW2Rz8E6HE3f5DB3wC8dVJTUgFIBCKuXn
         mcmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HOFyMUxYGQBhLcpZO7L3dsYCEwW75EtnDBtz4xAMgwA=;
        b=PfP5x8uLJ9pDbho74TKeCOG8Rqq9eLfoW1IUH7NWjJciMRhWddGKuhoDU0LIqfvnBA
         zoz6JgWw5pAXIWWHxcywUEeCO9TuRrBeY6UQeG6tlFVyd6jws1p1j3CIPSyDTQyLA7/T
         vuXTJUZVmPO6Z/nh3tZO0ti+wWmHa2BUmteGi+itW6S7M2Vqqi7JMhG6HjVduEYhTxl2
         niLvKE/BSrT1KHwui1P/euMuI2RSJ+WPiYB4VoovHydFZRaZDgycD9HuLDyf0zUUAcnv
         UvjKUtTvGjKnCb6XJGF+ET9YFHJO1jHcGLCjsb/vc23bmqjHuhDCqkGDhjDTRkeyG2cx
         jNbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lyUPYDSh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HOFyMUxYGQBhLcpZO7L3dsYCEwW75EtnDBtz4xAMgwA=;
        b=ZuKjdCXefi1fmJi2X4OT4vX/nyR61ja4dnBC52jJa/FjU1APTsoYZ0xLC4FmnfLzzz
         VQxH5zZ3SrS4XsCecquUMwVZp19pW+8fG0Fx+S6RUMN3gcsjcUEEXV817JD3ahLGT3tZ
         QQkl4Eedg0FqD3JKIt0GDMnlwqdx+Gaf5triCFWe+SUioNv42bXmfFssSmB+accVsn3Z
         3Ej6H2DCSIRok4/04aydoCJLi6VsS/oHf/geAJSY4fpoiLZltJ6s7RNnSnL+JG5wYgjd
         LI6WYn/Og3lYTrPZ59rBLzQYLwPgORGaVEiqQKJHTNmzQzzvGU+evsaSXNsAkJwsEmzy
         3g6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HOFyMUxYGQBhLcpZO7L3dsYCEwW75EtnDBtz4xAMgwA=;
        b=5CEQu5kmA2s8MWVfdBHmpq8rKQMcJMo/JR4TuiheoaRAAtpT2ASYs4zzpiC1M+ACvr
         LvZYGTBDV32dJbNQjXcIvCoVpwTD/E2fOzcrzga/to4x4a3LlW0fedWuppNjyhqhSc/o
         fDdaaj0BXBcG3FeCVE+cLe65WXIyQ1pkdpd/p+3+JCZ/kOKXPPwj/aUZNI+t/OGw8JAU
         EZuDctufNLvjD6Vls1Jr4ZE+k5HWQrAigtfNS3rhjZHTWjEmrBC4WMrYVfBi7WPIEzF0
         ggCwHAe7K1w8ksRBjdKOA7gJfKtw3/LEVf5EP5PbnI0sUtLaa/NCqsJ9OOP6LI/8KEZ1
         6nMQ==
X-Gm-Message-State: AOAM530Fs3m3k/SOE7ebCU1Tm2wOt/HzhEaUYqRWlQvFz89JzCeex98T
	s9Td+PsJSbudZt22p48bKn8=
X-Google-Smtp-Source: ABdhPJz1Ne6EvQYciAl8aHnQ/vLB/sBfNoWKbWuX8tUZUVAC1g25Z4gcuGo8AY2y8XJhnc1EZ3Lygw==
X-Received: by 2002:a63:8c42:: with SMTP id q2mr17039680pgn.325.1633932101872;
        Sun, 10 Oct 2021 23:01:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1e0c:: with SMTP id pg12ls3712013pjb.0.canary-gmail;
 Sun, 10 Oct 2021 23:01:41 -0700 (PDT)
X-Received: by 2002:a17:90a:bf82:: with SMTP id d2mr28543205pjs.201.1633932101257;
        Sun, 10 Oct 2021 23:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633932101; cv=none;
        d=google.com; s=arc-20160816;
        b=gU/VT8Qb65l0hZ9n8BUBxgzOI/i4rPHhZmKn2qqOxiQ/aXUlvyRHZubIkPFlVYG5TW
         gVSXHLVFzvDvNOn9Fcjt3HaG8MdwmFUd1MwipohIC3mAii6qm465f8uoe3PsgdnDR4eT
         bVUTHzbh280PD6FRifjB2/SKtKadDbTwdrBAScN6V9XNH2iQ2wk75Xto8/nqw5pqM8ZH
         CVsCMsTnooiwtoqAJQ/cdi8jhOjHCLWEp+8Dyi0VFOQtdLsm7OiuqubFXmsqb7UNNDQr
         nxpZQd7n2+I9DlEAlqmrLBBR679vykccn3RbuAUiqYg0M5F7H2rbUYZRrpwkPEZNa+hc
         5lXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7h13AY5afsp7vOYth4Tp6m8iDZB9FmezNoNd7LDicIs=;
        b=lvJqxKZvTXH1Y35HUj8JbFoo3BI8kju49Td4B1uP0DzZf+kO9WrFbBqNO5SKOlYzBd
         wk8C3/fGR0LDQxOPcVjG2WBCqTWGEwfq2eRcDwCf5KoXv/SSbJ+qhSr06FJhmVuhozkW
         /XNDDLyQUOmHZfkmZh2MH9wmGdrDREPqtH9HvhZ7wBNxeIZbgGNiiwd29xffQR7dUkgy
         uOLySprsLxHOev0Z8tcnkwYNKQKAIcUJlvOiMCLFH3qFHoRKdNmEY6g0mpZOIlD3CpuW
         kpzu+ndCsTVMJqNlI3il2QQKJpAIIKERTdIrfsTdK+5dSE6IKdTiO6p1H++r6JIj4bbE
         FaFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lyUPYDSh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id x17si331778pge.4.2021.10.10.23.01.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Oct 2021 23:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id u20-20020a9d7214000000b0054e170300adso20302381otj.13
        for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 23:01:41 -0700 (PDT)
X-Received: by 2002:a9d:3e04:: with SMTP id a4mr20242022otd.329.1633932100754;
 Sun, 10 Oct 2021 23:01:40 -0700 (PDT)
MIME-Version: 1.0
References: <YWLwUUNuRrO7AxtM@arighi-desktop>
In-Reply-To: <YWLwUUNuRrO7AxtM@arighi-desktop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 08:00:00 +0200
Message-ID: <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lyUPYDSh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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

On Sun, 10 Oct 2021 at 15:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> I can systematically reproduce the following soft lockup w/ the latest
> 5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I've
> tested so far).
>
> I've found this issue by running systemd autopkgtest (I'm using the
> latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happen with
> any recent version of systemd).
>
> I'm running this test inside a local KVM instance and apparently systemd
> is starting up its own KVM instances to run its tests, so the context is
> a nested KVM scenario (even if I don't think the nested KVM part really
> matters).
>
> Here's the oops:
>
> [   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [udevadm:333]
> [   36.466565] Modules linked in: btrfs blake2b_generic zstd_compress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
> [   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-rc4
> [   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
[...]
>
> If I disable CONFIG_KFENCE the soft lockup doesn't happen and systemd
> autotest completes just fine.
>
> We've decided to disable KFENCE in the latest Ubuntu Impish kernel
> (5.13) for now, because of this issue, but I'm still investigating
> trying to better understand the problem.
>
> Any hint / suggestion?

Can you confirm this is not a QEMU TCG instance? There's been a known
issue with it: https://bugs.launchpad.net/qemu/+bug/1920934

One thing that I've been wondering is, if we can make
CONFIG_KFENCE_STATIC_KEYS=n the default, because the static keys
approach is becoming more trouble than it's worth. It requires us to
re-benchmark the defaults. If you're thinking of turning KFENCE on by
default (i.e. CONFIG_KFENCE_SAMPLE_INTERVAL non-zero), you could make
this decision for Ubuntu with whatever sample interval you choose.
We've found that for large deployments 500ms or above is more than
adequate.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOw--ZNyhmn-GjuqU%2BaH5T98HMmBoCM4z%3DJFvajC913Qg%40mail.gmail.com.
