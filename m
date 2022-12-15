Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5X5OOAMGQES33VRUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CF9364D7CE
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 09:33:05 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1441866fa6csf6870705fac.22
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 00:33:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671093183; cv=pass;
        d=google.com; s=arc-20160816;
        b=zKPf/r9lbBRrx7y8ThhXLjJb/ooP7R/5AwsKpBYcxR5NJGIcTX6ceJcQTGIMY8yW16
         P5VT2R32h1HFZnjDEFxmmmYxCJXL+I3DSpBe6/FJNYk5hawqiBR8sOYh7ROlH/NpXcHa
         nkXA2E3IRk2usmd9h/QOJuckmHuzb4+g0Z08VXmScLmHOGTMX+poNcU4KkKyxKgPw4RK
         w+lsHvs4NJfo/If2nxrSLuevhFEuLpGQJx1cp64/X+jiwOQ6z2wjaR5S/tP2T/GcDU4o
         ke7IzQFo+rNo+2U1qOCH7hmJ9T7Ee/+7V4fnidORWf4Il6bPPd4D2NSqcUcI1n/8dzDz
         3o4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DmvGt+XOGy8lfXNtItjHt33ths+gMooISVmkZsce0oM=;
        b=OEOQJQapBd9Pb9e8MHsINFiv+rYhRh0JnrMzsEYXHvrEhktVwWpRFW2ipMfsPptbDX
         TClNeo0Nts2APVCi1WgyFE/mPNr3u9HscshLCPgSYd4yx+wvbbEzdwD8Nj6a79yX719c
         tjbK52xEgN07pA5nGVpSNLbHYu2uniR9+C7YQey2curZjfdr2N3PoWi5jlzh1nofNkUf
         QPAJU3hGjUNYCmHx2FBTIyzXpeW10gH4CS186FqKqY1A0LzSuGjux6RumABx3dk+Fauc
         hyUj2nbJg9+M7NwGB8i38v6lYHyGZiN9KaNN5GpNd9KdTR5bSV5FjzW8s/oGRUWznwr1
         TLrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gcsIYuVB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DmvGt+XOGy8lfXNtItjHt33ths+gMooISVmkZsce0oM=;
        b=p4g6amSAxPgIzI1RIxn4hjrkP8tzezgNW/8jT6rMOIJt7nsnRMYygVPslXu2I+MX2A
         fd+soF9vIG03R8mwwmZ9fsG6t87hjDEwZMqjCsE+JFA9yac/7n3xnHXfeO87TXjB7f5I
         i0UHuTV42qj06ah1waCqYiPEgfoJi/Zy2oQ6LEWxRfAfbIQs3Fkusz1hUPrmD2BEZpKh
         /Jt7R9/yDU9qU8wIVa69FZMKOQdY6r/LkXG+xHkYOybrtNzjWDchQiNNd6DfCAydJnFc
         AvNjLA2/Zx6F88+PAeR0nhJb4bVsngXXn3jm2q5elarQUxtHSmrJ35qZbQm0JHS9ocKd
         s5ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DmvGt+XOGy8lfXNtItjHt33ths+gMooISVmkZsce0oM=;
        b=lXU3L1HCjNB93xI7UxiZw5Gvb9vfObdhkKs7QAJuMTlYaY8EM3XzlKgxTJN0+rK3B1
         WXsSdeAnNrtuaxceF+CpevTyehSW9XL6i96WHTgAXU1RZg9ePU++Un/HJ520yM47WPxT
         cmX/72GBs9O9/qfyIU+jyY46RHKHavwt9zwd0g1veEeRDr0n9YfvpmTQfEVjcQtZeFe+
         S5ydiONuWxKEBWf23Qmbri5WUpwHy0YiWj3qYjH4qdkMyTl+BmJ0OPWGzDr2XlTSCD5g
         rkWUv3wXMR50Z52hhA57uslRi88oppH4WX2AG28Qp87diEa5JDYpUeshTXukSf1jV5sH
         47dA==
X-Gm-Message-State: ANoB5plsoWCVOGEpZ6NnXL8cxQEvgrgAMkeklqt4wGT4SzDyGFiaUsme
	OV2adsOAJbJ5tL3DKEWBAPA=
X-Google-Smtp-Source: AA0mqf7rkUjbAfj8K7a+hd2g4WhAcYP5sTzpnDLOFFbOuPbrZ+r8dnTsh7fEnCsQy6/Dl4zZhw89bw==
X-Received: by 2002:a9d:7097:0:b0:670:66a3:3319 with SMTP id l23-20020a9d7097000000b0067066a33319mr4238968otj.335.1671093183639;
        Thu, 15 Dec 2022 00:33:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6010:0:b0:61c:e180:124e with SMTP id h16-20020a9d6010000000b0061ce180124els3942030otj.7.-pod-prod-gmail;
 Thu, 15 Dec 2022 00:33:03 -0800 (PST)
X-Received: by 2002:a05:6830:608b:b0:66e:6e2d:77fd with SMTP id by11-20020a056830608b00b0066e6e2d77fdmr15463241otb.7.1671093183153;
        Thu, 15 Dec 2022 00:33:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671093183; cv=none;
        d=google.com; s=arc-20160816;
        b=kXlW89bX92HtsRlSeJyxS4sGtP0gGtalYCOofS+SJcseJu3+H1JScuyak06z1/d1Xt
         JXfhBRa+P4tWGn13JRKF2o6H+KcVRpgM5yhJ6KiWKBdeeeuWPl7GiuQKRBhDujSEN5GN
         +5bb/XhOTBs6kV1BdTh9D9wuzdCO7uob3GRKWtBM82xZKDqgE0yAw2pUF+zY1UwQk/k/
         24ZbU1mNsQj5N7iXdaPUEUosshcFyJsC6xIyqmgP9/OthG+Ovmnv+i9HDEYuHA747apv
         SmLYH1P5wV+vCV24at8OVgXWThPAsrMvRGxgapeQduJ4T2RrooB1tXzPAzAOFNV9p1Bl
         E90g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zw/RhO20UZoC9G6TTtJdTuGGtmTIwLpJWlVSECXA/JQ=;
        b=RZyjy69AmDGYkUjTNMqotjZSYU2qqo7dZr9U0rWmYFxwoFjgqJij0ZzXWb0fzyV7v2
         6BMPDaMPQqlUYR7wiFgJRHjDRuH2xGLFF6/wYfY3yCAs3JpSLT+3tiM3HR6Hz/xie1Ey
         yxGWUDDcwup+nRrHhrQB3yECxGJb4N59XKYZ42AlRmZRjA730I7G3xXCJnHHP3Hio2fj
         G1oPSK9AdUzZw2b1xr/3UMFlEwZ/UbQ+HtsmzjraBa9AGn9lMsdxDD0Kw8VA4dq526RS
         Md+nyEtjvBQMvpI6v33jEjhAhkQTvZqq9h+lJi6Kle5G0EePUruIxs0ovCCz8ObQ/mfY
         lqDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gcsIYuVB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id j2-20020a9d1782000000b0066da9f2faeesi786666otj.0.2022.12.15.00.33.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Dec 2022 00:33:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-3bfd998fa53so31825247b3.5
        for <kasan-dev@googlegroups.com>; Thu, 15 Dec 2022 00:33:03 -0800 (PST)
X-Received: by 2002:a81:9188:0:b0:379:3bb4:596f with SMTP id
 i130-20020a819188000000b003793bb4596fmr26819268ywg.238.1671093181145; Thu, 15
 Dec 2022 00:33:01 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvcmmOh93nOti72+woKvE+XvLg7apCYDUfu6oKtjPkHKw@mail.gmail.com>
In-Reply-To: <CA+G9fYvcmmOh93nOti72+woKvE+XvLg7apCYDUfu6oKtjPkHKw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Dec 2022 09:32:24 +0100
Message-ID: <CANpmjNOwsvfnJXzaFOUCYFRT_TM-z1YWqHv-nx3DY_V2f3xBhg@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in do_page_fault / spectre_v4_enable_task_mitigation
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, rcu <rcu@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dominique Martinet <asmadeus@codewreck.org>, Netdev <netdev@vger.kernel.org>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gcsIYuVB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Thu, 15 Dec 2022 at 08:32, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> [Please ignore if it is already reported, and not an expert of KCSAN]
>
> On Linux next-20221215 tag arm64 allmodconfig boot failed due to following
> data-race reported by KCSAN.
>
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>
> [    0.000000][    T0] Booting Linux on physical CPU 0x0000000000 [0x410fd034]
> [    0.000000][    T0] Linux version 6.1.0-next-20221214
> (tuxmake@tuxmake) (aarch64-linux-gnu-gcc (Debian 12.2.0-9) 12.2.0, GNU
> ld (GNU Binutils for Debian) 2.39) #2 SMP PREEMPT_DYNAMIC @1671022464
> [    0.000000][    T0] random: crng init done
> [    0.000000][    T0] Machine model: linux,dummy-virt
> ...
> [ 1067.461794][  T132] BUG: KCSAN: data-race in do_page_fault /
> spectre_v4_enable_task_mitigation
> [ 1067.467529][  T132]
> [ 1067.469146][  T132] write to 0xffff80000f00bfb8 of 8 bytes by task
> 93 on cpu 0:
> [ 1067.473790][  T132]  spectre_v4_enable_task_mitigation+0x2f8/0x340
> [ 1067.477964][  T132]  __switch_to+0xc4/0x200

Please provide line numbers with all reports - you can use the script
scripts/decode_stacktrace.sh (requires the vmlinux you found this
with) to do so.

It would be good to do this immediately, because having anyone else do
so is nearly impossible - and without line numbers this report will
very likely be ignored.

Thanks,
-- Marco

> [ 1067.480877][  T132]  __schedule+0x5ec/0x6c0
> [ 1067.483764][  T132]  schedule+0x6c/0x100
> [ 1067.486526][  T132]  worker_thread+0x7d8/0x8c0
> [ 1067.489581][  T132]  kthread+0x1b8/0x200
> [ 1067.492483][  T132]  ret_from_fork+0x10/0x20
> [ 1067.495450][  T132]
> [ 1067.497034][  T132] read to 0xffff80000f00bfb8 of 8 bytes by task
> 132 on cpu 0:
> [ 1067.501684][  T132]  do_page_fault+0x568/0xa40
> [ 1067.504938][  T132]  do_mem_abort+0x7c/0x180
> [ 1067.508051][  T132]  el0_da+0x64/0x100
> [ 1067.510712][  T132]  el0t_64_sync_handler+0x90/0x180
> [ 1067.514191][  T132]  el0t_64_sync+0x1a4/0x1a8
> [ 1067.517200][  T132]
> [ 1067.518758][  T132] 1 lock held by (udevadm)/132:
> [ 1067.521883][  T132]  #0: ffff00000b802c28
> (&mm->mmap_lock){++++}-{3:3}, at: do_page_fault+0x480/0xa40
> [ 1067.528399][  T132] irq event stamp: 1461
> [ 1067.531041][  T132] hardirqs last  enabled at (1460):
> [<ffff80000af83e40>] preempt_schedule_irq+0x40/0x100
> [ 1067.537176][  T132] hardirqs last disabled at (1461):
> [<ffff80000af82c84>] __schedule+0x84/0x6c0
> [ 1067.542788][  T132] softirqs last  enabled at (1423):
> [<ffff800008020688>] fpsimd_restore_current_state+0x148/0x1c0
> [ 1067.549480][  T132] softirqs last disabled at (1421):
> [<ffff8000080205fc>] fpsimd_restore_current_state+0xbc/0x1c0
> [ 1067.556127][  T132]
> [ 1067.557687][  T132] value changed: 0x0000000060000000 -> 0x0000000060001000
> [ 1067.562039][  T132]
> [ 1067.563631][  T132] Reported by Kernel Concurrency Sanitizer on:
> [ 1067.567480][  T132] CPU: 0 PID: 132 Comm: (udevadm) Tainted: G
>           T  6.1.0-next-20221214 #2
> 4185b46758ba972fed408118afddb8c426bff43a
> [ 1067.575669][  T132] Hardware name: linux,dummy-virt (DT)
>
>
> metadata:
>   repo: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/tree/?h=next-20221214
>   config: allmodconfig
>   arch: arm64
>   Build details:
> https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20221214/
>
> --
> Linaro LKFT
> https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOwsvfnJXzaFOUCYFRT_TM-z1YWqHv-nx3DY_V2f3xBhg%40mail.gmail.com.
