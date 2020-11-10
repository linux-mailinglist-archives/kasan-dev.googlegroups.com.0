Return-Path: <kasan-dev+bncBDOILZ6ZXABBB3WBVT6QKGQEL5UNRGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3889A2AE3F4
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 00:23:27 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id h2sf1942938wmm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 15:23:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605050607; cv=pass;
        d=google.com; s=arc-20160816;
        b=BgfBA0pXqVLi6YX09sqII01PRGI0fUnpSUjUQKUFmtzkQNNyB6NyldkT5YOQuAukm5
         vXmU0YCNBbonf6+382Dg4X9eMm8D9Z1FR/eibFq5OYZxqG6xWD/T+J9lLcxlwK9h5Ees
         KZjpH+osmp9hNDjBI0SoTkvqMyFIYQaPHBhUQwEseQic18mWq38aAKqirtTB5VUxxIbv
         wytlhjXWKWAFRVdF+/7vM13DLUCkANOX4let9NtSGsesQEHRkoC0jbeT7/bu3TuKNr7k
         9zdiYxEoah0RHLPXw+Vi7VHqd+0Gfo3BhpnmypiuYWNglvRwLkV0ruUTNXVp7ovx1BQ/
         Vs5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Wbehgi8IBhpHF/gp+3ljQmPmPRkeTs3dGOFwld5cXLc=;
        b=ZfaqV/+qj28miJV/puzVhKzbAsEp0V3ypGUGeaWPWghWp3CpkQoCygXBvI3dFuyzJE
         JmZYkle7PnDluGJ8T5zkDZPfcs1O1yd1MV/0tUi1Q6Z1C0cJQroRJjqeNqESn4hDAnRF
         L1s2NTJYFJc+M9fz0LSiOvz/uG44cUrdiG0l5DfRWPips2t7tsML2cPQSibE9j+pfU2g
         eO1zdk28Xo/kyRNkRQ4vUDL3FYUSIjSj9oTEpySnxxDnYmiemhM/ppwCkkaJzeKiClEn
         0fhEjMj5mzvOtbIux0iCnBSvB0MWdaNNPnWFhUAOS1m+irUbD4pkXo3qMZ95VFdq3maZ
         41Gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=uSONrwvL;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wbehgi8IBhpHF/gp+3ljQmPmPRkeTs3dGOFwld5cXLc=;
        b=hpvOuWQY8yfNiETrCHbAAv3Y1tTaGKRAqrSQ0JH4bQD1GUvK6pBlHrbfeLvk5RMben
         hv8tu3gAakPMsZR8H2/yfzMGlgfQspoa1x0zHwAuNR4IB5mnRiTf046h9FHF1aaKIQ8a
         mS97fdcyrYqfJikpl4iN5C0/pLfzB4nt5Vqp615gEqbqhLzvTe4pkz+QHM1JvVW/DONG
         +8QidP+ODRYnKdBwwBM80CYmY4rzjK4Bsk5NOW/xhbvBDoqsbjZyxogwKqUN0pVISOM+
         4yqlK/E9Jo3BKP3RJiMYb5Hls+mqXZygQyBDkrllWlaGGSgcY2bBiY2pyT78+bdXF1/T
         nNsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wbehgi8IBhpHF/gp+3ljQmPmPRkeTs3dGOFwld5cXLc=;
        b=rmYJPXmc96u6jR0nbLIzgYZZpuuk9cl4/eTUbjDp6rRRSXyv1FtcX3xQ1HxQeaeXK7
         MaqpFNfK8TP6MXFEpUXYZ7EuQsC4QSt1r6n6lM+KZgLPwFZifDT/E04pEKYuySFOZrKN
         C/F4U2JWx/ocwi+3IkmY1o5y9qC4SfX76OEIi2noMA/PEl1P94AGtkZJj6k6mGPORFPP
         46Tkc6aNS/NNCmWYg61Cx5PpRaCwKXThajq5oKvogDz8BubY1c5V/ENHNVLSXNM3zhDf
         BU2masDoqyOoLQ6OjsevGBeVX7Y7JSgM1ojIEm+NymjCB4pAUh4rp0lQcuACazR9yQcs
         CPIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PimDWnJC+tKVCGtk6oJYgAF8N7VGDOo5PLTV/azb9WPEQjM5J
	2mxSGMNHwtjisGqODwKiiqM=
X-Google-Smtp-Source: ABdhPJyuV/Kj+TbftDMxXUOyOMR/ToItFOO4b0vP+FYp3frOxL9O0vWxvv/IK9Cp2aczIZru+ebyhw==
X-Received: by 2002:a5d:6cc5:: with SMTP id c5mr26561138wrc.301.1605050607003;
        Tue, 10 Nov 2020 15:23:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls597104wrc.2.gmail; Tue, 10 Nov
 2020 15:23:26 -0800 (PST)
X-Received: by 2002:adf:c388:: with SMTP id p8mr26748983wrf.307.1605050606116;
        Tue, 10 Nov 2020 15:23:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605050606; cv=none;
        d=google.com; s=arc-20160816;
        b=KtuiFW3RiWg+PYIaGnugIx/DXzpq6AZfjF78Mmww1z88JBmlAyt0hAPx/Spd+q7+jn
         AJMLm2nCieQ+UQSoAR/EHC6KStHpmHN0hqulF4LeXyxzGjGJYvHV+SIP4WtbpgGozlJx
         /EAscs8ALamDHR1Jrzq2RmD+gmYrnqe77nFL3ogzeM4Mc0RYp8+zDAzSVClbZytlYyGv
         ldD1DRFPc7scwdG5DofeeAjgVSl/UEm/bMyL9qQ+LbfPslJSux9Mb+Bnh9iJi5vvi1a6
         h3C80pSRMnDtmxBcxsVF9+riYYqHnVryNMKfYbHtastOy5aDgIeGEsboUiZxfMvJ7rPo
         +pLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=snmzgSJawG90tTENS8PRBQJwFI4U/+eiuWYIm1kFYpU=;
        b=p3lAxPZox9RTGsbZqnxZkIlt8vPZpleshIds1T2LQHy8Xfty4wZDFm1CNR+HjriZDO
         Sry1xjwvN/089cNPUnWsA2GsC4KmiBR4jlrEnv/+i4qJr5zFsaFA12NFMeREj4TdgDFQ
         DuLlzw89AXW/c1UALNUI+Rr+hMxZ4dRE2TPcFatMOUuB4VgjNi7mobDbupY8zGlgL1PK
         gk3/DBS0K6pTg9iWOjm/8LIuqMeWcC3cTO6OMc7rMGSExi2c9u5h+HOrgvTvy2xLCoTh
         XVMKXvR6ZnVCnxGnBPD1sCXprxuxf6MJVh1NDQSJpoO6UXvsm2RJga9G5sYAAEsv2FKS
         mFoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=uSONrwvL;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id r21si7456wra.4.2020.11.10.15.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 15:23:26 -0800 (PST)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id f11so597874lfs.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 15:23:26 -0800 (PST)
X-Received: by 2002:a19:40c7:: with SMTP id n190mr2214361lfa.185.1605050605523;
 Tue, 10 Nov 2020 15:23:25 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com>
In-Reply-To: <20201110135320.3309507-1-elver@google.com>
From: Anders Roxell <anders.roxell@linaro.org>
Date: Wed, 11 Nov 2020 00:23:14 +0100
Message-ID: <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=uSONrwvL;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Tue, 10 Nov 2020 at 14:53, Marco Elver <elver@google.com> wrote:
>
> To toggle the allocation gates, we set up a delayed work that calls
> toggle_allocation_gate(). Here we use wait_event() to await an
> allocation and subsequently disable the static branch again. However, if
> the kernel has stopped doing allocations entirely, we'd wait
> indefinitely, and stall the worker task. This may also result in the
> appropriate warnings if CONFIG_DETECT_HUNG_TASK=y.
>
> Therefore, introduce a 1 second timeout and use wait_event_timeout(). If
> the timeout is reached, the static branch is disabled and a new delayed
> work is scheduled to try setting up an allocation at a later time.
>
> Note that, this scenario is very unlikely during normal workloads once
> the kernel has booted and user space tasks are running. It can, however,
> happen during early boot after KFENCE has been enabled, when e.g.
> running tests that do not result in any allocations.
>
> Link: https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com
> Reported-by: Anders Roxell <anders.roxell@linaro.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kfence/core.c | 6 +++++-
>  1 file changed, 5 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 9358f42a9a9e..933b197b8634 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -592,7 +592,11 @@ static void toggle_allocation_gate(struct work_struct *work)
>         /* Enable static key, and await allocation to happen. */
>         atomic_set(&allocation_gate, 0);
>         static_branch_enable(&kfence_allocation_key);
> -       wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
> +       /*
> +        * Await an allocation. Timeout after 1 second, in case the kernel stops
> +        * doing allocations, to avoid stalling this worker task for too long.
> +        */
> +       wait_event_timeout(allocation_wait, atomic_read(&allocation_gate) != 0, HZ);
>
>         /* Disable static key and reset timer. */
>         static_branch_disable(&kfence_allocation_key);
> --
> 2.29.2.222.g5d2a92d10f8-goog
>

I gave them a spin on next-20201105 [1] and on next-20201110 [2].

I eventually got to a prompt on next-20201105.
However, I got to this kernel panic on the next-20201110:

[...]
[ 1514.089966][    T1] Testing event system initcall: OK
[ 1514.806232][    T1] Running tests on all trace events:
[ 1514.857835][    T1] Testing all events:
[ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
[ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
flags=0x0 nice=0 stuck for 65s!
[...]
[ 7823.104349][   T28]       Tainted: G        W
5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
[ 7833.206491][   T28] "echo 0 >
/proc/sys/kernel/hung_task_timeout_secs" disables this message.
[ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
1872 ppid:     2 flags:0x00000428
[ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
[ 7889.178334][   T28] Call trace:
[ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
[ 7905.326856][   T28]  0xffff00000f7077b0
[ 7928.354644][   T28] INFO: lockdep is turned off.
[ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
[ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
  W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
[ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
[ 7934.053677][   T28] Call trace:
[ 7934.060276][   T28]  dump_backtrace+0x0/0x420
[ 7934.067635][   T28]  show_stack+0x38/0xa0
[ 7934.091277][   T28]  dump_stack+0x1d4/0x278
[ 7934.098878][   T28]  panic+0x304/0x5d8
[ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
[ 7934.123823][   T28]  watchdog+0x138/0x160
[ 7934.131561][   T28]  kthread+0x23c/0x260
[ 7934.138590][   T28]  ret_from_fork+0x10/0x18
[ 7934.146631][   T28] Kernel Offset: disabled
[ 7934.153749][   T28] CPU features: 0x0240002,20002004
[ 7934.161476][   T28] Memory Limit: none
[ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
blocked tasks ]---


Cheers,
Anders
[1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
[2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADYN%3D9%2B%3D-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR%2Bxg%40mail.gmail.com.
