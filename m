Return-Path: <kasan-dev+bncBCMIZB7QWENRBDOCRDXQKGQEH7KK2XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D4F5E10DD06
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 08:58:07 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id 2sf19381123pfx.11
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 23:58:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575100686; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZQCc02UficMMml4BCVCXjYcob1KP9xgJJ5elVtKl1d6zjxawrVnVV9bYz3MB7Y2E79
         tZKYJe5qtcjWQPiAIhwqXsP5xiEkX40Vzo1C9+/C069BtbseIhSe0UBkFw4UUvVq38fO
         fg6HEVmNmxZAEukkh+iOiIz6Z+YBjBhWMpEBfIOuuuSMfJPdM7qIxldlsAsmLAHsqCHJ
         aYemyG1lL9Ex8JXzDAExlwUmdT0acnQoZMOsIj09cvplfAaD8XvKzj+PAOgahwoL6NuE
         PAr37VWifU0jadJ/DbvM/zn+S29GPaWd6v+kbbxMOZlAT9GxP19mhs7trn6ADpX9hwsi
         nG9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5O5MzMdC0+cnE5wviem+91TILGBB18MMLFW5Qf3evIM=;
        b=E19h7BSMukQRvnr8QtXjhkSOw8sTZM6Gq2BBGu4BUwSEwKIzBSA6q2JZY1o65mG1wq
         Uq41WYNynSvFnSO2Av/akYMo6+voNbO5/pfNS49tdBjbHk9g84oGfY2HrwqvNCnkZusr
         c50nSERsGbFZA1cz/sF7rONYz7j0+NZtgJPnnakaQN7cyYB4SrfocQVwTfaq/546Wg/H
         75c9I7skzUtJIUG1BXy95y2oj2EyQxA0TQ4A8WMZIHyZW4AyY2x5kLN/6TRH2EIBVcPP
         EiLlb3ltbtuZ0Xv4mq/LSlidxVRXrbcBDG7NbzFHDLZryHnHURiqW4i1nPNJwEMuoubS
         PosA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eM0XQg7w;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5O5MzMdC0+cnE5wviem+91TILGBB18MMLFW5Qf3evIM=;
        b=Yao7ADZteSiwLEhUm5Vo4zwRqABHnwcJ5rHLAZcGnvt4/UjaGKx7oOX1fW+kTZ6oyM
         jic03Vae66aYGSBt1dmlUlmln++0+/uCGpTnkiFL5gDq25rUy2UsdlAo+SDa7gTdtdOU
         RrLOwNi0sZ6Tw7p/Za+xByj/qTXxdXz1AjWmqNRF4X7Wq3wKrbwvJ16rZLuC2RphraCv
         Lx7IKSTUaxIw4zeS3xWDi/TKFWydkVIK8XIRZqE6Jeq3SBBjDxAm3ZF7N/q5QuI+cpxz
         7QooMT5r1bKRELTqtEUXqrfb7bgS+zytnI1Oh8UL3GvAQkbRTKRIpFxUbc/qnRjbZNex
         ENsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5O5MzMdC0+cnE5wviem+91TILGBB18MMLFW5Qf3evIM=;
        b=ZaKe/cmsqwKvy++nrasdGEh+Yd20ik5sT6iAbuQgBxET1qlr5UQexbfzeU2YEcgyuh
         zogsxaQS+Wl7qDQEagcdVgyBmuLwWhSgSvNwkwDksRYYoF0g2GTt3WidDIQIdfTfn+fj
         8PKJ2SKrUFu/4R0C9VNioMNMKVPkfz/Eq0Cs1FhnAr6JDWjdtdKS8JzGouGQ65VZ3/8j
         yeocVAWuSS9ou+GBwmNlF2qAJ0zw/rY8gokmapFTuzIGwEwq+mamaH66PS+Cn7F7N7aJ
         oRJV5d9nnuBNwANkjrdjStK42u7f+DYnKdaiQ6EjkuCBO7OSYdgK9sbM7AiA/mjE6Mie
         A+PQ==
X-Gm-Message-State: APjAAAUB6hpNyTWvlB/pMCg5fi3HgPEawhWVc8AGSirkBN9p/l0yg1z1
	MzW9jVfhuJrvLDD5nLaJUsI=
X-Google-Smtp-Source: APXvYqxw+CJMZRBFY8I43hBCqlET4povgqoB4bxiYlGOqq+baVZ3EPyWaIC0lKkbJVigqDrS9IUWOg==
X-Received: by 2002:a63:5d03:: with SMTP id r3mr20884267pgb.306.1575100685792;
        Fri, 29 Nov 2019 23:58:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:91da:: with SMTP id z26ls5207785pfa.11.gmail; Fri, 29
 Nov 2019 23:58:05 -0800 (PST)
X-Received: by 2002:aa7:8695:: with SMTP id d21mr5738829pfo.199.1575100685422;
        Fri, 29 Nov 2019 23:58:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575100685; cv=none;
        d=google.com; s=arc-20160816;
        b=WX7WPzI5jXk8Bsrw6sIVoSqT3CHf++XLIv3eDcLvd4bXcoI4XU3a+KXATrpaFTgnOJ
         SZ7dOLfgDUiijteWI16xCzYX6Cew9X1RLAdqJZGOogc9Swe83YmqKi1EyOGeIKGi6wdi
         qLkNkyycYdCK65bg9qxdrA3Oufw8LQLmn4tt8+HeaaRNMSL1niZeR1rHWyUFInyBSY3D
         k72eo8nK3m2rAW1oUSpujWhpWRZrUeXQkICV0ATh3Fbe0DMYVTT4hI/V+bCSyD2voFxo
         P8GNFOcxz3WpFtuBilG07zH2KUPRgDpkE/43lHry+A/vA8oJD1wP8yZoT01yl5ZIy+u8
         AwWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M7cazaUnsITY1FKb1YrD4ScYodUQeo/iAP9GwMqKKXQ=;
        b=Kw1zpZBnqFbJ9krfxINyKgA7qzfeNX4NNSivgpUXRgm2Z9zPvdNfG41znIjdHf28AD
         T3pEqhRN55p0CfIZNGVMlEfip69lKDQiFT2YTSnG5bjDEMeZG5DCOd6BNXru56TCM/cf
         FP87CJLRLLmY8dVE1T0IlV+N0j8fS/63QH3XLCNFW6xx1oXLLdtxqVXdX1flWwZb41oJ
         N4WtuqH5PxGwnKwCXFi6Nu5CJxO/WZlaYvT4qBuY1UTBIG6+HN+hCGTjQHhe5JzYFkj4
         jYILVsx4doEKXW3cSJdogn3iLxSneL7r6UzXeVGiImEEM6teP4uZakWFSVCdUaQ1ZO3v
         7rbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eM0XQg7w;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id v36si1050109pgl.1.2019.11.29.23.58.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 23:58:05 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id d5so5864748qto.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 23:58:05 -0800 (PST)
X-Received: by 2002:ac8:3905:: with SMTP id s5mr39162303qtb.158.1575100684045;
 Fri, 29 Nov 2019 23:58:04 -0800 (PST)
MIME-Version: 1.0
References: <000000000000c280ba05988b6242@google.com>
In-Reply-To: <000000000000c280ba05988b6242@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 30 Nov 2019 08:57:52 +0100
Message-ID: <CACT4Y+Z_E8tNtt5y4r_Sp+dWDjxundr4vor9DYxDr8FNj5U90A@mail.gmail.com>
Subject: Re: BUG: sleeping function called from invalid context in __alloc_pages_nodemask
To: syzbot <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com>, 
	Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eM0XQg7w;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Sat, Nov 30, 2019 at 8:35 AM syzbot
<syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    419593da Add linux-next specific files for 20191129
> git tree:       linux-next
> console output: https://syzkaller.appspot.com/x/log.txt?x=12cc369ce00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
> dashboard link: https://syzkaller.appspot.com/bug?extid=4925d60532bf4c399608
> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com

+Daniel, kasan-dev
This is presumably from the new CONFIG_KASAN_VMALLOC

> BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2710, name:
> kworker/0:2
> 4 locks held by kworker/0:2/2710:
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: __write_once_size
> include/linux/compiler.h:247 [inline]
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: arch_atomic64_set
> arch/x86/include/asm/atomic64_64.h:34 [inline]
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: atomic64_set
> include/asm-generic/atomic-instrumented.h:868 [inline]
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: atomic_long_set
> include/asm-generic/atomic-long.h:40 [inline]
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: set_work_data
> kernel/workqueue.c:615 [inline]
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at:
> set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
>   #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at:
> process_one_work+0x88b/0x1740 kernel/workqueue.c:2235
>   #1: ffffc9000802fdc0 (pcpu_balance_work){+.+.}, at:
> process_one_work+0x8c1/0x1740 kernel/workqueue.c:2239
>   #2: ffffffff8983ff20 (pcpu_alloc_mutex){+.+.}, at:
> pcpu_balance_workfn+0xb7/0x1310 mm/percpu.c:1845
>   #3: ffffffff89851b18 (vmap_area_lock){+.+.}, at: spin_lock
> include/linux/spinlock.h:338 [inline]
>   #3: ffffffff89851b18 (vmap_area_lock){+.+.}, at:
> pcpu_get_vm_areas+0x3b27/0x3f00 mm/vmalloc.c:3431
> Preemption disabled at:
> [<ffffffff81a89ce7>] spin_lock include/linux/spinlock.h:338 [inline]
> [<ffffffff81a89ce7>] pcpu_get_vm_areas+0x3b27/0x3f00 mm/vmalloc.c:3431
> CPU: 0 PID: 2710 Comm: kworker/0:2 Not tainted
> 5.4.0-next-20191129-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> Workqueue: events pcpu_balance_workfn
> Call Trace:
>   __dump_stack lib/dump_stack.c:77 [inline]
>   dump_stack+0x197/0x210 lib/dump_stack.c:118
>   ___might_sleep.cold+0x1fb/0x23e kernel/sched/core.c:6800
>   __might_sleep+0x95/0x190 kernel/sched/core.c:6753
>   prepare_alloc_pages mm/page_alloc.c:4681 [inline]
>   __alloc_pages_nodemask+0x523/0x910 mm/page_alloc.c:4730
>   alloc_pages_current+0x107/0x210 mm/mempolicy.c:2211
>   alloc_pages include/linux/gfp.h:532 [inline]
>   __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
>   kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
>   kasan_populate_vmalloc_pte+0x2f/0x1c0 mm/kasan/common.c:753
>   apply_to_pte_range mm/memory.c:2041 [inline]
>   apply_to_pmd_range mm/memory.c:2068 [inline]
>   apply_to_pud_range mm/memory.c:2088 [inline]
>   apply_to_p4d_range mm/memory.c:2108 [inline]
>   apply_to_page_range+0x445/0x700 mm/memory.c:2133
>   kasan_populate_vmalloc+0x68/0x90 mm/kasan/common.c:791
>   pcpu_get_vm_areas+0x3c77/0x3f00 mm/vmalloc.c:3439
>   pcpu_create_chunk+0x24e/0x7f0 mm/percpu-vm.c:340
>   pcpu_balance_workfn+0xf1b/0x1310 mm/percpu.c:1934
>   process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
>   worker_thread+0x98/0xe40 kernel/workqueue.c:2410
>   kthread+0x361/0x430 kernel/kthread.c:255
>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>
>
> ---
> This bug is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this bug report. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/000000000000c280ba05988b6242%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ_E8tNtt5y4r_Sp%2BdWDjxundr4vor9DYxDr8FNj5U90A%40mail.gmail.com.
