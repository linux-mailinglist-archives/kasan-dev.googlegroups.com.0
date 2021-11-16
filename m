Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ4OZ2GAMGQEOAFL2QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 12EBD452F0C
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 11:26:49 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id bp17-20020a05620a459100b0045e893f2ed8sf1294332qkb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 02:26:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637058408; cv=pass;
        d=google.com; s=arc-20160816;
        b=ob58SnZzSz5XIJJVYeqDxF303iKZh1c5uArhhXk+fPXcCWMcWv45S18BPjmom0hVXC
         jcTR1z+yVVHpiDi/t9ZWN87Cekd0arLEZ3hyQ29qUNGgqCAXvb3dNKzLxLyusvAQX9d9
         ichmEVgoRXkMiwVboPm/JGVwZetV/rYJCAOPdhsV48NIwmHm1BFt/rfANiz3pGo15VwW
         d0p26e/Ef+Pv288V7TCRghr2gzI5fpi17CT/bvn33jGSTPNVI4itFY/OZFHo5wlWZTUL
         4wRTx8LuSEYVq3Oqh8AwOP+YjT3L6vy0l5ijQtWQ4diAoZDr7RmCVdJPtBQ8FEvJp3gR
         o4UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T0Bq2AFzvYxKDdkLjlJVbrlHRep7YR81g7X60Tt8VHg=;
        b=j8cwWaB7eM9GQnDtib9iGTImp0YzlkB5TP/kZjUOgtJvK+skCN+xQhbxA2AAQDjc2j
         KDmwro9VqXvMwqBVbvbqoM+zDAw3F7or/HMjLIHEoGqx9XP2STFeHdK9wpHL9rOVh8aI
         vJureyKPr7hrMGGpF0F0BbaWZ0je+NWIXNIZANxUg7QCCg4JySwXu0+kHy2y/5TcvVbq
         1zm6rzOwRN/ISXpOG551Us23k2CXDAkXLTdfXdY3dfTZ47wf1c32Z1zkpdd/m43NbJn7
         8sreQzaFznfdnqgdFTD1jxfzAqWStZEIa6acFxQKVJ9RXsO0MX8A0M2Z718IUjHmni/E
         mBAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KkKSymEq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T0Bq2AFzvYxKDdkLjlJVbrlHRep7YR81g7X60Tt8VHg=;
        b=A7vjsSUk/xg2NE8K7J3rLmcDiq0ArjPDi513XL0TGjnNWt2pt9OcM9ImkSGb0j+Y/k
         VDQgaLxIGQdMAed3qJHjfwIXHa3VLuAl3ETKmmMTJ19/z2vCh5zDvwUiJd6hRgLJFqEO
         QvjUequFVh9yd/3A3A/vmCv5IPeiqBBsd6AOV69WNtJmaXk8+KpG9f+wzfNOz5NBvv4B
         yc1hsgKVImSfIDByz7cbcVc9ySqxFT4qew7/BEmnKSw8XvSVcejGmJ+lgwsCfn0xF3gy
         S2QcNITMO7aCdi1llldowuBBxIz00XOhgbxV4MyOwsVPmpIfOvLaukvTAZwlaA7l7lWG
         Jtqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T0Bq2AFzvYxKDdkLjlJVbrlHRep7YR81g7X60Tt8VHg=;
        b=m2pIrzVxoOC3BolKP2RfB1j3fpbhftZgmFAJFy332boOwMnkC282KT7oSCD30kQK9x
         AQaohaEFrESgH1EKRfpQwivJtTQULnm9smKr/Zww8EwUZLAdGyvhvzgAyzUDcmWBcupY
         wFsxg+6dbX2PF1Jw1vp5xQ43EFdMX3tb4ILTlFWmjMy+XV+CRWFzMW7fMrQ9FKyB1BOz
         dvOmKtqgWEScPAvvQiDEE9iRkED0DiE7De0jboXlD+Vy6hRtrVa4Hcze21LbLVGuU7t9
         AsmSVboCbDMX+YPq9mhF3Q7CfF2lHaKnUqvpuF32Ec90OeEP1JFh2FjaBg9Ttrt7ycM4
         eijQ==
X-Gm-Message-State: AOAM533Ne9fNP9Chi3RWdV42UGdUr7a2+iLKY+AXbQnmAGSd5aDJuOaf
	bUXIWGeE2RGy6Idmw44kZbQ=
X-Google-Smtp-Source: ABdhPJwixVNFVw8Ou8FiD7OJKG+DEP7AExck+9K484d3reuDUJacOh5MWjai9DLDRl94i8OQrs4Y5w==
X-Received: by 2002:a05:620a:3193:: with SMTP id bi19mr5089750qkb.521.1637058407944;
        Tue, 16 Nov 2021 02:26:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1926:: with SMTP id bj38ls9196401qkb.7.gmail; Tue,
 16 Nov 2021 02:26:47 -0800 (PST)
X-Received: by 2002:a05:620a:148a:: with SMTP id w10mr5145803qkj.277.1637058407493;
        Tue, 16 Nov 2021 02:26:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637058407; cv=none;
        d=google.com; s=arc-20160816;
        b=Kmr8+GdELzS6zBmM/BMsswA3vV4UWTd6PAxnwCswEF5B86QkZb7/FwhldR2X3rLCf8
         2ezOUr7vARpFUnyw9KLVPx2mcWCFrlgtaqQ+cLPrWLREYWHMYZfAhAfM9Nwy9e+qYVf0
         nzJMEea61RgOhZPR4cGrrTSjGRcnacB682k8VULCf2DXjroFUeFWEr4c+bc6W9EjQyH9
         edLrvnH9Pm59JRBgRilZ9Rok+ak06Ccyvovxp9xmMduVZZC8dy/14HWgTbC2az3Upm/J
         jvYZmxPkF5oPrL+IpEPXcgenmpd8yjcL30w1wfqmiJVvMtqt1sd2WObp4TS5N2kHvMJs
         aBoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Dvv3p8AhGCNVaVD1e1tbe7DzFesl+DjfsxOQoQusrw=;
        b=FEgxQpYoe3k3IfUXdlsmcGPExXeOVIhbTtPJQ9h+YN53UcfBqtxKMI2rYy3TJtiMCm
         i2XB2ppTcPHJtPFaMq/oUD7fmAc8CBrNZ/n0V/FWj5B711zCIL5PY/yS4mhmHB2HaNrD
         VQwBIqjCwM06cGd9n5GGTsePySlZPoIfWLH4TOkJctvhHkhnGvfnk8EoI7eVO1nus/wU
         eBr26Adzj/5KdyAICFdL105vT69ag+fMYq9r1/bg2ood/GVIfQmf+ZzsxJG/ZRtHgIB5
         YoYhQTCi+B9W8guywLPJXcBBcW00YHiKsfTpSRLEDdqA0gNh8mSJ5ATEler/63OgEObg
         eEZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KkKSymEq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id i6si688380qko.3.2021.11.16.02.26.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 02:26:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id h16-20020a9d7990000000b0055c7ae44dd2so32647884otm.10
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 02:26:47 -0800 (PST)
X-Received: by 2002:a9d:662:: with SMTP id 89mr5027714otn.157.1637058407013;
 Tue, 16 Nov 2021 02:26:47 -0800 (PST)
MIME-Version: 1.0
References: <1637018582-10788-1-git-send-email-jun.miao@intel.com>
In-Reply-To: <1637018582-10788-1-git-send-email-jun.miao@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Nov 2021 11:26:35 +0100
Message-ID: <CANpmjNPqwOCwEP374wYaFg=-rLRWZ6fHit6zQxmH8sxuigVvew@mail.gmail.com>
Subject: Re: [V2][PATCH] rcu: avoid alloc_pages() when recording stack
To: Jun Miao <jun.miao@intel.com>
Cc: paulmck@kernel.org, urezki@gmail.com, josh@joshtriplett.org, 
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com, 
	joel@joelfernandes.org, qiang.zhang1211@gmail.com, rcu@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	jianwei.hu@windriver.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KkKSymEq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Tue, 16 Nov 2021 at 08:46, Jun Miao <jun.miao@intel.com> wrote:
> The default kasan_record_aux_stack() calls stack_depot_save() with GFP_NOWAIT,
> which in turn can then call alloc_pages(GFP_NOWAIT, ...).  In general, however,
> it is not even possible to use either GFP_ATOMIC nor GFP_NOWAIT in certain
> non-preemptive contexts/RT kernel including raw_spin_locks (see gfp.h and ab00db216c9c7).
> Fix it by instructing stackdepot to not expand stack storage via alloc_pages()
> in case it runs out by using kasan_record_aux_stack_noalloc().
>
> Jianwei Hu reported:
> BUG: sleeping function called from invalid context at kernel/locking/rtmutex.c:969
> in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 15319, name: python3
> INFO: lockdep is turned off.
> irq event stamp: 0
>   hardirqs last  enabled at (0): [<0000000000000000>] 0x0
>   hardirqs last disabled at (0): [<ffffffff856c8b13>] copy_process+0xaf3/0x2590
>   softirqs last  enabled at (0): [<ffffffff856c8b13>] copy_process+0xaf3/0x2590
>   softirqs last disabled at (0): [<0000000000000000>] 0x0
>   CPU: 6 PID: 15319 Comm: python3 Tainted: G        W  O 5.15-rc7-preempt-rt #1
>   Hardware name: Supermicro SYS-E300-9A-8C/A2SDi-8C-HLN4F, BIOS 1.1b 12/17/2018
>   Call Trace:
>     show_stack+0x52/0x58
>     dump_stack+0xa1/0xd6
>     ___might_sleep.cold+0x11c/0x12d
>     rt_spin_lock+0x3f/0xc0
>     rmqueue+0x100/0x1460
>     rmqueue+0x100/0x1460
>     mark_usage+0x1a0/0x1a0
>     ftrace_graph_ret_addr+0x2a/0xb0
>     rmqueue_pcplist.constprop.0+0x6a0/0x6a0
>      __kasan_check_read+0x11/0x20
>      __zone_watermark_ok+0x114/0x270
>      get_page_from_freelist+0x148/0x630
>      is_module_text_address+0x32/0xa0
>      __alloc_pages_nodemask+0x2f6/0x790
>      __alloc_pages_slowpath.constprop.0+0x12d0/0x12d0
>      create_prof_cpu_mask+0x30/0x30
>      alloc_pages_current+0xb1/0x150
>      stack_depot_save+0x39f/0x490
>      kasan_save_stack+0x42/0x50
>      kasan_save_stack+0x23/0x50
>      kasan_record_aux_stack+0xa9/0xc0
>      __call_rcu+0xff/0x9c0
>      call_rcu+0xe/0x10
>      put_object+0x53/0x70
>      __delete_object+0x7b/0x90
>      kmemleak_free+0x46/0x70
>      slab_free_freelist_hook+0xb4/0x160
>      kfree+0xe5/0x420
>      kfree_const+0x17/0x30
>      kobject_cleanup+0xaa/0x230
>      kobject_put+0x76/0x90
>      netdev_queue_update_kobjects+0x17d/0x1f0
>      ... ...
>      ksys_write+0xd9/0x180
>      __x64_sys_write+0x42/0x50
>      do_syscall_64+0x38/0x50
>      entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
> Links: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/include/linux/kasan.h?id=7cb3007ce2da27ec02a1a3211941e7fe6875b642
> Fixes: 84109ab58590 ("rcu: Record kvfree_call_rcu() call stack for KASAN")
> Fixes: 26e760c9a7c8 ("rcu: kasan: record and print call_rcu() call stack")
> Reported-by: Jianwei Hu <jianwei.hu@windriver.com>
> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Signed-off-by: Jun Miao <jun.miao@intel.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  kernel/rcu/tree.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index ef8d36f580fc..906b6887622d 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -2982,7 +2982,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>         head->func = func;
>         head->next = NULL;
>         local_irq_save(flags);
> -       kasan_record_aux_stack(head);
> +       kasan_record_aux_stack_noalloc(head);
>         rdp = this_cpu_ptr(&rcu_data);
>
>         /* Add the callback to our list. */
> @@ -3547,7 +3547,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
>                 return;
>         }
>
> -       kasan_record_aux_stack(ptr);
> +       kasan_record_aux_stack_noalloc(ptr);
>         success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
>         if (!success) {
>                 run_page_cache_worker(krcp);
> --
> 2.32.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPqwOCwEP374wYaFg%3D-rLRWZ6fHit6zQxmH8sxuigVvew%40mail.gmail.com.
