Return-Path: <kasan-dev+bncBC73HQ6VSAGBB5OZZ6GAMGQESXAFRUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F2AC4538A7
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 18:40:06 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id c19-20020ac81e93000000b002a71180fd3dsf16292376qtm.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 09:40:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637084405; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vw4ShZ1IqjUxoB8tvxYMDP5HqWpletJxthZ6zMSPmRdTBtAEqR7Ka2NqEH2npULReN
         L4rVoBl5IcN3TFEmiTpgA5OVS72zfACQz1qFFrAz4FeIus/NUBDIIV1+iJg8Ls4U7szD
         LU7/+10tm7n8g8lrcemtYfxt9u6dz9IK1R/M5xWPiiYWWndNb/V/k4YBxB/dv8vNu0sE
         cX9hii2RGVovzyjfkLj6/mKFmCWfI/vwZDlr59IUuNPiDC6LbhpCQguTfRqPe28QfEwG
         3SHcY4A9DrPCm6lPbWOZgdAmsBtiVqzj2CMpxdGYzDSm/G0fohK6JPg8VGYk0FmeSjcE
         PEHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=d1tmkK4CJMtZTNpq9YSljNv3aJiLrWQP4MvT1OVY7+0=;
        b=uvRx4dmob4f80TwXaWXF6owe+BDefLr2BPP38dAClVbuPpzu0c3AnaUSQ/wU+SyYoe
         leJstBLglSKNifjaNCsKMkg7GErTIxOPyb0jIszIlZBrOqLqeXgi8Md60YwQkBX40VVL
         9VqW1YpMuf1Wo0U5m2I/WNgqtf1AIh6T/FkZYJCG+/Gjif1oxpiw/jJTiRxN8D9K9uYx
         CLWbZNTzUK7kpb/9GKq/GWLLk1UMKiN5hqQ4ker/2aKv9AX4+2mcJGCxWc4p9Ba3zirg
         JMjMni1zgSAP3//iOP9tkKvyl/A/77IVj34E9i2Q5lj2mYxY/PMWN/WQF77slhyoKEtG
         LgcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A2UDpMBo;
       spf=pass (google.com: domain of juri.lelli@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=juri.lelli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d1tmkK4CJMtZTNpq9YSljNv3aJiLrWQP4MvT1OVY7+0=;
        b=dBY4Sj4joz1U6hA0LXCxTp9WGUsET5KVe3oDHEkCn6fq2A/SewdUVKHXghifXNGWZu
         bmKX87dblLbFtfBQzBR1UnWj+qdyaoO0qi3p0nBlpD7v1Q89JgzV/MeQtKRUIpHYpMXk
         al1yogX7rLNf/MahOHrx0/o0UGSiE8IVNtQ1pZz/eUIlXBc2eP5gWDFLJ8X5SsJbIzwf
         3twItusqAsyUogunnMbQwLan46WoDibu1+U95xO1xwsqybQRMUxJ9ekeeDAEKPC6k8Ep
         W8KqZybHJyMLqiY02wiyXVS7U04PEa2xCx4UiaGks/6oincS8Comxi6TXl8NQHn5gj3g
         dx9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d1tmkK4CJMtZTNpq9YSljNv3aJiLrWQP4MvT1OVY7+0=;
        b=IAuDJTv75j21Qa6jsyt+Gy7ZAgFcLBbi+K4aFyh7+TFt3dqWX0IhqKTTo28aVtVih8
         W8XbqadfvZe5KSnOorc97Mwd7hBi+IwkwOEqKOb1SZLUZfBGccXbZSxFMu1cOQGP0Eb/
         Tvr3Oz+ZnJnsi4YjuSROs+8u2A0LBHOQwirwqqIREoY79TUDGG1pxZ7/mfRpfb5ME4hX
         Z7mLErgYE2zCgQNtyl0ccIbvlBuPKHTXHooA4e/yPvaLn5HdwL7GMNw2s4XPT7E8z2to
         Qa4NNf7d5LaGmem9v/U5twGeP2i/XWds1vLfQf0TSjAsKzIfkYrWcQqqi+9CneQgYRqD
         aWUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oOkYTgL2YZcqNR4KzgqA6brDiWIy74m90pwvZHV4y/HHsRvYw
	Jhi8wBFragNSK7HfdtmkLU8=
X-Google-Smtp-Source: ABdhPJz9lo3yO0VKlXP9/koHT7DXp67gTM/naK/HQU1ii8P1WtffdEab9jB1jNwOPh40a4V+W/oVkA==
X-Received: by 2002:a05:6214:cac:: with SMTP id s12mr47709345qvs.60.1637084405434;
        Tue, 16 Nov 2021 09:40:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:180f:: with SMTP id t15ls6878291qtc.2.gmail; Tue,
 16 Nov 2021 09:40:05 -0800 (PST)
X-Received: by 2002:a05:622a:307:: with SMTP id q7mr9694989qtw.330.1637084404983;
        Tue, 16 Nov 2021 09:40:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637084404; cv=none;
        d=google.com; s=arc-20160816;
        b=kjjD9bAlNXJ1V5T6o/93pqp7GH/NNhqhgMa+7Vcxio74+jjZ/RQDOIbwevMB3Uo8I3
         EzJRvplnQVpJRX8CSs99rxEzyJjlx+xsRpzHQnk/+GxyNND0FlsbQSRi3sjwRlTi5NOK
         hjyEr089WKP8MQyZM+p6msqm3w6r+pgwUh7bEjWCMIC8U8yJedxtUEZD5hpXOjr8TvGq
         QYSzYhHAzuM/1L90XGls/VQewf0yPy1ZxCrdwQJwFPDHBu5iyj5qv+03hkdba38ZQNMx
         i6EoJ0knaVi/cwzA1fz1VKMmbKw0DydHo7WfwFGlJtZ8TJMiHkOq0Z1YU1pU16SHimUq
         AXJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Nr+r2xGROsXNBH9KeOUTHUo6tYTD1I9AjqYWE2OJRlU=;
        b=VQTs2oJhF6LSxNR+bTMqi8mk0LEE22pM1MUY1F/oST3DEuCDfby76HqtjuVJgGnmbS
         6YsUIDubavylg77shGH6pomrAq6ft45gdlQVap8NIWW6+N/y0XlGwjYmq5PFTdbNeH9r
         Mc7YdXqMtN8rMHu3iZTf62u/qdlOgobnkfKKZIjj6znTdXUOIX8gjSKjZ2J4gDmWegcO
         JuotYSaSblSyV+cwsiS0SaIsKR3iCDOQ5CuyhaJr97LowG7VUKZIE5hjji64k+cgJtyg
         fwJoYdNDubne7W2tYKbQ25XetigC5Aaz+IRLViLuqgmmZrYSbOK2VBibQxE72L2G3rh5
         NY6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A2UDpMBo;
       spf=pass (google.com: domain of juri.lelli@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=juri.lelli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id b8si419677qtg.5.2021.11.16.09.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 09:40:04 -0800 (PST)
Received-SPF: pass (google.com: domain of juri.lelli@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-446-2qU_h7H1O6GpExMRLNaAuQ-1; Tue, 16 Nov 2021 12:40:03 -0500
X-MC-Unique: 2qU_h7H1O6GpExMRLNaAuQ-1
Received: by mail-wr1-f70.google.com with SMTP id d3-20020adfa343000000b0018ed6dd4629so4660992wrb.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 09:40:02 -0800 (PST)
X-Received: by 2002:a05:600c:4f10:: with SMTP id l16mr9855678wmq.47.1637084401705;
        Tue, 16 Nov 2021 09:40:01 -0800 (PST)
X-Received: by 2002:a05:600c:4f10:: with SMTP id l16mr9855643wmq.47.1637084401466;
        Tue, 16 Nov 2021 09:40:01 -0800 (PST)
Received: from localhost.localdomain ([2a00:23c6:4a17:4f01:3a16:ae0:112c:ba92])
        by smtp.gmail.com with ESMTPSA id n1sm3718108wmq.6.2021.11.16.09.40.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 09:40:01 -0800 (PST)
Date: Tue, 16 Nov 2021 17:39:59 +0000
From: Juri Lelli <juri.lelli@redhat.com>
To: Jun Miao <jun.miao@intel.com>
Cc: paulmck@kernel.org, urezki@gmail.com, elver@google.com,
	josh@joshtriplett.org, rostedt@goodmis.org,
	mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com,
	joel@joelfernandes.org, qiang.zhang1211@gmail.com,
	rcu@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, jianwei.hu@windriver.com
Subject: Re: [V2][PATCH] rcu: avoid alloc_pages() when recording stack
Message-ID: <20211116173959.osdzlvv7niyxthd6@localhost.localdomain>
References: <1637018582-10788-1-git-send-email-jun.miao@intel.com>
MIME-Version: 1.0
In-Reply-To: <1637018582-10788-1-git-send-email-jun.miao@intel.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: juri.lelli@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=A2UDpMBo;
       spf=pass (google.com: domain of juri.lelli@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=juri.lelli@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Hi,

On 16/11/21 07:23, Jun Miao wrote:
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
> ---

I gave this a quick try on RT. No splats. Nice!

Tested-by: Juri Lelli <juri.lelli@redhat.com>

Best,
Juri

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116173959.osdzlvv7niyxthd6%40localhost.localdomain.
