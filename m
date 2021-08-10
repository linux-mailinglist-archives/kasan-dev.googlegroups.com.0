Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLEUZGEAMGQEPWVDL5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id C5DF33E5740
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 11:43:09 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id na18-20020a17090b4c12b0290178153d1c65sf1920123pjb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 02:43:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628588588; cv=pass;
        d=google.com; s=arc-20160816;
        b=RR7MeokKYTArKiRtmYP+Rw1QIlHwflGi1eiByjjOdPmRsPN+BGcA1n1pohm+r+muOj
         1d9YdlYmAnLBnC59Awm0R5yy/KIkuIcBwC6hRJ6iUdUMXrNsuKzNcwlmK8AEWzjC2gd3
         I/h9glG5Y3vjpZHdsYIYvBhxXbCJBP6CXFXSXdIjEeXs/ufgGbaAwhMvfsBCQ6OWUANo
         LOMRZdV0qWAEFVIs765dsRIoGsVi4MWBvrPG4Mt4AuG1DxLxAyc9ywE4rKFwrZVSL+rz
         8BYp9W6Gl60uzw+UvJzFqItMSLWd63DVbDKAWPcnpe9eFIshZS+SZo/SbQY3+NXKIzBn
         7DQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g3yAnmFxNcGGDwH7IoNlmkM1aJPHmeyHA333wF3kT/4=;
        b=Wu+5HL2u/xQ9MtqoRRBDhmnLgiZJprkQFPVA9ju3/EPoHWu52wLHnTsWElRnnpuX/E
         vk+sj5DN7T4KVt8RmcKIg0xsQiFf815K2la9c3XZbifpsuV7lYsAjcXB5P4cSdZATFcQ
         j83BySO7eXAm6FA6etckBc+Nn2Gv+znf4jWx/ChiXz/XbvSkfpGErz/j78nqoUokEwuH
         Z/3dEf5bo+t9ITP5s5mKiShXddj2p0JodngyvLZu9m4nq75wcnIlPsoxCaynhHdMyVvO
         2d3C+T+xKk8vvJeG/K+mLIdnJ6MvZ6K3aAHOijOvyoK/aEGWq2O4c8bJCMP/AZHqYLVZ
         +pAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DIn7CsWu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g3yAnmFxNcGGDwH7IoNlmkM1aJPHmeyHA333wF3kT/4=;
        b=ZepuNUi3VqDA2PwA+pddbuXeWMcXyW1pdHn5UfUUD8NatMgr0y0/z9uVu+eK8K3HuW
         F68Xv3hhjvOf8ycG3vXWeJ/Ebqi/CA/+YVF7TLMy8+5hNVjUufz/+Y7oSM5AgbhLG2De
         5tEkCJpQJisyHNA8nnFEmMMwnoZteVHky6RGKL4qXu1kR24E+Uvhuz1zVkFtJz0US+Qy
         40DUcXshcrICsase21LQAhAIYk5nEjUfskSwdCts3fpbE3uneoa6AsN4NgLfqven3qSo
         +BvsG5tby4haYUGKrDoaeybyEt9oxxq6iwSAw/D5+gJ+KcQOsFSa97tpBYhcMLHEdXVL
         g16w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g3yAnmFxNcGGDwH7IoNlmkM1aJPHmeyHA333wF3kT/4=;
        b=iiw/P2xTMAT81YOD4VncHxKZ8g6tXSSbfyIa8wQoHyaG1Si9y5qTKXXi5JEi40fIEH
         iDCaK4O4rtcY6T3Z2NYOtezrUVF81Epe4QhgjF57SAHplim81KYt81+27DBVCNjuo9zn
         m0o28LcPe9uUxZk19Yb6AhXWlLG7h+r9wI7pHwcFv3d4W7/f8wkkMnNL0JH7V02PibMV
         LSbJm6TX4Tlq2lwaGyMydY9nJ0yzLOlq51CcIN0Iyalb5CAi/WqIqXMB+spjBo1P7v+B
         g+YIAbUFUrcD3OLrUx3u0huvSy7tp6o6egcxV3QIOySGt9d4R03B6N/JtXDqzKDCvxX3
         o1HA==
X-Gm-Message-State: AOAM532QisQUdYorZF2orpkSWESjBabjABROfA1Hr87LHy2MOUHOdvqa
	09FRXbb313j80ZKLbJ9BP1E=
X-Google-Smtp-Source: ABdhPJw1JOzU21bZYRHzWxA9VhFrnybkxr5KVNzN39DfvsGq5C/3hEoEbpqiRvg6ISRPJ59MeQyrug==
X-Received: by 2002:a62:878c:0:b029:3c5:f729:ef00 with SMTP id i134-20020a62878c0000b02903c5f729ef00mr22599266pfe.43.1628588588499;
        Tue, 10 Aug 2021 02:43:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e40e:: with SMTP id r14ls7075352pfh.4.gmail; Tue, 10 Aug
 2021 02:43:07 -0700 (PDT)
X-Received: by 2002:a65:6787:: with SMTP id e7mr551680pgr.345.1628588587802;
        Tue, 10 Aug 2021 02:43:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628588587; cv=none;
        d=google.com; s=arc-20160816;
        b=WqQCsMiCmzZpmNBH7GulQ9d9mWxVCSFOnVu2x73FKL4DqsfS9yFFarsJuDd2wSy0fs
         fc0NGdyNBAdZ2UD5x79m9x6HNxBWHWhBNriJj1ckUY01BevfDDX8Yx7EYotesDB6xT7S
         T/gFTLEPZ/KVl01vNDlHXHUt7IZxRsd2vL5/jBTAFvgaC2eEp/mZ6OrRWXz2jpkkP0vB
         IkFcEl9sJ5CFmxahOW75jvei6o9AF+DMzp5gTDRpC1FiV6HLRUb46WmU5QugST9A/6hd
         64lgl5Dw18AYeUalx2Acoakns3kuJ/mPkiu56TnWn1WBt2TGnyzSIxwVsALkM9t0W1v/
         IEAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0V41XQkQgxcQV9SfL614DR4FGIaNIfXk5Ilo3cf9nAI=;
        b=XKuvuK6aqpMEMgBljFSs1Md+CXfrmF4YIsVObhNMh07bx5Y3panwmF2V31K+HPA3LY
         ilF4Qa/RRt1SKtN47wwNeHZP7YEouaUcDGxez4M00fP3NgTwnLVieFsUaRB7j5dhWRzM
         QJYVTUcgxVD9teHUeo7KBHAoYLpXYX53fiWnD5XfjEwCPkUe4b5YsMPll4nDGL982yLh
         2+nta7Uqi1l4kzR3TbFKC+Y73LqWQAl1dK1bPidV3NdyXkEULPPW6mF6wEFiCX09L8qm
         9XR9qLCfTAj44WVSvBQ/eE6iJrc0+0OxIYp13x9//OY4RZq1CaZwTilz3ISEWe1qtvnA
         pIdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DIn7CsWu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc30.google.com (mail-oo1-xc30.google.com. [2607:f8b0:4864:20::c30])
        by gmr-mx.google.com with ESMTPS id t17si538964pfg.3.2021.08.10.02.43.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Aug 2021 02:43:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as permitted sender) client-ip=2607:f8b0:4864:20::c30;
Received: by mail-oo1-xc30.google.com with SMTP id y14-20020a4acb8e0000b029028595df5518so4568075ooq.6
        for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 02:43:07 -0700 (PDT)
X-Received: by 2002:a4a:3c57:: with SMTP id p23mr12505664oof.14.1628588587071;
 Tue, 10 Aug 2021 02:43:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210809155909.333073de@theseus.lan>
In-Reply-To: <20210809155909.333073de@theseus.lan>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Aug 2021 11:42:54 +0200
Message-ID: <CANpmjNOg_1uc5w4s+UjZkhYM9m43qwhtqcXaTt9yJRLgOoAFFw@mail.gmail.com>
Subject: Re: [PATCH PREEMPT_RT] kcov: fix locking splat from kcov_remote_start()
To: Clark Williams <williams@redhat.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DIn7CsWu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as
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

On Mon, 9 Aug 2021 at 22:59, Clark Williams <williams@redhat.com> wrote:
> Saw the following splat on 5.14-rc4-rt5 with:
>
> CONFIG_KCOV=y
> CONFIG_KCOV_INSTRUMENT_ALL=y
> CONFIG_KCOV_IRQ_AREA_SIZE=0x40000
> CONFIG_RUNTIME_TESTING_MENU=y
>
> kernel: ehci-pci 0000:00:1d.0: USB 2.0 started, EHCI 1.00
> kernel: BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:35
> kernel: in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 34, name: ksoftirqd/3
> kernel: 4 locks held by ksoftirqd/3/34:
> kernel:  #0: ffff944376d989f8 ((softirq_ctrl.lock).lock){+.+.}-{2:2}, at: __local_bh_disable_ip+0xe0/0x190
> kernel:  #1: ffffffffbbfb61e0 (rcu_read_lock){....}-{1:2}, at: rt_spin_lock+0x5/0xd0
> kernel:  #2: ffffffffbbfb61e0 (rcu_read_lock){....}-{1:2}, at: __local_bh_disable_ip+0xbd/0x190
> kernel:  #3: ffffffffbc086518 (kcov_remote_lock){....}-{2:2}, at: kcov_remote_start+0x119/0x4a0
> kernel: irq event stamp: 4653
> kernel: hardirqs last  enabled at (4652): [<ffffffffbafb85ce>] _raw_spin_unlock_irqrestore+0x6e/0x80
> kernel: hardirqs last disabled at (4653): [<ffffffffba2517c8>] kcov_remote_start+0x298/0x4a0
> kernel: softirqs last  enabled at (4638): [<ffffffffba110a5b>] run_ksoftirqd+0x9b/0x100
> kernel: softirqs last disabled at (4644): [<ffffffffba149f12>] smpboot_thread_fn+0x2b2/0x410
> kernel: CPU: 3 PID: 34 Comm: ksoftirqd/3 Not tainted 5.14.0-rc4-rt5+ #3
> kernel: Hardware name:  /NUC5i7RYB, BIOS RYBDWi35.86A.0359.2016.0906.1028 09/06/2016
> kernel: Call Trace:
> kernel:  dump_stack_lvl+0x7a/0x9b
> kernel:  ___might_sleep.cold+0xf3/0x107
> kernel:  rt_spin_lock+0x3a/0xd0
> kernel:  ? kcov_remote_start+0x119/0x4a0
> kernel:  kcov_remote_start+0x119/0x4a0
> kernel:  ? led_trigger_blink_oneshot+0x83/0xa0
> kernel:  __usb_hcd_giveback_urb+0x161/0x1e0
> kernel:  usb_giveback_urb_bh+0xb6/0x110
> kernel:  tasklet_action_common.constprop.0+0xe8/0x110
> kernel:  __do_softirq+0xe2/0x525
> kernel:  ? smpboot_thread_fn+0x31/0x410
> kernel:  run_ksoftirqd+0x8c/0x100
> kernel:  smpboot_thread_fn+0x2b2/0x410
> kernel:  ? smpboot_register_percpu_thread+0x130/0x130
> kernel:  kthread+0x1de/0x210
> kernel:  ? set_kthread_struct+0x60/0x60
> kernel:  ret_from_fork+0x22/0x30
> kernel: usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.14
>
>
> Change kcov_remote_lock from regular spinlock_t to raw_spinlock_t so that
> we don't get "sleeping function called from invalid context" on PREEMPT_RT kernel.
>
> Signed-off-by: Clark Williams <williams@redhat.com>

Reviewed-by: Marco Elver <elver@google.com>

Indeed, most other debugging tools are using raw_spinlock or
arch_spinlock, I guess KCOV was still lagging behind. Should this go
into mainline?

> ---
>  kernel/kcov.c | 28 ++++++++++++++--------------
>  1 file changed, 14 insertions(+), 14 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 80bfe71bbe13..60f903f8a46c 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -82,7 +82,7 @@ struct kcov_remote {
>         struct hlist_node       hnode;
>  };
>
> -static DEFINE_SPINLOCK(kcov_remote_lock);
> +static DEFINE_RAW_SPINLOCK(kcov_remote_lock);
>  static DEFINE_HASHTABLE(kcov_remote_map, 4);
>  static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>
> @@ -375,7 +375,7 @@ static void kcov_remote_reset(struct kcov *kcov)
>         struct hlist_node *tmp;
>         unsigned long flags;
>
> -       spin_lock_irqsave(&kcov_remote_lock, flags);
> +       raw_spin_lock_irqsave(&kcov_remote_lock, flags);
>         hash_for_each_safe(kcov_remote_map, bkt, tmp, remote, hnode) {
>                 if (remote->kcov != kcov)
>                         continue;
> @@ -384,7 +384,7 @@ static void kcov_remote_reset(struct kcov *kcov)
>         }
>         /* Do reset before unlock to prevent races with kcov_remote_start(). */
>         kcov_reset(kcov);
> -       spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +       raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
>  }
>
>  static void kcov_disable(struct task_struct *t, struct kcov *kcov)
> @@ -638,18 +638,18 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 kcov->t = t;
>                 kcov->remote = true;
>                 kcov->remote_size = remote_arg->area_size;
> -               spin_lock_irqsave(&kcov_remote_lock, flags);
> +               raw_spin_lock_irqsave(&kcov_remote_lock, flags);
>                 for (i = 0; i < remote_arg->num_handles; i++) {
>                         if (!kcov_check_handle(remote_arg->handles[i],
>                                                 false, true, false)) {
> -                               spin_unlock_irqrestore(&kcov_remote_lock,
> +                               raw_spin_unlock_irqrestore(&kcov_remote_lock,
>                                                         flags);
>                                 kcov_disable(t, kcov);
>                                 return -EINVAL;
>                         }
>                         remote = kcov_remote_add(kcov, remote_arg->handles[i]);
>                         if (IS_ERR(remote)) {
> -                               spin_unlock_irqrestore(&kcov_remote_lock,
> +                               raw_spin_unlock_irqrestore(&kcov_remote_lock,
>                                                         flags);
>                                 kcov_disable(t, kcov);
>                                 return PTR_ERR(remote);
> @@ -658,7 +658,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 if (remote_arg->common_handle) {
>                         if (!kcov_check_handle(remote_arg->common_handle,
>                                                 true, false, false)) {
> -                               spin_unlock_irqrestore(&kcov_remote_lock,
> +                               raw_spin_unlock_irqrestore(&kcov_remote_lock,
>                                                         flags);
>                                 kcov_disable(t, kcov);
>                                 return -EINVAL;
> @@ -666,14 +666,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                         remote = kcov_remote_add(kcov,
>                                         remote_arg->common_handle);
>                         if (IS_ERR(remote)) {
> -                               spin_unlock_irqrestore(&kcov_remote_lock,
> +                               raw_spin_unlock_irqrestore(&kcov_remote_lock,
>                                                         flags);
>                                 kcov_disable(t, kcov);
>                                 return PTR_ERR(remote);
>                         }
>                         t->kcov_handle = remote_arg->common_handle;
>                 }
> -               spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +               raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
>                 return 0;
> @@ -845,10 +845,10 @@ void kcov_remote_start(u64 handle)
>                 return;
>         }
>
> -       spin_lock(&kcov_remote_lock);
> +       raw_spin_lock(&kcov_remote_lock);
>         remote = kcov_remote_find(handle);
>         if (!remote) {
> -               spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +               raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
>                 return;
>         }
>         kcov_debug("handle = %llx, context: %s\n", handle,
> @@ -869,7 +869,7 @@ void kcov_remote_start(u64 handle)
>                 size = CONFIG_KCOV_IRQ_AREA_SIZE;
>                 area = this_cpu_ptr(&kcov_percpu_data)->irq_area;
>         }
> -       spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +       raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
>
>         /* Can only happen when in_task(). */
>         if (!area) {
> @@ -1008,9 +1008,9 @@ void kcov_remote_stop(void)
>         spin_unlock(&kcov->lock);
>
>         if (in_task()) {
> -               spin_lock(&kcov_remote_lock);
> +               raw_spin_lock(&kcov_remote_lock);
>                 kcov_remote_area_put(area, size);
> -               spin_unlock(&kcov_remote_lock);
> +               raw_spin_unlock(&kcov_remote_lock);
>         }
>
>         local_irq_restore(flags);
> --
> 2.31.1
>
>
>
> --
> The United States Coast Guard
> Ruining Natural Selection since 1790
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809155909.333073de%40theseus.lan.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOg_1uc5w4s%2BUjZkhYM9m43qwhtqcXaTt9yJRLgOoAFFw%40mail.gmail.com.
