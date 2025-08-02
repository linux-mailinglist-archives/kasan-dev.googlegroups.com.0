Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBYMGXLCAMGQE4QG3RMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E328BB1901A
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 23:30:11 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-24011c9da24sf26737185ad.1
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 14:30:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754170210; cv=pass;
        d=google.com; s=arc-20240605;
        b=DxEGcwUwHRpUpQe9rtua7cejMBWN8e4HVpd3RcDLZdM3tRSRUDa588V5NyaFHzK0AM
         DGJcunb9wK7H7GbnJOlABV4f7FV+s00K4GlIYniOlExYeCUzeKdwEgd6YNVB8EkmFXtW
         qrBEqfQ41vtPUUHYqis2PvOitioOZPtn1EqmgaUjnkgf0894kZ20HSAYSWp5kzG7cTua
         LgKbrDWZk74QUEwIsGPAboA8Cs+txVV7xLJEaYrEs4fvyShMmrw1tGDzW00p9UTxj+56
         5lUVFSwy35EjGHz7fV9+7CnKOEoyY/IifuSJakgxHeNltxYE6CModlU01idbM0FzJPzl
         8TzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bI5yjmi29c7Cwci+VgrG+hYEJfm6ay78oi2zUOXZm9k=;
        fh=W8H4MQe5EGjqmIq86Roc28lwSXWRNVHWXSMYPl890d0=;
        b=gYGVHM9uwis7Uh+bh+PrWc4xB/i5wMkPZcMkr8RqMD4Odx/t5rDylABJPZZV2VwTZu
         eBjMXEtBG6ixV4FOcIXaxI2ysOsRrcyPjg0k5bEFo6zVA9NAXRDScYyaRAXxywC8Ur1r
         N4Y5qB2TDOZaRWtJnEFosB3T7FPt0OKFOOyEX3Je1StlGXubxf5qwuhQ/slTPfSSEpqy
         VkKuJ3vRoojdvbIoA2AEOlzPJlaxlez/fq8dsgEU0cOgJCJMngtn9X0ruGif7y8uPSZ5
         N9XU3jSx6i5m+r8BEKXCeNUfw+Elr8wm9JCBx2J9wKSaGDqvMMI8xWEfDQLb3QXIT8lc
         06Ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="j7yjvp/T";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754170210; x=1754775010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bI5yjmi29c7Cwci+VgrG+hYEJfm6ay78oi2zUOXZm9k=;
        b=OMfpHqif2+a+93d57o6G/HXenRE6I61nT+bcjomuF8VQ5wt5/G3Gm0gerJ1jmk7tjt
         hnp4koerCI/1LT+LpB30uckKPelpDOgDML6f3l0aLlMNeOh8JEbfG/qjZLpNy59NLg6e
         vzpz4smGClGhURTVkkv1VD7wU0fq+d7LjiKcpz5NIqhatWnLZcwZraaQakFvBu0JBtF5
         qAyORhiX+UVQNnno2jh/1PaVNp4O7Q2V9AC0tZkwK1hlgHL4LcdgsAx9vG0bnF/t36VU
         aDVpc4zyOW7/oob5Pussr5TaNuIpqUVm1ba0Vpa5QHhSLSk0WSXWxXISLlVhNOalM+su
         F6Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754170210; x=1754775010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bI5yjmi29c7Cwci+VgrG+hYEJfm6ay78oi2zUOXZm9k=;
        b=MpwHkTUIPiny4+e7ewpRflm9Eqi/8YTHsP/ZF0ZfwilJs1SOhYZW0tnYqEavAknAqA
         z3+9T5+ZYvkMxC7gGzeU/KZgPaV1upX55WF0HlMx0cohwbtEbEWsuwhOpgT0BllNSDPk
         xRKkSYdaXv0122m6fuuUBQpY8UMLKINeOCyi2PhT/zZLBfJA/QaH5VKVVlBJyi57+sis
         T36G+9+Gd1tih0tpnYZdcaYDM8eI8Um06CFHJ6Ght2OqW+UG+8Y6IlDtDaQV2QpJBnQJ
         GXToQ+q5cgjBfKMBpliuGFHzVq0N7z0x1Nu3r3bpzPl2XkOGWPc+4wI0gV4XyCqzSqj2
         +e7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVV5fUqYXnZYxEbaPjDcCmeNRwgOa+s4EeHBbPSuDtbQaEL61GQ3UprFevARYCEoAoDzLIy5w==@lfdr.de
X-Gm-Message-State: AOJu0YyFoC5CGi/ar79WVIZllXJn+3tS71s/DOEe7sMhpMRyKfycz+Ob
	uPMYLAJ3qN3yVjFMoewB5k8hGtKNt125AhHSgMJyBDI7hO7x2TFO2hAW
X-Google-Smtp-Source: AGHT+IF6zOsvGUyhAEb5nduI/Uaq3fSiYd6pxPe1Xh20u27+7/D596vXhyreaC9WuD0/6ciJK6174A==
X-Received: by 2002:a17:902:e889:b0:234:325:500b with SMTP id d9443c01a7336-24246bedf75mr70369175ad.22.1754170209865;
        Sat, 02 Aug 2025 14:30:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdyTISmmJ/X11CWT4Lgu3Gc07nbXAVpQF4th8r86X18dQ==
Received: by 2002:a17:903:1ac3:b0:23f:8c3c:e26e with SMTP id
 d9443c01a7336-241d1f0cfacls16309375ad.0.-pod-prod-00-us; Sat, 02 Aug 2025
 14:30:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULezmG+lYFtw7lH5+2isxfEFnwKhEQ5tExaQM/F8kREdf4WtD7ZadINchbIQuWyoZWISPZB/+LzQE=@googlegroups.com
X-Received: by 2002:a17:902:c406:b0:240:1ed3:fc28 with SMTP id d9443c01a7336-2424699a755mr68388255ad.12.1754170208386;
        Sat, 02 Aug 2025 14:30:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754170208; cv=none;
        d=google.com; s=arc-20240605;
        b=K6EJAQJmPtZvuGFK8Veikrl+/5BRID1Yr937ciLtWjmZqp73No/FlSdDRoV9Jybbr0
         PezJN2d1Mwr1r9FqGHLNF3yigsgN04sl9mCgsYtF+S+QRXxrxEoDBMiGrhitso/d5LCh
         6Bu++e8jPXALQUTkE6Imknyj2cLURYevguxyfNEUvoLAkTHRm/lqkDhDNpMC5TLl7VXi
         TikjPeYADoMwuiI+XWfQzC/LYvYXJ/VME9ycfcI0F4Prp4heFERvj0QvyVlcVsecxtRE
         hreIsaKHOf34kq7SQhUDROEmyJnHX8+kSH4OxXNJhNjQiH51RJXrXRHLORRrpazSJXu6
         Bn8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8ZHe6+rreB9Szsc6ioIZd0/ZPCNc3ZJxfaeFf6vGBKE=;
        fh=G+oqlCXTz7T7JTbY2RSs3jKYo30EskjOoE2wJNNupM4=;
        b=XeI69N0wDdB9eht1JjBqDn+aCe7B817IaWV/GCdMuLRurywwAaN7zZInaeCTg7GTEK
         3s49NegLlKiyZN3VwAaPoZrPtDoxhWczXel9NIDjXOfYudEVCbAfz0nchJyKkytAMnSJ
         yCE2iOHGnzJA/KlKdJcm20tNKQG3y21yrDEhpIWHtUQkP+NWTVkU4b6jTpk8gQ0Af/Ef
         8Obn4Kf1vrk9o6OJNAi0aM7KLV7FtxWVDbApXoZlAt8iIJcFQX/dGD/rokNvd1IgY0s9
         aGAgwX00Gv7l1UgDoftP4pi4ycRI3t08Hbl06aN0SZLaSPg4NCcKS8e1dGi0dPXblEYC
         yzRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="j7yjvp/T";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si3117835ad.5.2025.08.02.14.30.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 02 Aug 2025 14:30:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id F272141696;
	Sat,  2 Aug 2025 21:30:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3659EC4CEEF;
	Sat,  2 Aug 2025 21:30:07 +0000 (UTC)
Date: Sat, 2 Aug 2025 22:30:03 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	"ppbuk5246 @ gmail . com" <ppbuk5246@gmail.com>,
	linux-kernel@vger.kernel.org,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alan Stern <stern@rowland.harvard.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	stable@vger.kernel.org, kasan-dev@googlegroups.com,
	syzkaller@googlegroups.com, linux-usb@vger.kernel.org,
	linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH v2] kcov, usb: Fix invalid context sleep in softirq path
 on PREEMPT_RT
Message-ID: <2025080251-villain-subsoil-e28d@gregkh>
References: <20250802142647.139186-3-ysk@kzalloc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250802142647.139186-3-ysk@kzalloc.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b="j7yjvp/T";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Sat, Aug 02, 2025 at 02:26:49PM +0000, Yunseong Kim wrote:
> The KCOV subsystem currently utilizes standard spinlock_t and local_lock_t
> for synchronization. In PREEMPT_RT configurations, these locks can be
> implemented via rtmutexes and may therefore sleep. This behavior is
> problematic as kcov locks are sometimes used in atomic contexts or protect
> data accessed during critical instrumentation paths where sleeping is not
> permissible.
> 
> Address these issues to make kcov PREEMPT_RT friendly:
> 
> 1. Convert kcov->lock and kcov_remote_lock from spinlock_t to
>    raw_spinlock_t. This ensures they remain true, non-sleeping
>    spinlocks even on PREEMPT_RT kernels.
> 
> 2. Refactor the KCOV_REMOTE_ENABLE path to move memory allocations
>    out of the critical section. All necessary struct kcov_remote
>    structures are now pre-allocated individually in kcov_ioctl()
>    using GFP_KERNEL (allowing sleep) before acquiring the raw
>    spinlocks.
> 
> 3. Modify the ioctl handling logic to utilize these pre-allocated
>    structures within the critical section. kcov_remote_add() is
>    modified to accept a pre-allocated structure instead of allocating
>    one internally.
> 
> 4. Remove the local_lock_t protection for kcov_percpu_data in
>    kcov_remote_start/stop(). Since local_lock_t can also sleep under
>    RT, and the required protection is against local interrupts when
>    accessing per-CPU data, it is replaced with explicit
>    local_irq_save/restore().
> 
> Link: https://lore.kernel.org/all/20250725201400.1078395-2-ysk@kzalloc.com/t/#u
> Fixes: f85d39dd7ed8 ("kcov, usb: disable interrupts in kcov_remote_start_usb_softirq")
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Cc: Alan Stern <stern@rowland.harvard.edu>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: Byungchul Park <byungchul@sk.com>
> Cc: stable@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> Cc: syzkaller@googlegroups.com
> Cc: linux-usb@vger.kernel.org
> Cc: linux-rt-devel@lists.linux.dev
> Signed-off-by: Yunseong Kim <ysk@kzalloc.com>
> ---
>  kernel/kcov.c | 243 +++++++++++++++++++++++++++-----------------------
>  1 file changed, 130 insertions(+), 113 deletions(-)
> 
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 187ba1b80bda..9c8e4325cff8 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -54,7 +54,7 @@ struct kcov {
>  	 */
>  	refcount_t		refcount;
>  	/* The lock protects mode, size, area and t. */
> -	spinlock_t		lock;
> +	raw_spinlock_t		lock;
>  	enum kcov_mode		mode;
>  	/* Size of arena (in long's). */
>  	unsigned int		size;
> @@ -84,13 +84,12 @@ struct kcov_remote {
>  	struct hlist_node	hnode;
>  };
>  
> -static DEFINE_SPINLOCK(kcov_remote_lock);
> +static DEFINE_RAW_SPINLOCK(kcov_remote_lock);
>  static DEFINE_HASHTABLE(kcov_remote_map, 4);
>  static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>  
>  struct kcov_percpu_data {
>  	void			*irq_area;
> -	local_lock_t		lock;
>  
>  	unsigned int		saved_mode;
>  	unsigned int		saved_size;
> @@ -99,9 +98,7 @@ struct kcov_percpu_data {
>  	int			saved_sequence;
>  };
>  
> -static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
> -	.lock = INIT_LOCAL_LOCK(lock),
> -};
> +static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data);
>  
>  /* Must be called with kcov_remote_lock locked. */
>  static struct kcov_remote *kcov_remote_find(u64 handle)
> @@ -116,15 +113,9 @@ static struct kcov_remote *kcov_remote_find(u64 handle)
>  }
>  
>  /* Must be called with kcov_remote_lock locked. */
> -static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle)
> +static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle,
> +					   struct kcov_remote *remote)
>  {
> -	struct kcov_remote *remote;
> -
> -	if (kcov_remote_find(handle))
> -		return ERR_PTR(-EEXIST);
> -	remote = kmalloc(sizeof(*remote), GFP_ATOMIC);
> -	if (!remote)
> -		return ERR_PTR(-ENOMEM);
>  	remote->handle = handle;
>  	remote->kcov = kcov;
>  	hash_add(kcov_remote_map, &remote->hnode, handle);
> @@ -404,9 +395,8 @@ static void kcov_remote_reset(struct kcov *kcov)
>  	int bkt;
>  	struct kcov_remote *remote;
>  	struct hlist_node *tmp;
> -	unsigned long flags;
>  
> -	spin_lock_irqsave(&kcov_remote_lock, flags);
> +	raw_spin_lock(&kcov_remote_lock);
>  	hash_for_each_safe(kcov_remote_map, bkt, tmp, remote, hnode) {
>  		if (remote->kcov != kcov)
>  			continue;
> @@ -415,7 +405,7 @@ static void kcov_remote_reset(struct kcov *kcov)
>  	}
>  	/* Do reset before unlock to prevent races with kcov_remote_start(). */
>  	kcov_reset(kcov);
> -	spin_unlock_irqrestore(&kcov_remote_lock, flags);
> +	raw_spin_unlock(&kcov_remote_lock);
>  }
>  
>  static void kcov_disable(struct task_struct *t, struct kcov *kcov)
> @@ -450,7 +440,7 @@ void kcov_task_exit(struct task_struct *t)
>  	if (kcov == NULL)
>  		return;
>  
> -	spin_lock_irqsave(&kcov->lock, flags);
> +	raw_spin_lock_irqsave(&kcov->lock, flags);
>  	kcov_debug("t = %px, kcov->t = %px\n", t, kcov->t);
>  	/*
>  	 * For KCOV_ENABLE devices we want to make sure that t->kcov->t == t,
> @@ -475,12 +465,12 @@ void kcov_task_exit(struct task_struct *t)
>  	 * By combining all three checks into one we get:
>  	 */
>  	if (WARN_ON(kcov->t != t)) {
> -		spin_unlock_irqrestore(&kcov->lock, flags);
> +		raw_spin_unlock_irqrestore(&kcov->lock, flags);
>  		return;
>  	}
>  	/* Just to not leave dangling references behind. */
>  	kcov_disable(t, kcov);
> -	spin_unlock_irqrestore(&kcov->lock, flags);
> +	raw_spin_unlock_irqrestore(&kcov->lock, flags);
>  	kcov_put(kcov);
>  }
>  
> @@ -492,14 +482,14 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>  	struct page *page;
>  	unsigned long flags;
>  
> -	spin_lock_irqsave(&kcov->lock, flags);
> +	raw_spin_lock_irqsave(&kcov->lock, flags);
>  	size = kcov->size * sizeof(unsigned long);
>  	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
>  	    vma->vm_end - vma->vm_start != size) {
>  		res = -EINVAL;
>  		goto exit;
>  	}
> -	spin_unlock_irqrestore(&kcov->lock, flags);
> +	raw_spin_unlock_irqrestore(&kcov->lock, flags);
>  	vm_flags_set(vma, VM_DONTEXPAND);
>  	for (off = 0; off < size; off += PAGE_SIZE) {
>  		page = vmalloc_to_page(kcov->area + off);
> @@ -511,7 +501,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>  	}
>  	return 0;
>  exit:
> -	spin_unlock_irqrestore(&kcov->lock, flags);
> +	raw_spin_unlock_irqrestore(&kcov->lock, flags);
>  	return res;
>  }
>  
> @@ -525,7 +515,7 @@ static int kcov_open(struct inode *inode, struct file *filep)
>  	kcov->mode = KCOV_MODE_DISABLED;
>  	kcov->sequence = 1;
>  	refcount_set(&kcov->refcount, 1);
> -	spin_lock_init(&kcov->lock);
> +	raw_spin_lock_init(&kcov->lock);
>  	filep->private_data = kcov;
>  	return nonseekable_open(inode, filep);
>  }
> @@ -586,10 +576,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>  			     unsigned long arg)
>  {
>  	struct task_struct *t;
> -	unsigned long flags, unused;
> -	int mode, i;
> -	struct kcov_remote_arg *remote_arg;
> -	struct kcov_remote *remote;
> +	unsigned long unused;
> +	int mode;
>  
>  	switch (cmd) {
>  	case KCOV_ENABLE:
> @@ -627,69 +615,80 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>  		kcov_disable(t, kcov);
>  		kcov_put(kcov);
>  		return 0;
> -	case KCOV_REMOTE_ENABLE:
> -		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> -			return -EINVAL;
> -		t = current;
> -		if (kcov->t != NULL || t->kcov != NULL)
> -			return -EBUSY;
> -		remote_arg = (struct kcov_remote_arg *)arg;
> -		mode = kcov_get_mode(remote_arg->trace_mode);
> -		if (mode < 0)
> -			return mode;
> -		if ((unsigned long)remote_arg->area_size >
> -		    LONG_MAX / sizeof(unsigned long))
> -			return -EINVAL;
> -		kcov->mode = mode;
> -		t->kcov = kcov;
> -	        t->kcov_mode = KCOV_MODE_REMOTE;
> -		kcov->t = t;
> -		kcov->remote = true;
> -		kcov->remote_size = remote_arg->area_size;
> -		spin_lock_irqsave(&kcov_remote_lock, flags);
> -		for (i = 0; i < remote_arg->num_handles; i++) {
> -			if (!kcov_check_handle(remote_arg->handles[i],
> -						false, true, false)) {
> -				spin_unlock_irqrestore(&kcov_remote_lock,
> -							flags);
> -				kcov_disable(t, kcov);
> -				return -EINVAL;
> -			}
> -			remote = kcov_remote_add(kcov, remote_arg->handles[i]);
> -			if (IS_ERR(remote)) {
> -				spin_unlock_irqrestore(&kcov_remote_lock,
> -							flags);
> -				kcov_disable(t, kcov);
> -				return PTR_ERR(remote);
> -			}
> -		}
> -		if (remote_arg->common_handle) {
> -			if (!kcov_check_handle(remote_arg->common_handle,
> -						true, false, false)) {
> -				spin_unlock_irqrestore(&kcov_remote_lock,
> -							flags);
> -				kcov_disable(t, kcov);
> -				return -EINVAL;
> -			}
> -			remote = kcov_remote_add(kcov,
> -					remote_arg->common_handle);
> -			if (IS_ERR(remote)) {
> -				spin_unlock_irqrestore(&kcov_remote_lock,
> -							flags);
> -				kcov_disable(t, kcov);
> -				return PTR_ERR(remote);
> -			}
> -			t->kcov_handle = remote_arg->common_handle;
> -		}
> -		spin_unlock_irqrestore(&kcov_remote_lock, flags);
> -		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
> -		kcov_get(kcov);
> -		return 0;
>  	default:
>  		return -ENOTTY;
>  	}
>  }
>  
> +static int kcov_ioctl_locked_remote_enabled(struct kcov *kcov,
> +				 unsigned int cmd, unsigned long arg,
> +				 struct kcov_remote *remote_handles,
> +				 struct kcov_remote *remote_common_handle)
> +{
> +	struct task_struct *t;
> +	int mode, i, ret;
> +	struct kcov_remote_arg *remote_arg;
> +
> +	if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +		return -EINVAL;
> +	t = current;
> +	if (kcov->t != NULL || t->kcov != NULL)
> +		return -EBUSY;
> +	remote_arg = (struct kcov_remote_arg *)arg;
> +	mode = kcov_get_mode(remote_arg->trace_mode);
> +	if (mode < 0)
> +		return mode;
> +	if ((unsigned long)remote_arg->area_size >
> +		LONG_MAX / sizeof(unsigned long))
> +		return -EINVAL;
> +	kcov->mode = mode;
> +	t->kcov = kcov;
> +	t->kcov_mode = KCOV_MODE_REMOTE;
> +	kcov->t = t;
> +	kcov->remote = true;
> +	kcov->remote_size = remote_arg->area_size;
> +	raw_spin_lock(&kcov_remote_lock);
> +	for (i = 0; i < remote_arg->num_handles; i++) {
> +		if (!kcov_check_handle(remote_arg->handles[i],
> +					false, true, false)) {
> +			ret = -EINVAL;
> +			goto err;
> +		}
> +		if (kcov_remote_find(remote_arg->handles[i])) {
> +			ret = -EEXIST;
> +			goto err;
> +		}
> +		kcov_remote_add(kcov, remote_arg->handles[i],
> +			&remote_handles[i]);
> +	}
> +	if (remote_arg->common_handle) {
> +		if (!kcov_check_handle(remote_arg->common_handle,
> +					true, false, false)) {
> +			ret = -EINVAL;
> +			goto err;
> +		}
> +		if (kcov_remote_find(remote_arg->common_handle)) {
> +			ret = -EEXIST;
> +			goto err;
> +		}
> +		kcov_remote_add(kcov,
> +			remote_arg->common_handle, remote_common_handle);
> +		t->kcov_handle = remote_arg->common_handle;
> +	}
> +	raw_spin_unlock(&kcov_remote_lock);
> +	/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
> +	kcov_get(kcov);
> +	return 0;
> +
> +err:
> +	raw_spin_unlock(&kcov_remote_lock);
> +	kcov_disable(t, kcov);
> +	kfree(remote_common_handle);
> +	kfree(remote_handles);
> +
> +	return ret;
> +}
> +
>  static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  {
>  	struct kcov *kcov;
> @@ -697,6 +696,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  	struct kcov_remote_arg *remote_arg = NULL;
>  	unsigned int remote_num_handles;
>  	unsigned long remote_arg_size;
> +	struct kcov_remote *remote_handles, *remote_common_handle;
>  	unsigned long size, flags;
>  	void *area;
>  
> @@ -716,16 +716,16 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  		area = vmalloc_user(size * sizeof(unsigned long));
>  		if (area == NULL)
>  			return -ENOMEM;
> -		spin_lock_irqsave(&kcov->lock, flags);
> +		raw_spin_lock_irqsave(&kcov->lock, flags);
>  		if (kcov->mode != KCOV_MODE_DISABLED) {
> -			spin_unlock_irqrestore(&kcov->lock, flags);
> +			raw_spin_unlock_irqrestore(&kcov->lock, flags);
>  			vfree(area);
>  			return -EBUSY;
>  		}
>  		kcov->area = area;
>  		kcov->size = size;
>  		kcov->mode = KCOV_MODE_INIT;
> -		spin_unlock_irqrestore(&kcov->lock, flags);
> +		raw_spin_unlock_irqrestore(&kcov->lock, flags);
>  		return 0;
>  	case KCOV_REMOTE_ENABLE:
>  		if (get_user(remote_num_handles, (unsigned __user *)(arg +
> @@ -743,18 +743,35 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>  			return -EINVAL;
>  		}
>  		arg = (unsigned long)remote_arg;
> -		fallthrough;
> +		remote_handles = kmalloc_array(remote_arg->num_handles,
> +					sizeof(struct kcov_remote), GFP_KERNEL);
> +		if (!remote_handles)
> +			return -ENOMEM;
> +		remote_common_handle = kmalloc(sizeof(struct kcov_remote), GFP_KERNEL);
> +		if (!remote_common_handle) {
> +			kfree(remote_handles);
> +			return -ENOMEM;
> +		}
> +
> +		raw_spin_lock_irqsave(&kcov->lock, flags);
> +		res = kcov_ioctl_locked_remote_enabled(kcov, cmd, arg,
> +				remote_handles, remote_common_handle);
> +		raw_spin_unlock_irqrestore(&kcov->lock, flags);
> +		kfree(remote_arg);
> +		break;
>  	default:
>  		/*
> +		 * KCOV_ENABLE, KCOV_DISABLE:
>  		 * All other commands can be normally executed under a spin lock, so we
>  		 * obtain and release it here in order to simplify kcov_ioctl_locked().
>  		 */
> -		spin_lock_irqsave(&kcov->lock, flags);
> +		raw_spin_lock_irqsave(&kcov->lock, flags);
>  		res = kcov_ioctl_locked(kcov, cmd, arg);
> -		spin_unlock_irqrestore(&kcov->lock, flags);
> -		kfree(remote_arg);
> -		return res;
> +		raw_spin_unlock_irqrestore(&kcov->lock, flags);
> +		break;
>  	}
> +
> +	return res;
>  }
>  
>  static const struct file_operations kcov_fops = {
> @@ -862,7 +879,7 @@ void kcov_remote_start(u64 handle)
>  	if (!in_task() && !in_softirq_really())
>  		return;
>  
> -	local_lock_irqsave(&kcov_percpu_data.lock, flags);
> +	local_irq_save(flags);
>  
>  	/*
>  	 * Check that kcov_remote_start() is not called twice in background
> @@ -870,7 +887,7 @@ void kcov_remote_start(u64 handle)
>  	 */
>  	mode = READ_ONCE(t->kcov_mode);
>  	if (WARN_ON(in_task() && kcov_mode_enabled(mode))) {
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		local_irq_restore(flags);
>  		return;
>  	}
>  	/*
> @@ -879,15 +896,15 @@ void kcov_remote_start(u64 handle)
>  	 * happened while collecting coverage from a background thread.
>  	 */
>  	if (WARN_ON(in_serving_softirq() && t->kcov_softirq)) {
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		local_irq_restore(flags);
>  		return;
>  	}
>  
> -	spin_lock(&kcov_remote_lock);
> +	raw_spin_lock(&kcov_remote_lock);
>  	remote = kcov_remote_find(handle);
>  	if (!remote) {
> -		spin_unlock(&kcov_remote_lock);
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		raw_spin_unlock(&kcov_remote_lock);
> +		local_irq_restore(flags);
>  		return;
>  	}
>  	kcov_debug("handle = %llx, context: %s\n", handle,
> @@ -908,17 +925,17 @@ void kcov_remote_start(u64 handle)
>  		size = CONFIG_KCOV_IRQ_AREA_SIZE;
>  		area = this_cpu_ptr(&kcov_percpu_data)->irq_area;
>  	}
> -	spin_unlock(&kcov_remote_lock);
> +	raw_spin_unlock(&kcov_remote_lock);
>  
>  	/* Can only happen when in_task(). */
>  	if (!area) {
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		local_irq_restore(flags);
>  		area = vmalloc(size * sizeof(unsigned long));
>  		if (!area) {
>  			kcov_put(kcov);
>  			return;
>  		}
> -		local_lock_irqsave(&kcov_percpu_data.lock, flags);
> +		local_irq_save(flags);
>  	}
>  
>  	/* Reset coverage size. */
> @@ -930,7 +947,7 @@ void kcov_remote_start(u64 handle)
>  	}
>  	kcov_start(t, kcov, size, area, mode, sequence);
>  
> -	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +	local_irq_restore(flags);
>  
>  }
>  EXPORT_SYMBOL(kcov_remote_start);
> @@ -1004,12 +1021,12 @@ void kcov_remote_stop(void)
>  	if (!in_task() && !in_softirq_really())
>  		return;
>  
> -	local_lock_irqsave(&kcov_percpu_data.lock, flags);
> +	local_irq_save(flags);
>  
>  	mode = READ_ONCE(t->kcov_mode);
>  	barrier();
>  	if (!kcov_mode_enabled(mode)) {
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		local_irq_restore(flags);
>  		return;
>  	}
>  	/*
> @@ -1017,12 +1034,12 @@ void kcov_remote_stop(void)
>  	 * actually found the remote handle and started collecting coverage.
>  	 */
>  	if (in_serving_softirq() && !t->kcov_softirq) {
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		local_irq_restore(flags);
>  		return;
>  	}
>  	/* Make sure that kcov_softirq is only set when in softirq. */
>  	if (WARN_ON(!in_serving_softirq() && t->kcov_softirq)) {
> -		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +		local_irq_restore(flags);
>  		return;
>  	}
>  
> @@ -1037,22 +1054,22 @@ void kcov_remote_stop(void)
>  		kcov_remote_softirq_stop(t);
>  	}
>  
> -	spin_lock(&kcov->lock);
> +	raw_spin_lock(&kcov->lock);
>  	/*
>  	 * KCOV_DISABLE could have been called between kcov_remote_start()
>  	 * and kcov_remote_stop(), hence the sequence check.
>  	 */
>  	if (sequence == kcov->sequence && kcov->remote)
>  		kcov_move_area(kcov->mode, kcov->area, kcov->size, area);
> -	spin_unlock(&kcov->lock);
> +	raw_spin_unlock(&kcov->lock);
>  
>  	if (in_task()) {
> -		spin_lock(&kcov_remote_lock);
> +		raw_spin_lock(&kcov_remote_lock);
>  		kcov_remote_area_put(area, size);
> -		spin_unlock(&kcov_remote_lock);
> +		raw_spin_unlock(&kcov_remote_lock);
>  	}
>  
> -	local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> +	local_irq_restore(flags);
>  
>  	/* Get in kcov_remote_start(). */
>  	kcov_put(kcov);
> -- 
> 2.50.0
> 

Hi,

This is the friendly patch-bot of Greg Kroah-Hartman.  You have sent him
a patch that has triggered this response.  He used to manually respond
to these common problems, but in order to save his sanity (he kept
writing the same thing over and over, yet to different people), I was
created.  Hopefully you will not take offence and will fix the problem
in your patch and resubmit it so that it can be accepted into the Linux
kernel tree.

You are receiving this message because of the following common error(s)
as indicated below:

- This looks like a new version of a previously submitted patch, but you
  did not list below the --- line any changes from the previous version.
  Please read the section entitled "The canonical patch format" in the
  kernel file, Documentation/process/submitting-patches.rst for what
  needs to be done here to properly describe this.

If you wish to discuss this problem further, or you have questions about
how to resolve this issue, please feel free to respond to this email and
Greg will reply once he has dug out from the pending patches received
from other developers.

thanks,

greg k-h's patch email bot

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2025080251-villain-subsoil-e28d%40gregkh.
