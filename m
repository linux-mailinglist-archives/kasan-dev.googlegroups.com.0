Return-Path: <kasan-dev+bncBC7OBJGL2MHBB46U76JAMGQE3CASFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 194B75086B6
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 13:11:48 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id y20-20020a197514000000b0046cbe2da153sf484048lfe.19
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 04:11:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650453107; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2V3vqq4zCWeTQ0PYZugIh2YEjhrQcvO6GsOmyYWBFkCODinVXus8F/9FBdsGCJF8O
         v/ix+kHWLqURzWRtHqm1AweSzmN3aCzCgKkU8xMfyHpkcvgEgQlJ0oyYfXOE84fGaGoX
         33OCPDgDzSQN1zSmPIXMN7mhmCNEnnbwv7ZWECFoO0UX7VjAUs8tM3fmhAIy0Ajnk8Xp
         shL7B08di49vnjSFO8oi2UcKjVMM9T/Q46/ghm4X8yZW5O3RAureHvg9kLKdL3rfyfBZ
         Xt2OtcrNE1zHElZxsHAfdweSGN0SND0ATU17dOO/MyT0z6LLZjFCIKYPJQrDDAOOfzag
         8l5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yDba/Jvhg5qJm9PG7DO9H+W2F4fNpf2jeIV8ENCrbXc=;
        b=QW7bgvNBVxlfi2UWoZZpMyXGL130BYmvegPOo6xlunW2FUxQao8d2pCpazUXsEtXC4
         bzmNeSaj8Aa8cmY01jhUvArM0ZpLbNWOdYr4xT7tWVf7s7JMNnRDGI4liRN58vU7s+a4
         hDGumqg2fg4Eh6YLd8Uos3elqx8msi28exRgwRrhpts8rA3Fq9cWJxYpDnjMSotaDyf/
         I5kqJlkT10/QpnYFOZO9Kn/2K+INRreg4Uf9nswC76RS+BipYAtLgBFzzq5O6cviAAL6
         D8fhMg4/1mDwfHmZDr7Ak07m9M0/sc3jcwoLE0QVCPxVkVp2mbokJkKxQHp6sORwWLZy
         q2Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cXqr5uB6;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yDba/Jvhg5qJm9PG7DO9H+W2F4fNpf2jeIV8ENCrbXc=;
        b=eyiBFTxz8fhJEA8JPQoWf12iRfIWhw88Nrk0EOpAMKprHpf1iwNgIodCYEsv0s+eVN
         2o4kZoxS/neKZ6sX/X5eUenNJgdDD7rJfl0uq3Xe29+obC0NJokN+r0+dZ0Nx/tfrSRj
         fCgyJ0gmPjVSheA7NbXTxfN4qHKnQiGK/CyTHKprmRrZH0Q7paoBVmpnQ3x66DVOb1yK
         ggZqBKgtlfdOpr5YyFJr3wgu+ORdE44S9F6igXEY9CwY02nGj6H+JWOQ/oeza5VtbBB+
         3RdvMa1eqbjTjXoztefaQQBWu6UQArl2m2lNIVuE8S73VnVcl3XF5JgJRt8rsxHzP4sX
         4rpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yDba/Jvhg5qJm9PG7DO9H+W2F4fNpf2jeIV8ENCrbXc=;
        b=wWpcTCzzfdnEX8MCHQjau2KteLalqey1BEPi2qR5kSNJs8h34UMlKHJ0gZuy7tJuRq
         H6L9RqA3RVsr+nH09SXmPJp68lwy9lKvbqs+wurtWyXET+Fcy5HcgomKW272FTtZot79
         7xhmoBGLaTY/Ww+jXs+ERt6Qj6+8ZvXN74MRaQLbtlcPq1VO8LeLZ5UkysuIPh62z3JM
         vMKEiOQ6Z09wc4y3xBYC4e04QybMZdm3efjbUC38v2mygBmHOyDimDy2FQcv0WRSwRzA
         p6ma0Dg5lGEjAx4knHJPUkbqXou8CTHBdrhK562+A2KT3KerR+yHDyX6QudFVHMXTeme
         dffg==
X-Gm-Message-State: AOAM533nI1PY6VwIebFHxWYnFz/K6asFtRR8suDTUQFEVlIbh6KVY7sE
	FJ+EGfG8+MRuuNlqP6dmKwM=
X-Google-Smtp-Source: ABdhPJwyl2RKlQxTEzR/eGK9Ig41AwzVDaIYcga7R+/7GSmVqlInQYujnZ7dT4yh7A38+6bfRqTjEA==
X-Received: by 2002:ac2:4e98:0:b0:448:3039:d170 with SMTP id o24-20020ac24e98000000b004483039d170mr15355499lfr.233.1650453107538;
        Wed, 20 Apr 2022 04:11:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als1601963lfa.2.gmail; Wed, 20 Apr 2022
 04:11:46 -0700 (PDT)
X-Received: by 2002:a05:6512:3d94:b0:471:2436:f8f4 with SMTP id k20-20020a0565123d9400b004712436f8f4mr12382541lfv.441.1650453106011;
        Wed, 20 Apr 2022 04:11:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650453106; cv=none;
        d=google.com; s=arc-20160816;
        b=saWUqSSh00LFlkihcWS4IATIppaPvpDgzBRGU0wEPpzfzNfWATw0h0gJ5ZH8KbMZcC
         eClPdW8Ns0PEcFCs2W70cnU8RvQ5Q85/Q34Zfu3bcS/tFm6digf9T0N6SrcbYw7LngHS
         qpDJeOI3nHwHy4OSim3bAi3Sh0xKdE4EzB7ss0YlfvgmWuleMNb3T574BIIoWIqQIVqc
         vqMYR+1Ef8nqAB6ENSn8tnAOfPUtZ5VBSGxJTzWXeOHCpziE11Vd1Du1/DT2XgsQVZuL
         A7KNEiIu4XghJW9c0UP7Ds9Nbkw19gu1RXLxAEC3aX365kAFzByT7cs6j+WwnCIpJ5TW
         kKHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=60zzKcjTCPwbmakqWfB1fDtmewNBaOu9rlb+E9ZxVuA=;
        b=hRBxRlcc65BEoLwgoAtSw2uDACOowNNNnLRBVI9fDdEue4i7piknLBuAYf3XakGJit
         RxKTu73FZ0S99sX9njmxqNdHPjLmuUisYYF1yJlokjUXh/XCackB1MZ4jPuX629w6DKI
         4CgpqfxqBGOUmvDzZmk+RF8bgwg6r0Pyz8NDIcGUioOkEcw7okZSR9bVaRnO7Tr5pnXa
         Lyc+AXp/zcqV/Vu9mn97UgyLuGJqT65r3yWw9pwlkLFl9Bil0m9YmVRtf2Xz/WPzENvM
         +plhiu+og7rDigKJvVToYoNR4xDbiNvpXrmIb7Fntmp2qPq7n8IQ/M6RjeyEKtMEyiFH
         IebA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cXqr5uB6;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id e8-20020a05651c04c800b0024d9b30d79dsi99855lji.4.2022.04.20.04.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Apr 2022 04:11:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id x3so948457wmj.5
        for <kasan-dev@googlegroups.com>; Wed, 20 Apr 2022 04:11:45 -0700 (PDT)
X-Received: by 2002:a05:600c:3494:b0:390:8a95:1b95 with SMTP id a20-20020a05600c349400b003908a951b95mr3089004wmq.15.1650453105485;
        Wed, 20 Apr 2022 04:11:45 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:64a4:39d5:81cc:c8fd])
        by smtp.gmail.com with ESMTPSA id v18-20020adfc5d2000000b0020589b76704sm15987523wrg.70.2022.04.20.04.11.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Apr 2022 04:11:45 -0700 (PDT)
Date: Wed, 20 Apr 2022 13:11:39 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, young.liuyang@huawei.com,
	zengweilin@huawei.com, chenzefeng2@huawei.com,
	nixiaoming@huawei.com, wangbing6@huawei.com,
	wangfangpeng1@huawei.com, zhongjubin@huawei.com
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
Message-ID: <Yl/qa2w3q9kyXcQl@elver.google.com>
References: <20220420104927.59056-1-huangshaobo6@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220420104927.59056-1-huangshaobo6@huawei.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cXqr5uB6;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Wed, Apr 20, 2022 at 06:49PM +0800, Shaobo Huang wrote:
> From: huangshaobo <huangshaobo6@huawei.com>
> 
> when writing out of bounds to the red zone, it can only be detected at
> kfree. However, there were many scenarios before kfree that caused this
> out-of-bounds write to not be detected. Therefore, it is necessary to
> provide a method for actively detecting out-of-bounds writing to the red
> zone, so that users can actively detect, and can be detected in the
> system reboot or panic.
> 
> for example, if the application memory is out of bounds and written to
> the red zone in the kfence object, the system suddenly panics, and the
> following log can be seen during system reset:

Interesting idea - however, when KFENCE is deployed to a fleet, the same
bug will eventually manifest as an OOB that hits a guard page (because
random placement), and produce the normal out-of-bounds message.

Have you found new bugs this way?

But doing this check on panic doesn't seem to hurt. But please see
comments below.

> BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x70
> 
> Corrupted memory at 0x(____ptrval____) [ ! ] (in kfence-#59):
>  atomic_notifier_call_chain+0x49/0x70
>  panic+0x134/0x278
>  sysrq_handle_crash+0x11/0x20
>  __handle_sysrq+0x99/0x160
>  write_sysrq_trigger+0x26/0x30
>  proc_reg_write+0x51/0x70
>  vfs_write+0xb6/0x290
>  ksys_write+0x9c/0xd0
>  __do_fast_syscall_32+0x67/0xe0
>  do_fast_syscall_32+0x2f/0x70
>  entry_SYSCALL_compat_after_hwframe+0x45/0x4d
> 
> kfence-#59: 0x(____ptrval____)-0x(____ptrval____),size=100,cache=kmalloc-128
>  allocated by task 77 on cpu 0 at 28.018073s:
>  0xffffffffc007703d
>  do_one_initcall+0x3c/0x1e0
>  do_init_module+0x46/0x1d8
>  load_module+0x2397/0x2860
>  __do_sys_init_module+0x160/0x190
>  __do_fast_syscall_32+0x67/0xe0
>  do_fast_syscall_32+0x2f/0x70
>  entry_SYSCALL_compat_after_hwframe+0x45/0x4d

Is this a real bug? Or one you injected?

> Suggested-by: chenzefeng <chenzefeng2@huawei.com>
> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> ---
>  mm/kfence/core.c | 28 ++++++++++++++++++++++++++++
>  1 file changed, 28 insertions(+)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 9b2b5f56f4ae..85cc3ca4b71c 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -29,6 +29,9 @@
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/string.h>
> +#include <linux/notifier.h>
> +#include <linux/reboot.h>
> +#include <linux/panic_notifier.h>
>  
>  #include <asm/kfence.h>
>  
> @@ -716,6 +719,29 @@ static const struct file_operations objects_fops = {
>  	.release = seq_release,
>  };
>  
> +static void kfence_check_all_canary(void)
> +{
> +	int i;
> +
> +	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +		struct kfence_metadata *meta = &kfence_metadata[i];
> +
> +		if (meta->state == KFENCE_OBJECT_ALLOCATED)
> +			for_each_canary(meta, check_canary_byte);
> +	}
> +}
> +
> +static int kfence_check_canary_callback(struct notifier_block *nb,
> +					unsigned long reason, void *arg)
> +{
> +	kfence_check_all_canary();
> +	return NOTIFY_OK;
> +}
> +
> +static struct notifier_block kfence_check_canary_notifier = {
> +	.notifier_call = kfence_check_canary_callback,
> +};

Sorry to be pedantic, but this is a pretty random place to put this
code. Can you put it after the debugfs section, perhaps with:

--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -748,6 +748,10 @@ static int __init kfence_debugfs_init(void)
 
 late_initcall(kfence_debugfs_init);
 
+/* === Reboot Notifier ====================================================== */
+
+< your code here >
+
 /* === Allocation Gate Timer ================================================ */
 
 static struct delayed_work kfence_timer;

>  static int __init kfence_debugfs_init(void)
>  {
>  	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
> @@ -806,6 +832,8 @@ static void kfence_init_enable(void)
>  
>  	WRITE_ONCE(kfence_enabled, true);
>  	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +	register_reboot_notifier(&kfence_check_canary_notifier);
> +	atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);

Executing this on panic is reasonable. However,
register_reboot_notifier() tells me this is being executed on *every*
reboot (not just panic). I think that's not what we want, because that
may increase reboot latency depending on how many KFENCE objects we
have. Is it possible to *only* do the check on panic?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yl/qa2w3q9kyXcQl%40elver.google.com.
