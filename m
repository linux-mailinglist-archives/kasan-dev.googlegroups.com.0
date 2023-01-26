Return-Path: <kasan-dev+bncBDW2JDUY5AORBBM4ZSPAMGQEJILH5TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 733F167D9A2
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 00:34:30 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id u11-20020a05620a430b00b007052a66d201sf2030614qko.23
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 15:34:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674776069; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwt+oP5b3+BUM8C8GWaehHB7PQ7CkI6Nx1tSJcpHwhjITizm0mHG7irR4uzuZneWUR
         5OuRAyqc9vCLmR4sKy01SRWWjUyHPWAMvIfeD6oGBwsWlb7GAEd9EQ624PlAoLDBli/o
         Thd9vYoa++Sta+6r6NhF0mFsy+c1JtqkAecPcOnWMIcbhR/Fnx1br2Rzl2YvjWPWPGPs
         yecMVKrA44xRruB5RpxlBQm66gU2R9baui6+RCok2wKQUOoUXBAL5DSdBtYVU2bZvIxD
         4u5wXDOdiuiEcH9QtFeRrjMlBY9RYQ4/ql1cXd1RmVfqr9+hUgkloDYgOYTcTbNUWEr/
         tg2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=yeSdbVOw1QSOJtIsqyTTsliMUo834lwaOdP9q50VvPA=;
        b=RTcl1KR2J5C76RhIhGDqvVthn88m0WbKCqmvtVIaF3d2LWihOkT1D4grbnvo0b08nI
         LtKXhANdMPrkQjF39ZfVrYp4ijCTBfZXh0Jypzry07wyPoLpTrHfeN4kqDK1dnLa2o/t
         c3hSOsqS6QV6n5k4Bqm2JP+Y8vxWuqOW45mpaoxtnZiia2tS+ULwWVnywAoVPfCm1a14
         nICB1GUB0md9HVeJMamxwPRg5sOfShwufZE3EDcBvzD8jm0R4l+uZz8gWmxEdkeElji9
         M4ygTA2qsX3uWjXp6PvNQ835Xje4nlIKaGCwjJ7fQoHn/kK4eGOgfxcuLGIud95xC3zy
         s15Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=V7pzD6Pv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yeSdbVOw1QSOJtIsqyTTsliMUo834lwaOdP9q50VvPA=;
        b=oK1QSHOfyAHTVpviZmT09L/Uvvc0gDDvHffSn8slI1s2RG+aMk1SdiS0PNLFmFP/YM
         7v16AaFx27aQD/0xQDKFiEvi59jhLJkqFW9Jt+aQs9vo7Edzzv98KYijKkq7D6evZMzi
         Ee3+gqwW8kUw+ZdnVCibXYv28CJjjKZK3QxwnEfXACudS0CoRvG0ooUWeIDpIt/zwPHe
         X1HWNG7OfrpgwusZKtmPbp+tT9YIV8+I2YIUH/XRoGoLN71dZyu20GpxtCfarpMco/bk
         lpS9PdQtqB2nzdDcTwZVX5X8SBC+7wKjC/iSuEt/1Kf5I/ynl0LxzSyOuz95eF7w9oxX
         tUTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=yeSdbVOw1QSOJtIsqyTTsliMUo834lwaOdP9q50VvPA=;
        b=d7JhuA8UHcay8I/7atQM/H+6iCcQPHAHrYQZf9iXC+bNfx9CDu8N1vKedaa2C530At
         yvc0u8LYnrnlCKB5gTt0AjcG+nu8+jezfmEXvfWzVvk40NastQ0yXwOcEcYoyM+EEunZ
         8YvH+aayobJdozNWB6pj2iAhb/f2+kqzTyIEN4wz7+wCjoa8frJE9KphoGvqcZD5ZPzg
         +qsisDv9YV6s6ISqJ7UzgJ3kZzMqd3ZvA8l2v+xbNG8azObTVaG0mZ59RdOmhXOXDgUB
         vHRx9hy010qjQxWHqiwcNJl6u5OBLhwpFsvuCj0a6bNhZnAeVO3sI95vx2z0kf468SpU
         f7zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yeSdbVOw1QSOJtIsqyTTsliMUo834lwaOdP9q50VvPA=;
        b=CPsOLQUr7fQvt7MpRwMtg6A245Sj5Sm4s+xyWG9BMGDiqW+NR89khwjC48/Ymerkw9
         PkXt3dmlFsRuhYQwW2iaTIu8xn6TsEEIIwU7T+9AGg+haiKZEbOumln+PkDVxH1G1K8S
         Ez0d+p8VO5dMbRKGFL0v8wZpWxISOJCsAUu78f4q+BsVo0yZJhsS6faYh1YxAMz2d/PJ
         8jKdGon/BbLhmPKiHGXuS+WuGhD36NFKu5+b7wKjzamG4BGU6QnYXBNWB5ZZm4QF9n8T
         1T5koDuffBdPR59ecopO0EXebfB/QWo0WqkO465IfNjOA88TH2OeoVkGFj/9lFPIAVp/
         +Plg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp6COULmHskDQ0rrLdZfZ0OusGb+maT6w5gKrzI4dxbYN6LaGpz
	jTKrNCawqgHmngAYD2rKorU=
X-Google-Smtp-Source: AMrXdXv5iGZ64Oz8NfXkfOHFGMhg9kEiS4tJKOL22DslVGxHqbP8QWl153JR+3o/zv9q0ghKAkWJvA==
X-Received: by 2002:a05:6214:3a05:b0:534:a680:eb58 with SMTP id nw5-20020a0562143a0500b00534a680eb58mr2339024qvb.3.1674776069252;
        Thu, 26 Jan 2023 15:34:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1b05:b0:3b0:98a4:96b8 with SMTP id
 bb5-20020a05622a1b0500b003b098a496b8ls2491812qtb.8.-pod-prod-gmail; Thu, 26
 Jan 2023 15:34:28 -0800 (PST)
X-Received: by 2002:a05:622a:1ba6:b0:3b6:3406:81b6 with SMTP id bp38-20020a05622a1ba600b003b6340681b6mr12014844qtb.11.1674776068658;
        Thu, 26 Jan 2023 15:34:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674776068; cv=none;
        d=google.com; s=arc-20160816;
        b=jWw9A8hIPs3Q6DzAbxk15LKoUhe524ZMH/g1g/TcF76wLtqgygEz2B6eITIIS0wjsq
         IXYLg6goMApfbyTgci89XMfWPPcLP1VWqVTfDl4y3BwkjUklVvcxQpvIjAYuabmnolms
         Z7OUXakZCVVn0Lm0p25BKh6HPGBWzhmpC+rk5Q66n8dP/KEM87+JwjjQRjm2p9KsuSwE
         ZR9jbTvWLkksbZrwIC03nND00G7TLdlORlr3MmRUnPeRnxtSfW1A+E2YT/jVAmGzyT+Y
         q7Vtm12V7q4E7k2doC+xJxU9rKrL9etAEig2FdZiwBnaW7HIziZSe9T9pBUTiMb9egCt
         qnHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZmlCUBRCPwLvDMyRKhmvFFYyCxvm8e49EMH29s2svEk=;
        b=LnrEmT0GLPgOra+hxFyA9Eq/tdVthASvFjytakdCWzRQk09uF7D2fsn5Lkp1ilF7Tw
         SSZoWMMPfpLWkzc4VTo8GLHBLAvUXvEhD2oBAo+cxa+DPHfQZIMZUdte9mQsXm/Tyve+
         XU6zojbAUKNwo/EYyJkgl2KzRIz1R8Vz54azS14suCdq290u/kMmd8/zPcznw3UaMOXH
         F407ac9UKg5CVK5ynH+HjcSrpN49dOHufd+d3tJe49nQRV6CMQGB08lkBF4n1ELzcYOU
         5mzrJKO8zTO9A0qXqlmw9lE5y5k8ZzlKBBSHSi9IoX7IZtt/us3yeki8ousVpQBr8sR6
         ++4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=V7pzD6Pv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id ca23-20020a05622a1f1700b003b62b73ff50si246986qtb.4.2023.01.26.15.34.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jan 2023 15:34:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id f3so2183933pgc.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jan 2023 15:34:28 -0800 (PST)
X-Received: by 2002:a05:6a00:23c2:b0:592:5653:facb with SMTP id
 g2-20020a056a0023c200b005925653facbmr365495pfc.28.1674776067755; Thu, 26 Jan
 2023 15:34:27 -0800 (PST)
MIME-Version: 1.0
References: <150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu>
In-Reply-To: <150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 27 Jan 2023 00:34:16 +0100
Message-ID: <CA+fCnZcnwN-FGbteoMwFeHrGoM-5Gv5bs2udvRtzk-MT6s+B9w@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix Oops due to missing calls to kasan_arch_is_ready()
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Nathan Lynch <nathanl@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=V7pzD6Pv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jan 26, 2023 at 8:08 AM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> On powerpc64, you can build a kernel with KASAN as soon as you build it
> with RADIX MMU support. However if the CPU doesn't have RADIX MMU,
> KASAN isn't enabled at init and the following Oops is encountered.
>
>   [    0.000000][    T0] KASAN not enabled as it requires radix!
>
>   [    4.484295][   T26] BUG: Unable to handle kernel data access at 0xc00e000000804a04
>   [    4.485270][   T26] Faulting instruction address: 0xc00000000062ec6c
>   [    4.485748][   T26] Oops: Kernel access of bad area, sig: 11 [#1]
>   [    4.485920][   T26] BE PAGE_SIZE=64K MMU=Hash SMP NR_CPUS=2048 NUMA pSeries
>   [    4.486259][   T26] Modules linked in:
>   [    4.486637][   T26] CPU: 0 PID: 26 Comm: kworker/u2:2 Not tainted 6.2.0-rc3-02590-gf8a023b0a805 #249
>   [    4.486907][   T26] Hardware name: IBM pSeries (emulated by qemu) POWER9 (raw) 0x4e1200 0xf000005 of:SLOF,HEAD pSeries
>   [    4.487445][   T26] Workqueue: eval_map_wq .tracer_init_tracefs_work_func
>   [    4.488744][   T26] NIP:  c00000000062ec6c LR: c00000000062bb84 CTR: c0000000002ebcd0
>   [    4.488867][   T26] REGS: c0000000049175c0 TRAP: 0380   Not tainted  (6.2.0-rc3-02590-gf8a023b0a805)
>   [    4.489028][   T26] MSR:  8000000002009032 <SF,VEC,EE,ME,IR,DR,RI>  CR: 44002808  XER: 00000000
>   [    4.489584][   T26] CFAR: c00000000062bb80 IRQMASK: 0
>   [    4.489584][   T26] GPR00: c0000000005624d4 c000000004917860 c000000001cfc000 1800000000804a04
>   [    4.489584][   T26] GPR04: c0000000003a2650 0000000000000cc0 c00000000000d3d8 c00000000000d3d8
>   [    4.489584][   T26] GPR08: c0000000049175b0 a80e000000000000 0000000000000000 0000000017d78400
>   [    4.489584][   T26] GPR12: 0000000044002204 c000000003790000 c00000000435003c c0000000043f1c40
>   [    4.489584][   T26] GPR16: c0000000043f1c68 c0000000043501a0 c000000002106138 c0000000043f1c08
>   [    4.489584][   T26] GPR20: c0000000043f1c10 c0000000043f1c20 c000000004146c40 c000000002fdb7f8
>   [    4.489584][   T26] GPR24: c000000002fdb834 c000000003685e00 c000000004025030 c000000003522e90
>   [    4.489584][   T26] GPR28: 0000000000000cc0 c0000000003a2650 c000000004025020 c000000004025020
>   [    4.491201][   T26] NIP [c00000000062ec6c] .kasan_byte_accessible+0xc/0x20
>   [    4.491430][   T26] LR [c00000000062bb84] .__kasan_check_byte+0x24/0x90
>   [    4.491767][   T26] Call Trace:
>   [    4.491941][   T26] [c000000004917860] [c00000000062ae70] .__kasan_kmalloc+0xc0/0x110 (unreliable)
>   [    4.492270][   T26] [c0000000049178f0] [c0000000005624d4] .krealloc+0x54/0x1c0
>   [    4.492453][   T26] [c000000004917990] [c0000000003a2650] .create_trace_option_files+0x280/0x530
>   [    4.492613][   T26] [c000000004917a90] [c000000002050d90] .tracer_init_tracefs_work_func+0x274/0x2c0
>   [    4.492771][   T26] [c000000004917b40] [c0000000001f9948] .process_one_work+0x578/0x9f0
>   [    4.492927][   T26] [c000000004917c30] [c0000000001f9ebc] .worker_thread+0xfc/0x950
>   [    4.493084][   T26] [c000000004917d60] [c00000000020be84] .kthread+0x1a4/0x1b0
>   [    4.493232][   T26] [c000000004917e10] [c00000000000d3d8] .ret_from_kernel_thread+0x58/0x60
>   [    4.495642][   T26] Code: 60000000 7cc802a6 38a00000 4bfffc78 60000000 7cc802a6 38a00001 4bfffc68 60000000 3d20a80e 7863e8c2 792907c6 <7c6348ae> 20630007 78630fe0 68630001
>   [    4.496704][   T26] ---[ end trace 0000000000000000 ]---
>
> The Oops is due to kasan_byte_accessible() not checking the readiness
> of KASAN. Add missing call to kasan_arch_is_ready() and bail out when
> not ready. The same problem is observed with ____kasan_kfree_large()
> so fix it the same.
>
> Also, as KASAN is not available and no shadow area is allocated for
> linear memory mapping, there is no point in allocating shadow mem for
> vmalloc memory as shown below in /sys/kernel/debug/kernel_page_tables
>
>   ---[ kasan shadow mem start ]---
>   0xc00f000000000000-0xc00f00000006ffff  0x00000000040f0000       448K         r  w       pte  valid  present        dirty  accessed
>   0xc00f000000860000-0xc00f00000086ffff  0x000000000ac10000        64K         r  w       pte  valid  present        dirty  accessed
>   0xc00f3ffffffe0000-0xc00f3fffffffffff  0x0000000004d10000       128K         r  w       pte  valid  present        dirty  accessed
>   ---[ kasan shadow mem end ]---
>
> So, also verify KASAN readiness before allocating and poisoning
> shadow mem for VMAs.

Hi Cristophe,

Would it possible to unify kasan_arch_is_ready with the already
existing kasan_enabled check?

Both functions seem to be serving a similar purpose: for example this
patch adds kasan_arch_is_ready into __kasan_poison_vmalloc, which is
called by kasan_poison_vmalloc when kasan_enabled returns true.

The kasan_enabled is only implemented for HW_TAGS right now, but it
should be easy enough to make it work other cases by
kasan_flag_enabled into common.c and adding __wrappers for
shadow-related functions into include/linux/kasan.h. This way
architectures won't need to define their own static key and duplicate
the functionality.

I don't mind having this patch applied as is, considering that it's a
fix. However, if the unification that I mentioned is possible, that
would be a nice improvement.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcnwN-FGbteoMwFeHrGoM-5Gv5bs2udvRtzk-MT6s%2BB9w%40mail.gmail.com.
