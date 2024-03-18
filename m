Return-Path: <kasan-dev+bncBDV37XP3XYDRBWER4GXQMGQEPNWGVXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32FD387EA7E
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 14:59:54 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-69629cf067fsf4410846d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 06:59:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710770393; cv=pass;
        d=google.com; s=arc-20160816;
        b=X0WA1utjmfdqplEhVK3pMWnIgoI4c7iHivPkoqzclF/QctMysfjye8L3R/SCkb56YU
         vUvHMFVmOr9dgkgF4DDaFGAFDzL/m0bNJWpza7jUOSN/Pl04yh3qY6FPRhy3zgOniaTS
         oD/QtV21XbvQ2lZ2kcmj261fnhMxGmAJ1Zmd2xb3F8G+SZtooB5eoJNrXeTpxYY2xe7j
         j6UH2b20IoO7wuGa03aJSN1tNv9GDwIWttYqshL7HcjU4RX4Xvtx5Soshuop1JAVvCT6
         QKdZ0gTOVj1rFzSNPCfDW8XuA5wGq14QoyZq2FEx7F5Tbv/XMEbiitCqG0JUvhAYfnWE
         5uGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=U1oB/y2HwduEW1NJSe6OgBn3Oz8mlhXXlnoX1jU4gn0=;
        fh=bcWKG538OSZgyx/4Kl9mvLo/hpkkjwF9om1mE575Wps=;
        b=Q0lIjxWCk95U/t6XR1O/kciEJAar1MyXSBRpVsxmAgtGxzZXJxNSNtfcvy6ox1gX9C
         TIPOrj/+CqFK4zNRu5sa+bXc5nUgQHeuT6+Cyuo384JQjgaiK1y5nslCrCZaN8k/CcEo
         sfyuBMz6aajJTZDt8dsOZ02ttFasrxtxuEUJ3FIkcv/nFwTITak4UJCCEv1HhejfwBuX
         mTnD4iW5fQf6+9VKtRVGHVJGRjBK1mR/5y5xqrwLe/yQrZlllObRwGcwIIiWyE/Ivyfr
         uWRQax5CrIzOyXuOEf1BPCcdS9almZUU9JRrl1JaPYX/RhMGoLvAR0rKkDCybxil0T+c
         imuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710770393; x=1711375193; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U1oB/y2HwduEW1NJSe6OgBn3Oz8mlhXXlnoX1jU4gn0=;
        b=GvPG3fSrKCl6vOb9MjDncEFJ8JZMOLJtxzlle/B6i3gZTEPN2W+QAfN6V2CSO0Mo3x
         QgkPmDfJA9RHw/CheVOVde/8UlbPcWZmwHdgEK92Fw50gostyS7XFJ+7zFWnpFnRqlpu
         ypjmDKWkkn7+mQThAJrdTwjTmTAX617njR2m5MUUblHmUe8TB2b0L6cOr5qMmak5ZAUj
         9ACyPnMume9khJkzbEqFqSMTrcmZQT6lJ12vAkrhoxtcN9OEq1ZoDFgmNeUKdevpCz/x
         9EO+W5XA3UP9hZl221zAOXF7qBjYSLocLdDA6DDslVQuj4r+DmmY7EcTSmaidr8eYy51
         6DwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710770393; x=1711375193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U1oB/y2HwduEW1NJSe6OgBn3Oz8mlhXXlnoX1jU4gn0=;
        b=OkZdiVrbgS/8YhIYwhFyDqXfF3h5oohTr/UznL142p2joIJC0tmIPLnxVhJKSy+Uuu
         7g+H5WAXbgOQg0m/TD0vKsuzMatzRysRj4G857Y7t55jSzFY3vZoKsg2hjvrZH4U6H/V
         mBzB8nxwjJTVULY2vNJkYXlSADf0eSazWXlPGf/vbygFae4ZH/fmPtJZHy1AODr5vK/0
         I28DZnTISYc4vzstLWwbop7aJZaF9P0dTctgdCgCHIkdRmvRy5guRlyC9A7VS/cbF0Qo
         3FwPtmt87yUC1jA+RczkCgVU3OIopTkCrzIzGlHDqkkCUWs+CiBCjRQMvNI1qBz2UHfM
         fxtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzAprlzlLggPQ/RUMX0y+PBXOb4evXx4md9fHnLbyratHQq2StJPzs9oKtiltdiKUcctFjr08Es+GQM61MsfRbuwK5SiNA8w==
X-Gm-Message-State: AOJu0YxKS/JZdjah/CqJK26Ee9LnYX1wrXNIe0/A3ytqBw8FGJVVjohj
	SzmaczC5uvdT/lY/xb3aZduX7l4eVhnPjaNPedR+Et/WARAZfETV
X-Google-Smtp-Source: AGHT+IGhAE5MeKYOulk58Eo1Nxktkif8dBsCFs8OzREL/wVwlzc1CnnJcXdbk+9XWnUuF3FXlY+MwA==
X-Received: by 2002:a0c:cd11:0:b0:690:c0d2:6fab with SMTP id b17-20020a0ccd11000000b00690c0d26fabmr11981831qvm.16.1710770392973;
        Mon, 18 Mar 2024 06:59:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:224d:b0:68c:d848:72ac with SMTP id
 c13-20020a056214224d00b0068cd84872acls6458500qvc.2.-pod-prod-04-us; Mon, 18
 Mar 2024 06:59:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBKjV5b2l/wWVESV3ZL6SGztlwyOSpRJu/yhJsVXGRNDx6ux+aYdaKr8sfHkjFqvZGfu+eQJJRSYZ605YEmy0FyDB5BhM992qgjg==
X-Received: by 2002:a05:6122:169a:b0:4d4:1cca:1a72 with SMTP id 26-20020a056122169a00b004d41cca1a72mr8346439vkl.6.1710770391893;
        Mon, 18 Mar 2024 06:59:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710770391; cv=none;
        d=google.com; s=arc-20160816;
        b=XBHYuvlpJYj/hPLn5sbrV6u/sAh37RcgexVcz3b/YH+6OGJBHOozkkM2OyuxST4Q3u
         uHdE/+D/GiFKxbRRzf/ShXL8V1bv03VK1fqQDPFBBbBgQp+9sLSGLaw087A7Xgz4x95s
         1O9JekKSQW7XmIxSyAugoDIvPT/0iWegV4ziv1sO+QzQWf5jsepago4GoB8ZVXakOcsT
         d+78sXg0Bg6azaNGaiyd70IvT4+Ahya7rFsito18HXHJkwgy+naNrc0jtU/Sj0+CVRU2
         C9y6Ge+SOusqSY3L0rpVHeGIhIv+9nZDBrQVmF3+JPvL2zNYBvKF1QroKgFCaykRQswy
         C/WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=n9Rp8YeTnXnw58dGkqmYBgPBqpenecVOB0D1D2bXhtA=;
        fh=ohUeQDCQsKg+X75nyjQIpG0C5bpqy/mUWP6Cpnn28GY=;
        b=oZLrDC/pCTUVo0rsnqRvgQPi286lhhcLuVi2eOR9ZBCBFu1FMwM2x8ZW3kvRxGZrNZ
         4I1AibKWq4jqX+8sZxv5oGSr+UXfNbVon8NdNgMN9rTcHE1zMllb44sffAzdnLqDCznA
         61J1Zvtqih/7Y/BF9hUDP9wU3GltumKhSExeu2td5QS4hP8NhfYbxBjNd76GyzZ4nvtv
         K/177+Cyl9buWm6fx+WcGFOYWk6qLJiRPipp8eq1WtxXDe6c4F+UHsfuZwFOYWyDknCw
         NFnr+5j6+GDdV0+RItDBZcHzfDryWn9O4dXnbcovOf12XQeNOitIs4AlMBUoU1Zyy9B9
         cGmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id et2-20020a0561221c0200b004d41fe2c37csi825644vkb.5.2024.03.18.06.59.51
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Mar 2024 06:59:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4A10CDA7;
	Mon, 18 Mar 2024 07:00:26 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.71.172])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D01B03F67D;
	Mon, 18 Mar 2024 06:59:49 -0700 (PDT)
Date: Mon, 18 Mar 2024 13:59:44 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Changbin Du <changbin.du@huawei.com>, elver@google.com,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [BUG] kmsan: instrumentation recursion problems
Message-ID: <ZfhI0F-vXMMw1GzC@FVFF77S0Q05N>
References: <20240308043448.masllzeqwht45d4j@M910t>
 <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
 <20240311093036.44txy57hvhevybsu@M910t>
 <20240311110223.nzsplk6a6lzxmzqi@M910t>
 <ndf5znadjpm4mcscns66bhcgvvykmcou3kjkqy54fcvgtvu7th@vpaomrytk4af>
 <czcb6tjpfu3ry5j6blzkhw5hg2thfkir7xkxholzqqpnv5pj4f@jtdhzoif5m2q>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <czcb6tjpfu3ry5j6blzkhw5hg2thfkir7xkxholzqqpnv5pj4f@jtdhzoif5m2q>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Ilya,

On Wed, Mar 13, 2024 at 02:41:21AM +0100, Ilya Leoshkevich wrote:
> On Wed, Mar 13, 2024 at 12:52:33AM +0100, Ilya Leoshkevich wrote:
> > On Mon, Mar 11, 2024 at 07:02:23PM +0800, Changbin Du wrote:
> > > On Mon, Mar 11, 2024 at 05:30:36PM +0800, Changbin Du wrote:
> > > > On Fri, Mar 08, 2024 at 10:39:15AM +0100, Marco Elver wrote:
> > > > > On Fri, 8 Mar 2024 at 05:36, 'Changbin Du' via kasan-dev
> > > > > <kasan-dev@googlegroups.com> wrote:
> > > > > >
> > > > > > Hey, folks,
> > > > > > I found two instrumentation recursion issues on mainline kernel.
> > > > > >
> > > > > > 1. recur on preempt count.
> > > > > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()
> > > > > >
> > > > > > 2. recur in lockdep and rcu
> > > > > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()
> > > > > >
> > > > > >
> > > > > > Here is an unofficial fix, I don't know if it will generate false reports.
> > > > > >
> > > > > > $ git show
> > > > > > commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
> > > > > > Author: Changbin Du <changbin.du@huawei.com>
> > > > > > Date:   Fri Mar 8 20:21:48 2024 +0800
> > > > > >
> > > > > >     kmsan: fix instrumentation recursions
> > > > > >
> > > > > >     Signed-off-by: Changbin Du <changbin.du@huawei.com>
> > > > > >
> > > > > > diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> > > > > > index 0db4093d17b8..ea925731fa40 100644
> > > > > > --- a/kernel/locking/Makefile
> > > > > > +++ b/kernel/locking/Makefile
> > > > > > @@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
> > > > > >
> > > > > >  # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> > > > > >  KCSAN_SANITIZE_lockdep.o := n
> > > > > > +KMSAN_SANITIZE_lockdep.o := n
> > > > > 
> > > > > This does not result in false positives?
> > > > >
> > > This does result lots of false positives.
> > > 
> > > > I saw a lot of reports but seems not related to this.
> > > > 
> > > > [    2.742743][    T0] BUG: KMSAN: uninit-value in unwind_next_frame+0x3729/0x48a0
> > > > [    2.744404][    T0]  unwind_next_frame+0x3729/0x48a0
> > > > [    2.745623][    T0]  arch_stack_walk+0x1d9/0x2a0
> > > > [    2.746838][    T0]  stack_trace_save+0xb8/0x100
> > > > [    2.747928][    T0]  set_track_prepare+0x88/0x120
> > > > [    2.749095][    T0]  __alloc_object+0x602/0xbe0
> > > > [    2.750200][    T0]  __create_object+0x3f/0x4e0
> > > > [    2.751332][    T0]  pcpu_alloc+0x1e18/0x2b00
> > > > [    2.752401][    T0]  mm_init+0x688/0xb20
> > > > [    2.753436][    T0]  mm_alloc+0xf4/0x180
> > > > [    2.754510][    T0]  poking_init+0x50/0x500
> > > > [    2.755594][    T0]  start_kernel+0x3b0/0xbf0
> > > > [    2.756724][    T0]  __pfx_reserve_bios_regions+0x0/0x10
> > > > [    2.758073][    T0]  x86_64_start_kernel+0x92/0xa0
> > > > [    2.759320][    T0]  secondary_startup_64_no_verify+0x176/0x17b
> > > > 
> > > Above reports are triggered by KMEMLEAK and KFENCE.
> > > 
> > > Now with below fix, I was able to run kmsan kernel with:
> > >   CONFIG_DEBUG_KMEMLEAK=n
> > >   CONFIG_KFENCE=n
> > >   CONFIG_LOCKDEP=n
> > > 
> > > KMEMLEAK and KFENCE generate too many false positives in unwinding code.
> > > LOCKDEP still introduces instrumenting recursions.
> > 
> > FWIW I see the same issue on s390, and the best I could come up with so
> > far was also disabling lockdep.
> > 
> > For KFENCE I have the following [1] though, maybe this will be helpful
> > to you as well?
> > 
> > [1] https://patchwork.kernel.org/project/linux-mm/patch/20231213233605.661251-17-iii@linux.ibm.com/
> > 
> > [...]
> 
> So, I tried to brute force the issue and came up with the following.
> The goal was to minimize the usage of __no_sanitize_memory in order to
> avoid false positives. I don't propose to commit this, I'm posting this
> to highlight the intermediate problems that need to be solved.

Just for the record, as-is the patch below would cause new noinstr-safety
issues, which I've commented on below. So there are likely some larger changes
necessary there.

I reckon the arch/s390/include/asm/preempt.h changes are good as-is; I've been
meaning to do the same for arm64's asm/preempt.h with some other noinstr
cleanups.

> From e3834f4e4ebe2596542a7464f8cc487e2c8e37c9 Mon Sep 17 00:00:00 2001
> From: Ilya Leoshkevich <iii@linux.ibm.com>
> Date: Wed, 13 Mar 2024 01:18:22 +0100
> Subject: [PATCH] s390/kmsan: Fix lockdep recursion
> 
> After commit 5ec8e8ea8b77 ("mm/sparsemem: fix race in accessing
> memory_section->usage"), an infinite mutual recursion between
> kmsan_get_metadata() and lock_acquire() arose.
> 
> Teach lockdep recursion detection to handle it. The goal is to make
> lock_acquire() survive until lockdep_recursion_inc(). This requires
> solving a number of intermediate problems:
> 
> 0. Disable KMSAN checks in lock_acquire().
> 
> 1. lock_acquire() calls instrumented trace_lock_acquire().
>    Force inlining.
> 
> 2. trace_lock_acquire() calls instrumented cpu_online().
>    Force inlining.
> 
> 3: trace_lock_acquire() calls instrumented rcu_is_watching(), which in
>    turn calls instrumented __preempt_count_add().
>    Disable instrumentation in rcu_is_watching().
>    Disabling checks is not enough, because __preempt_count_add() would
>    call __msan_instrument_asm_store().
>    Force inlinining of __preempt_count_add().
> 
> 4: lock_acquire() inlines lockdep_enabled(), which inlines
>    __preempt_count_add(), which calls __msan_instrument_asm_store().
>    Don't inline lockdep_enabled() and disable KMSAN instrumentation in it.
> 
> 5: lock_acquire() calls check_flags(), which calls the instrumented
>    preempt_count().
>    Always inline preempt_count().
> 
> 6: lock_acquire() inlines lockdep_recursion_inc(), which needs to
>    update KMSAN metadata.
>    Do not inline lockdep_recursion_inc(), disable KMSAN instrumentation
>    in it.
> 
> 7: lock_acquire() calls instrumented lockdep_nmi().
>    Force inlining.
> 
> With that, the KMSAN+lockdep kernel boots again, but unfortunately it
> is very slow.
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/preempt.h | 12 ++++++------
>  include/linux/cpumask.h         |  2 +-
>  include/linux/tracepoint.h      |  2 +-
>  kernel/locking/lockdep.c        | 10 +++++++---
>  kernel/rcu/tree.c               |  1 +
>  5 files changed, 16 insertions(+), 11 deletions(-)
> 
> diff --git a/arch/s390/include/asm/preempt.h b/arch/s390/include/asm/preempt.h
> index bf15da0fedbc..225ce14bb0d6 100644
> --- a/arch/s390/include/asm/preempt.h
> +++ b/arch/s390/include/asm/preempt.h
> @@ -12,7 +12,7 @@
>  #define PREEMPT_NEED_RESCHED	0x80000000
>  #define PREEMPT_ENABLED	(0 + PREEMPT_NEED_RESCHED)
>  
> -static inline int preempt_count(void)
> +static __always_inline int preempt_count(void)
>  {
>  	return READ_ONCE(S390_lowcore.preempt_count) & ~PREEMPT_NEED_RESCHED;
>  }
> @@ -44,7 +44,7 @@ static inline bool test_preempt_need_resched(void)
>  	return !(READ_ONCE(S390_lowcore.preempt_count) & PREEMPT_NEED_RESCHED);
>  }
>  
> -static inline void __preempt_count_add(int val)
> +static __always_inline void __preempt_count_add(int val)
>  {
>  	/*
>  	 * With some obscure config options and CONFIG_PROFILE_ALL_BRANCHES
> @@ -59,7 +59,7 @@ static inline void __preempt_count_add(int val)
>  	__atomic_add(val, &S390_lowcore.preempt_count);
>  }
>  
> -static inline void __preempt_count_sub(int val)
> +static __always_inline void __preempt_count_sub(int val)
>  {
>  	__preempt_count_add(-val);
>  }
> @@ -79,7 +79,7 @@ static inline bool should_resched(int preempt_offset)
>  
>  #define PREEMPT_ENABLED	(0)
>  
> -static inline int preempt_count(void)
> +static __always_inline int preempt_count(void)
>  {
>  	return READ_ONCE(S390_lowcore.preempt_count);
>  }
> @@ -102,12 +102,12 @@ static inline bool test_preempt_need_resched(void)
>  	return false;
>  }
>  
> -static inline void __preempt_count_add(int val)
> +static __always_inline void __preempt_count_add(int val)
>  {
>  	S390_lowcore.preempt_count += val;
>  }
>  
> -static inline void __preempt_count_sub(int val)
> +static __always_inline void __preempt_count_sub(int val)
>  {
>  	S390_lowcore.preempt_count -= val;
>  }

FWIW, I think it's worthwhile to make these preempt functions __always_inline
now; they're already used by noinstr code, and *not* being __always_inline
could permit unwanted instrumentation today.

So it's probably worth splitting that out into its own patch.

> diff --git a/include/linux/cpumask.h b/include/linux/cpumask.h
> index cfb545841a2c..af6515e5def8 100644
> --- a/include/linux/cpumask.h
> +++ b/include/linux/cpumask.h
> @@ -1099,7 +1099,7 @@ static __always_inline unsigned int num_online_cpus(void)
>  #define num_present_cpus()	cpumask_weight(cpu_present_mask)
>  #define num_active_cpus()	cpumask_weight(cpu_active_mask)
>  
> -static inline bool cpu_online(unsigned int cpu)
> +static __always_inline bool cpu_online(unsigned int cpu)
>  {
>  	return cpumask_test_cpu(cpu, cpu_online_mask);
>  }
> diff --git a/include/linux/tracepoint.h b/include/linux/tracepoint.h
> index 88c0ba623ee6..34bc35aa2f4b 100644
> --- a/include/linux/tracepoint.h
> +++ b/include/linux/tracepoint.h
> @@ -252,7 +252,7 @@ static inline struct tracepoint *tracepoint_ptr_deref(tracepoint_ptr_t *p)
>  	extern int __traceiter_##name(data_proto);			\
>  	DECLARE_STATIC_CALL(tp_func_##name, __traceiter_##name);	\
>  	extern struct tracepoint __tracepoint_##name;			\
> -	static inline void trace_##name(proto)				\
> +	static __always_inline void trace_##name(proto)			\
>  	{								\
>  		if (static_key_false(&__tracepoint_##name.key))		\
>  			__DO_TRACE(name,				\
> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> index 151bd3de5936..86244a7e8533 100644
> --- a/kernel/locking/lockdep.c
> +++ b/kernel/locking/lockdep.c
> @@ -111,7 +111,8 @@ late_initcall(kernel_lockdep_sysctls_init);
>  DEFINE_PER_CPU(unsigned int, lockdep_recursion);
>  EXPORT_PER_CPU_SYMBOL_GPL(lockdep_recursion);
>  
> -static __always_inline bool lockdep_enabled(void)
> +__no_sanitize_memory
> +static noinline bool lockdep_enabled(void)
>  {
>  	if (!debug_locks)
>  		return false;
> @@ -457,7 +458,8 @@ void lockdep_init_task(struct task_struct *task)
>  	task->lockdep_recursion = 0;
>  }

This needs to be __always_inline or noinstr, as it is used by noninstr code
(e.g. lock_is_held_type()).

>  
> -static __always_inline void lockdep_recursion_inc(void)
> +__no_sanitize_memory
> +static noinline void lockdep_recursion_inc(void)
>  {
>  	__this_cpu_inc(lockdep_recursion);
>  }

Likewise.

Mark.

> @@ -5687,7 +5689,7 @@ static void verify_lock_unused(struct lockdep_map *lock, struct held_lock *hlock
>  #endif
>  }
>  
> -static bool lockdep_nmi(void)
> +static __always_inline bool lockdep_nmi(void)
>  {
>  	if (raw_cpu_read(lockdep_recursion))
>  		return false;
> @@ -5716,6 +5718,7 @@ EXPORT_SYMBOL_GPL(read_lock_is_recursive);
>   * We are not always called with irqs disabled - do that here,
>   * and also avoid lockdep recursion:
>   */
> +__no_kmsan_checks
>  void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>  			  int trylock, int read, int check,
>  			  struct lockdep_map *nest_lock, unsigned long ip)
> @@ -5758,6 +5761,7 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>  }
>  EXPORT_SYMBOL_GPL(lock_acquire);
>  
> +__no_kmsan_checks
>  void lock_release(struct lockdep_map *lock, unsigned long ip)
>  {
>  	unsigned long flags;
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index d9642dd06c25..8c587627618e 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -692,6 +692,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
>   * Make notrace because it can be called by the internal functions of
>   * ftrace, and making this notrace removes unnecessary recursion calls.
>   */
> +__no_sanitize_memory
>  notrace bool rcu_is_watching(void)
>  {
>  	bool ret;
> -- 
> 2.44.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZfhI0F-vXMMw1GzC%40FVFF77S0Q05N.
