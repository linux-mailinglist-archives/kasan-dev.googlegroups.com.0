Return-Path: <kasan-dev+bncBDKJVFPCVIJBB5MYUT7AKGQEML6G4BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 88CB92CDA9A
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 17:04:06 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id w8sf3290631ybq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 08:04:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607011445; cv=pass;
        d=google.com; s=arc-20160816;
        b=xQBd6iBYD9VvFZB8lyxUVGWYaGEuQwGIlDeG80zJHmSFY11I6bNXGtoztaEXAzn/z1
         cHzNCmZr3Z7e3SdGG0fW4vmSYqslioG2B5reJEYJ9Y/u+uipMtlP/1jAq37/rgJzVd8e
         UzvSB7uRivM4eKi/Q56L9eA20ePEuRThUXBOxIE0zgqj/hZSGbaeByAi93nBGULk8cxb
         VVfZPUa0jsEsxg9gjVGGnAkCGppv6VX1s5ehuWK/MPU5QoHBkPUAiQ25GQYBF4vqn1IT
         KF7oUgkaqtK3WlChwKPtHXsZ3ycu8BA8uAjaRnSMl4LQEgW4DSP8fH6U8NRwHzPGBIc4
         En8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=JduCykdBKOFOSa4uPvkx77AO2r6z8ZetpiGTt1bKz4k=;
        b=xv/xrqhn47ZXTTjyhCFweV88HUSjUsFIHEJW6bV8NVTcDS46CnWNP3EWcwE/js1r9t
         Uj1BT4AFkSYlRaqZ0l+4Jd8Hcr3YaRkyzwOW7hwT0PrT07Ri3tcAIIxayGZ9gc0Lc8n4
         c9Hz13Cvi2DEnzjNqVWF/x3c4MzfGFXyJRnuTVW2LUAcm3a06E5OO/xIsmHElbpVPgcV
         FINQsK3+II1tXNGplJeczZCCcausHaYd9DjHqG1k9HpWh3EFX1erfgUccbYhv28jYPO4
         13/TA8h9tgZXi8Uv6Y+8cv03HMqtUKjvKh+ejO3uZmlUIcO8rA+dneGy8N8C3KbrEKOK
         mfTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NdKVsRCm;
       spf=pass (google.com: domain of qcai@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=qcai@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JduCykdBKOFOSa4uPvkx77AO2r6z8ZetpiGTt1bKz4k=;
        b=l5MEwJ76nBgvF6EA9G5T1MYLSDuWyvErKN6ScZvwR7hP5a4ZoeyQDnNYSGW8n+BS1h
         D64Cldu8A0r6Tm7THNWWwdgp9XFe7GG1dC4V6mn8YNg50gz6fyHi32PzjDN/r0bWTxzE
         9Gz7FpSYguzJ/o88F7vENSjuSvQIX5cGY64VN3BeNuMvBUSCneCrW9nHp6p/FrlyptlM
         uD1/Y5oalATKMs41RbF3ivH2myn6DAsZCnEhJeTrlsJMoOxcGg/B1hsXDso7YFSMu3SB
         wlgOr/nHByOdHxlc1NIfJcipRdfZPXdqv2rggjH1q1BBg85aXYT2esOSXb7sq4uMhkcH
         ddsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JduCykdBKOFOSa4uPvkx77AO2r6z8ZetpiGTt1bKz4k=;
        b=ZI2bJvA7GpqgfFhQ/hAGFMKEQr6X3adqvQd1XO1Mxl78lnXP4shVT/wY/cgXVOdBpP
         MNn2zMs+CxEO7iJYk84bIq4UYxj1H6QoG04c25RSfihYF7uCFDIJCaXsiuVgoX3Duhwn
         qod54FIfW6MLaIfqwfxm9lnafuQhrdnrNd6Q5PhZux76SKNKDfluEkkB/UgHAyqM7RBT
         kJNJAEpKZDt2muNoGEklAeKqi0X12XPkQje6PUPcEZvcTMmzhm4HoXaO3PXAD9VtTs0Q
         DgNKiWUeYDT4emFH3zJ1AnJ2Pm/rUZPfBRrurqs0OEC5PPZR2I/KJK8sEZn6IUMO+RNQ
         rlBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eDmFVuG/7+BICdCQTdmVLiPDCUk19Vfx5mXUZej9SNF/7FbX7
	00WmZybSNVVNLn/Miozl89c=
X-Google-Smtp-Source: ABdhPJxnswwvgP8eKkfsYGsdWB5wh/UFq8MVzVnAJm/4cxKoNK9xomSAX4omvttAZZJW2fGzF5dz9w==
X-Received: by 2002:a25:738d:: with SMTP id o135mr5215392ybc.349.1607011445429;
        Thu, 03 Dec 2020 08:04:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b581:: with SMTP id q1ls2947358ybj.6.gmail; Thu, 03 Dec
 2020 08:04:05 -0800 (PST)
X-Received: by 2002:a25:70d5:: with SMTP id l204mr5424817ybc.19.1607011444955;
        Thu, 03 Dec 2020 08:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607011444; cv=none;
        d=google.com; s=arc-20160816;
        b=N3gpYOQQP6YtNshpR9FDJG5F4g82eCpdgi23AuGT4C9TikWG502QvJZtXxLEyEDDvm
         MJ9E0cVzr5LLRytJz2bgp56DQPoxLYibMyd6TnrqLzNMKmE/eoVlOfZ+Q1zCPlIKLVAm
         zI15uvWEwsYnnPCmJF3uSyL1R6hGPkb0FmGN3VylaW4QQWqtPp9wuGWwc4d2CQltCE/9
         qhGDiQmeZKrgOTlLGY0+2Jc6D4W4FSj32JrjzAs136ON+hjjgeOdDHzPqfkurdvpv16L
         BzD8BIp6X6FTqGD2oNWhayjDMvPJl6vTGLv2mXvKzPnDvLgbdZStOXgiOxQYavuXheJt
         EeNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=Hr22txaoNLWqIIxA6KQdTOKASYpvNDdZFmcQSpDcxdk=;
        b=RbZ2p/eIaZe7449S7v6x8OuhR8urQmHove3RnYqTnoi+27aZPSHI+gboTjkKhyHARU
         gCR0WA8a/7+pxnjeCb87cLPRP7waCLTirl6E2s3By0mkN+SXy6iuEhVga13lD1K8kLWS
         J8KleSwVS7fhyA9J9kyIqz9sSha2duXmR8/HbWf8z+KhvighE/jnGQ2HhwglV/aZkffk
         mzZotckLlUnsQQiH3CFWaH3dRkucbDCRr8P2HR3an4747dMUEL3sgXKVxGsx6Gbi8RzD
         MUfEzgRq2watovaHaXm/DiHZyQrg91eqG01MJjIcDCietbjnhXeKwVdo2wGxE0Qa26xE
         FAuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NdKVsRCm;
       spf=pass (google.com: domain of qcai@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=qcai@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id e4si181124ybp.4.2020.12.03.08.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Dec 2020 08:04:04 -0800 (PST)
Received-SPF: pass (google.com: domain of qcai@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-582-GaqNXf5rPDaJQJAgyB5ReA-1; Thu, 03 Dec 2020 11:03:54 -0500
X-MC-Unique: GaqNXf5rPDaJQJAgyB5ReA-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 90A4B2AB;
	Thu,  3 Dec 2020 16:03:40 +0000 (UTC)
Received: from ovpn-66-132.rdu2.redhat.com (unknown [10.10.67.132])
	by smtp.corp.redhat.com (Postfix) with ESMTP id F164B1002C11;
	Thu,  3 Dec 2020 16:03:36 +0000 (UTC)
Message-ID: <7733019eb8c506eee8d29e380aae683a8972fd19.camel@redhat.com>
Subject: Re: [PATCH v2] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
From: Qian Cai <qcai@redhat.com>
To: vjitta@codeaurora.org, minchan@kernel.org, glider@google.com, 
	dan.j.williams@intel.com, broonie@kernel.org, mhiramat@kernel.org
Cc: linux-kernel@vger.kernel.org, akpm@linux-foundation.org, 
	ylal@codeaurora.org, vinmenon@codeaurora.org, kasan-dev@googlegroups.com, 
	sfr@canb.auug.org.au, linux-next@vger.kernel.org
Date: Thu, 03 Dec 2020 11:03:36 -0500
In-Reply-To: <1606365835-3242-1-git-send-email-vjitta@codeaurora.org>
References: <1606365835-3242-1-git-send-email-vjitta@codeaurora.org>
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: qcai@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NdKVsRCm;
       spf=pass (google.com: domain of qcai@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=qcai@redhat.com;
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

On Thu, 2020-11-26 at 10:13 +0530, vjitta@codeaurora.org wrote:
> From: Yogesh Lal <ylal@codeaurora.org>
> 
> Add a kernel parameter stack_hash_order to configure STACK_HASH_SIZE.
> 
> Aim is to have configurable value for STACK_HASH_SIZE, so that one
> can configure it depending on usecase there by reducing the static
> memory overhead.
> 
> One example is of Page Owner, default value of STACK_HASH_SIZE lead
> stack depot to consume 8MB of static memory. Making it configurable
> and use lower value helps to enable features like CONFIG_PAGE_OWNER
> without any significant overhead.
> 
> Suggested-by: Minchan Kim <minchan@kernel.org>
> Signed-off-by: Yogesh Lal <ylal@codeaurora.org>
> Signed-off-by: Vijayanand Jitta <vjitta@codeaurora.org>

Reverting this commit on today's linux-next fixed boot crash with KASAN.

.config:
https://cailca.coding.net/public/linux/mm/git/files/master/x86.config
https://cailca.coding.net/public/linux/mm/git/files/master/arm64.config


[    5.135848][    T0] random: get_random_u64 called from __kmem_cache_create+0x2e/0x490 with crng_init=0
[    5.135909][    T0] BUG: unable to handle page fault for address: 00000000002ac6d0
[    5.152733][    T0] #PF: supervisor read access in kernel mode
[    5.158585][    T0] #PF: error_code(0x0000) - not-present page
[    5.164438][    T0] PGD 0 P4D 0 
[    5.167670][    T0] Oops: 0000 [#1] SMP KASAN NOPTI
[    5.172566][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.10.0-rc6-next-20201203+ #3
[    5.180685][    T0] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385 Gen10, BIOS A40 07/10/2019
[    5.189950][    T0] RIP: 0010:stack_depot_save+0xf4/0x460
stack_depot_save at lib/stackdepot.c:272
[    5.195362][    T0] Code: 00 00 83 ff 01 0f 84 b3 00 00 00 8b 0d 35 67 39 08 b8 01 00 00 00 48 d3 e0 48 8b 0d 46 9c 27 11 48 83 e8 01 21 d8 4c 8d 34 c1 <4d> 8b 2e 4d 85 ed 0f 84 ca 00 00 00 41 8d 74 24 ff 48 c1 e6 03 eb
[    5.214927][    T0] RSP: 0000:ffffffff99007c18 EFLAGS: 00010002
[    5.220865][    T0] RAX: 00000000000558da RBX: 00000000caa558da RCX: 0000000000000000
[    5.228726][    T0] RDX: 0000000000000cc0 RSI: 00000000e11e461a RDI: 0000000000000001
[    5.236590][    T0] RBP: ffffffff99007c68 R08: 000000002ff39dab R09: 0000000000000007
[    5.244450][    T0] R10: ffffffff99007b60 R11: 0000000000000005 R12: 0000000000000008
[    5.252313][    T0] R13: ffff8881000400b7 R14: 00000000002ac6d0 R15: 0000000000000078
[    5.260173][    T0] FS:  0000000000000000(0000) GS:ffff88881e800000(0000) knlGS:0000000000000000
[    5.268996][    T0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    5.275674][    T0] CR2: 00000000002ac6d0 CR3: 0000000cc8814000 CR4: 00000000000406b0
[    5.283534][    T0] Call Trace:
[    5.286687][    T0]  kasan_save_stack+0x2f/0x40
[    5.291225][    T0]  ? kasan_save_stack+0x19/0x40
[    5.295939][    T0]  ? ____kasan_kmalloc.constprop.8+0x85/0xa0
[    5.301793][    T0]  ? __kmem_cache_create+0x26a/0x490
[    5.306950][    T0]  ? create_boot_cache+0x75/0x98
[    5.311751][    T0]  ? kmem_cache_init+0x42/0x146
[    5.316471][    T0]  ? mm_init+0x64/0x87
[    5.320399][    T0]  ? start_kernel+0x14c/0x3a7
[    5.324945][    T0]  ? secondary_startup_64_no_verify+0xc2/0xcb
[    5.330885][    T0]  ? lockdep_hardirqs_on_prepare+0x3d0/0x3d0
[    5.336733][    T0]  ? lockdep_hardirqs_on_prepare+0x3d0/0x3d0
[    5.342590][    T0]  ? __isolate_free_page+0x540/0x540
[    5.347742][    T0]  ? find_held_lock+0x33/0x1c0
[    5.352371][    T0]  ? __alloc_pages_nodemask+0x534/0x700
[    5.357784][    T0]  ? __alloc_pages_slowpath.constprop.110+0x20f0/0x20f0
[    5.364600][    T0]  ? __kasan_init_slab_obj+0x20/0x30
[    5.369753][    T0]  ? unpoison_range+0xf/0x30
[    5.374207][    T0]  ____kasan_kmalloc.constprop.8+0x85/0xa0
kasan_set_track at mm/kasan/common.c:47
(inlined by) set_alloc_info at mm/kasan/common.c:405
(inlined by) ____kasan_kmalloc at mm/kasan/common.c:436
[    5.379886][    T0]  __kmem_cache_create+0x26a/0x490
early_kmem_cache_node_alloc at mm/slub.c:3566
(inlined by) init_kmem_cache_nodes at mm/slub.c:3606
(inlined by) kmem_cache_open at mm/slub.c:3858
(inlined by) __kmem_cache_create at mm/slub.c:4468
[    5.384864][    T0]  create_boot_cache+0x75/0x98
create_boot_cache at mm/slab_common.c:568
[    5.389493][    T0]  kmem_cache_init+0x42/0x146
[    5.394035][    T0]  mm_init+0x64/0x87
[    5.397791][    T0]  start_kernel+0x14c/0x3a7
[    5.402159][    T0]  ? copy_bootdata+0x19/0x47
[    5.406615][    T0]  secondary_startup_64_no_verify+0xc2/0xcb
[    5.412380][    T0] Modules linked in:
[    5.416136][    T0] CR2: 00000000002ac6d0
[    5.420158][    T0] ---[ end trace c97cf41616dddbe6 ]---
[    5.425483][    T0] RIP: 0010:stack_depot_save+0xf4/0x460
[    5.430898][    T0] Code: 00 00 83 ff 01 0f 84 b3 00 00 00 8b 0d 35 67 39 08 b8 01 00 00 00 48 d3 e0 48 8b 0d 46 9c 27 11 48 83 e8 01 21 d8 4c 8d 34 c1 <4d> 8b 2e 4d 85 ed 0f 84 ca 00 00 00 41 8d 74 24 ff 48 c1 e6 03 eb
[    5.450464][    T0] RSP: 0000:ffffffff99007c18 EFLAGS: 00010002
[    5.456403][    T0] RAX: 00000000000558da RBX: 00000000caa558da RCX: 0000000000000000
[    5.464264][    T0] RDX: 0000000000000cc0 RSI: 00000000e11e461a RDI: 0000000000000001
[    5.472127][    T0] RBP: ffffffff99007c68 R08: 000000002ff39dab R09: 0000000000000007
[    5.479988][    T0] R10: ffffffff99007b60 R11: 0000000000000005 R12: 0000000000000008
[    5.487849][    T0] R13: ffff8881000400b7 R14: 00000000002ac6d0 R15: 0000000000000078
[    5.495712][    T0] FS:  0000000000000000(0000) GS:ffff88881e800000(0000) knlGS:0000000000000000
[    5.504534][    T0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    5.510998][    T0] CR2: 00000000002ac6d0 CR3: 0000000cc8814000 CR4: 00000000000406b0
[    5.518860][    T0] Kernel panic - not syncing: Fatal exception
[    5.524915][    T0] ---[ end Kernel panic - not syncing: Fatal exception ]---

> ---
>  lib/stackdepot.c | 27 ++++++++++++++++++++++-----
>  1 file changed, 22 insertions(+), 5 deletions(-)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 81c69c0..ce53598 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -141,14 +141,31 @@ static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
>  	return stack;
>  }
>  
> -#define STACK_HASH_ORDER 20
> -#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
> +static unsigned int stack_hash_order = 20;
> +#define STACK_HASH_SIZE (1L << stack_hash_order)
>  #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
>  #define STACK_HASH_SEED 0x9747b28c
>  
> -static struct stack_record *stack_table[STACK_HASH_SIZE] = {
> -	[0 ...	STACK_HASH_SIZE - 1] = NULL
> -};
> +static struct stack_record **stack_table;
> +
> +static int __init setup_stack_hash_order(char *str)
> +{
> +	kstrtouint(str, 0, &stack_hash_order);
> +	return 0;
> +}
> +early_param("stack_hash_order", setup_stack_hash_order);
> +
> +static int __init init_stackdepot(void)
> +{
> +	int i;
> +
> +	stack_table = kvmalloc(sizeof(struct stack_record *) * STACK_HASH_SIZE, GFP_KERNEL);
> +	for (i = 0; i < STACK_HASH_SIZE; i++)
> +		stack_table[i] = NULL;
> +	return 0;
> +}
> +
> +early_initcall(init_stackdepot);
>  
>  /* Calculate hash for a stack */
>  static inline u32 hash_stack(unsigned long *entries, unsigned int size)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7733019eb8c506eee8d29e380aae683a8972fd19.camel%40redhat.com.
