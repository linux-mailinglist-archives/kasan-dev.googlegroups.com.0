Return-Path: <kasan-dev+bncBC32535MUICBBWFY7OMQMGQEVWYQECI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B105D5F6876
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:47:06 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id v4-20020aa78504000000b0056186e60814sf1183434pfn.19
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:47:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665064025; cv=pass;
        d=google.com; s=arc-20160816;
        b=LTCbmgvvfaLHjOvaZxb2jZG+U32jZUNpXHViacik6ZXJu7lqgNg6pc0oD3fU/LI4Wy
         cJgb1FxW1VqwOS65jcBHAb8cCgbZ2cCbcaSgAokROXaT3/e21aLA68kHdW4TmEREKJPN
         sZ2sEGukl5ZQiL6fIIRgy2VzLyyE9uFt/LDm+P7OMgOvh5sr3GLz3OS5NAXcvJMLoywB
         W2iQdBgelQ+gic2hZbXyTPPpcUyuK54fcOFwgQPZLlf7CGuJaBFRdiQABbZRByr2E504
         yAXI7HWbocW1leEOZXH5l02QRWtiht4w1a+EPG5CeL9GP6meeyGH5PTm+zjMqs8+sGVi
         y6+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:subject:cc:to
         :organization:from:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=VqmN26vKiYquECOXxpDwhpkVxjHn9hz2xQFAyTFVKNE=;
        b=ik0ejmuCJDB2GoK7EE/VlyYYNGqsy8Q2tlwzZykhrVCH3O5VRM9i21iuA9cDbpMVSm
         dt3upynHgyIJhR4oxCqdkLCfgC9Flrdyl+E5E2Sjz1BJPcU1aZhVAigBfubyk5GH6z7x
         2x8QwLAaOQkqhgyYFFzBTVFIn3wlyWaIHea5IcW6sUPsf4qO5XpWhBfj4bTKnaVQ0Yxw
         C0oczTL62E8SV3TTngRsSJBnOyhcKfPDAOiJG6WUIzRaL0DCE474qC9DLO9KAHYuE2+B
         bAFy+995IsFACjQYp7P6O2zUTbYihKulDl+b279wRCDcuyRbwslw/EF7c3yc+d9mAaqK
         Kwcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UKKk5Ljj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:subject:cc:to:organization:from
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=VqmN26vKiYquECOXxpDwhpkVxjHn9hz2xQFAyTFVKNE=;
        b=QHwWgfZxF3guCeFt/b8gvKJjbb6iIAnUDgSg3gwH7Kx5bnenmzcGxNQzhHyEde29HT
         QS+1nBkMyvhP0Lpm9jIyFVnioIyjFFqYWwZe8CgJyXgx53lKtCko75x2cfEOdDx0L2Fm
         SAd7hG/w56FangSHkEGHHIMXTTCthhW6NdiCqw9B7pefYepWiQjw53oPkkwbPQjTw7wL
         stgR+YF/ZOhnrK8lfIAOJjq6PuoxxMwif5oLICoVvBkczHa8kkGNGCgFH/fwv0kk00Vj
         foGOG+qwUyeYAueSsTn3qCKUVyj+tMuznMeUxLGTZbiNd2k0zQXHoQhLTomR15d1qKFl
         EUMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:subject:cc:to:organization:from:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VqmN26vKiYquECOXxpDwhpkVxjHn9hz2xQFAyTFVKNE=;
        b=o7jHSZALTMHbQG2aqBAAYICYBaq6MLr2g5oB7nmf7VutgU2ZWN7L7/J1Ffm65ZjIcZ
         C8cH40si8cLpG08/anNLD0+Ox/6+zSHxLPi9v1A0oXMvbZal47i5HH2rlwOzaDxjaX6d
         WXFkwAGh4WXNm2XfH8S5yKU6P8Jhm7T1jnrbhJc/YcGXsSkRJtuaAzTi/TVunGC0Sp+o
         t+MKNqbEjiWv8Eu5dwDhkzIAq1gmWIGKYq/VP6TOXS5gFwfObkcqqSK66aFpJZZcOLTd
         OtIKMZNrTrVDV2HTC3YUZEitE3DH/eGFmhPgm1kNCHZOhgCgvQYkDr7n45vWzulzcLAT
         nQtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1kHA5SGukHOxxqdS5hxvNSR2D/J+jEYG8VPx4vftbjXFvilyAw
	LKNq1PxBgjAl3ahPMiZ73Rc=
X-Google-Smtp-Source: AMsMyM68XlIzMlrlR3qkR9CvvueVpDHzRjbYWnodeVjPWiWCq28ZA0gx+hmTHTPLSjbVT/vMJ3mpbg==
X-Received: by 2002:aa7:85d7:0:b0:562:6079:3481 with SMTP id z23-20020aa785d7000000b0056260793481mr2730pfn.77.1665064025116;
        Thu, 06 Oct 2022 06:47:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6aca:0:b0:434:cb11:5486 with SMTP id f193-20020a636aca000000b00434cb115486ls1151244pgc.5.-pod-prod-gmail;
 Thu, 06 Oct 2022 06:47:04 -0700 (PDT)
X-Received: by 2002:a63:ff5a:0:b0:42c:61f:b81 with SMTP id s26-20020a63ff5a000000b0042c061f0b81mr38333pgk.254.1665064024223;
        Thu, 06 Oct 2022 06:47:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665064024; cv=none;
        d=google.com; s=arc-20160816;
        b=QsnnvkpYIxsT77f5vW7rx9qMJxk7W3sf/bwTMcyjavDt9jqlQF10UUg+84h1I/AHXB
         FksQ0trIzOHKyAzQx+zMn3e/C/W0jXHCny3uNNwoUm5BrKTcmpkTudEVg4G7iEj4vQfa
         LoCraLm20rbOXo0NQMfnq9LhacIFkRtI7yrpytUvwla7SCIqXnSajMsxubv5Dw3TWg7w
         fss0bU8lvhtjAI67Xut51zp9n+UZ1Of8Pguj0ZWeSymk3SsMbY++Egv3w8pBSi3iXzRP
         YxdgVXUpFm1wkkT5IzMorWX0Q/HkHIQ1eQ9Brkpgh7Ed3AQwV8Clgkh4WpvY6Jjrr5cg
         EsZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:subject:cc:to
         :organization:from:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Skvbx9xbdFNqMOGk1nVf/Aq3EKcM8w6ila1egEkLVWg=;
        b=ycd3gqx+LCqCbcDiM12mhnvFH6oN+bHj91exB2YFMiFDjLHSDQTiGpXqMLzClpeq93
         TWkvUNOLj+MMIhppczyTvfiEP6MkK8fmFbhBiCLA5aLPhNN4baQxeV8sazUajRuEhSKb
         yyPNtvFvGNqHf/zxpWdtPtynIIgdLPMqSioVfir8+CYap4j6hNqtZ1bP4cz77d2aKXz2
         RJyVFJ13L5ykmZRC84Ty9mloXjyOKlGUejBN0aOxInyLm4eiHFuO2ebySbWAHF7LUbxI
         rRT1uMuEkmb59nxs1feumXP43HLrlIdD+JjBgsQmEgyLT/WWHblOgTzmSwj+3BfeVSiR
         o7mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UKKk5Ljj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ne1-20020a17090b374100b0020a605eff06si185145pjb.2.2022.10.06.06.47.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:47:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-627-wdQ-iXnQPMuP1mn0S8NDOA-1; Thu, 06 Oct 2022 09:47:02 -0400
X-MC-Unique: wdQ-iXnQPMuP1mn0S8NDOA-1
Received: by mail-wm1-f71.google.com with SMTP id f25-20020a7bc8d9000000b003b4768dcd9cso591915wml.9
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 06:47:01 -0700 (PDT)
X-Received: by 2002:a05:6000:1d93:b0:22e:5d8a:c8f8 with SMTP id bk19-20020a0560001d9300b0022e5d8ac8f8mr34334wrb.324.1665064020979;
        Thu, 06 Oct 2022 06:47:00 -0700 (PDT)
X-Received: by 2002:a05:6000:1d93:b0:22e:5d8a:c8f8 with SMTP id bk19-20020a0560001d9300b0022e5d8ac8f8mr34318wrb.324.1665064020609;
        Thu, 06 Oct 2022 06:47:00 -0700 (PDT)
Received: from ?IPV6:2003:cb:c705:3700:aed2:a0f8:c270:7f30? (p200300cbc7053700aed2a0f8c2707f30.dip0.t-ipconnect.de. [2003:cb:c705:3700:aed2:a0f8:c270:7f30])
        by smtp.gmail.com with ESMTPSA id f62-20020a1c3841000000b003b31fc77407sm5605467wma.30.2022.10.06.06.46.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:47:00 -0700 (PDT)
Message-ID: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
Date: Thu, 6 Oct 2022 15:46:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
To: Alexander Potapenko <glider@google.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: "linux-mm@kvack.org" <linux-mm@kvack.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com
Subject: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UKKk5Ljj;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

we're currently hitting a weird vmap issue in debug kernels with KASAN enabled
on fairly large VMs. I reproduced it on v5.19 (did not get the chance to
try 6.0 yet because I don't have access to the machine right now, but
I suspect it persists).

It seems to trigger when udev probes a massive amount of devices in parallel
while the system is booting up. Once the system booted, I no longer see any
such issues.


[  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.836622] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
[  165.837461] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
[  165.840573] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.841059] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.841428] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.841819] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.842123] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.843359] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.844894] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
[  165.847028] CPU: 253 PID: 4995 Comm: systemd-udevd Not tainted 5.19.0 #2
[  165.935689] Hardware name: Lenovo ThinkSystem SR950 -[7X12ABC1WW]-/-[7X12ABC1WW]-, BIOS -[PSE130O-1.81]- 05/20/2020
[  165.947343] Call Trace:
[  165.950075]  <TASK>
[  165.952425]  dump_stack_lvl+0x57/0x81
[  165.956532]  warn_alloc.cold+0x95/0x18a
[  165.960836]  ? zone_watermark_ok_safe+0x240/0x240
[  165.966100]  ? slab_free_freelist_hook+0x11d/0x1d0
[  165.971461]  ? __get_vm_area_node+0x2af/0x360
[  165.976341]  ? __get_vm_area_node+0x2af/0x360
[  165.981219]  __vmalloc_node_range+0x291/0x560
[  165.986087]  ? __mutex_unlock_slowpath+0x161/0x5e0
[  165.991447]  ? move_module+0x4c/0x630
[  165.995547]  ? vfree_atomic+0xa0/0xa0
[  165.999647]  ? move_module+0x4c/0x630
[  166.003741]  module_alloc+0xe7/0x170
[  166.007747]  ? move_module+0x4c/0x630
[  166.011840]  move_module+0x4c/0x630
[  166.015751]  layout_and_allocate+0x32c/0x560
[  166.020519]  load_module+0x8e0/0x25c0
[  166.024623]  ? layout_and_allocate+0x560/0x560
[  166.029586]  ? kernel_read_file+0x286/0x6b0
[  166.034269]  ? __x64_sys_fspick+0x290/0x290
[  166.038946]  ? userfaultfd_unmap_prep+0x430/0x430
[  166.044203]  ? lock_downgrade+0x130/0x130
[  166.048698]  ? __do_sys_finit_module+0x11a/0x1c0
[  166.053854]  __do_sys_finit_module+0x11a/0x1c0
[  166.058818]  ? __ia32_sys_init_module+0xa0/0xa0
[  166.063882]  ? __seccomp_filter+0x92/0x930
[  166.068494]  do_syscall_64+0x59/0x90
[  166.072492]  ? do_syscall_64+0x69/0x90
[  166.076679]  ? do_syscall_64+0x69/0x90
[  166.080864]  ? do_syscall_64+0x69/0x90
[  166.085047]  ? asm_sysvec_apic_timer_interrupt+0x16/0x20
[  166.090984]  ? lockdep_hardirqs_on+0x79/0x100
[  166.095855]  entry_SYSCALL_64_after_hwframe+0x63/0xcd



Some facts:

1. The #CPUs seems to be more important than the #MEM

Initially we thought the memory size would be the relevant trigger,
because we've only seen it on 8TiB machines. But I was able to
reproduce also on a "small" machine with ~450GiB.

We've seen this issue only on machines with a lot (~448) logical CPUs.

On such systems, I was not able to reproduce when booting the kernel with
"nosmt" so far, which could indicate some kind of concurrency problem.


2. CONFIG_KASAN_INLINE seems to be relevant

This issue only seems to trigger with KASAN enabled, and what I can tell,
only with CONFIG_KASAN_INLINE=y:

CONFIG_KASAN_INLINE: "but makes the kernel's .text size much bigger.", that
should include kernel module to be loaded.


3. All systems have 8, equally sized NUMA nodes

... which implies, that at least one node is practically completely filled with
KASAN data. I remember adjusting the system size with "mem=", such that some
nodes were memory-less but NODE 0 would still have some free memory.
I remember that it still triggered.



My current best guess is that this is a combination of large VMAP demands
(e.g., kernel modules with quite a size due to CONFIG_KASAN_INLINE) and
eventually a concurrency issue with large #CPUs. But I might be wrong and
this might be something zone/node related.

Does any of that ring a bell -- especially why it would fail with 448 logical
CPUs but succeed with 224 logical CPUs (nosmt)?

My best guess would be that the purge_vmap_area_lazy() logic in alloc_vmap_area()
might not be sufficient when there is a lot of concurrency: simply purging
once and then failing might be problematic in corner cases where there is a lot of
concurrent vmap action going on. But that's just my best guess.


Cheers!

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8aaaeec8-14a1-cdc4-4c77-4878f4979f3e%40redhat.com.
