Return-Path: <kasan-dev+bncBCAP7WGUVIKBBLVR26XAMGQEOBOP7VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 840B685D66C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 12:04:16 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-68c53f2816dsf70742526d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 03:04:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708513455; cv=pass;
        d=google.com; s=arc-20160816;
        b=sx00RINfEQ7E6OJf+lOu/dMZaZkIIUVpnFmIRNDWogaDHVS6fx637HBIRus8FTUYrd
         MlbIr7Ell+T5lyPWBHJ3N1eH2NewThOt7Z3okdyeEG7LEmP+h/OX4sP7YT97WPdm02sm
         toTKFsHl1XVZOKCcXZ1bgazLyzXBY3/En9L5ooShfErlgWDucM6mztTjJfTVXgGGMzEi
         5zQ0ZBfxgzDPQdp+/BMjTYHgYm4U600mqpudKqMpXqSxEbqBwm+VwlnZSccoxvBUkACy
         SLKCe8NkjFUORdoacHiu6f9DJe8mMwsoSqIddwUOuUUhRDRAYMYT0GtyHq6sG4TbAVsy
         IuLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:cc:references:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=uOj617T4NMg314AKFe2p4k3kdc/1SU5Lnq2LdR31e7c=;
        fh=pgIyPNwO0/zlG2JlrUzdw5GZ3zY0KjFM82K7B2+vN+g=;
        b=iWvEXfiqskNYwAguSZvJJ1YFFlijdEyulU18hRhg7vL21//K0hbzbGMSPNCXJylmk1
         v0V4ETmG6zaFzadxxjrIndRaCHoveIWHias0oTK83Y++q0huSTrofgfW44d9c9Pat1HT
         4ZFbJHqm0WbzYBw6ycQHFr57i1a7byGwlZSHucSW9slpl1B8LU/GnS/lQZfUH5OZjVPl
         7+EN2uhNodlBqV14SCdwzww6ZjGqPVqktrKZ9Ewh3HSa1woZ6+FP2dehEYEJPWpTkLlE
         kEnhev4CClTJvb0gqdnB+AQaK5YnhcHfbzWdhf6VFZ0PI7gYRnzpU818Ij/vW+/3RgDV
         /c5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708513455; x=1709118255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:cc:references:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uOj617T4NMg314AKFe2p4k3kdc/1SU5Lnq2LdR31e7c=;
        b=h6BfCmaFK9Pu+Pau7R+2zYbc6Dicai+MXXEbXXaNGwRKboKImCOed6GvH9n2V4GP7T
         fmMxZnqvU8jZumyEJuIzr+qD95hCmPPUYwMhwjuZcLcnZrW1LKcK7rpY+4GTqXTcSj7b
         zxUyTwTnLr1mONr9QTOp4rVkYvScyBPKhdJEfLgAA+chm5Afqr8uqKBeFlMU4cJ4eNpP
         skOqZk0T7O803B9dXAmCUZy+nEA8GiDkQKmlQj7JefHix0ti0icpCidFNw9DD4p126Wg
         RU7aLc3JiUqsOnTHXjupy3gEvtJ8mnYIH/NM+IL7lzg5P5CEEZIP7wg9D3qpjaWCfNNU
         7whw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708513455; x=1709118255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to:cc
         :references:to:from:content-language:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uOj617T4NMg314AKFe2p4k3kdc/1SU5Lnq2LdR31e7c=;
        b=l7PxZmlEEzL2NEPKFs8UHR9tvXZkWImCkb105rv9ewLmYUSJ31WKJgoS/TrQARrMjZ
         pJQ3GjDQK2ja9fF7xFtGvP05uQLKKvCshGMcv/FSG/6dALvnN+jxkba4//kj0ivjTA4h
         xjkj/LXGgfEMHooJ1H1XxmvNy0CEsGBtt1irvx47B27bq2Tj5xY3kd1Geo14WzBqZEUP
         iUymXxvYQH5S3y4DKyKDjuBC80XZDM0R4czICbfLbNfN6+3+6pWXrUwM0ir/86WclfE2
         +NGFopuoGrZfwjTTXZMBkTttRtqIgETXtDYGvPtWpStJyGkGMi1NHC7/F/W5TYexnSQ4
         lbzQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWO+ptjUpNlog3IPYjvzEfZrQsP1ZIHZWTMLJHxuMR2KiSLveAkIuSf94jicLWEkv4mLgqr+g14gw+MIOAdlm3bsD5kLsdK9Q==
X-Gm-Message-State: AOJu0YwzPl+SzXPlWqxEq6pkLlk1yN9aLxg6os0fdmpW22oxkvS17Kcq
	9ev2LpDQZQBbqqcMvZikNjNXP08b5K9JTKoQxBUavxKJfXnYu/mB
X-Google-Smtp-Source: AGHT+IFP5eIA46vksYbnSQWHw4mxGsYWoWc7PNY/Vy+6s41a9MFt615F6iLdXQ8hAhmpSoNtFeh0/w==
X-Received: by 2002:a05:6214:c44:b0:68f:6f65:3518 with SMTP id r4-20020a0562140c4400b0068f6f653518mr8007707qvj.62.1708513455318;
        Wed, 21 Feb 2024 03:04:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5b8b:0:b0:68c:a87d:febd with SMTP id 11-20020ad45b8b000000b0068ca87dfebdls988406qvp.1.-pod-prod-04-us;
 Wed, 21 Feb 2024 03:04:14 -0800 (PST)
X-Received: by 2002:a05:6122:2516:b0:4ce:7663:af1f with SMTP id cl22-20020a056122251600b004ce7663af1fmr6730992vkb.7.1708513454228;
        Wed, 21 Feb 2024 03:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708513454; cv=none;
        d=google.com; s=arc-20160816;
        b=ccyV9cFlHq44lysW/FgM8Ef9TDofTe98cRI2Gi5Ehgz0cjUUKS2X7kX+8U1MkVRtdB
         Grw81Nj6ks2oDoC/wDR0ndthrXKLy7ZeIWcX3Ao5uPzjfzVkkyK1wjY62t54+M1Bz2yn
         Dnlp4n6/XyqPpd7Icfa2yfbRl0ToKs/5S4dtrmG6Lx22lsD/4mN7PS5Pv/L5n0DI9qy9
         6un8B2/HpTdn6kMEqZmVHAHTfiWfGCpQi1yS5CPxnGXXbmr35H4Z9xGO1INg0URQlX56
         DFYT65o2bAdYzzNDreqW9YITDbAURy+sF0YlkQClSikMQZjcWuyP0KzWwbHV9+o5yIyh
         IdDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:cc:references:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=ratA5LNCWQWvfAJ3Wum/9oSAuJbYWl/VGQcJUeuqFoQ=;
        fh=oaV0t2uohpbcc3NrOlVg7dWntstWQBrW+kyqL+XAXTg=;
        b=k6YrMPKF7Ey1zmstBI7N71epwmrPKbeEL3dnr7XrJ4aFShUX6aLJ3Zo0qfDdEuiPDi
         L0HaU/MiVGKLi0AzNLCvdOmOfgRULzaBghYaSTsFU5MmqlP3Vyr+0EsLzB4Nzb/Ej9ls
         Us7egAzwLGNsColKK7YduPJDQpvg4HO112fTcp0bgdIHNZTWlDDS5npjOvJIC197m2E8
         vab2vXkKTs5tfoPlDAKvos6YL7xg9B+zXBYQ4jCRlXvhKuC2OVRMOrjgshd2QXhRn7/Z
         OmxzjnnuzUFayRSSiSYYvQcT+EwRFMSw6M4M5CqACuUoCVHMGmmzuGvvLPzb9TSOs0ZH
         cdFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id fi13-20020a0561224d0d00b004c027d19fd3si398389vkb.5.2024.02.21.03.04.13
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 03:04:13 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav111.sakura.ne.jp (fsav111.sakura.ne.jp [27.133.134.238])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41LB46XG029869;
	Wed, 21 Feb 2024 20:04:06 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav111.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp);
 Wed, 21 Feb 2024 20:04:06 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41LB452M029854
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 21 Feb 2024 20:04:05 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <c577ec03-3d83-4000-986a-cb9561224fe1@I-love.SAKURA.ne.jp>
Date: Wed, 21 Feb 2024 20:04:06 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [virtualization?] KMSAN: uninit-value in virtqueue_add
 (4)
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: kasan-dev <kasan-dev@googlegroups.com>,
        syzbot <syzbot+d7521c1e3841ed075a42@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Alexander Potapenko <glider@google.com>
References: <000000000000fd588e060de27ef4@google.com>
 <2c1dad81-9b22-47fb-b0e9-6e4a2a2c67be@I-love.SAKURA.ne.jp>
Cc: linux-mm <linux-mm@kvack.org>
In-Reply-To: <2c1dad81-9b22-47fb-b0e9-6e4a2a2c67be@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

I tried to reproduce this problem in my environment, and I found that
just consuming almost all memory trivially generates below one.
This might be the same cause?

$ ./scripts/faddr2line vmlinux free_unref_page_prepare+0x130/0xfc0
free_unref_page_prepare+0x130/0xfc0:
arch_static_branch_jump at arch/x86/include/asm/jump_label.h:55
(inlined by) memcg_kmem_online at include/linux/memcontrol.h:1840
(inlined by) free_pages_prepare at mm/page_alloc.c:1096
(inlined by) free_unref_page_prepare at mm/page_alloc.c:2346

----------------------------------------
[    0.000000][    T0] Linux version 6.8.0-rc5 (root@ubuntu) (Ubuntu clang version 14.0.0-1ubuntu1.1, Ubuntu LLD 14.0.0) #1089 SMP PREEMPT_DYNAMIC Tue Feb 20 22:50:10 UTC 2024
[   76.193709][ T2962] =====================================================
[   76.221751][ T2962] BUG: KMSAN: use-after-free in obj_malloc+0x6cc/0x7b0
[   76.229392][ T2962]  obj_malloc+0x6cc/0x7b0
[   76.234874][ T2962]  zs_malloc+0xdbd/0x1400
[   76.239897][ T2962]  zs_zpool_malloc+0xa5/0x1b0
[   76.248589][ T2962]  zpool_malloc+0x110/0x150
[   76.261388][ T2962]  zswap_store+0x2bbb/0x3d30
[   76.286128][ T2962]  swap_writepage+0x15b/0x4f0
[   76.305337][ T2962]  pageout+0x41d/0xef0
[   76.329597][ T2962]  shrink_folio_list+0x4d7a/0x7480
[   76.352303][ T2962]  evict_folios+0x30f1/0x5170
[   76.375539][ T2962]  try_to_shrink_lruvec+0x983/0xd20
[   76.397057][ T2962]  shrink_one+0x72d/0xeb0
[   76.405789][ T2962]  shrink_many+0x70d/0x10b0
[   76.413973][ T2962]  lru_gen_shrink_node+0x577/0x850
[   76.424001][ T2962]  shrink_node+0x13d/0x1de0
[   76.432440][ T2962]  shrink_zones+0x878/0x14a0
[   76.441432][ T2962]  do_try_to_free_pages+0x2ac/0x16a0
[   76.453092][ T2962]  try_to_free_pages+0xd9e/0x1910
[   76.469480][ T2962]  __alloc_pages_slowpath+0x147a/0x2bd0
[   76.494976][ T2962]  __alloc_pages+0xb8c/0x1050
[   76.521081][ T2962]  alloc_pages_mpol+0x8e0/0xc80
[   76.544806][ T2962]  alloc_pages+0x224/0x240
[   76.558044][ T2962]  pipe_write+0xabe/0x2ba0
[   76.582897][ T2962]  vfs_write+0xfb0/0x1b80
[   76.604669][ T2962]  ksys_write+0x275/0x500
[   76.613269][ T2962]  __x64_sys_write+0xdf/0x120
[   76.622218][ T2962]  do_syscall_64+0xd1/0x1b0
[   76.629765][ T2962]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
[   76.638984][ T2962] 
[   76.645171][ T2962] Uninit was stored to memory at:
[   76.653234][ T2962]  obj_malloc+0x70a/0x7b0
[   76.660989][ T2962]  zs_malloc+0xdbd/0x1400
[   76.667451][ T2962]  zs_zpool_malloc+0xa5/0x1b0
[   76.674667][ T2962]  zpool_malloc+0x110/0x150
[   76.682273][ T2962]  zswap_store+0x2bbb/0x3d30
[   76.688772][ T2962]  swap_writepage+0x15b/0x4f0
[   76.695427][ T2962]  pageout+0x41d/0xef0
[   76.701864][ T2962]  shrink_folio_list+0x4d7a/0x7480
[   76.708623][ T2962]  evict_folios+0x30f1/0x5170
[   76.715962][ T2962]  try_to_shrink_lruvec+0x983/0xd20
[   76.723092][ T2962]  shrink_one+0x72d/0xeb0
[   76.730491][ T2962]  shrink_many+0x70d/0x10b0
[   76.736930][ T2962]  lru_gen_shrink_node+0x577/0x850
[   76.743338][ T2962]  shrink_node+0x13d/0x1de0
[   76.749527][ T2962]  shrink_zones+0x878/0x14a0
[   76.757753][ T2962]  do_try_to_free_pages+0x2ac/0x16a0
[   76.784738][ T2962]  try_to_free_pages+0xd9e/0x1910
[   76.794060][ T2962]  __alloc_pages_slowpath+0x147a/0x2bd0
[   76.809193][ T2962]  __alloc_pages+0xb8c/0x1050
[   76.819106][ T2962]  alloc_pages_mpol+0x8e0/0xc80
[   76.825845][ T2962]  alloc_pages+0x224/0x240
[   76.833084][ T2962]  pipe_write+0xabe/0x2ba0
[   76.839441][ T2962]  vfs_write+0xfb0/0x1b80
[   76.846688][ T2962]  ksys_write+0x275/0x500
[   76.861721][ T2962]  __x64_sys_write+0xdf/0x120
[   76.887481][ T2962]  do_syscall_64+0xd1/0x1b0
[   76.912683][ T2962]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
[   76.941992][ T2962] 
[   76.960534][ T2962] Uninit was created at:
[   76.967351][ T2962]  free_unref_page_prepare+0x130/0xfc0
[   76.974685][ T2962]  free_unref_page_list+0x139/0x1050
[   76.980910][ T2962]  shrink_folio_list+0x7139/0x7480
[   76.987899][ T2962]  evict_folios+0x30f1/0x5170
[   76.994206][ T2962]  try_to_shrink_lruvec+0x983/0xd20
[   77.000665][ T2962]  shrink_one+0x72d/0xeb0
[   77.007039][ T2962]  shrink_many+0x70d/0x10b0
[   77.013652][ T2962]  lru_gen_shrink_node+0x577/0x850
[   77.024303][ T2962]  shrink_node+0x13d/0x1de0
[   77.050110][ T2962]  shrink_zones+0x878/0x14a0
[   77.075727][ T2962]  do_try_to_free_pages+0x2ac/0x16a0
[   77.100888][ T2962]  try_to_free_pages+0xd9e/0x1910
[   77.106076][ T2962]  __alloc_pages_slowpath+0x147a/0x2bd0
[   77.111944][ T2962]  __alloc_pages+0xb8c/0x1050
[   77.117585][ T2962]  alloc_pages_mpol+0x8e0/0xc80
[   77.124268][ T2962]  alloc_pages+0x224/0x240
[   77.130464][ T2962]  pipe_write+0xabe/0x2ba0
[   77.136968][ T2962]  vfs_write+0xfb0/0x1b80
[   77.143088][ T2962]  ksys_write+0x275/0x500
[   77.168816][ T2962]  __x64_sys_write+0xdf/0x120
[   77.193213][ T2962]  do_syscall_64+0xd1/0x1b0
[   77.217003][ T2962]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
[   77.245384][ T2962] 
[   77.271236][ T2962] CPU: 2 PID: 2962 Comm: a.out Not tainted 6.8.0-rc5 #1089
[   77.287165][ T2962] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[   77.300986][ T2962] =====================================================
[   77.309323][ T2962] Disabling lock debugging due to kernel taint
[   77.317501][ T2962] Kernel panic - not syncing: kmsan.panic set ...
[   77.328533][ T2962] CPU: 2 PID: 2962 Comm: a.out Tainted: G    B              6.8.0-rc5 #1089
[   77.384024][ T2962] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[   77.432726][ T2962] Call Trace:
[   77.454709][ T2962]  <TASK>
[   77.480712][ T2962]  dump_stack_lvl+0x1f6/0x280
[   77.510291][ T2962]  dump_stack+0x29/0x30
[   77.538912][ T2962]  panic+0x4ed/0xc90
[   77.565356][ T2962]  kmsan_report+0x2d1/0x2e0
[   77.593241][ T2962]  ? kmsan_internal_poison_memory+0x49/0x90
[   77.625512][ T2962]  ? kmsan_internal_poison_memory+0x7d/0x90
[   77.653002][ T2962]  ? __msan_warning+0x98/0x120
[   77.662635][ T2962]  ? obj_malloc+0x6cc/0x7b0
[   77.669636][ T2962]  ? zs_malloc+0xdbd/0x1400
[   77.677036][ T2962]  ? zs_zpool_malloc+0xa5/0x1b0
[   77.693619][ T2962]  ? zpool_malloc+0x110/0x150
[   77.724160][ T2962]  ? zswap_store+0x2bbb/0x3d30
[   77.736985][ T2962]  ? swap_writepage+0x15b/0x4f0
[   77.744190][ T2962]  ? pageout+0x41d/0xef0
[   77.750941][ T2962]  ? shrink_folio_list+0x4d7a/0x7480
[   77.758465][ T2962]  ? evict_folios+0x30f1/0x5170
[   77.768334][ T2962]  ? try_to_shrink_lruvec+0x983/0xd20
[   77.789768][ T2962]  ? shrink_one+0x72d/0xeb0
[   77.803770][ T2962]  ? shrink_many+0x70d/0x10b0
[   77.823518][ T2962]  ? lru_gen_shrink_node+0x577/0x850
[   77.831064][ T2962]  ? shrink_node+0x13d/0x1de0
[   77.838508][ T2962]  ? shrink_zones+0x878/0x14a0
[   77.853087][ T2962]  ? do_try_to_free_pages+0x2ac/0x16a0
[   77.870947][ T2962]  ? try_to_free_pages+0xd9e/0x1910
[   77.898331][ T2962]  ? __alloc_pages_slowpath+0x147a/0x2bd0
[   77.927623][ T2962]  ? __alloc_pages+0xb8c/0x1050
[   77.954001][ T2962]  ? alloc_pages_mpol+0x8e0/0xc80
[   77.977357][ T2962]  ? alloc_pages+0x224/0x240
[   77.999681][ T2962]  ? pipe_write+0xabe/0x2ba0
[   78.014454][ T2962]  ? vfs_write+0xfb0/0x1b80
[   78.023741][ T2962]  ? ksys_write+0x275/0x500
[   78.031807][ T2962]  ? __x64_sys_write+0xdf/0x120
[   78.040331][ T2962]  ? do_syscall_64+0xd1/0x1b0
[   78.047608][ T2962]  ? entry_SYSCALL_64_after_hwframe+0x63/0x6b
[   78.055721][ T2962]  ? entry_SYSCALL_64_after_hwframe+0x63/0x6b
[   78.072687][ T2962]  ? __msan_metadata_ptr_for_load_8+0x24/0x40
[   78.081809][ T2962]  ? filter_irq_stacks+0xb9/0x230
[   78.087869][ T2962]  ? filter_irq_stacks+0xb9/0x230
[   78.095051][ T2962]  ? should_fail_ex+0x91/0xa20
[   78.101839][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.107538][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.114253][ T2962]  ? kmsan_get_shadow_origin_ptr+0x4d/0xb0
[   78.122152][ T2962]  ? __should_failslab+0x24f/0x2e0
[   78.129024][ T2962]  ? __msan_metadata_ptr_for_load_8+0x24/0x40
[   78.136577][ T2962]  ? __should_failslab+0x24f/0x2e0
[   78.156694][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.162925][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.169811][ T2962]  ? kmsan_get_shadow_origin_ptr+0x4d/0xb0
[   78.177276][ T2962]  __msan_warning+0x98/0x120
[   78.183309][ T2962]  obj_malloc+0x6cc/0x7b0
[   78.188246][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.193961][ T2962]  zs_malloc+0xdbd/0x1400
[   78.198774][ T2962]  ? kmsan_get_shadow_origin_ptr+0x4d/0xb0
[   78.204373][ T2962]  zs_zpool_malloc+0xa5/0x1b0
[   78.209487][ T2962]  ? zs_zpool_destroy+0x50/0x50
[   78.215875][ T2962]  zpool_malloc+0x110/0x150
[   78.221423][ T2962]  zswap_store+0x2bbb/0x3d30
[   78.226784][ T2962]  swap_writepage+0x15b/0x4f0
[   78.232645][ T2962]  ? generic_swapfile_activate+0xee0/0xee0
[   78.238777][ T2962]  pageout+0x41d/0xef0
[   78.244187][ T2962]  shrink_folio_list+0x4d7a/0x7480
[   78.250349][ T2962]  evict_folios+0x30f1/0x5170
[   78.256857][ T2962]  try_to_shrink_lruvec+0x983/0xd20
[   78.263215][ T2962]  shrink_one+0x72d/0xeb0
[   78.268410][ T2962]  shrink_many+0x70d/0x10b0
[   78.274632][ T2962]  lru_gen_shrink_node+0x577/0x850
[   78.281485][ T2962]  shrink_node+0x13d/0x1de0
[   78.287756][ T2962]  ? mem_cgroup_soft_limit_reclaim+0x34/0x17a0
[   78.295195][ T2962]  ? filter_irq_stacks+0xb9/0x230
[   78.301832][ T2962]  ? stack_depot_save_flags+0x2c/0x810
[   78.308677][ T2962]  ? kmsan_internal_set_shadow_origin+0x66/0xe0
[   78.315638][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.321575][ T2962]  ? kmsan_get_shadow_origin_ptr+0x4d/0xb0
[   78.328726][ T2962]  shrink_zones+0x878/0x14a0
[   78.335109][ T2962]  ? __module_address+0x114/0x890
[   78.341766][ T2962]  do_try_to_free_pages+0x2ac/0x16a0
[   78.348484][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.357673][ T2962]  try_to_free_pages+0xd9e/0x1910
[   78.382022][ T2962]  ? kmsan_get_shadow_origin_ptr+0x4d/0xb0
[   78.409072][ T2962]  __alloc_pages_slowpath+0x147a/0x2bd0
[   78.435039][ T2962]  ? get_page_from_freelist+0x11ed/0x1b00
[   78.461720][ T2962]  __alloc_pages+0xb8c/0x1050
[   78.474860][ T2962]  alloc_pages_mpol+0x8e0/0xc80
[   78.481368][ T2962]  alloc_pages+0x224/0x240
[   78.487579][ T2962]  pipe_write+0xabe/0x2ba0
[   78.494006][ T2962]  ? kmsan_get_shadow_origin_ptr+0x4d/0xb0
[   78.501316][ T2962]  ? filter_irq_stacks+0x1d8/0x230
[   78.508179][ T2962]  ? kmsan_get_metadata+0x146/0x1c0
[   78.515408][ T2962]  ? pipe_read+0x2220/0x2220
[   78.530652][ T2962]  vfs_write+0xfb0/0x1b80
[   78.553685][ T2962]  ksys_write+0x275/0x500
[   78.576529][ T2962]  __x64_sys_write+0xdf/0x120
[   78.599958][ T2962]  do_syscall_64+0xd1/0x1b0
[   78.623046][ T2962]  ? irqentry_exit+0x16/0x50
[   78.646375][ T2962]  ? exc_page_fault+0x7c/0x180
[   78.667298][ T2962]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
[   78.693772][ T2962] RIP: 0033:0x7f24b1f14887
[   78.712875][ T2962] Code: 10 00 f7 d8 64 89 02 48 c7 c0 ff ff ff ff eb b7 0f 1f 00 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 51 c3 48 83 ec 28 48 89 54 24 18 48 89 74 24
[   78.769621][ T2962] RSP: 002b:00007ffd348e7138 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
[   78.779659][ T2962] RAX: ffffffffffffffda RBX: 0000000000000089 RCX: 00007f24b1f14887
[   78.788322][ T2962] RDX: 0000000000001000 RSI: 000055fd4849e040 RDI: 00000000000000ea
[   78.799066][ T2962] RBP: 000055fd4849e040 R08: 0000000000000000 R09: 00007f24b2094740
[   78.808645][ T2962] R10: 00007f24b20de0c8 R11: 0000000000000246 R12: 00007ffd348e7140
[   78.819277][ T2962] R13: 000055fd4849b160 R14: 000055fd4849dd80 R15: 00007f24b20dd040
[   78.828758][ T2962]  </TASK>
[   78.856768][ T2962] Kernel Offset: disabled
[   78.861472][ T2962] Rebooting in 10 seconds..
----------------------------------------

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c577ec03-3d83-4000-986a-cb9561224fe1%40I-love.SAKURA.ne.jp.
