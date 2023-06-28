Return-Path: <kasan-dev+bncBDAZZCVNSYPBBCVM6GSAMGQEHT3664Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AABE741592
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jun 2023 17:47:24 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-666e5f0d639sf2627028b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jun 2023 08:47:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687967242; cv=pass;
        d=google.com; s=arc-20160816;
        b=GTVmrIWBcGQ4DCxIR8n2XMYb9/J4k1xez7WlM1S/4BYHPqR6EGXcfbjHdtkw3s8vCH
         UlmwzOgsGog+Znnz71zlM8FHn4MGlomgBFjmDOnAR+eDFzqisQxtj44tEOLvNfX/HV0J
         jBbBLChKLg2bP6tk3ZCx+sn3Y6Z8BNsGTy6bZ8rReHA4Uc6ccwK6IWqFTT+GUiaZzlfM
         oEozWL9YiJybs4IuaYmSia+9skcx8ZBVVCP0hMXVYysvLLpVQuiDUia2Pj0wruFt0c9f
         +784Ea25FR3e2isBQXPFPg+H7Od6/qMR/W+Y/SwW6lKG0CTZ5OY+NIjc6XWtpASbTy8c
         FhYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4KsqSez5ej8z38uXzQNUFJYOoo5cgbWN/ZthVPAzeRg=;
        b=VGvCxflj/x+q3c6TVHPyT8ei47d2h3nMdj7wxiqLTuZemEYDVfRAv+Qi5+P+zv+IyS
         2XvEcRfUFUD6Mp/FtEA8VdrMIzv7R60/ZqL3px/Ym0EuEmc3H5CV6uZUeFltfD0GaF2Q
         y7mn+54aKLWn7sn246d+TFhBKeBK4ODSmkzu1L8GVMI7USbsIr1OtOdm57Z5PJt16t62
         AvvLlIO01PO6ZTdUbTDKGDEovfPUjn5iKzNpsTzTldqA5bc8tCZma8lyObXKcYASIXLx
         2EmdFLWHPI1eqCpxcWIBUYuto9eBYyjcyqTwY6nyXubd5cAHsMoJsqZVHXkRcGZ7GRRj
         OKUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q7WRoGUf;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687967242; x=1690559242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4KsqSez5ej8z38uXzQNUFJYOoo5cgbWN/ZthVPAzeRg=;
        b=euaQGiWGQCRFViIiAxShgkZS79pxBA+PGnTR033TYdN2mmLb0XISLAyforuuJwlE+V
         r8vKZ7AJRdZrvb2FzxkL+Y9vFUp4ARTTt7016LMUjsV/2DoDAbbfgHqUVuKCt44DuzE8
         HBr1sPIZr4YfaZ7JZxTC4a1drL1fNV35AIZb3ErNC7BqY5KtjnpvhHyLVc753cWlThks
         S/BVsssrbyOEnRN7PO8Pb4D8zBJi0jAg5xQ/VRLPsdfSQQxjjALJAHCb9YYOic59+K0n
         y4GYfrJd1Usj+kmaEF7SxHbreSvMUGeHYz/NqivbZh1JsnEuH6hwrt8OAUxM7Fvps4Ok
         DY+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687967242; x=1690559242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4KsqSez5ej8z38uXzQNUFJYOoo5cgbWN/ZthVPAzeRg=;
        b=jXaGMNnvsa4BLBppAtB1Bft3Kb2r0Vj2EEN10fvLNjKJftzCRQICfDOoVzj5/sHto4
         YalcmPAsXk4JeZs8MnLVZ1pzB/Pocs/xVz8IHT7lshvsWsrpqvgLzAFRBnhwQAt1X2zU
         fXuZajljsyObj4ejkJN525A5Rp2gztXLoCvSZHX6wU7c9zzB1UXTNzoBXgbZORq6UFVC
         owHBLRQQBzcsA7jgJXRMxTtnXFERQTRW4GqhwI8OILCTbFIFHdNUK/OejAGSfwpU4rzR
         3Hbh5lwT3KYNCjzZIjNKf2okYmqKG4+NMO4d6RwgnG3yTpBszI2pZZQWUMDZhGe8mgSc
         6eaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw1AlBQpy9eWaBTHW25p/hKezEHh3wb1WQQy27YNJoivGbM2aPH
	bi7nWDJcXm0n/5Ol9yyLks0=
X-Google-Smtp-Source: ACHHUZ7sIQ6TiV+SnRcNUj61IT44EnqqkcM5OigzspZGBQ4fiLJHLX+gRN5yCLoDo77ZlG38y3vLQg==
X-Received: by 2002:a05:6a20:a121:b0:126:23d:cd03 with SMTP id q33-20020a056a20a12100b00126023dcd03mr11854727pzk.9.1687967242487;
        Wed, 28 Jun 2023 08:47:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:834a:0:b0:669:e427:4b0f with SMTP id h71-20020a62834a000000b00669e4274b0fls2840959pfe.2.-pod-prod-04-us;
 Wed, 28 Jun 2023 08:47:21 -0700 (PDT)
X-Received: by 2002:a05:6a20:1394:b0:127:8833:cce3 with SMTP id hn20-20020a056a20139400b001278833cce3mr6467147pzc.8.1687967241607;
        Wed, 28 Jun 2023 08:47:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687967241; cv=none;
        d=google.com; s=arc-20160816;
        b=WfD1BT/Vo+es7QNMh5Qt3zth/y9FpfhY7BkKh/epVg+ygTZvSuncIC0OCF04WERsk4
         nQ8TIxS/Y1l9SErKSyb4vvUH8dlKZZ3K/fpRmGXc65zg0xd4DPRo8fFZoL7+F8PXWVlo
         5qG+3x6YqwU9vybM19EKU/vQFE+3ogJ3K3Mj86jWia1apDPieKvuwRxPsut/MveSkbj4
         eXoqHmzC9PXCNtlseB4zMnRuhDHs9IzpHZy4ZXKFKQ0C3+aFLu6YTdIwFhFb61h9Orw6
         ujQ/rM/h/2MRS7mcuW/HMEqvFWqfnPccrv5uzMUqOKNc18CplHn4S4TuskwX0czZjnOw
         FaDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=L1D3kzYp74bTc6MklXWPe/RPfxOnbnYqjTR79BG7rN0=;
        fh=GV3KiSqTZcHbRYaYP/rFdPbCQDZo8YCB7soT2/7RWUw=;
        b=TeCZRePvN0FyjvWpuxubXpPH61QlVpxgBUu9wqwzc9v/X+HqptGAudLA7VpNS0e/D3
         0wW2gk8vGr+SjHJNAjyXIFm7kX/T1plJZftlHw437UjltpYhdg4CQE5H89nKA9vfASMP
         4TsZXA7KeVFNUClo0D8AmQpY0k7bpP+2QjOpM2Uhjvulylab3DnXG8CErbpEqHkinpxB
         UZhyEsoQ5DVKP2zR/4QnhHwW51UgEN7tv/Sn2eZdMwjJiEHtYOIgfByjVj/F9pojJeoC
         QuPESvSbzqaCuG0Yqu5Rc4GfGeeEd6J/HSY2KWffnnavpPeNdK2+a7owzl519TS+tqxG
         e60A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q7WRoGUf;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g18-20020a635212000000b00542924cbf7esi732032pgb.5.2023.06.28.08.47.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Jun 2023 08:47:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 08B3F61365;
	Wed, 28 Jun 2023 15:47:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0D01FC433C0;
	Wed, 28 Jun 2023 15:47:18 +0000 (UTC)
Date: Wed, 28 Jun 2023 16:47:15 +0100
From: Will Deacon <will@kernel.org>
To: catalin.marinas@arm.com
Cc: ryabinin.a.a@gmail.com, andreyknvl@gmail.com, pcc@google.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: HW-KASAN and CONFIG_SLUB_DEBUG_ON=y screams about redzone corruption
Message-ID: <20230628154714.GB22090@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Q7WRoGUf;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi memory tagging folks,

While debugging something else, I ended up running v6.4 on an arm64 (v9)
fastmodel with both CONFIG_SLUB_DEBUG_ON=y and CONFIG_KASAN_HW_TAGS=y.
This makes the system pretty unusable, as I see a tonne of kmalloc
Redzone corruption messages pretty much straight out of startup (example
below).

Please can you take a look?

Cheers,

Will

--->8

[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=8, Nodes=1
[    0.000000] =============================================================================
[    0.000000] BUG kmalloc-128 (Not tainted): kmalloc Redzone overwritten
[    0.000000] -----------------------------------------------------------------------------
[    0.000000] 
[    0.000000] 0xffff00080001a9b0-0xf1ff00080001a9ff @offset=2480. First byte 0x0 instead of 0xcc
[    0.000000] Allocated in apply_wqattrs_prepare+0x90/0x2a4 age=0 cpu=0 pid=0
[    0.000000]  kmalloc_trace+0x34/0x6c
[    0.000000]  apply_wqattrs_prepare+0x90/0x2a4
[    0.000000]  apply_workqueue_attrs+0x5c/0xb4
[    0.000000]  alloc_workqueue+0x368/0x4f8
[    0.000000]  workqueue_init_early+0x2e8/0x3ac
[    0.000000]  start_kernel+0x168/0x394
[    0.000000]  __primary_switched+0xbc/0xc4
[    0.000000] Slab 0xfffffc0020000680 objects=21 used=8 fp=0xffff00080001ac80 flags=0xbfffc0000010200(slab|head|node=0|zone=2|lastcpupid=0xffff|kasantag=0x0)
[    0.000000] Object 0xf1ff00080001a980 @offset=17437937757178562944 fp=0x0000000000000000
[    0.000000] 
[    0.000000] Redzone  ffff00080001a900: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a910: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a920: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a930: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a940: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a950: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a960: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Redzone  ffff00080001a970: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
[    0.000000] Object   ffff00080001a980: 00 00 00 00 00 00 00 00 ff 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a990: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a9a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a9b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a9c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a9d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a9e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Object   ffff00080001a9f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    0.000000] Redzone  ffff00080001aa00: cc cc cc cc cc cc cc cc                          ........
[    0.000000] Padding  ffff00080001aa54: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[    0.000000] Padding  ffff00080001aa64: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[    0.000000] Padding  ffff00080001aa74: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a              ZZZZZZZZZZZZ
[    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.4.0-00001-g56e11237836c #1
[    0.000000] Hardware name: FVP Base RevC (DT)
[    0.000000] Call trace:
[    0.000000]  dump_backtrace+0xec/0x108
[    0.000000]  show_stack+0x18/0x2c
[    0.000000]  dump_stack_lvl+0x50/0x68
[    0.000000]  dump_stack+0x18/0x24
[    0.000000]  print_trailer+0x1ec/0x230
[    0.000000]  check_bytes_and_report+0x110/0x154
[    0.000000]  check_object+0x31c/0x360
[    0.000000]  free_to_partial_list+0x174/0x5d8
[    0.000000]  __slab_free+0x220/0x28c
[    0.000000]  __kmem_cache_free+0x364/0x3dc
[    0.000000]  kfree+0x50/0x70
[    0.000000]  apply_wqattrs_prepare+0x244/0x2a4
[    0.000000]  apply_workqueue_attrs+0x5c/0xb4
[    0.000000]  alloc_workqueue+0x368/0x4f8
[    0.000000]  workqueue_init_early+0x2e8/0x3ac
[    0.000000]  start_kernel+0x168/0x394
[    0.000000]  __primary_switched+0xbc/0xc4
[    0.000000] Disabling lock debugging due to kernel taint
[    0.000000] FIX kmalloc-128: Restoring kmalloc Redzone 0xffff00080001a9b0-0xf1ff00080001a9ff=0xcc
[    0.000000] FIX kmalloc-128: Object at 0xf1ff00080001a980 not freed



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230628154714.GB22090%40willie-the-truck.
