Return-Path: <kasan-dev+bncBDKJVFPCVIJBBLFYUT7AKGQEBB2E6NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B8892CDBF6
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 18:11:09 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id x129sf3525248ybg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 09:11:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607015468; cv=pass;
        d=google.com; s=arc-20160816;
        b=hL3legCDzLyxk9brjtEqOEHmNIkfm2WoSUNB0TOHHGaQu7Ig8jNwqXIF9q39CMW6rf
         2LSH4xDGPLqVHbB1pd1cSOz9+vFbIax7qEbyx/Nupn9X3AziBS37GqxUPM19ioquCdMo
         2UXImJ6SSjOU0lLgswujJD3UDiYJPeGwiGKjWQe0yJyUi7knXVOqirK97QB36VEO/483
         Kh8QDBquK2erNKxNbvbmU0B5q+MGjw/aXuTkyj9Pu20FlIDZHv42ZOEjWHTCqYrlklaM
         SEB3yJ9/pG0TxgLoNssJ1KU64nqF3/EMLVbtODIcan4/HVxXj+AYgHhXjeSuN3S0HN1q
         c0lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=wttjXj8FnlEBhThnIfZntEgCkV0Y0O4agjGBAjs2zgc=;
        b=KBW7z6yOSXaEuMcS1Jzq6JSc03ztEzjJchv82Ewd2ngZF0rfvh/OVh/Y4UKEr0DE38
         il//QPwazg01JSUeRq5jC9rcmzHabilBj59aesxkMF8Q789sdFs5Jccl9vAA+uik8eS9
         wDMRBpn1z/pWQxi3hSgonrZDW24flCyeV/PbYOeXNqeBOj2g+A5XwOI8r0tGwCll9Zx+
         z3xpx2H8lWWTejYQs/J3Wv94zO0m+9nDiLuMTE3ntFGUVXjrnRk3TQfllxBIn1caAOrj
         GeuFzVAktM+vPkjY6NkXJzLiRzZyB7ec2oqrrLys4JSkKawCYvP/ZFHyUtMOqdvcxW8q
         XjTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cGsB5548;
       spf=pass (google.com: domain of qcai@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=qcai@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wttjXj8FnlEBhThnIfZntEgCkV0Y0O4agjGBAjs2zgc=;
        b=WfDiJz1E1VJr/H2La7PnPBXTo9p+d92/sTtyxlj07gBlREPhp1LVpRZGMCuQJ6uV+O
         wvOTub+LLpPuOKL1fM4+UVzn3gpE6o6PF4whRz5o+QVbK7WkmJkHHdEdPtZ92K7LofMD
         EBDHWsyou7oog9R4tku+bot2pNLvN94ZGhU2fzyHEmLMR3xczkPihI4wIishWnpuqITQ
         O7Gtnw1MB3AdCgDwanUrDfmAZuxXcJrk/X+yi2ERXBOXkP8B2a/eAI16DYHg3SNwwdP+
         qnuqVNZv/4lljfnsSPwuJJw6fa6ZYSqlNVglMiQ5E8y/TxdkIeXFudb5fesvZXnDQ8T2
         EsgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wttjXj8FnlEBhThnIfZntEgCkV0Y0O4agjGBAjs2zgc=;
        b=lLKA593yjOBbh5VMb4GEEtp8SnD6v7gML0Ap8vjtt0+Bp/dtxvb21NBidJmXRPoMUr
         DgHAdPdgo7gF8rEca8H/hHbSZseekB2MUJBBzJ2NibxRvj5cUYpLmPuL7mA0Mdn+CSMY
         +q2gQbPdONUAvMQ7TMqNzbqFPU1ThyCFjrkAV4YBP0rH9tj2eNAyqlnoQwfCArJBC6Cs
         1MB0rXegbgY37z4N3GlQoGagM5vblaq2qSPKAi5XGFZGuQc2Fyv/hDkjwdbo5UNM8D31
         Ip7rI6mRCx5Du5T0nU98f2PC/9j9Do7XRGYeH+6/aW5C/nMqenhB2n5+6dOWdYYuz/wo
         bfew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jz613nN5602umFjyDSx3KXcm7XB6kuXmKGbkPI4o2TwFlMeuH
	VIwwEHKzUPKWOjt8GGgPwSU=
X-Google-Smtp-Source: ABdhPJzBI9PWBnAO6naApmsTLqtvcq3rr1X2/8yuVcqRtfKfm8rL7OD2ffLkIJfShekVlOZjyqI9bQ==
X-Received: by 2002:a25:a4a1:: with SMTP id g30mr48447ybi.195.1607015468533;
        Thu, 03 Dec 2020 09:11:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c0d3:: with SMTP id c202ls3068582ybf.5.gmail; Thu, 03
 Dec 2020 09:11:08 -0800 (PST)
X-Received: by 2002:a25:7453:: with SMTP id p80mr72294ybc.31.1607015468064;
        Thu, 03 Dec 2020 09:11:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607015468; cv=none;
        d=google.com; s=arc-20160816;
        b=QUjCHHqrnFyL4Zjtv+0C1nUx5hcAsBXWmeoQUG5Q2d9/Qm8PNIWqhy0Mwxye2rl3E3
         zDEXNpU1NsUZGwNgqiTSvMBoelEQ2staj97IFCfE8ZGyov7Nhjn0g2y6e08UWIgwbzZ2
         8YJa4GyWPSqyxrnar0aP35HXC025XtogYyiF9YG2YmGol50KlPze66KItkXmk1hTGlgc
         8bGW8z5KaWXpqs4QX+bm93KI3fK7K/YIauMIZezcjitd9WRvrhwGTSHX76No4Beg3OC+
         YRNnWxwcLzppfD67yOYl0cDxon1piYcgT4Lz5Fizsx4zHEBFVFQXmrRNBS3OT6Hz2A5a
         1P2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=uhkrIbkP+2I5PD5prOOeLdY5JuL7PV97yJKzCyL+Jhc=;
        b=uNmfjmHrErX7gHYSFUHPPji4xZXmwboSd2NOCjKX7xeKcgMOf2nwy4/dlwGTMZ2c17
         ryXlaKLwl+W1YmFiI4gXfEYKy8led9HVck+T6/wImYEY9VWx9gGtt8TQSM+3ykuDCW7K
         UyTObK/IMH57XmpLjsO1f4HXOYpaIe613MdMBeJGkMuDfxWwRPbuSMt7o3nfTwOFwIVD
         RQQRs7CR13Ro+v7AKeSmV7bpdcijWHyTD42yQcGwOgfFv5HeHpXNoO6RPEKDLwuzJPWI
         YQ0YJTqKp9izeBWR71GzkDrWM9RvTsI5VLG6gXIesGUUdZ6uPoA3btg+FynqC73iiC1c
         YCpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cGsB5548;
       spf=pass (google.com: domain of qcai@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=qcai@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id m3si8091ybf.1.2020.12.03.09.11.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Dec 2020 09:11:08 -0800 (PST)
Received-SPF: pass (google.com: domain of qcai@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-48-gAySmrSKMpGBPP4yfuhAEg-1; Thu, 03 Dec 2020 12:10:59 -0500
X-MC-Unique: gAySmrSKMpGBPP4yfuhAEg-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 1AE05858181;
	Thu,  3 Dec 2020 17:10:57 +0000 (UTC)
Received: from ovpn-66-132.rdu2.redhat.com (unknown [10.10.67.132])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 08B8060CE0;
	Thu,  3 Dec 2020 17:10:54 +0000 (UTC)
Message-ID: <840af74e06e2515c84eb86df2825d466bcf75e96.camel@redhat.com>
Subject: Re: [PATCH v3 1/1] kasan: fix object remain in offline per-cpu
 quarantine
From: Qian Cai <qcai@redhat.com>
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 Matthias Brugger <matthias.bgg@gmail.com>, Nicholas Tang
 <nicholas.tang@mediatek.com>, Miles Chen <miles.chen@mediatek.com>
Cc: wsd_upstream@mediatek.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-mediatek@lists.infradead.org, linux-arm-kernel@lists.infradead.org, 
	sfr@canb.auug.org.au, linux-next@vger.kernel.org
Date: Thu, 03 Dec 2020 12:10:54 -0500
In-Reply-To: <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Original-Sender: qcai@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cGsB5548;
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

On Wed, 2020-12-02 at 15:53 +0800, Kuan-Ying Lee wrote:
> We hit this issue in our internal test.
> When enabling generic kasan, a kfree()'d object is put into per-cpu
> quarantine first. If the cpu goes offline, object still remains in
> the per-cpu quarantine. If we call kmem_cache_destroy() now, slub
> will report "Objects remaining" error.

Reverting this commit on the top of today's linux-next fixed memory corruptions
while doing CPU hotplug.

.config: https://cailca.coding.net/public/linux/mm/git/files/master/x86.config

[  421.539476][  T120] BUG kmalloc-128 (Not tainted): Object already free
[  421.546047][  T120] -----------------------------------------------------------------------------
[  421.546047][  T120] 
[  421.557165][  T120] INFO: Allocated in memcg_alloc_page_obj_cgroups+0x86/0x140 age=755 cpu=21 pid=2316
[  421.566533][  T120] 	__slab_alloc+0x55/0x70
[  421.570744][  T120] 	__kmalloc_node+0xdc/0x280
[  421.575215][  T120] 	memcg_alloc_page_obj_cgroups+0x86/0x140
[  421.580910][  T120] 	allocate_slab+0xd8/0x610
[  421.585299][  T120] 	___slab_alloc+0x4cb/0x830
[  421.589770][  T120] 	__slab_alloc+0x55/0x70
[  421.593985][  T120] 	kmem_cache_alloc+0x225/0x280
[  421.598724][  T120] 	vm_area_dup+0x76/0x2a0
[  421.602940][  T120] 	__split_vma+0x90/0x4b0
[  421.607151][  T120] 	mprotect_fixup+0x5da/0x7d0
[  421.611712][  T120] 	do_mprotect_pkey+0x41a/0x7c0
[  421.616447][  T120] 	__x64_sys_mprotect+0x74/0xb0
[  421.621181][  T120] 	do_syscall_64+0x33/0x40
[  421.625479][  T120] 	entry_SYSCALL_64_after_hwframe+0x44/0xa9
[  421.631262][  T120] INFO: Freed in quarantine_put+0xb5/0x1b0 age=3 cpu=21 pid=120
[  421.638795][  T120] 	quarantine_put+0xe7/0x1b0
[  421.643270][  T120] 	slab_free_freelist_hook+0x71/0x1a0
[  421.648529][  T120] 	kfree+0xe2/0x5d0
[  421.652215][  T120] 	__free_slab+0x1f8/0x300
[  421.656517][  T120] 	qlist_free_all+0x56/0xc0
[  421.660903][  T120] 	kasan_cpu_offline+0x1a/0x20
[  421.665550][  T120] 	cpuhp_invoke_callback+0x1dd/0x1530
[  421.670811][  T120] 	cpuhp_thread_fun+0x343/0x690
[  421.675547][  T120] 	smpboot_thread_fn+0x30f/0x780
[  421.680371][  T120] 	kthread+0x359/0x420
[  421.684317][  T120] 	ret_from_fork+0x22/0x30
[  421.688616][  T120] INFO: Slab 0x0000000080d42669 objects=12 used=11 fp=0x000000000ce8ce1d flags=0x4bfffc000010201
[  421.699031][  T120] INFO: Object 0x000000000ce8ce1d @offset=1408 fp=0x0000000000000000
[  421.699031][  T120] 
[  421.709186][  T120] Redzone 000000002d1421b0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.719339][  T120] Redzone 0000000018565a7c: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.729492][  T120] Redzone 00000000d8a699c9: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.739645][  T120] Redzone 00000000af065f39: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.749800][  T120] Redzone 00000000480c8db9: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.759954][  T120] Redzone 00000000c37ee06b: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.770106][  T120] Redzone 0000000040f9cbf1: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.780256][  T120] Redzone 00000000e714e01e: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[  421.790408][  T120] Object 000000000ce8ce1d: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.800471][  T120] Object 0000000046eb4462: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.810536][  T120] Object 00000000c3a122ae: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.820599][  T120] Object 00000000d0195822: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.830665][  T120] Object 000000008332e5f7: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.840729][  T120] Object 00000000a04f77eb: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.850796][  T120] Object 00000000326e9ce3: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[  421.860862][  T120] Object 00000000fa32b4b7: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b a5  kkkkkkkkkkkkkkk.
[  421.870926][  T120] Redzone 000000001d59aa8f: bb bb bb bb bb bb bb bb                          ........
[  421.880382][  T120] Padding 00000000f49e6727: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[  421.890537][  T120] Padding 000000007eb7befd: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[  421.900691][  T120] Padding 00000000c69f7c35: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[  421.910842][  T120] CPU: 21 PID: 120 Comm: cpuhp/21 Tainted: G    B             5.10.0-rc6-next-20201203+ #8
[  421.920733][  T120] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385 Gen10, BIOS A40 07/10/2019
[  421.930011][  T120] Call Trace:
[  421.933174][  T120]  dump_stack+0x99/0xcb
[  421.937210][  T120]  free_debug_processing.cold.98+0x6a/0x111
[  421.942993][  T120]  ? __free_slab+0x1f8/0x300
[  421.947467][  T120]  ? __free_slab+0x1f8/0x300
[  421.951942][  T120]  __slab_free+0x302/0x560
[  421.956241][  T120]  ? lockdep_hardirqs_on_prepare+0x27c/0x3d0
[  421.962110][  T120]  ? quarantine_put+0x10a/0x1b0
[  421.966846][  T120]  ? trace_hardirqs_on+0x1c/0x150
[  421.971754][  T120]  ? slab_free_freelist_hook+0x71/0x1a0
[  421.977192][  T120]  kfree+0x595/0x5d0
[  421.980967][  T120]  ? __free_slab+0x1f8/0x300
[  421.985439][  T120]  __free_slab+0x1f8/0x300
[  421.989738][  T120]  ? qlist_free_all+0x2f/0xc0
[  421.994299][  T120]  qlist_free_all+0x56/0xc0
[  421.998684][  T120]  ? qlist_free_all+0xc0/0xc0
[  422.003244][  T120]  kasan_cpu_offline+0x1a/0x20
[  422.007893][  T120]  cpuhp_invoke_callback+0x1dd/0x1530
[  422.013152][  T120]  cpuhp_thread_fun+0x343/0x690
[  422.017887][  T120]  ? __cpuhp_state_remove_instance+0x490/0x490
[  422.023934][  T120]  smpboot_thread_fn+0x30f/0x780
[  422.028756][  T120]  ? smpboot_register_percpu_thread+0x370/0x370
[  422.034888][  T120]  ? trace_hardirqs_on+0x1c/0x150
[  422.039800][  T120]  ? __kthread_parkme+0xd1/0x1a0
[  422.044622][  T120]  ? smpboot_register_percpu_thread+0x370/0x370
[  422.050753][  T120]  kthread+0x359/0x420
[  422.054704][  T120]  ? kthread_create_on_node+0xc0/0xc0
[  422.059965][  T120]  ret_from_fork+0x22/0x30

> 
> [   74.982625] =============================================================================
> [   74.983380] BUG test_module_slab (Not tainted): Objects remaining in test_module_slab on __kmem_cache_shutdown()
> [   74.984145] -----------------------------------------------------------------------------
> [   74.984145]
> [   74.984883] Disabling lock debugging due to kernel taint
> [   74.985561] INFO: Slab 0x(____ptrval____) objects=34 used=1 fp=0x(____ptrval____) flags=0x2ffff00000010200
> [   74.986638] CPU: 3 PID: 176 Comm: cat Tainted: G    B             5.10.0-rc1-00007-g4525c8781ec0-dirty #10
> [   74.987262] Hardware name: linux,dummy-virt (DT)
> [   74.987606] Call trace:
> [   74.987924]  dump_backtrace+0x0/0x2b0
> [   74.988296]  show_stack+0x18/0x68
> [   74.988698]  dump_stack+0xfc/0x168
> [   74.989030]  slab_err+0xac/0xd4
> [   74.989346]  __kmem_cache_shutdown+0x1e4/0x3c8
> [   74.989779]  kmem_cache_destroy+0x68/0x130
> [   74.990176]  test_version_show+0x84/0xf0
> [   74.990679]  module_attr_show+0x40/0x60
> [   74.991218]  sysfs_kf_seq_show+0x128/0x1c0
> [   74.991656]  kernfs_seq_show+0xa0/0xb8
> [   74.992059]  seq_read+0x1f0/0x7e8
> [   74.992415]  kernfs_fop_read+0x70/0x338
> [   74.993051]  vfs_read+0xe4/0x250
> [   74.993498]  ksys_read+0xc8/0x180
> [   74.993825]  __arm64_sys_read+0x44/0x58
> [   74.994203]  el0_svc_common.constprop.0+0xac/0x228
> [   74.994708]  do_el0_svc+0x38/0xa0
> [   74.995088]  el0_sync_handler+0x170/0x178
> [   74.995497]  el0_sync+0x174/0x180
> [   74.996050] INFO: Object 0x(____ptrval____) @offset=15848
> [   74.996752] INFO: Allocated in test_version_show+0x98/0xf0 age=8188 cpu=6 pid=172
> [   75.000802]  stack_trace_save+0x9c/0xd0
> [   75.002420]  set_track+0x64/0xf0
> [   75.002770]  alloc_debug_processing+0x104/0x1a0
> [   75.003171]  ___slab_alloc+0x628/0x648
> [   75.004213]  __slab_alloc.isra.0+0x2c/0x58
> [   75.004757]  kmem_cache_alloc+0x560/0x588
> [   75.005376]  test_version_show+0x98/0xf0
> [   75.005756]  module_attr_show+0x40/0x60
> [   75.007035]  sysfs_kf_seq_show+0x128/0x1c0
> [   75.007433]  kernfs_seq_show+0xa0/0xb8
> [   75.007800]  seq_read+0x1f0/0x7e8
> [   75.008128]  kernfs_fop_read+0x70/0x338
> [   75.008507]  vfs_read+0xe4/0x250
> [   75.008990]  ksys_read+0xc8/0x180
> [   75.009462]  __arm64_sys_read+0x44/0x58
> [   75.010085]  el0_svc_common.constprop.0+0xac/0x228
> [   75.011006] kmem_cache_destroy test_module_slab: Slab cache still has objects
> 
> Register a cpu hotplug function to remove all objects in the offline
> per-cpu quarantine when cpu is going offline. Set a per-cpu variable
> to indicate this cpu is offline.
> 
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: Guangye Yang <guangye.yang@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> ---
>  mm/kasan/quarantine.c | 40 ++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 40 insertions(+)
> 
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 4c5375810449..cac7c617df72 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -29,6 +29,7 @@
>  #include <linux/srcu.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> +#include <linux/cpuhotplug.h>
>  
>  #include "../slab.h"
>  #include "kasan.h"
> @@ -43,6 +44,7 @@ struct qlist_head {
>  	struct qlist_node *head;
>  	struct qlist_node *tail;
>  	size_t bytes;
> +	bool offline;
>  };
>  
>  #define QLIST_INIT { NULL, NULL, 0 }
> @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>  	local_irq_save(flags);
>  
>  	q = this_cpu_ptr(&cpu_quarantine);
> +	if (q->offline) {
> +		qlink_free(&info->quarantine_link, cache);
> +		local_irq_restore(flags);
> +		return;
> +	}
>  	qlist_put(q, &info->quarantine_link, cache->size);
>  	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>  		qlist_move_all(q, &temp);
> @@ -328,3 +335,36 @@ void quarantine_remove_cache(struct kmem_cache *cache)
>  
>  	synchronize_srcu(&remove_cache_srcu);
>  }
> +
> +static int kasan_cpu_online(unsigned int cpu)
> +{
> +	this_cpu_ptr(&cpu_quarantine)->offline = false;
> +	return 0;
> +}
> +
> +static int kasan_cpu_offline(unsigned int cpu)
> +{
> +	struct qlist_head *q;
> +
> +	q = this_cpu_ptr(&cpu_quarantine);
> +	/* Ensure the ordering between the writing to q->offline and
> +	 * qlist_free_all. Otherwise, cpu_quarantine may be corrupted
> +	 * by interrupt.
> +	 */
> +	WRITE_ONCE(q->offline, true);
> +	barrier();
> +	qlist_free_all(q, NULL);
> +	return 0;
> +}
> +
> +static int __init kasan_cpu_quarantine_init(void)
> +{
> +	int ret = 0;
> +
> +	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> +				kasan_cpu_online, kasan_cpu_offline);
> +	if (ret < 0)
> +		pr_err("kasan cpu quarantine register failed [%d]\n", ret);
> +	return ret;
> +}
> +late_initcall(kasan_cpu_quarantine_init);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/840af74e06e2515c84eb86df2825d466bcf75e96.camel%40redhat.com.
