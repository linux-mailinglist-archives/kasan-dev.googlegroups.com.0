Return-Path: <kasan-dev+bncBCAP7WGUVIKBBLPQ4KXAMGQE6Y3PLCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CD5B986156D
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 16:22:22 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3651fbce799sf155105ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 07:22:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708701741; cv=pass;
        d=google.com; s=arc-20160816;
        b=BEbQLJhQKl4N/y4yTxZHfJqtTG7yNGS8QCp6K5j1ouVDwBRvfTyrc2x7Ydi2Xrw0+/
         TAMdT/76UO7ncgm65TuGAuXCZedCJx+uZy50PkP11nsFGyB9qbpD8E2eJBoB3/L6bAze
         aoHgqItoFv96yMzSs3m3vd+E2RMDXMya0w4YrZY/ulmhRrbN7gnvP44E/R3r9MJAsSLI
         Jsf8Uh+nref3YG5+7tuv+LZkAvtmfQUXDH7XzpZNfGnJqqVZLCRwom55dPATXYBBbjRm
         ymT4sWA37tqXDmymiwRAw97iREkaDxYFnt7UrnNTkT2cIUHGiyvFEyXT8oYE0y3x38nZ
         TYGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=HQcFPqR0mzkCBGekPS8JpXh/bMkCjfA9VSP4+9gwh78=;
        fh=t50YKgjZFCjR67Id66TifKYbpuJ5FGuo8CexCphxG8k=;
        b=K8U3GimC9Nbz0b7TPr8BTrq+YIf9GvNL1hJQjMsqDhEel9pmwMiZADnrrVgasntTwF
         PS9QAnJRYXFTTOhSSVoTi3FLeCt+NIHEd/jkHm0PKAPVnv8dS1yobsf6KSDLmNh/3SpX
         bVHmSJO6QJTRXp0whu7rk98UOyNzEFS2lCSo6QGKaEmqKDJ98jlL1hRnStp02psg0Tv5
         CoxW7tbsRnDzqTJUa8dWu+H8KhCOlVhNnDlZStnKKG+DrOyvcvn+HP4rHV8Tx7HDH51/
         4rqyAkM2ZZ+ZUxSjj/r1D9q6kwNSjXYmSNcTPA4KLSTWytoBAzuVFkC8jOFMBCw9fyfE
         KppQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708701741; x=1709306541; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HQcFPqR0mzkCBGekPS8JpXh/bMkCjfA9VSP4+9gwh78=;
        b=kWGcOcf+H/6Vm1NLF3og2pVbhHZ6+zuztfrJtLbUK9USu0u0DG0ZBjGKZr3dHH/23q
         V2yhKkt538TS+S5brh2DhS1U5x8iKbyALugyZWgFU8g7ETovWv5dWWs/Y6HY+ojXxnte
         I9SNYz3D14BKnl/BljNOGBrWfiyxgbL8LsGoUoes94zzoL11ZLsoUv53lWLjWV/6LnVE
         NVCXSaGrXw46yEMnh/k/Jct25aK4GskJO9DPh5vhMYuKv/MAb33VzPzD7rySPZ+lCcDZ
         pUp6neSp81PknM5L7QCa2KOGbMwoRCWbSpB8Z48E6RSTe1lj9ut8AYLPRlYjqTIQpFUC
         Drkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708701741; x=1709306541;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HQcFPqR0mzkCBGekPS8JpXh/bMkCjfA9VSP4+9gwh78=;
        b=MPCmzNjuj8xNKoHyraZ5wUXkSzYD8FrL30GUrlL7GeqJPf6MCHeleHhIb2ITwWYsF3
         A3+sDn046DNMhu8w6TxxTMkbhXDHKalJuaFj2gzj+aJsGq3vjIyN/ags7BxpJNRAwQqs
         rdKuAfvdYOYH/gPRLE8mbWpywc88ZkTE5wPGW2SjxBl6KozQm9FDDLkTL7k6zOS9Auxs
         NMLnWHVxcbPGdsaUQmYT4AjBz+Uf822B8MqlYipNPCH6qYldboFy65bCvDklC5ApE8zn
         Qekffy8d3CQsWLm1u5EUTGC4rQTKbpVfzqvc82l6pNxaYuo3gNaDyn/QoiJHJYchSJGd
         dIWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxst8jR0wt4f6pxT17Y3vfQH4jptXUAvUJtJDwbhQwJwL+RPgNjX8iq1m1H4jMUwFdMs0pJLepFYDI3cJrMk7KfjmJ4kcCtw==
X-Gm-Message-State: AOJu0YzAMdMCrd5sEtRhvkIXjeJEemSE3ZXTi4dpDDotYHeSAiYbckEB
	H6+8YnbjL9Nj7eUjkUuNEpBRz1O4efk0THoBrn5VmPf6s5Jx5Rpu
X-Google-Smtp-Source: AGHT+IGoBkNxqZ6ehhXuA6Nj2Guv3kye9O9rp15JgiB233XKA9TpwMUZDUp3b57osdFiWPv9DufRCQ==
X-Received: by 2002:a05:6e02:3046:b0:365:3320:fe1 with SMTP id be6-20020a056e02304600b0036533200fe1mr815205ilb.20.1708701741257;
        Fri, 23 Feb 2024 07:22:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:32cd:b0:21e:3b64:cda4 with SMTP id
 r13-20020a05687032cd00b0021e3b64cda4ls988805oac.0.-pod-prod-03-us; Fri, 23
 Feb 2024 07:22:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWBwuf+4jfYAFEFWzMfdcXhdnAj1U3nLvL3/AJ8s6njhjgc37VBEf39gUOBwuLpYfZ6IdHw2QRPRqhjvEfMjMXnDU0Tuo8O8XIog==
X-Received: by 2002:a05:6870:c394:b0:21e:6080:d541 with SMTP id g20-20020a056870c39400b0021e6080d541mr95898oao.48.1708701740268;
        Fri, 23 Feb 2024 07:22:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708701740; cv=none;
        d=google.com; s=arc-20160816;
        b=VVnMcD833BtCFpgAtwhOcnIamc6buMvCwxu4E3lK8bn8LarInP42WjIqypbwYT2PdA
         UGd+Z61PCg0o9PtJi8jv/HlX82WX1QeaMrnr97IREeEgidhmA2ektj82up5qLtAI8G5V
         kQLAtXCPO5Motf0w2TM8fWxVsuZ8mL09NZ4GGepEBg3b+ORaguk8+LVOZOOHW9wRBx8B
         FL5OYvH9knCCgw8kPfaWOupD8XLuT4x5fqPh1il79/FvBgCqJu/RfwWr6mgHU3AwFuwC
         LFEYETl+wBlRQbdtFQ4HBfvKdPbRN4vRh71CVuwpx/JvbrXxsdVAucIk9E+ULJ9PiMRy
         70tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Wbo+3NIdKlqMCnkFOBVs2GkLzROI0Vz3hWQRmIvv1Po=;
        fh=KfLsvyDDQmaKpGuRmqQvDVGEpKPYtMaYXUZf0Td+47Q=;
        b=hO5jGfnuNFFQxroKCIu6RB2Zc+hP0PmCileLTdpexrXMaQVmH8RHOvm0XANCFWV1tn
         AIbohu3649cLzP6DQdHqTHuXZXdfZilNH3HFBYeOEmqchs9YmBeiZzHlNs4cM9psG9RJ
         eLrRJPR1ssulI0KSgMDQjX46CGlpbqP8bfZH+w1RrIoObGIAedbmfxSjR+L3Sm0kD+Eo
         pNuugHExqrxgH2iDbr4DI/pWNKqkY3Vu4f1Egh9VuQEGyFWkl8ngdeDjLx9hbBQ48SL/
         NJxvjAclUhog6j1ItOLSnFDQ330zB4QX5Wl3owJg42MaQJyloJC85jQxO4Udt1SLmxcn
         a+Qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id vl7-20020a0568710e8700b0021e848b6f2csi1228024oab.3.2024.02.23.07.22.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Feb 2024 07:22:19 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav313.sakura.ne.jp (fsav313.sakura.ne.jp [153.120.85.144])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41NFM5Cl065122;
	Sat, 24 Feb 2024 00:22:05 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav313.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp);
 Sat, 24 Feb 2024 00:22:05 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41NFM5kN065118
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 24 Feb 2024 00:22:05 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <6dd78966-1459-465d-a80a-39b17ecc38a6@I-love.SAKURA.ne.jp>
Date: Sat, 24 Feb 2024 00:22:03 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [mm/page_alloc or mm/vmscan or mm/zswap] use-after-free in
 obj_malloc()
Content-Language: en-US
To: Sergey Senozhatsky <senozhatsky@chromium.org>,
        Alexander Potapenko <glider@google.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>, Yosry Ahmed
 <yosryahmed@google.com>,
        Nhat Pham <nphamcs@gmail.com>, Minchan Kim <minchan@kernel.org>,
        linux-mm <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>,
        Mark-PK Tsai <mark-pk.tsai@mediatek.com>
References: <d041ca52-8e0b-48b3-9606-314ac2a53408@I-love.SAKURA.ne.jp>
 <20240223044356.GJ11472@google.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <20240223044356.GJ11472@google.com>
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

On 2024/02/23 13:43, Sergey Senozhatsky wrote:
> On (24/02/23 11:10), Tetsuo Handa wrote:
>>
>> I can observe this bug during evict_folios() from 6.7.0 to 6.8.0-rc5-00163-gffd2cb6b718e.
>> Since I haven't observed with 6.6.0, this bug might be introduced in 6.7 cycle.
> 
> Can we please run a bisect?

Bisection pointed at commit afb2d666d025 ("zsmalloc: use copy_page for full page copy"),
for copy_page() is implemented as non-instrumented code where KMSAN cannot handle.
On x86_64, copy_page() is defined at arch/x86/lib/copy_page_64.S as below.

----------------------------------------
/*
 * Some CPUs run faster using the string copy instructions (sane microcode).
 * It is also a lot simpler. Use this when possible. But, don't use streaming
 * copy unless the CPU indicates X86_FEATURE_REP_GOOD. Could vary the
 * prefetch distance based on SMP/UP.
 */
        ALIGN
SYM_FUNC_START(copy_page)
        ALTERNATIVE "jmp copy_page_regs", "", X86_FEATURE_REP_GOOD
        movl    $4096/8, %ecx
        rep     movsq
        RET
SYM_FUNC_END(copy_page)
EXPORT_SYMBOL(copy_page)
----------------------------------------

To fix this problem, we need to implement copy_page() etc. in a way
KMSAN can handle.

Question to KASAN people:
Is it possible to add annotation for KMSAN into assembly code?
Do we need to disable assembly version and force use of C version
when KMSAN is enabled?

> 
> There are some zsmalloc patches for 6.8 (mm-unstable), I don't recall
> anything in 6.7.
> 
>> ----------------------------------------
>> [    0.000000][    T0] Linux version 6.8.0-rc5-00163-gffd2cb6b718e (root@ubuntu) (Ubuntu clang version 14.0.0-1ubuntu1.1, Ubuntu LLD 14.0.0) #1094 SMP PREEMPT_DYNAMIC Fri Feb 23 01:45:21 UTC 2024
>> [   50.026544][ T2974] =====================================================
>> [   50.030627][ T2974] BUG: KMSAN: use-after-free in obj_malloc+0x6cc/0x7b0
>> [   50.034611][ T2974]  obj_malloc+0x6cc/0x7b0
>>                                                            obj_malloc at mm/zsmalloc.c:0
>> [   50.037250][ T2974]  zs_malloc+0xdbd/0x1400
>>                                                            zs_malloc at mm/zsmalloc.c:0
>> [   50.039852][ T2974]  zs_zpool_malloc+0xa5/0x1b0
>>                                                            zs_zpool_malloc at mm/zsmalloc.c:372
>> [   50.044707][ T2974]  zpool_malloc+0x110/0x150
>>                                                            zpool_malloc at mm/zpool.c:258
>> [   50.049607][ T2974]  zswap_store+0x2bbb/0x3d30
>>                                                            zswap_store at mm/zswap.c:1637
>> [   50.054463][ T2974]  swap_writepage+0x15b/0x4f0
>>                                                            swap_writepage at mm/page_io.c:198
>> [   50.059392][ T2974]  pageout+0x41d/0xef0
>>                                                            pageout at mm/vmscan.c:654
>> [   50.064057][ T2974]  shrink_folio_list+0x4d7a/0x7480
>>                                                            shrink_folio_list at mm/vmscan.c:1316
>> [   50.069176][ T2974]  evict_folios+0x30f1/0x5170
>>                                                            evict_folios at mm/vmscan.c:4521
>> [   50.074082][ T2974]  try_to_shrink_lruvec+0x983/0xd20
>> [   50.079352][ T2974]  shrink_one+0x72d/0xeb0
>> [   50.084061][ T2974]  shrink_many+0x70d/0x10b0
>> [   50.088859][ T2974]  lru_gen_shrink_node+0x577/0x850
>> [   50.094192][ T2974]  shrink_node+0x13d/0x1de0
>> [   50.099028][ T2974]  shrink_zones+0x878/0x14a0
>> [   50.103958][ T2974]  do_try_to_free_pages+0x2ac/0x16a0
>> [   50.109138][ T2974]  try_to_free_pages+0xd9e/0x1910
>> [   50.114190][ T2974]  __alloc_pages_slowpath+0x147a/0x2bd0
>> [   50.119555][ T2974]  __alloc_pages+0xb8c/0x1050
>> [   50.124472][ T2974]  alloc_pages_mpol+0x8e0/0xc80
>> [   50.129367][ T2974]  alloc_pages+0x224/0x240
>> [   50.134022][ T2974]  pipe_write+0xabe/0x2ba0
>> [   50.138632][ T2974]  vfs_write+0xfb0/0x1b80
>> [   50.143171][ T2974]  ksys_write+0x275/0x500
>> [   50.147723][ T2974]  __x64_sys_write+0xdf/0x120
>> [   50.152431][ T2974]  do_syscall_64+0xd1/0x1b0
>> [   50.157106][ T2974]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
>> [   50.162382][ T2974] 
>> [   50.165956][ T2974] Uninit was stored to memory at:
>> [   50.170819][ T2974]  obj_malloc+0x70a/0x7b0
>>                                                            set_freeobj at mm/zsmalloc.c:476
>>                                                            (inlined by) obj_malloc at mm/zsmalloc.c:1333
>> [   50.175341][ T2974]  zs_malloc+0xdbd/0x1400
>>                                                            zs_malloc at mm/zsmalloc.c:0
>> [   50.179923][ T2974]  zs_zpool_malloc+0xa5/0x1b0
>>                                                            zs_zpool_malloc at mm/zsmalloc.c:372
>> [   50.184636][ T2974]  zpool_malloc+0x110/0x150
>>                                                            zpool_malloc at mm/zpool.c:258
>> [   50.189257][ T2974]  zswap_store+0x2bbb/0x3d30
>>                                                            zswap_store at mm/zswap.c:1637
>> [   50.193918][ T2974]  swap_writepage+0x15b/0x4f0
>>                                                            swap_writepage at mm/page_io.c:198
>> [   50.198615][ T2974]  pageout+0x41d/0xef0
>>                                                            pageout at mm/vmscan.c:654
>> [   50.203012][ T2974]  shrink_folio_list+0x4d7a/0x7480
>>                                                            shrink_folio_list at mm/vmscan.c:1316
>> [   50.207772][ T2974]  evict_folios+0x30f1/0x5170
>>                                                            evict_folios at mm/vmscan.c:4521
>> [   50.212321][ T2974]  try_to_shrink_lruvec+0x983/0xd20
>> [   50.217092][ T2974]  shrink_one+0x72d/0xeb0
>> [   50.221441][ T2974]  shrink_many+0x70d/0x10b0
>> [   50.225891][ T2974]  lru_gen_shrink_node+0x577/0x850
>> [   50.230614][ T2974]  shrink_node+0x13d/0x1de0
>> [   50.235128][ T2974]  shrink_zones+0x878/0x14a0
>> [   50.239646][ T2974]  do_try_to_free_pages+0x2ac/0x16a0
>> [   50.244461][ T2974]  try_to_free_pages+0xd9e/0x1910
>> [   50.249151][ T2974]  __alloc_pages_slowpath+0x147a/0x2bd0
>> [   50.254148][ T2974]  __alloc_pages+0xb8c/0x1050
>> [   50.258679][ T2974]  alloc_pages_mpol+0x8e0/0xc80
>> [   50.263289][ T2974]  alloc_pages+0x224/0x240
>> [   50.267767][ T2974]  pipe_write+0xabe/0x2ba0
>> [   50.272190][ T2974]  vfs_write+0xfb0/0x1b80
>> [   50.276543][ T2974]  ksys_write+0x275/0x500
>> [   50.280931][ T2974]  __x64_sys_write+0xdf/0x120
>> [   50.289451][ T2974]  do_syscall_64+0xd1/0x1b0
>> [   50.303402][ T2974]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
>> [   50.318721][ T2974] 
>> [   50.328931][ T2974] Uninit was created at:
>> [   50.341845][ T2974]  free_unref_page_prepare+0x130/0xfc0
>>                                                            arch_static_branch_jump at arch/x86/include/asm/jump_label.h:55
>>                                                            (inlined by) memcg_kmem_online at include/linux/memcontrol.h:1840
>>                                                            (inlined by) free_pages_prepare at mm/page_alloc.c:1096
>>                                                            (inlined by) free_unref_page_prepare at mm/page_alloc.c:2346
>> [   50.356492][ T2974]  free_unref_page_list+0x139/0x1050
>>                                                            free_unref_page_list at mm/page_alloc.c:2532
>> [   50.370898][ T2974]  shrink_folio_list+0x7139/0x7480
>>                                                            list_empty at include/linux/list.h:373
>>                                                            (inlined by) list_splice at include/linux/list.h:545
>>                                                            (inlined by) shrink_folio_list at mm/vmscan.c:1490
>> [   50.385025][ T2974]  evict_folios+0x30f1/0x5170
>>                                                            evict_folios at mm/vmscan.c:4521
>> [   50.398448][ T2974]  try_to_shrink_lruvec+0x983/0xd20
>> [   50.412660][ T2974]  shrink_one+0x72d/0xeb0
>> [   50.425591][ T2974]  shrink_many+0x70d/0x10b0
>> [   50.438827][ T2974]  lru_gen_shrink_node+0x577/0x850
>> [   50.454390][ T2974]  shrink_node+0x13d/0x1de0
>> [   50.479401][ T2974]  shrink_zones+0x878/0x14a0
>> [   50.529610][ T2974]  do_try_to_free_pages+0x2ac/0x16a0
>> [   50.544397][ T2974]  try_to_free_pages+0xd9e/0x1910
>> [   50.559556][ T2974]  __alloc_pages_slowpath+0x147a/0x2bd0
>> [   50.574932][ T2974]  __alloc_pages+0xb8c/0x1050
>> [   50.589024][ T2974]  alloc_pages_mpol+0x8e0/0xc80
>> [   50.603421][ T2974]  alloc_pages+0x224/0x240
>> [   50.616483][ T2974]  pipe_write+0xabe/0x2ba0
>> [   50.629601][ T2974]  vfs_write+0xfb0/0x1b80
>> [   50.643009][ T2974]  ksys_write+0x275/0x500
>> [   50.656157][ T2974]  __x64_sys_write+0xdf/0x120
>> [   50.670080][ T2974]  do_syscall_64+0xd1/0x1b0
>> [   50.683405][ T2974]  entry_SYSCALL_64_after_hwframe+0x63/0x6b
>> [   50.698626][ T2974] 
>> ----------------------------------------

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6dd78966-1459-465d-a80a-39b17ecc38a6%40I-love.SAKURA.ne.jp.
