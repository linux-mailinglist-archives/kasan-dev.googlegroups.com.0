Return-Path: <kasan-dev+bncBDOILZ6ZXABBBS6SS6UAMGQEY4D2UTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 109D87A31B0
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 19:43:41 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-32009388bb6sf125053f8f.1
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 10:43:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694886220; cv=pass;
        d=google.com; s=arc-20160816;
        b=JnnhawAc4uB+n7m9UvZkdr7o60eW1XU7Q7mIL9l8AZNgYqMO1WZDZ1STMbcI52TlJr
         /b5nrGzhFCZmZTcBZR2U2UnV/uU05m+1iuXn13hh1qqB+NBwD/ZZ8uXLId393eF3k/hi
         n4Ae3T2du4jLY4e8ni0Qk7fUwSZyKd3Z1sRPiBLLngaWk+sLDPBtqyAyBVHMt5bvzoLn
         G3HUUpNJilkopUUJw3aa3XlIVaOZvvK4U1EC0BjCxHSM4vZWoZo3U1EDdPGAStA3Uahr
         T70NJy2fLYn8gOcrsgYOJ0CYZzWYfCH3mJ5LfxoqGhr4icKEINz2U86IA3ZLY7Z7b0BV
         BagA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lxhXhmfY9wIPgwssxeDnMa//q0NnlDdJ4sfDbYQA5Jk=;
        fh=Fc24TgRI/RKdyBqPH96qdjUxlrTvTn1GK1CP+gRXGh0=;
        b=0Vjq8e0epwauEE+xpGayZSGxdJyadHD6FBBsSAAuaLRQCGxTfTDBkU5IoDemSdXrZp
         faqCauv9nuCoJ5i61LVtqu/ysjknBJ89axfgUTYq+QXWt5Gw1pwfWIzkoeaz8fTWjyl4
         jZwO5XKBCu0YN4UtGEkJ6FpCh6mydngujCiNszqZOjtgCKZq87ZtclSk1HCAqzOPko7I
         DBCCrNJzO7kAHDPHWPeEATQ7pfdXmuuRV0PCu315tUhhammo7RMn/KD8GDAokQrYfeaa
         OHJv/HqXbxdZTGlLsn5XbIqksEgV7hJn1hcBxnMwOABVPTQ6MhOvCeyxTgzPBtfH/kww
         brHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Z+OCqUL9;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694886220; x=1695491020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lxhXhmfY9wIPgwssxeDnMa//q0NnlDdJ4sfDbYQA5Jk=;
        b=pJEOWuW/1sghkyNL+EbN4j1Dk7AecfP3hw8MNlTYvlzXpqeieRTD5oJnDwl8mXyV+Y
         +3eJWloKZGpgXDoOI+H/zSx9+mhdGoeUhaLwxOW8A8xMA5yod8cxzON9dNgpgd+zwxlj
         oLHy3RmNK5DCD8FbSV/3G2tFJ9veC6uTt4q4ZV2HNap8MabIAZpG++RIZnJTjsLfY3Xb
         Z/FTJEuAOUupPcAafgihe5nzCXzXSo8gQMl5JWwpHM9WBOa+wzEM+cYvCYvlVHdiy4JX
         ZSKz8qL6jial8nMc4fvBnFn8MhtRYoI9mzt2ILrObG6k61kenFRxmpoCi36qXXTO4/wa
         K+9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694886220; x=1695491020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=lxhXhmfY9wIPgwssxeDnMa//q0NnlDdJ4sfDbYQA5Jk=;
        b=Sc40g38IRw38HkPx3rvX3amfNqA7Gm6eoBYq7X/xAKX9UoKWQCCjEUnUa1tJe4rfwT
         D9CjXPwVMK8/3iXCIpsbTB/yqMXO0TG+cxN/Cc97a9ETvJP+pNGyRZOV5Q5f8fHWETmj
         1LzBC6NxyabpDo4IJNZ5Kw9Pnj1LGjCKPd/IJJzviB0xXLM8gXJbyzIl0ejfL7swRep7
         CzgbbHuO76EozMmp9o23cS5vEz4R2mrLInIbOIqEQ5iTli1thmGiTjJJHw7HzjnG1ZCL
         t1ARuaHS3Bpseg3hPw8yx9qhT63Ioz/h2wD6PLECEtyNPowi0uIEHWpjyQecXtsnrBTG
         WVdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwrdT05bT516Y1BHvi2QPfMXDkWkuYJB443kAveQ/8jONDL+Rxz
	1svhBgelkbT4qE9YUIeWowE=
X-Google-Smtp-Source: AGHT+IEULHBiHi5KXFIeqdeHgbEPSxcunGMU2RUiaw1cEdlno+pQMBM8Ne89rUUiIFIAZtC+qdY6ag==
X-Received: by 2002:adf:ed88:0:b0:31a:eb77:2ae7 with SMTP id c8-20020adfed88000000b0031aeb772ae7mr3603270wro.64.1694886220065;
        Sat, 16 Sep 2023 10:43:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:45cb:0:b0:317:79ec:7a0 with SMTP id b11-20020a5d45cb000000b0031779ec07a0ls792019wrs.1.-pod-prod-04-eu;
 Sat, 16 Sep 2023 10:43:38 -0700 (PDT)
X-Received: by 2002:a05:600c:2a54:b0:3fe:4cbc:c345 with SMTP id x20-20020a05600c2a5400b003fe4cbcc345mr4652645wme.41.1694886218412;
        Sat, 16 Sep 2023 10:43:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694886218; cv=none;
        d=google.com; s=arc-20160816;
        b=pO/HbkRkaDg6pGEdSANJSvg7tta9qbfywvRfid02fN7l6oJ6pRqrXvunOlExlS0B6g
         LpTJru85T5muRxYLGyyyTbpz6a8Piw72fEOD7jNwVkjAzLMxgA7rLj2H7JlUmU6K6tvi
         KNBJwRmQjZjQJNaB8HkIq5RFBlL8ZP1e70YNiiosAE6dp8kCrh2+EuCjOdD4D3gDyWXK
         UYZQH45EtZHvsWdn+iV2gnWbFiDai4ApPtSYY2ri6t2BxQps00u3GC6USL1tbnCOGG6h
         4F2VBqvZRkuUTSnMd+mlOzEaf8NJZT3V52r3ETJzEUo4aAjeHduxXnPNVGurWZhFvD+V
         AQ0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=TIVt11VXEPQxcMmnR7p7Lc2b9PwXHp0ElLuvknOACcw=;
        fh=Fc24TgRI/RKdyBqPH96qdjUxlrTvTn1GK1CP+gRXGh0=;
        b=FL2GtCFn/8E6hawtwkZF7dN4W7zIncSJ0+oyOn4R+vFS1q7txe4kMFqla/h1a1ljlW
         jy9vUZOUw126ZnO1m1oQoLVNlQ2/7HYir32OBvezY1iVr6COjh6hiE4laVZINg5tBpyC
         9hYngiHF1HTok2kTLIsgfG2AoHIU7zcanK67z+bJPZm9wigGkHXKzbxZw19dH3a4OwZs
         AA1X/4Gh5H+23fOsmVbDpcIAIqXndv9oJlMe57BAogTyz/2LkV7MpbPBL+EYHGbX0EKW
         Zmc2Win6BqBPtNzpVlIr+/GUk5z9998yF5FyIlzEK9LtoTFagTSOKiTF1dVnlNcaCP/Z
         U9ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Z+OCqUL9;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id m17-20020a05600c3b1100b003fe1f9a8405si35311wms.0.2023.09.16.10.43.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Sep 2023 10:43:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-5008d16cc36so5304062e87.2
        for <kasan-dev@googlegroups.com>; Sat, 16 Sep 2023 10:43:38 -0700 (PDT)
X-Received: by 2002:ac2:5976:0:b0:4fb:911b:4e19 with SMTP id h22-20020ac25976000000b004fb911b4e19mr4035596lfp.35.1694886217563;
        Sat, 16 Sep 2023 10:43:37 -0700 (PDT)
Received: from mutt (c-9b0ee555.07-21-73746f28.bbcust.telenor.se. [85.229.14.155])
        by smtp.gmail.com with ESMTPSA id w10-20020ac254aa000000b004fdc0f2caafsm1103942lfk.48.2023.09.16.10.43.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 16 Sep 2023 10:43:36 -0700 (PDT)
Date: Sat, 16 Sep 2023 19:43:35 +0200
From: Anders Roxell <anders.roxell@linaro.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>, arnd@arndb.de,
	sfr@canb.auug.org.au
Subject: Re: [PATCH v2 12/19] lib/stackdepot: use list_head for stack record
 links
Message-ID: <20230916174334.GA1030024@mutt>
References: <cover.1694625260.git.andreyknvl@google.com>
 <d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=Z+OCqUL9;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On 2023-09-13 19:14, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Switch stack_record to use list_head for links in the hash table
> and in the freelist.
> 
> This will allow removing entries from the hash table buckets.
> 
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 

Building on an arm64 kernel from linux-next tag next-20230915, and boot
that in QEMU. I see the following kernel panic.

[   67.398850][    T1] Unable to handle kernel read from unreadable memory at virtual address 0000000000000010
[   67.407996][    T1] Mem abort info:
[   67.411023][    T1]   ESR = 0x0000000096000004
[   67.414757][    T1]   EC = 0x25: DABT (current EL), IL = 32 bits
[   67.419945][    T1]   SET = 0, FnV = 0
[   67.423172][    T1]   EA = 0, S1PTW = 0
[   67.426669][    T1]   FSC = 0x04: level 0 translation fault
[   67.431357][    T1] Data abort info:
[   67.434593][    T1]   ISV = 0, ISS = 0x00000004, ISS2 = 0x00000000
[   67.439801][    T1]   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
[   67.444948][    T1]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[   67.449910][    T1] [0000000000000010] user address but active_mm is swapper
[   67.456236][    T1] Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP
[   67.462181][    T1] Modules linked in:
[   67.465435][    T1] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G                T  6.6.0-rc1-next-20230915 #2 e95cf19845fbc1e6a5f0694214d59e527e463469
[   67.477126][    T1] Hardware name: linux,dummy-virt (DT)
[   67.481994][    T1] pstate: 804000c5 (Nzcv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   67.488454][    T1] pc : stack_depot_save_flags+0x2a8/0x780
[   67.493348][    T1] lr : stack_depot_save_flags+0x2a8/0x780
[   67.498339][    T1] sp : ffff80008000b870
[   67.501670][    T1] x29: ffff80008000b870 x28: 00000000650dddc5 x27: 0000000000000000
[   67.508658][    T1] x26: ffff80008470a000 x25: ffff80008000b9e8 x24: 0000000000000001
[   67.515564][    T1] x23: 000000000000000e x22: ffff80008000b988 x21: 0000000000000001
[   67.522430][    T1] x20: ffff00007b40d070 x19: 000000006ee80007 x18: ffff80008000d080
[   67.529365][    T1] x17: 0000000000000000 x16: 0000000000000000 x15: 2030303178302f30
[   67.536101][    T1] x14: 0000000000000000 x13: 205d315420202020 x12: 0000000000000000
[   67.542985][    T1] x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
[   67.549863][    T1] x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
[   67.556764][    T1] x5 : 0000000000000000 x4 : 0000000000000000 x3 : 0000000000000000
[   67.563687][    T1] x2 : 0000000000000000 x1 : 0000000000000000 x0 : 0000000000000000
[   67.570500][    T1] Call trace:
[   67.573275][    T1]  stack_depot_save_flags+0x2a8/0x780
[   67.577794][    T1]  stack_depot_save+0x4c/0xc0
[   67.582062][    T1]  ref_tracker_alloc+0x354/0x480
[   67.586273][    T1]  sk_alloc+0x280/0x5f8
[   67.590064][    T1]  __netlink_create+0x84/0x200
[   67.594009][    T1]  __netlink_kernel_create+0x11c/0x500
[   67.598816][    T1]  rtnetlink_net_init+0xc4/0x180
[   67.603052][    T1]  ops_init+0x100/0x2c0
[   67.606827][    T1]  register_pernet_operations+0x228/0x480
[   67.611568][    T1]  register_pernet_subsys+0x5c/0xc0
[   67.616282][    T1]  rtnetlink_init+0x60/0xb00
[   67.620086][    T1]  netlink_proto_init+0x374/0x400
[   67.624465][    T1]  do_one_initcall+0x2c8/0x840
[   67.628518][    T1]  do_initcalls+0x21c/0x340
[   67.632527][    T1]  kernel_init_freeable+0x3b0/0x480
[   67.636905][    T1]  kernel_init+0x58/0x380
[   67.640768][    T1]  ret_from_fork+0x10/0x40
[   67.644606][    T1] Code: eb1b029f 540008c0 91004360 97caa437 (b9401360) 
[   67.650293][    T1] ---[ end trace 0000000000000000 ]---
[   67.654948][    T1] Kernel panic - not syncing: Oops: Fatal exception
[   67.660229][    T1] ---[ end Kernel panic - not syncing: Oops: Fatal exception ]---

The full log can be found [1] and the .config file [2]. I bisected down
to this commit, see the bisect log [3].

When reverted these two commits I managed to build and the kernel
booted.

47590ecf1166 ("lib/stackdepot: use list_head for stack record links")
8729f3c26fc2 ("lib/stackdepot: allow users to evict stack traces")


Cheers,
Anders
[1] http://ix.io/4GyE
[2] https://people.linaro.org/~anders.roxell/next-20230915.config
[3] http://ix.io/4GyG

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230916174334.GA1030024%40mutt.
