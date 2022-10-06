Return-Path: <kasan-dev+bncBDK7LR5URMGRBWXL7OMQMGQESD3YCMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 035865F6ABA
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 17:35:55 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id i26-20020adfaada000000b0022e2f38ffccsf665239wrc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 08:35:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665070554; cv=pass;
        d=google.com; s=arc-20160816;
        b=0dAySF5PgBLUSfqUrCBKCSV+VyhoBRI+64oTsYDP8akc/maZVfSetJ/1GW5E6cfdrt
         ddIZYFmRGpb3beOcBhViYj3vPzpHolphJc795N1ZuyHDHdczhpt5HReGuqjKV/NYw3S9
         pzvY+0IL8mP6ub8DWqgDNTVYZ4e9bqWrHSAjqVskefo9CexSnh9s237zHWaDlnTspy0Z
         AbRr3qyp8Fx7IasKS5WD/cN8vUWe6I6qWy/mFiEOvXBV7JRLxHcaX6aC/52hCMdS3K2Z
         Q1mauWZgUV4KTsmP6I4wAiFYyIK/r9DrdRTgNN6qoQp7c9C6Mt8MK/rHgBRPxl5w3ovM
         cXxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=USM4Ew9eRJriD4kObKYSP4iXetK7+KpPve0innTdFs0=;
        b=wNEYsDOzRz9DK7N6OU2mYVsa3NdM4SVEQNhyJ5PDbT76KVHOiPYJhxvvJgnPTBvlag
         m+HxOD7NMvpEpJZuHK2NbMZy2KZOy0LcbyEbHf/we2yc0UCL9Z2T7zZ7KGWtpthXMYk9
         h5WsPOBDEQXrcs9YBrQFagbgdJJdptJn4dg3hvh4/KFP6eH68IV36O59Y8fBua9jzFO3
         mSG2VpxMR/zTEDa6uK4pjRyLJFzoFRH40vMxMAYJtVTPaiq3/BI+3Ask8f1RoBX9j2hK
         U3hVw32ieDb1R/tX8VzlQC0E/sQm66X7hfiLaQ5WEuA0qcqwEsp6iQGHdgZyxDsFEbJi
         DYUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HRnOx16I;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=USM4Ew9eRJriD4kObKYSP4iXetK7+KpPve0innTdFs0=;
        b=NSzLM9b1t65iuZTbQPz/vd/VDx/oCn19O5YO7Geg4Jrj2SlRCCwPRoJfxotDBg1PUg
         /FHf40g2cVIi2XBuAsed7u/6KldL4MOZX3D98pYprKUMTyyiy+PJTAn5besqBIOf/1fa
         xd0nulZs84r0OHWSf9vgyhLLDVh6KwtJxkkAGvnToi/U0N2UuFZIKABRpB3G/h9C34Bj
         swpWT7kgnjw59VvCjyO0JBm+s+Izv/miQyIfK+VZXBHVUOgZvRWobaHj/Vp2H+6mx9+M
         uRloIBNJiHl11C2XYh5v0p2A3ADNqJ+1PZNYeCZjgCnZpHEDgy9EGB0NBzS4l2QIIa89
         plLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=USM4Ew9eRJriD4kObKYSP4iXetK7+KpPve0innTdFs0=;
        b=Wb45qvl68u9lQt59iyXNX6XdD0bHQ3m3P1j/SgdMjJdoCXfUEmANZ42B9U6Xf4RZT6
         RdRXwAnd36yoi3ZvybdltidZVPP/RDlbLg45i8K8nrOmEXjrB70EivwDI7sG8XORcCMf
         in+Ho14TyIEepYvJZjlFppLmVxfrB0jRjiaNqz2fVplaw5CbUrHA2Z0I6W/Kb9KXX5jj
         2mxPIJiysMsspk9qyz+WUZZpcsPFc9n7YFT6KN9F/NwOxTXL6buteyzcYKfj0/ukru06
         1b1JvOot3cJCMy3eFfXBTYwSMqjog6agnJMf8RgdIGnP+iUa+sNNUK27B3wP421RbhZN
         Rkqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=USM4Ew9eRJriD4kObKYSP4iXetK7+KpPve0innTdFs0=;
        b=Mtg0o0Eb1DFgqk22qsvgP62e1Op5PDvcDFLbVng8gi6IKuFiVHqOBRwTD6Qcj3LyWl
         sZbTLm5E3lmUJXXz/b0pWzFy+qReZ94S4sCsjr2+aYnLw+ugBxbNgQ8KTsUTZrjrr4Ee
         gFswiDlnpjLU3P0vqfauqu7uS6MSUodHteMoSgh56SeAdJpScZsoe2in1qkbLzCEE8e1
         q4b2Ws+ZuaV6/nDKr43Rx15877djJrMaldzQmIxrbFhW9O5PnR0NEGQo7KtuAkTtHPwZ
         T4fYvePm9Y8+LpykxfGNZmivCn1kYlnrbKP4ZeXyjjMd+j112Qxu/7q1SHMUe68WSSJu
         bs2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1QHhW5obME2sX+t1Cfi6MN7kTOu4le0Vubvbh5g8lj/SLJpeBq
	c7d5NStcYWFmJQAz4Vmf/po=
X-Google-Smtp-Source: AMsMyM504N7Sr7NguOp/B43lf+KojU3D81F2mnrzlk9/NtCpnw+Zdcg9rrS83J7aY9zBU3hRoRwsyg==
X-Received: by 2002:a1c:ed0b:0:b0:3c1:d16e:a827 with SMTP id l11-20020a1ced0b000000b003c1d16ea827mr246051wmh.127.1665070554527;
        Thu, 06 Oct 2022 08:35:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:70b:b0:22e:5d8a:c92d with SMTP id
 bs11-20020a056000070b00b0022e5d8ac92dls4178018wrb.1.-pod-prod-gmail; Thu, 06
 Oct 2022 08:35:53 -0700 (PDT)
X-Received: by 2002:a5d:4385:0:b0:22e:34df:5511 with SMTP id i5-20020a5d4385000000b0022e34df5511mr381831wrq.712.1665070553517;
        Thu, 06 Oct 2022 08:35:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665070553; cv=none;
        d=google.com; s=arc-20160816;
        b=VYIlw7510Q11+WaUlJEjGuM+IWXS93BK+ilyNfLzXP0tNQXuIGfO2+4EDUNkLxRJcA
         h+hMuJtNnF0jYSFEcnO6eYKiWH7DV7GNri2tY7y4h+Vd0gYX666irZnofGwkTRqV20nw
         QrHQxBkzpyKoinfb/OzbJjdt93KzQwJn9V4/uSsK2npDtRMbONFWtYpa/0Ye4g7R+9ZO
         8mLZcrqSrEQkPItWEgKUFbMmhqdwKaN5lSZNMyshkfoAktwRdmefu8UJpLot+GX2yiWF
         ooyM8S3OGvXSJPnXgs28LXy+8BoQQTc0lydKjocRXQtrKq//kQD+o0iaGqN23v+N/vVM
         cu/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=6CuEgzY/EsQIVYA7F7bbwn+/BSxzEsOn8OyorR31d+4=;
        b=tEAJq+qa/gXvUlmj4ht/tvtqc/GHleGgQvbF+uCsGxgjmIkdESBg93LAM9gj9p8nqc
         vD2iQxY3kFVlOvxsDwtxLcd/x8hqkRY7yc6IaGrrvjzXTWF2/8xF0E8xX3xiFJkznYIX
         o1hbSwDMwzfLAwocVBMX0RP5f7wisXWFZJxeBzLW+G0NWVRKSRN9etSUmKyPA420e+E7
         kI1BRk7fJm15/yFgmnaL+UMi/UHbY+vi1xPikFexLVQhsY9HwIa9fnI58CowRM7XUHht
         UmXHUWjoAkCR/F9XUAGyFfKSaHCMjHa53K6op2YnQ3dxf+gPlrgu+iYZ8TYYpbVMux5k
         iT1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HRnOx16I;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id l189-20020a1c25c6000000b003a49e4e7e14si361412wml.0.2022.10.06.08.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 08:35:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id f9so2629584ljk.12
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 08:35:53 -0700 (PDT)
X-Received: by 2002:a05:651c:17a1:b0:26c:87c:c104 with SMTP id bn33-20020a05651c17a100b0026c087cc104mr74977ljb.419.1665070553064;
        Thu, 06 Oct 2022 08:35:53 -0700 (PDT)
Received: from pc636 (host-90-235-28-254.mobileonline.telia.com. [90.235.28.254])
        by smtp.gmail.com with ESMTPSA id o20-20020a056512231400b004979ec19380sm2717433lfu.285.2022.10.06.08.35.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 08:35:52 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Thu, 6 Oct 2022 17:35:49 +0200
To: David Hildenbrand <david@redhat.com>
Cc: Alexander Potapenko <glider@google.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
Message-ID: <Yz711WzMS+lG7Zlw@pc636>
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=HRnOx16I;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> Hi,
> 
> we're currently hitting a weird vmap issue in debug kernels with KASAN enabled
> on fairly large VMs. I reproduced it on v5.19 (did not get the chance to
> try 6.0 yet because I don't have access to the machine right now, but
> I suspect it persists).
> 
> It seems to trigger when udev probes a massive amount of devices in parallel
> while the system is booting up. Once the system booted, I no longer see any
> such issues.
> 
> 
> [  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.836622] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
> [  165.837461] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
> [  165.840573] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.841059] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.841428] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.841819] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.842123] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.843359] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.844894] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.847028] CPU: 253 PID: 4995 Comm: systemd-udevd Not tainted 5.19.0 #2
> [  165.935689] Hardware name: Lenovo ThinkSystem SR950 -[7X12ABC1WW]-/-[7X12ABC1WW]-, BIOS -[PSE130O-1.81]- 05/20/2020
> [  165.947343] Call Trace:
> [  165.950075]  <TASK>
> [  165.952425]  dump_stack_lvl+0x57/0x81
> [  165.956532]  warn_alloc.cold+0x95/0x18a
> [  165.960836]  ? zone_watermark_ok_safe+0x240/0x240
> [  165.966100]  ? slab_free_freelist_hook+0x11d/0x1d0
> [  165.971461]  ? __get_vm_area_node+0x2af/0x360
> [  165.976341]  ? __get_vm_area_node+0x2af/0x360
> [  165.981219]  __vmalloc_node_range+0x291/0x560
> [  165.986087]  ? __mutex_unlock_slowpath+0x161/0x5e0
> [  165.991447]  ? move_module+0x4c/0x630
> [  165.995547]  ? vfree_atomic+0xa0/0xa0
> [  165.999647]  ? move_module+0x4c/0x630
> [  166.003741]  module_alloc+0xe7/0x170
> [  166.007747]  ? move_module+0x4c/0x630
> [  166.011840]  move_module+0x4c/0x630
> [  166.015751]  layout_and_allocate+0x32c/0x560
> [  166.020519]  load_module+0x8e0/0x25c0
>
Can it be that we do not have enough "module section" size? I mean the
section size, which is MODULES_END - MODULES_VADDR is rather small so
some modules are not loaded due to no space.

CONFIG_RANDOMIZE_BASE also creates some offset overhead if enabled on
your box. But it looks it is rather negligible.

Maybe try to increase the module-section size to see if it solves the
problem.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz711WzMS%2BlG7Zlw%40pc636.
