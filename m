Return-Path: <kasan-dev+bncBC7M5BFO7YCRBPVZ46BQMGQESPS62RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 95607362806
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 20:51:43 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 126-20020a4a17840000b02901e5e0ccc28asf2863872ooe.13
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 11:51:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618599102; cv=pass;
        d=google.com; s=arc-20160816;
        b=zGY6Apr7IUYWVcElVIJ2DRampccxGzVtMO4DIkVITbYmT90j4djH5FGGK/I7eS2ajE
         Lv4oB+ikvhh/Ju+UFedLkJ4qlM3XbdruF+zZF2TdgyFoDhSVnddoSxl7PBxozKmN/bVS
         jB68G/dzMi6BoLSQwOceHBwAXLTl8wmTDQGZNTy8jQnBlaGdYytqQei0uVPnNSxaxGI9
         EVhNIoadTkBOffiEssz35UOQBZmJZHrytZcIU4YUMyJnjrt1c1OBEhbrvkWbpYYOOwM5
         cJPWwiMrbrr8S+bdFdA1zUM4A0kwPPEtn1+8+4iTYJUkZ7EAH4cGHfnlnAFylsIXSs7s
         B84g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pgGsZIHrd7A2hMh22rMvkT2XH+vdzDj5IMQJ037jza4=;
        b=vnahnkM3nzWRzHUKFNRCyldYnG4Ty4Axw93EHVV1MtsEtJXRQBX0+en1GKXqe56mUy
         1WVpiXi8uzudVEMWzpfOGPsxq8OMKDHbE6lAYe0wOX2ToVuu1x8ct/rQOKIfrdgATl+5
         9PtcDV7jvc0GNH83MUr6QL5Iwo+1zGmDOpYhTxpTonzntePBXwCJv4urFplZMLuTs8vt
         zA4e/NF17wAL7wbT9h9g+iyDJKOTCjF+LTLrnmGMN4TG3sk04CkWBcI+DyfhdjdtIN7/
         89W6pE7/xeBX1ff91aBX2+XGd+pZN5h0mSTdcsbLGMcX+zBdjZ75SrVs9yyf3rdUl+m/
         MPHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lcF00QwL;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pgGsZIHrd7A2hMh22rMvkT2XH+vdzDj5IMQJ037jza4=;
        b=S108mFrHHaFde8IR0diPPyqlYBaAZGGpeGk9d408dHAbm80fFws3ImntG0/if+SXWS
         agdfjw6vsoOc/2CztVfUJ8rpj4DvPhUj/PFv9tRJetJ5MLmOC/gMrITxVjvHJXSPPkEO
         Tf+cgfKBizTdqYpEeBJWj2gpwvfgYT3Is1Njw7LlWEnkLkaAiSxibksh5iFEpcK9dm2i
         PMHRPUciqDnTQ9Sfa1is9CBgPV0ifugnq3dDsLNxBDpGHWiwzK6GQNLHXbX9kxZwBJ7m
         kGcQ0LTMJwza4e9pqcLqsf5yiBDckP1XZGuQNlbWB3hRt+CuixLvV205Qutinlx2ZT9l
         e0MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pgGsZIHrd7A2hMh22rMvkT2XH+vdzDj5IMQJ037jza4=;
        b=FAXCXQDTRpk4T6P4T9IlZDa8i/KHBDfpNTRxATDxPu9YgJoHnCfGtX7C3AiDu6PO5q
         +sFopWU0Ng/YmYjYpacNSgxHl2jc1yniAUveWM4OV3d/ZOzOL4lV6Q7bX3IoTCfRTnK6
         ibaH/jbnldi74Ar2+rq8hrSLskAQ2NgE0F9WvomnycFFnSG8VNfzgLEYepqTR9HKxBWK
         3Oxphp4rrpkDXlkXKd+ZBtexX55zhfJQMGqhNtPbRG1Z4qEz2nFZ6i9dAROc2H4xTB20
         iS9fF4cX0OrLL4FBLNdb7prZL4wgcnbtSwMaPjZsMKQLAUbHSz17bd3dkx3+Ujz8IAlo
         ktvg==
X-Gm-Message-State: AOAM532yFRK9NwaQftYTp/Vs52OK8OInYFvM89zrqlp4zzOek2IMkGvf
	kcXANnE/2i3p5BMDbb2I0/E=
X-Google-Smtp-Source: ABdhPJybT2miD5d8SdduchoZ+yPUyS28YRkjkm9li0iAdReP8GcJaF8B28ybE2MbTOCPQMz8pzcZJQ==
X-Received: by 2002:a4a:8247:: with SMTP id t7mr4377594oog.53.1618599102526;
        Fri, 16 Apr 2021 11:51:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d088:: with SMTP id i8ls664444oor.4.gmail; Fri, 16 Apr
 2021 11:51:42 -0700 (PDT)
X-Received: by 2002:a4a:be86:: with SMTP id o6mr4363980oop.70.1618599102126;
        Fri, 16 Apr 2021 11:51:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618599102; cv=none;
        d=google.com; s=arc-20160816;
        b=AJVMyEZw9EbMEOGk/UgER/Gb828c5AXqq5wl4XuUI5i2/63LZAqKJJBRhAn7KhA2d2
         7lHm9f2Vk9mNnIIecSQrWh+YRwi8gv0qEapVGJ3Oi5qKxcvWcGBkrUhG301+m7bSy3SC
         rHOQx39TZMn0inPAU0pB6SXPmcebqaNAbLVWN7ACAx8CBxPXQABx2Hgk2RRDNynPHoxG
         by1iQr+fDXYgnOG6s7nrtKX4nvqXGl8HXFZLZhmAlWCC3yB3yU4z7ozfEA9zzbK9tB2/
         d3cwfpLg9dP8DF70N3RY5iydZ4g8S7WQGtm0vbPwNSDHIqAgBZsBRHReE6occsgNx+wz
         oTpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2r2vkwG9UCNB7xrSeMaXDYuTdlG3jHjzPkkxswC7vmg=;
        b=z4NpjfJeG1u+M7DhHHRknxR6RfO+MuDYT/clp1UKDTVtmaViw9w5kYVVYFo34ctx7w
         pJhTpxryLTyfUQ4BBCqbILrRvplT3lr5Pf0O4KQFN+MsTktQz7dWEewLr8tjuuJlK8tT
         lDLUSgfaHkArQFhQB6JP8QoTAcq+tbdh+r5+tm0RFQZsJqTuuRb6xBvmr83VM59uj7Su
         X9MVRjfBB4GaUigF5jw49e3qVuexRudwwRvFKVFp7IVAW3iqTL9mzaPMMEpL08k4i61b
         82aQhSI14WZEXGSMYlLDJknb+gZHLCmuFxVM84UeCXf7+XObyPBHjJ1D2fraogjiYDBF
         fMqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lcF00QwL;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id w136si538756oif.0.2021.04.16.11.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Apr 2021 11:51:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id k18so23916151oik.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Apr 2021 11:51:42 -0700 (PDT)
X-Received: by 2002:a05:6808:1444:: with SMTP id x4mr7654073oiv.142.1618599101889;
        Fri, 16 Apr 2021 11:51:41 -0700 (PDT)
Received: from localhost ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id y25sm1608634otj.64.2021.04.16.11.51.40
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 16 Apr 2021 11:51:40 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Fri, 16 Apr 2021 11:51:39 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v4 1/3] riscv: Move kernel mapping outside of linear
 mapping
Message-ID: <20210416185139.GA42339@roeck-us.net>
References: <20210409061500.14673-1-alex@ghiti.fr>
 <20210409061500.14673-2-alex@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210409061500.14673-2-alex@ghiti.fr>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lcF00QwL;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::229 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Fri, Apr 09, 2021 at 02:14:58AM -0400, Alexandre Ghiti wrote:
> This is a preparatory patch for relocatable kernel and sv48 support.
> 
> The kernel used to be linked at PAGE_OFFSET address therefore we could use
> the linear mapping for the kernel mapping. But the relocated kernel base
> address will be different from PAGE_OFFSET and since in the linear mapping,
> two different virtual addresses cannot point to the same physical address,
> the kernel mapping needs to lie outside the linear mapping so that we don't
> have to copy it at the same physical offset.
> 
> The kernel mapping is moved to the last 2GB of the address space, BPF
> is now always after the kernel and modules use the 2GB memory range right
> before the kernel, so BPF and modules regions do not overlap. KASLR
> implementation will simply have to move the kernel in the last 2GB range
> and just take care of leaving enough space for BPF.
> 
> In addition, by moving the kernel to the end of the address space, both
> sv39 and sv48 kernels will be exactly the same without needing to be
> relocated at runtime.
> 
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>

In next-20210416, when booting a riscv32 image in qemu, this patch results in:

[    0.000000] Linux version 5.12.0-rc7-next-20210416 (groeck@desktop) (riscv32-linux-gcc (GCC) 10.3.0, GNU ld (GNU Binutils) 2.36.1) #1 SMP Fri Apr 16 10:38:09 PDT 2021
[    0.000000] OF: fdt: Ignoring memory block 0x80000000 - 0xa0000000
[    0.000000] Machine model: riscv-virtio,qemu
[    0.000000] earlycon: uart8250 at MMIO 0x10000000 (options '115200')
[    0.000000] printk: bootconsole [uart8250] enabled
[    0.000000] efi: UEFI not found.
[    0.000000] Kernel panic - not syncing: init_resources: Failed to allocate 160 bytes
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.12.0-rc7-next-20210416 #1
[    0.000000] Hardware name: riscv-virtio,qemu (DT)
[    0.000000] Call Trace:
[    0.000000] [<80005292>] walk_stackframe+0x0/0xce
[    0.000000] [<809f4db8>] dump_backtrace+0x38/0x46
[    0.000000] [<809f4dd4>] show_stack+0xe/0x16
[    0.000000] [<809ff1d0>] dump_stack+0x92/0xc6
[    0.000000] [<809f4fee>] panic+0x10a/0x2d8
[    0.000000] [<80c02b24>] setup_arch+0x2a0/0x4ea
[    0.000000] [<80c006b0>] start_kernel+0x90/0x628
[    0.000000] ---[ end Kernel panic - not syncing: init_resources: Failed to allocate 160 bytes ]---

Reverting it fixes the problem. I understand that the version in -next is
different to this version of the patch, but I also tried v4 and it still
crashes with the same error message.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210416185139.GA42339%40roeck-us.net.
