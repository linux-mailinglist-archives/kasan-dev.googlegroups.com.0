Return-Path: <kasan-dev+bncBCHPRM5QQQKRBOX5Y25AMGQEZOBPL3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 28CB29E58F3
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2024 15:54:52 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4349d895ef8sf10180165e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2024 06:54:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733410491; cv=pass;
        d=google.com; s=arc-20240605;
        b=NP8sInk++W6F+JKfXvrVbDMyfGCbC0bU27/i5NkhLqoWlbKQHbAl6OvuHZJ7PSNid1
         IBzabx8cw9C4B4IQB1ViRyY1rok2qn9KUX2WcFiMNH7qecN/HbhN4z7Ns2DePGnWraBp
         l7WJVX7pOx9548kVO8Hp+tIN9BvecnF/LS0qbqYyk51bsUYfWBDErFGtkNBmdLjlZ2xQ
         isi9CLi1Vhq/aSTnyjLMYUIB5f8a+1Q6JhzRYI8V1lEWW1fekeuRNzJO5LNH6fn4JxYI
         vw/+0yDmE01UG+DClbvqU0iXw7+pNth6UCs7N0WY5eei0Jyglm3YbZchgF2D9qXEt+n+
         Ch0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:from:cc:to:content-language
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=ioiUP5Q+N04m8gguyX2e091q44wC4Jfiftnn9OPsWyo=;
        fh=pRqfWFHX+n2g2nl7F/9YssseE72gICi5sZ32sgeYN50=;
        b=B/IGJ2w5rZVHxT+8ucnmWTFFOB+VI10z4EGLgHveEx09yUeYP9UnEtwH9v8zQIthDE
         jv3wA5xPl1QbsZ6QiDjO6bIQBuIZhZuVq1tFZAMBfuiJ6cUqR4ZuJwStGOx5IhiLeBbv
         2+5c+kSIAyKlmsZMxdou/i4vc5PLEo59BSBhQ1/zrhuE0BCQK/jN0ZOqjB9SZIJV8tJO
         0Y3ovLIVQRSYDSjPjMCwBeFlJmIkG++Qo74aJkZi2KrB9d3JsnVfx8MbLUjlxhlP4Xu+
         ezjrpFyOE63JDniwSpZqy+J/vTuNHZ1mjtFNDobVJn0jUUYw6kxiaprIzmwO8NgiQ+i4
         03aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733410491; x=1734015291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:from:cc:to:content-language:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ioiUP5Q+N04m8gguyX2e091q44wC4Jfiftnn9OPsWyo=;
        b=TQjbibJVV8+50hLCFhGdkoxlMFxM2XyCKPEqUDDcfFFvsNJTRWkxvzII9kKPIJR7xm
         bQRsI00JOFAIwNv2U1exw5dJuEAhQVMAON3EgLwHZvDfS8CUkYTMx4MUjOy3+aGOVnfr
         2Quk/wDn9SFzV/tihKb2PK+L6Mg+mnW4ob4VkBQQdR5SzqWjRehqtxuC5AorBLidcGGu
         88fi0c08KzujnzDcaIpGl9i2kJyhUqUA3cqYQha3qIBgw5YJyyC5yse1RtPT1x3n8aOK
         7TcMzR3J/ev9Xs3svtvHB3S3ruJHRLm+FPm8R+do0g+Ajr/At8YSvr+GCBLEi7Y9k6+E
         3/hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733410491; x=1734015291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:from:cc
         :to:content-language:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ioiUP5Q+N04m8gguyX2e091q44wC4Jfiftnn9OPsWyo=;
        b=petXJYlzsXoChC2yo0ofHNEp7/zfFx+uUsmJFlJdvogQRRGeFsif4s3CRjJZoX2wqY
         J1MmgWqLep63l8pumm1JgdwRHdSWoXs05JD2jqNccvBXqDb7GHIBKKs3M/YRQdT1u8Eq
         4QYOAmWuwHsxZGcMy8MNlZzJZmSzz99rIeW8Nccy4tvF0ke+ffn0hrEFAl/ef5HIi3If
         e3qW62iI+v2UwGQFOh5tOxqXI+6LZiSmD9AgiSornBaJ+2AffoXXZSW8vuPOs/OWKOuZ
         mHSQCy5erQXy7wtTPMsXpP3bpQb9AyEbG77pfgnBbM/rn+SuOHE3ZTNT/ZNe91Dq/pPQ
         xHgw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4v7pvX0gOwvBfax52tOQmhUpNg4wVgaWrZ2nMCYcQIVg6/iWzQ3ELyW7VN7SSJlbHZxFX0g==@lfdr.de
X-Gm-Message-State: AOJu0Yx8NUMCDgv01next/+eqX4j3LfE0J1DAFwZ2ycP0y/Td5TrKczR
	aJJOu44XuNXD/z4FD67wwiQmZ8rSrZah8Alq1qLLI9VD3XEnG/ZB
X-Google-Smtp-Source: AGHT+IEVcnRINtnQAFHeA4wgvpYLzOzmhcYuIIbeuZYTsYkAK00mjuSGprWv03/vrDeF9/NTa6yonA==
X-Received: by 2002:a05:600c:4ecf:b0:434:a26c:8291 with SMTP id 5b1f17b1804b1-434d0a0e2c0mr99830815e9.24.1733410490580;
        Thu, 05 Dec 2024 06:54:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5802:b0:434:a059:b74e with SMTP id
 5b1f17b1804b1-434d9626622ls8435105e9.2.-pod-prod-05-eu; Thu, 05 Dec 2024
 06:54:47 -0800 (PST)
X-Received: by 2002:a05:600c:4f03:b0:434:a852:ba77 with SMTP id 5b1f17b1804b1-434d09d0432mr106212495e9.15.1733410486922;
        Thu, 05 Dec 2024 06:54:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733410486; cv=none;
        d=google.com; s=arc-20240605;
        b=gGnBUaayTUNoyGJwQUmCHFOd0qJ5CVyrcYCxjUgVYQUfc3GBISJeIigvy3iznGV1Xu
         QtqHwVK/0iJNxSYR1Vsu1AeJTqSoERcN6YQjS64voITWMueN6TBNuYpcv45eD8k9rFCW
         rTLaukUwrNdnm3kxGr2PbS9JtYxlTwCk1STnmR4VvAi9dbdGBxqHePIPD0DbLqlAFXWk
         TYm8xi/3qpAwZYtIxtZAgwgL6dxU+M3j6J3a2dDyksqgkEIPv8RZNIcJFuCKoLY5GxLK
         sThuwsd+wuzDZ1tUV4HVinQOgMufgc3WuAL3usKrdqEgrp8Z2wv2zWMdXTBE90Mi2xb3
         u99g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:from:cc:to:content-language
         :user-agent:mime-version:date:message-id;
        bh=82zRfxBhbpMp4JJQgBQ2OdsoYy0jZ1yWartOyzXMvSA=;
        fh=oIfFa1f2fYSVHaCiEqzFYuQ37rKpgIO9y9OYK8FMfRw=;
        b=MTq+J6M5GEyWqPH7kNCaILsIvSszzzM7i3krZuQIJwKcL6pkTHRtOZlh6Oaxc5yorF
         6HOV+IujEYbjHLqUYozw2/qCClFOQRiE+r2Zq8V7G1MquqzLGlMNUbMxs3xmJKzZSy3K
         wP9psh6EvUBY8VZMKpjx4fhF7vDYLWHd1/0dIu0CBpqxrMXA4j2nCwpBNTujG1n4r6hx
         nK2FkfXzrrGNaCOiZXIbEcqb4YclyRS/2nJdaUPQnkPC63s5geBy8W3b6TovD2qaM6Iy
         GUdkHDgqPL285SLrhn1dZzPjt/+goGUwAAFJObWtdTtlBSQWuvms2VRRT9NLvpy8fd5T
         Yi2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
Received: from metis.whiteo.stw.pengutronix.de (metis.whiteo.stw.pengutronix.de. [2a0a:edc0:2:b01:1d::104])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-434da13ea8fsi443305e9.1.2024.12.05.06.54.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2024 06:54:46 -0800 (PST)
Received-SPF: pass (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104 as permitted sender) client-ip=2a0a:edc0:2:b01:1d::104;
Received: from ptz.office.stw.pengutronix.de ([2a0a:edc0:0:900:1d::77] helo=[127.0.0.1])
	by metis.whiteo.stw.pengutronix.de with esmtp (Exim 4.92)
	(envelope-from <a.fatoum@pengutronix.de>)
	id 1tJDFe-0008Hp-Hr; Thu, 05 Dec 2024 15:54:46 +0100
Message-ID: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de>
Date: Thu, 5 Dec 2024 15:54:43 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-US
To: kasan-dev@googlegroups.com, iommu@lists.linux.dev,
 Arnd Bergmann <arnd@arndb.de>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Christoph Hellwig
 <hch@lst.de>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Robin Murphy <robin.murphy@arm.com>, "Paul E . McKenney"
 <paulmck@kernel.org>, elver@google.com, Kees Cook <keescook@chromium.org>,
 Pengutronix Kernel Team <kernel@pengutronix.de>
From: Ahmad Fatoum <a.fatoum@pengutronix.de>
Subject: Using KASAN to catch streaming DMA API violations
Content-Type: text/plain; charset="UTF-8"
X-SA-Exim-Connect-IP: 2a0a:edc0:0:900:1d::77
X-SA-Exim-Mail-From: a.fatoum@pengutronix.de
X-SA-Exim-Scanned: No (on metis.whiteo.stw.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: a.fatoum@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104
 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
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

Hello,

This is a follow-up to a discussion that took place in the Kernel Sanitizers
Office Hours (IIRC) at this year's Plumbers Event in Vienna.

I had asked about how KCSAN could detect races due to DMA[1] and Arnd
suggested that we could use KASAN to detect the CPU accessing buffers that
it doesn't have ownership of. I mentioned having implemented[2] this exact scheme
in the barebox bootloader's KASAN support and promised to type up an email
about it to help getting a similar functionality into the kernel, but first
some context:

The streaming DMA API is used to annotate ownership transfer of buffers in
memory shared between the kernel and a DMA-capable device.

The relevant kernel documentation is:

  https://www.kernel.org/doc/Documentation/DMA-API.txt
  https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt

But I'll give a quick recap. There are four key operations:

 - dma_map_single() moves a range of memory from CPU to device ownership

 - dma_sync_single_for_cpu() can be called on all or a subset of the range
   mapped by dma_map_single() to move ownership back to the CPU

 - dma_sync_single_for_device() moves back all oo a subset of the range
   mapped by dma_map_single() to the ownership of the device

 - dma_unmap_single() gives back ownership of a range of memory to the CPU

It's a bug for the CPU or the device to access a streaming DMA mapping while
it's owned by the other side. On many systems, that bug will manifest itself
as memory corruption due to loss of cache coherence.

To make it easier to spot some misuses of the API, the kernel has a
CONFIG_DMA_API_DEBUG feature, which will run sanity checks when using the API.
It can't however detect if a memory access happens to a buffer while it's
owned by other side, which is where KASAN can come in by having CONFIG_DMA_API_DEBUG
record ownership information into the KASAN shadow memory.

That way accessing a device mapped buffer before sync'ing it to the CPU is
detected like KASAN would detect a use-after-free.  When the ownership is moved
back to the CPU, the memory is unpoisoned and such an access would be allowed
again.

I had implemented this scheme[3] in the barebox bootloader and it works ok:

  BUG: KASAN: dma-mapped-to-device in eqos_send+0xdc/0x1a8
  Read of size 4 at addr 0000000040419f00

  Call trace:
  [<7fbd4980>] (unwind_backtrace+0x0/0xb0) from [<7fbd4a40>] (dump_stack+0x10/0x18)
  [<7fbd4a40>] (dump_stack+0x10/0x18) from [<7fba2360>] (kasan_report+0x11c/0x290)
  [<7fba2360>] (kasan_report+0x11c/0x290) from [<7fba1f44>] (__asan_load4+0x54/0xb8)
  [<7fba1f44>] (__asan_load4+0x54/0xb8) from [<7fb2e52c>] (eqos_send+0xdc/0x1a8)
  [<7fb2e52c>] (eqos_send+0xdc/0x1a8) from [<7fbb6544>] (eth_send+0x154/0x16c)
  [<7fbb6544>] (eth_send+0x154/0x16c) from [<7fbb7114>] (net_ip_send+0xe8/0xf8)
  [<7fbb7114>] (net_ip_send+0xe8/0xf8) from [<7fbb7d10>] (net_udp_send+0x68/0x78)


The aforementioned barebox functionality goes a step further and also used
the shadow memory information to detect repeated syncs without an ownership
change. While this is not a bug, my impression is that this is unnecessary
overhead and a diagnostic could help correct a developer's misunderstanding
of the API.

I hope to kick off a discussion about this with my mail here and perhaps even
motivate someone else to port it over or reimplement it. :D

[1]: when CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN is enabled
[2]: https://lore.barebox.org/barebox/20240910114832.2984195-1-a.fatoum@pengutronix.de/
[3]: https://github.com/barebox/barebox/blob/master/drivers/dma/debug.c

Cheers,
Ahmad

-- 
Pengutronix e.K.                           |                             |
Steuerwalder Str. 21                       | http://www.pengutronix.de/  |
31137 Hildesheim, Germany                  | Phone: +49-5121-206917-0    |
Amtsgericht Hildesheim, HRA 2686           | Fax:   +49-5121-206917-5555 |

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/72ad8ca7-5280-457e-9769-b8a645966105%40pengutronix.de.
