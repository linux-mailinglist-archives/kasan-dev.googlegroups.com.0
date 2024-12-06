Return-Path: <kasan-dev+bncBCMIZB7QWENRB3WEZK5AMGQE2IJRMPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id BF73A9E6791
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2024 08:06:24 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43498af79a6sf9551985e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2024 23:06:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733468784; cv=pass;
        d=google.com; s=arc-20240605;
        b=VLPos/LrQslOCIc401UrLP1cZgV211NGyhvPyArlR7OKvTdANoO9Qv4v8tUe/ogWlp
         eaKrfwv1sty99UvKzss2LxEc1SJlGXOX/+OAR8bRQOCI22W0QVfC4K5Xd8M2QLJDRYWO
         8XUNTzWQOr1tvAvJgUhUaKfjMbX/fjLkyt67NxmaCbduF68J1Dto+YJWSvVCXbXFPYIT
         I8I7Cq1wHHc4mbCGIJckQDNxUv8GKMRxpUf8zSazDdEYY4Yxzc1v4FSZPWtsDzhoG9rF
         jAYw31jAAo+/PNvRHkjRT4HaHTGv0UEVTLJ46j2pVEvraJnmqS890PtsnXYMwynp2kwO
         iOJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=07HwZdneebK9ZM2xlICc2tnm2UDd8HZIX7SK7+xdpP8=;
        fh=C6MYDvY8ZkrBeHbr8c2yKlOuXnkli6Mk5XBE27k5TyI=;
        b=OEBB2q9By5j41DempyGB4EtzcppFdgG5g+vwRDXDo60o+IntDh4tlGPwC/wStl4W2I
         iUPS7MX373DNTIwJRLWbmnTzyDxPIjfPl8rzYmM4DyJhxeuDfwzBytRRFN33RjcYuXsJ
         3M9tSzVc06HRAG2xgpDylPAxDWuqWScxWID5k8x+q85UkWcN+j9VZ0SRjjlGj+ZCdfoH
         P8YcCSLmy+WLFpL8QrdqhBAsTVTtB0h2ZR+MC+kJMVFRqoSbYLxStseMP64k14ajYrR8
         APtgiwRTEVBCzkxCXW3/+qCFY2mRN6ZXIvhOE9oKW7kJI0gwRm/pUSmQStUjC4b0vApM
         fmdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=c1oQNkgS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733468784; x=1734073584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=07HwZdneebK9ZM2xlICc2tnm2UDd8HZIX7SK7+xdpP8=;
        b=FeLCAp4FXlpaGh7ZJp1e1nrUVyBPAPGwoaUtYlutlM3xgDAbRuaNKlsF5hho2WAh1c
         Mm8nRg3ADx3gQXL1ZdgnjIcUYC7Y/cBT43UVL66nRa/iK6BREbWpXE5sgnJ6zB2TQMwf
         SPQmYig25jwJzADVAy4L7u23rBOxOtts/9x2G1j4yw6LjTgzNm8l2krBreNDhFGLzrk6
         7/vNPhLVZYNGEVA1RM3yBS2Gqtdvifi5QR4MFUrmKNjBU9sVGymWLvPPk4zZAuDMLbNt
         KAhZuVYrrnZO6yoAZLccUwduUUqJEC85T34pH5DYL+pjINx9F5Ya0NnDCsdRWQw/ofy0
         n5OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733468784; x=1734073584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=07HwZdneebK9ZM2xlICc2tnm2UDd8HZIX7SK7+xdpP8=;
        b=VQud8JzMspq4i+ZJBwwEm0ygrJbKuwaX7jtc3S7lwKyDg8MI5BJV8DWD6sRTCBQ1wB
         LeT2jhRcNOkK5DG+WAYDxOT+XWKtk3PFiDFviPDt4deUmXQF6KS3RMweEn+JnS6NQvRY
         B7TySPrFyypah5/N3mGiJMfl6HJGtc37cxfW18XywJ+9fNdqYN35BANL6U0q5aSDJUJf
         b6YGRZuKpRbV87q5TN9oALPD+Gceq3em3eQOa9e9wbRQzlStFQb1e0oT6lMxPaW+5fVR
         ruUiwiXpDkztK5vJ9c15zP1DOcHHphePAtJ8TSor/VsBu2imSDkhZ0SS4xkhCyxLazTi
         lrag==
X-Forwarded-Encrypted: i=2; AJvYcCVG8idEUSn885knHSyxIgrwInwg/txrnlMz5K/q3OGFDyjVRf0v4k7Mmh/m7KuZRQ/JDi4AgA==@lfdr.de
X-Gm-Message-State: AOJu0Yyf6BAQAZ4vJrka6P/d/bi0Q2vDZeOjaXqG1yqn5DFQAfNo1O8y
	ekrRnYQ0DHv5XsG6CsB7uWwr0yGy+B/nY0hytYs3AD1v3mGyohHr
X-Google-Smtp-Source: AGHT+IGq8W6AlzFNEIduEdYEoQ5GLSnuqMOmYjHMc8PC6q/OeMNh97HkFHHQH0iVcQpvdBOtfhvZLw==
X-Received: by 2002:a05:600c:45c7:b0:434:9fca:d6c3 with SMTP id 5b1f17b1804b1-434d927b20emr43968085e9.9.1733468783365;
        Thu, 05 Dec 2024 23:06:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4695:b0:434:9dc9:1422 with SMTP id
 5b1f17b1804b1-434d95d2eb2ls2699515e9.0.-pod-prod-00-eu; Thu, 05 Dec 2024
 23:06:21 -0800 (PST)
X-Received: by 2002:a05:600c:1c99:b0:434:a09c:4f9c with SMTP id 5b1f17b1804b1-434ddee992fmr13785185e9.16.1733468781137;
        Thu, 05 Dec 2024 23:06:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733468781; cv=none;
        d=google.com; s=arc-20240605;
        b=Vd1ySfPlgkk0//4YSwmS2AEvz94tlIcIQmhkbAAlZEaCIR4bsrC9sgSZhmZaVnYqx6
         LlzRJE7tmpKslXseSIWXi25ts9m4qOno2595FC683ItX3pyFWnpy+Ak7LIyWu/y22ust
         BPVkg1+VkZOXkXc8yrdyZWnKSpvTAC+b95yVE/cVF6Ts+pxEWJ3ITZw40rzi+/hdh3h/
         i61Ezvpjs5q16hLDnSkNjEh5itG9ZKSJNqEcDxCEETGiitRbGI8oK5daQDCQdSHHAaTP
         BaUAjjQruyjOEDehB5JkpES2OiuSVoxtLJ9Qhcj/dBmwCmtupY0Po7nGAur7osrEUJFa
         YFMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DQonzwxQTSP4xOxfibkeem1n9wtDkmxWgdzvZNrDp6g=;
        fh=zc2enHjexjizNyJ3HfDdPrUaLhcWtgEZ0Nt9rjQWZoc=;
        b=KMH2FZ/eymTbW5o+AbxNxDqJT/nRv7gm+8fh2hxXzvwoM+BdA5siFF5oz8wpZ+bOSu
         XNWE+niaZpRopOpjUqwz4cIXLcSXgUuyli84FNGt2DoOaOmPidjToyB8G7hp0NX0eJqX
         Ifjj/tDtXhzElNtMjONZ2riPn7RwtwcLOC/gZfJhVSPoqJj3cYB8ANuf/SEI6vcqDTAq
         zHANYQJG5fbmp+gUiSO4DAxE1eLq5OV1RuA+RuCvgYIty69k12DLDFIa1Xo3B1lBWptZ
         61M6fHxy83hNh341aJkOed6zoIAdBdEVQDemk6Yixab7bsJ1EABL+VqWuhbmnWSG2aSp
         bJoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=c1oQNkgS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-434d04e6f48si5502245e9.0.2024.12.05.23.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2024 23:06:21 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-30024c73101so13701191fa.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2024 23:06:21 -0800 (PST)
X-Gm-Gg: ASbGnctbzqOHySgpsW4wA1xkFaACigzByVJU0ZZepjTcFgt+qR2srhPnjyOxVNjVVRx
	nKGSXu9iuwkDcGK5ZumIeoYXOMYedCl56GXkvpE1SAaZlLIXsNDGECcS5t38+p6sA
X-Received: by 2002:a2e:be11:0:b0:300:159a:1638 with SMTP id
 38308e7fff4ca-3002dee4cf6mr6619391fa.17.1733468780250; Thu, 05 Dec 2024
 23:06:20 -0800 (PST)
MIME-Version: 1.0
References: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de>
In-Reply-To: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Dec 2024 08:06:09 +0100
Message-ID: <CACT4Y+Y5_8KYm2bjKPiwk5UP2Y_AbowV8c_Ai5UPmOn2GD+GEg@mail.gmail.com>
Subject: Re: Using KASAN to catch streaming DMA API violations
To: Ahmad Fatoum <a.fatoum@pengutronix.de>
Cc: kasan-dev@googlegroups.com, iommu@lists.linux.dev, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Christoph Hellwig <hch@lst.de>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Robin Murphy <robin.murphy@arm.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, elver@google.com, Kees Cook <keescook@chromium.org>, 
	Pengutronix Kernel Team <kernel@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=c1oQNkgS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 5 Dec 2024 at 15:54, Ahmad Fatoum <a.fatoum@pengutronix.de> wrote:
>
> Hello,
>
> This is a follow-up to a discussion that took place in the Kernel Sanitizers
> Office Hours (IIRC) at this year's Plumbers Event in Vienna.
>
> I had asked about how KCSAN could detect races due to DMA[1] and Arnd
> suggested that we could use KASAN to detect the CPU accessing buffers that
> it doesn't have ownership of. I mentioned having implemented[2] this exact scheme
> in the barebox bootloader's KASAN support and promised to type up an email
> about it to help getting a similar functionality into the kernel, but first
> some context:
>
> The streaming DMA API is used to annotate ownership transfer of buffers in
> memory shared between the kernel and a DMA-capable device.
>
> The relevant kernel documentation is:
>
>   https://www.kernel.org/doc/Documentation/DMA-API.txt
>   https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt
>
> But I'll give a quick recap. There are four key operations:
>
>  - dma_map_single() moves a range of memory from CPU to device ownership
>
>  - dma_sync_single_for_cpu() can be called on all or a subset of the range
>    mapped by dma_map_single() to move ownership back to the CPU
>
>  - dma_sync_single_for_device() moves back all oo a subset of the range
>    mapped by dma_map_single() to the ownership of the device
>
>  - dma_unmap_single() gives back ownership of a range of memory to the CPU
>
> It's a bug for the CPU or the device to access a streaming DMA mapping while
> it's owned by the other side. On many systems, that bug will manifest itself
> as memory corruption due to loss of cache coherence.
>
> To make it easier to spot some misuses of the API, the kernel has a
> CONFIG_DMA_API_DEBUG feature, which will run sanity checks when using the API.
> It can't however detect if a memory access happens to a buffer while it's
> owned by other side, which is where KASAN can come in by having CONFIG_DMA_API_DEBUG
> record ownership information into the KASAN shadow memory.
>
> That way accessing a device mapped buffer before sync'ing it to the CPU is
> detected like KASAN would detect a use-after-free.  When the ownership is moved
> back to the CPU, the memory is unpoisoned and such an access would be allowed
> again.
>
> I had implemented this scheme[3] in the barebox bootloader and it works ok:
>
>   BUG: KASAN: dma-mapped-to-device in eqos_send+0xdc/0x1a8
>   Read of size 4 at addr 0000000040419f00
>
>   Call trace:
>   [<7fbd4980>] (unwind_backtrace+0x0/0xb0) from [<7fbd4a40>] (dump_stack+0x10/0x18)
>   [<7fbd4a40>] (dump_stack+0x10/0x18) from [<7fba2360>] (kasan_report+0x11c/0x290)
>   [<7fba2360>] (kasan_report+0x11c/0x290) from [<7fba1f44>] (__asan_load4+0x54/0xb8)
>   [<7fba1f44>] (__asan_load4+0x54/0xb8) from [<7fb2e52c>] (eqos_send+0xdc/0x1a8)
>   [<7fb2e52c>] (eqos_send+0xdc/0x1a8) from [<7fbb6544>] (eth_send+0x154/0x16c)
>   [<7fbb6544>] (eth_send+0x154/0x16c) from [<7fbb7114>] (net_ip_send+0xe8/0xf8)
>   [<7fbb7114>] (net_ip_send+0xe8/0xf8) from [<7fbb7d10>] (net_udp_send+0x68/0x78)
>
>
> The aforementioned barebox functionality goes a step further and also used
> the shadow memory information to detect repeated syncs without an ownership
> change. While this is not a bug, my impression is that this is unnecessary
> overhead and a diagnostic could help correct a developer's misunderstanding
> of the API.
>
> I hope to kick off a discussion about this with my mail here and perhaps even
> motivate someone else to port it over or reimplement it. :D
>
> [1]: when CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN is enabled
> [2]: https://lore.barebox.org/barebox/20240910114832.2984195-1-a.fatoum@pengutronix.de/
> [3]: https://github.com/barebox/barebox/blob/master/drivers/dma/debug.c


Hi Ahmad,

This looks great. The example stack you posted - is it a real bug, or
an injected one? Has it found any real ones?

Added the link to https://bugzilla.kernel.org/show_bug.cgi?id=198661
so that it's not lost.

I guess this memory usually does not come from kmalloc, right?
Otherwise it would be possible to use kasan_record_aux_stack() to
attach the stack of the last sync operation.

Re repeated syncs. If not all of them will be fixed, then at least for
the kernel it should be under a separate config b/c syzbot does not
tolerate false positives.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY5_8KYm2bjKPiwk5UP2Y_AbowV8c_Ai5UPmOn2GD%2BGEg%40mail.gmail.com.
