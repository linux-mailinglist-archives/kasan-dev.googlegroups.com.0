Return-Path: <kasan-dev+bncBCHPRM5QQQKRBJHCZK5AMGQE2OVTG2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F4639E6870
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2024 09:09:10 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-53e1c91bc98sf166562e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2024 00:09:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733472549; cv=pass;
        d=google.com; s=arc-20240605;
        b=F+uKXfkknyJDxY5++xDCKRDzIaUjIxmKXBFwlnciT+/ormrVB+DKvarfhbG8ry8wSm
         us3Y4hTzXC01KhqxiQSuLWN2yYNEWbWRxhgwXVjy8tTXItOi+3LlRSh3Opwc5ziportv
         sVm8ZDLUeWsU2z5Jf31agA/5YHkYMqweIv2mrXUB9q5p8eevjPGy+izJqGcjU5qoFmqL
         XuENIGeLi7FsJSbanv2NHiQPQVHnfaizCGeR2tdsoqAr1Vxoq7uHuvKpkYxLoTZirodD
         d+WfdH6ATqI5LH8BZQJ+JP05R8jSY14m/R1EdAMlHlrIwSmBHIb+UIVeLWdTyyw6nkqS
         eKzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=/CyN/4XWGokpxWKeEyjsG0YycDyLqi/bnFV1GvxJ6Zc=;
        fh=NNGMs6wK1H1PpF0E7ApQT8H7qhD7P/ed736WiP65YHE=;
        b=AS1WDDDaJBsPrIBoYLBWJmhFkaxwo5e/v5jisotd1yjyEyQiQsWoKzaDWJEHBuYrXL
         h6EIxxnUausDym9odELdIAjCkBnb7/gFpJZz/2Hu8EIp/kKPSiTxsWOS2DyRDbweg3lb
         XTo+dTdiZ2ryfvUKXptqYCwCFWWjNLiMOzhrKEly+llWAdHN5mRQqy2mquyk4qgFk+75
         c9MkORAhBFm6Tzqz6mzcG/lqJVGrvZDXQzy0F+mTNXuEspc5umnJeQKuaHC6unvlx396
         6nKTBPjMXS8cUCKgkV7LEIkWF9P5eMq9/p8tmz/hmvwXfzotcNByrzMulIZe/2ZYx49U
         P++g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733472549; x=1734077349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/CyN/4XWGokpxWKeEyjsG0YycDyLqi/bnFV1GvxJ6Zc=;
        b=Sx89Hl8DiA+V8wXkIHED63oImhXwLgYkXxuSIV5aflbr/3fNifjl7B35Aa5Jg9iTwr
         XVJ9Z7xvakyT0W2DoI2mcCWLMGJKL8LmjoXEuqWLnuuvsnnvQYAtvWqtKRbSXr/R6E2e
         eIkpj2P8M46vwoPYhcTMbTUgqRleM7lzxxLgFWIMdrQYTqIhKHWXbpaz24ZAZJhT5yU5
         4zT2mP0xhlLPQiE9OxYhdmPcELdVUtHCiaRIY6RVJc/XOG1LLN+v+acpoTfMIDc9/cOh
         QaosD9ZaxActGK98wr67E+2RO0uC0PeqPZKxHA6ZUGihS3o4UvXoQaLsauKqYrrOrjcd
         ickw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733472549; x=1734077349;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/CyN/4XWGokpxWKeEyjsG0YycDyLqi/bnFV1GvxJ6Zc=;
        b=F+yDrX/gmPTt83Z5X4NZkg7w59ahI5JAD8UqhF7pe9oJSskUxd0DEx/srlJH4+27gx
         AYx3N4OvtjBo2rEYajgOKqOVy3Af3vzZMARgVZQDvst+EYamU1iSzDH8xNUFmUhzyvJI
         Mcqj/gVzW8y3axWJ0ooqbo8bEOcowPa0oQm8OIY8IJxOu3zszlGzdsTBXMpT8JphY+8J
         ZII+5ci/WnV7K8THULTCI9P4z+F+Ap6aQPiDmsgaXiE+3d2gZMJ72xdYQrHBxTrLktov
         uT6UFMlLylKpzUQrCSI8K4qeUmKOlVOU3VQICKLL2t78eX9IrJqLrg6GZAUOk81ruElz
         MhAQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4ACFfE21+/5oGryMUBb5bYYn4UAOXPjjU5T+IcGZPz0SeEc5iL/54TVcMQ7b6qkKr2k8lBA==@lfdr.de
X-Gm-Message-State: AOJu0YyIVvmcSdo1qw3Pup1bXqFU6D/RI2sXrFkV/ocMXdLTB/yrOJtl
	yIqKo1BTQHLSs6DWzzH34RDsPADaOApFguhvaXQM3Lao8eITeiT6
X-Google-Smtp-Source: AGHT+IEf2M1S5ItNQSlgMKCtAlCthFTzqpP9cUH7FxaHKBvxT8iCQCE8ZbLUBWs1Ec7JBR1D3AO1kQ==
X-Received: by 2002:a05:6512:e88:b0:539:ea7a:7688 with SMTP id 2adb3069b0e04-53e2c2b1338mr896622e87.1.1733472548762;
        Fri, 06 Dec 2024 00:09:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b22:b0:53d:dd7e:1749 with SMTP id
 2adb3069b0e04-53e2194a584ls520782e87.0.-pod-prod-07-eu; Fri, 06 Dec 2024
 00:09:06 -0800 (PST)
X-Received: by 2002:a05:6512:308b:b0:53e:1c23:81ef with SMTP id 2adb3069b0e04-53e2c2b8f3cmr986185e87.18.1733472546244;
        Fri, 06 Dec 2024 00:09:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733472546; cv=none;
        d=google.com; s=arc-20240605;
        b=RUofYFD0vHEbj1nPs7FOqape9vfUjI/UT1jIJ/qHpcjBPPwWClwc97B044dYaKNQaJ
         qwEtSmxZxh4AJkrPU1qpUuYl3hJbA2MONybJiJak9RaNAHDolxcZU49GNQrU+MfXDTQ5
         QNLBB9lMscMIErJtUJZDpckor0K6cOTwLXWu9saf2tz0h2Pln7k5sInPN3nlMCJIN4mD
         Y7UZ2nTVotl1W67ZNSqsR9qCPQD1T5AHTSbX9cvimYk+Lvv+i4D23MJvSkBIgkowKxjd
         ABkwPEawAXlXhO+dcv9MA6v/P0W+Ay/Swz+tqCKuc2fTscqh9SncSevP3Z1v+LEEvmfB
         wmEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=HLYbFtoHZcLc0st6cXuExnHiN6WDqRcYMnvNmdJz4i8=;
        fh=AbgfGaAX0LqBs0583dca54GR5El8ShcwHJfzUMefRjg=;
        b=GTggeFIvMXIrSSN91fh3fSGGbbARTCljtHJpAP+nXL4tsvA22GY5VyHQeE3aqu4A+B
         CTE5tFaAUvbb2LRVIsGOjpyngGOazcWdasxwGkJGW5+l77Y1+Bm2xFmrqLyrXDO0Oo4y
         7DyXh/sxtFuq9Y/W6OG0kiZV3jVxwMdya5szv6rBy+XRTKjB5V/sG2DI6cfafq83J1ln
         Qd5Oq90fxCdq03nsXVbEeGWx30OoxO939YG6j9gHYZqON9rrz8Ymqk0uvsnGtoxnslkK
         WSo/RaI1t3T/pxhwjHyfRUoPT2DppVrcZc7+4X6qF264mz1IMCEJlYBDEMxSRgaxHQTP
         sXkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
Received: from metis.whiteo.stw.pengutronix.de (metis.whiteo.stw.pengutronix.de. [2a0a:edc0:2:b01:1d::104])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53e229b9329si96846e87.8.2024.12.06.00.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Dec 2024 00:09:06 -0800 (PST)
Received-SPF: pass (google.com: domain of a.fatoum@pengutronix.de designates 2a0a:edc0:2:b01:1d::104 as permitted sender) client-ip=2a0a:edc0:2:b01:1d::104;
Received: from ptz.office.stw.pengutronix.de ([2a0a:edc0:0:900:1d::77] helo=[127.0.0.1])
	by metis.whiteo.stw.pengutronix.de with esmtp (Exim 4.92)
	(envelope-from <a.fatoum@pengutronix.de>)
	id 1tJTOb-0007hr-Ez; Fri, 06 Dec 2024 09:09:05 +0100
Message-ID: <380e2207-7578-4aff-8ced-8653100a2983@pengutronix.de>
Date: Fri, 6 Dec 2024 09:09:01 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Using KASAN to catch streaming DMA API violations
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, iommu@lists.linux.dev,
 Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Christoph Hellwig
 <hch@lst.de>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Robin Murphy <robin.murphy@arm.com>, "Paul E . McKenney"
 <paulmck@kernel.org>, elver@google.com, Kees Cook <keescook@chromium.org>,
 Pengutronix Kernel Team <kernel@pengutronix.de>
References: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de>
 <CACT4Y+Y5_8KYm2bjKPiwk5UP2Y_AbowV8c_Ai5UPmOn2GD+GEg@mail.gmail.com>
Content-Language: en-US
From: Ahmad Fatoum <a.fatoum@pengutronix.de>
In-Reply-To: <CACT4Y+Y5_8KYm2bjKPiwk5UP2Y_AbowV8c_Ai5UPmOn2GD+GEg@mail.gmail.com>
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

Hi Dmitry,

On 06.12.24 08:06, Dmitry Vyukov wrote:
> On Thu, 5 Dec 2024 at 15:54, Ahmad Fatoum <a.fatoum@pengutronix.de> wrote:
>>
>> Hello,
>>
>> This is a follow-up to a discussion that took place in the Kernel Sanitizers
>> Office Hours (IIRC) at this year's Plumbers Event in Vienna.
>>
>> I had asked about how KCSAN could detect races due to DMA[1] and Arnd
>> suggested that we could use KASAN to detect the CPU accessing buffers that
>> it doesn't have ownership of. I mentioned having implemented[2] this exact scheme
>> in the barebox bootloader's KASAN support and promised to type up an email
>> about it to help getting a similar functionality into the kernel, but first
>> some context:
>>
>> The streaming DMA API is used to annotate ownership transfer of buffers in
>> memory shared between the kernel and a DMA-capable device.
>>
>> The relevant kernel documentation is:
>>
>>   https://www.kernel.org/doc/Documentation/DMA-API.txt
>>   https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt
>>
>> But I'll give a quick recap. There are four key operations:
>>
>>  - dma_map_single() moves a range of memory from CPU to device ownership
>>
>>  - dma_sync_single_for_cpu() can be called on all or a subset of the range
>>    mapped by dma_map_single() to move ownership back to the CPU
>>
>>  - dma_sync_single_for_device() moves back all oo a subset of the range
>>    mapped by dma_map_single() to the ownership of the device
>>
>>  - dma_unmap_single() gives back ownership of a range of memory to the CPU
>>
>> It's a bug for the CPU or the device to access a streaming DMA mapping while
>> it's owned by the other side. On many systems, that bug will manifest itself
>> as memory corruption due to loss of cache coherence.
>>
>> To make it easier to spot some misuses of the API, the kernel has a
>> CONFIG_DMA_API_DEBUG feature, which will run sanity checks when using the API.
>> It can't however detect if a memory access happens to a buffer while it's
>> owned by other side, which is where KASAN can come in by having CONFIG_DMA_API_DEBUG
>> record ownership information into the KASAN shadow memory.
>>
>> That way accessing a device mapped buffer before sync'ing it to the CPU is
>> detected like KASAN would detect a use-after-free.  When the ownership is moved
>> back to the CPU, the memory is unpoisoned and such an access would be allowed
>> again.
>>
>> I had implemented this scheme[3] in the barebox bootloader and it works ok:
>>
>>   BUG: KASAN: dma-mapped-to-device in eqos_send+0xdc/0x1a8
>>   Read of size 4 at addr 0000000040419f00
>>
>>   Call trace:
>>   [<7fbd4980>] (unwind_backtrace+0x0/0xb0) from [<7fbd4a40>] (dump_stack+0x10/0x18)
>>   [<7fbd4a40>] (dump_stack+0x10/0x18) from [<7fba2360>] (kasan_report+0x11c/0x290)
>>   [<7fba2360>] (kasan_report+0x11c/0x290) from [<7fba1f44>] (__asan_load4+0x54/0xb8)
>>   [<7fba1f44>] (__asan_load4+0x54/0xb8) from [<7fb2e52c>] (eqos_send+0xdc/0x1a8)
>>   [<7fb2e52c>] (eqos_send+0xdc/0x1a8) from [<7fbb6544>] (eth_send+0x154/0x16c)
>>   [<7fbb6544>] (eth_send+0x154/0x16c) from [<7fbb7114>] (net_ip_send+0xe8/0xf8)
>>   [<7fbb7114>] (net_ip_send+0xe8/0xf8) from [<7fbb7d10>] (net_udp_send+0x68/0x78)
>>
>>
>> The aforementioned barebox functionality goes a step further and also used
>> the shadow memory information to detect repeated syncs without an ownership
>> change. While this is not a bug, my impression is that this is unnecessary
>> overhead and a diagnostic could help correct a developer's misunderstanding
>> of the API.
>>
>> I hope to kick off a discussion about this with my mail here and perhaps even
>> motivate someone else to port it over or reimplement it. :D
>>
>> [1]: when CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN is enabled
>> [2]: https://lore.barebox.org/barebox/20240910114832.2984195-1-a.fatoum@pengutronix.de/
>> [3]: https://github.com/barebox/barebox/blob/master/drivers/dma/debug.c
> 
> 
> Hi Ahmad,
> 
> This looks great. The example stack you posted - is it a real bug, or
> an injected one? Has it found any real ones?

That was an injected one. The code is recent enough not to have hit a
barebox release yet.
 
I have gotten feedback that it was useful during driver development,
but it hasn't found an issue yet. I did run it though against issues
that were pointed out by reviewer feedback.

> Added the link to https://bugzilla.kernel.org/show_bug.cgi?id=198661
> so that it's not lost.

Cool, I didn't know that the discussion restarted in the Bugzilla.

> I guess this memory usually does not come from kmalloc, right?

No, kmalloc() in barebox is just TLSF with DMA-suitable alignment.

> Otherwise it would be possible to use kasan_record_aux_stack() to
> attach the stack of the last sync operation.

barebox architectures currently only implement stack_dump(). It needs
to be split into stack walk, kallsyms lookup and printing to console,
before a kasan_record_aux_stack() equivalent can be implemented.

> Re repeated syncs. If not all of them will be fixed, then at least for
> the kernel it should be under a separate config b/c syzbot does not
> tolerate false positives.

Agreed.

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/380e2207-7578-4aff-8ced-8653100a2983%40pengutronix.de.
