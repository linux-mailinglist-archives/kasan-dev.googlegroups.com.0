Return-Path: <kasan-dev+bncBC5L5P75YUERBRNYYLUQKGQE2EDHY7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7331B6D1E9
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 18:20:22 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id s10sf2697617lfp.14
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 09:20:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563466822; cv=pass;
        d=google.com; s=arc-20160816;
        b=tloOOUbOC92xeAY8hQs018J+H+5pmLod037mtnLSBcbAFNM87TgTXc4DfpGyfxKnnq
         ZDGBfwoaT7oTF4T12GO3TPQBBRtceXgvwzrepsSildV6cW33T/Ms4nE2Mt41URWe5xC5
         qDVeXbd2tvIwa5RkZIjMrLPlwarwpKc8E1zbii3lhQ5EnhICzvk59kTPQ42lL3T7QLr+
         g8JPuZ698n19bWFex0zlvG7dwjEP7z/fLGiOCfS/Ho+Pg/27m83cvQ5LlE0mN8nFqpgN
         GdqKUgPayTGkKwA20rAzntoKNRPzFqcTqyTsQP3YcdsMUZL7NYhQ3lJUPYRh+WuWtMGa
         E/tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=hE1U2sy6adRs3LxxCj4BFsqAnqy59DGw6P35/bSLgT8=;
        b=OWb5qy5HNKHVyrlx8FDS5pvyouaCLvVQTRIHgMrTtWxgmDudoJHXOaUDAjR7qONdyo
         CB3flGAw3f0FTd1ESaBxmbXXHdZObV4lCSG9uXk1lulreXIYiEmp+OPCMRNonHIL5rTE
         JfWpHQ0/xf/uxX7Dm+s1TgjoGV16JL0Z8dQF7i8LxePglrtogF02+nd+YKibwblbMJSp
         V/ojzxijjjz/N91Hc2lcaSgSlP7Syn7UO//N5eSkE3ZUMykCXG2Kr+Wr60m0K6FuNY1M
         KhJh/gIl6WoU88AudESoR3j9u6ttyv0wZKdiDIUy1IJyEnvuzHequWuHkQUFwGZ+qeu2
         ++zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hE1U2sy6adRs3LxxCj4BFsqAnqy59DGw6P35/bSLgT8=;
        b=Hg18SePOLyF1PZTbOS4VI5MoPXqzYc6nIFoNhKenUj+mPOoYU9kqta1vgO7BycAxm4
         xl5jhzkhY5kF9iBomtDXTpd6mdw2vLxoPtJVgz8RAfCoe/7KKUMoDQhOjULIiXdHb1AA
         XI6GLfd38JfHU66arMf42ERrFl3WUs1j3qUxUqHVH0FzAMt0K563uz3jcRM+qMEt3PTq
         ieVwwnnUZY7uX0UMLwlpY3OSb02tONzCq9woXtEFAmi7wUbIchJI19H4KXtq/8/PuPDU
         h6vU+JTWt+NmI1cNGD0Q5lJREQMhVp4VuMwp3k2DaoPN6zb82krp7pZ3Rcq3b/J6xs6g
         qijQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hE1U2sy6adRs3LxxCj4BFsqAnqy59DGw6P35/bSLgT8=;
        b=c85NVYls5QxlgNO3kdEEp9vj3gN0yaTneWxdFVspe+AR+z2pahNImq7O4aDXUJ6GL+
         cF0JhwQbG8Vv/BqOW442wmlTxtcsGG3gUPDWDXqPp+3IRJOwChEXMkg5ycLAS+Q1b6u8
         Q0dW/5ChIA575cF/idd+jZGeJDe7XqBDOx6NvF1d0JvZMMbESyxot9qoCrtrn1IBaTgR
         EQETKYqk/YxlnHmoLJOU4QcRCM1HWVlnA12DCOuzIFEIjMLRFudDpB6dB59mpq2roGPa
         z+KsKofMNRrjCrAKQ7NRtlNQIOep1TUdfHMJOS8N/4Vt84H75BErvURiicX6ADo7/geS
         LkBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXwvxwN2+Pf9Kt/ZuQ6IwcNr7d+P7c2r9kHTe7bFnPEq2uDElPt
	CgDsv94eGsX0LbyIEJCsf8k=
X-Google-Smtp-Source: APXvYqxqH8WONVEnw0BygreeyLCkkPlu3t5ep3GW186Yv4c9yfz8bQAzf9LCcha6z/YlHvesvs8VXw==
X-Received: by 2002:ac2:546a:: with SMTP id e10mr21918067lfn.75.1563466822022;
        Thu, 18 Jul 2019 09:20:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5213:: with SMTP id a19ls2353058lfl.8.gmail; Thu, 18 Jul
 2019 09:20:21 -0700 (PDT)
X-Received: by 2002:ac2:51a3:: with SMTP id f3mr20528592lfk.94.1563466821610;
        Thu, 18 Jul 2019 09:20:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563466821; cv=none;
        d=google.com; s=arc-20160816;
        b=MK8Cj6PJSIDaxgPzK7KJmF6BcLibxkU0qHbvW01aGuONxXGkZ5Wi8La4+W76Xej/je
         ulPA+TVqy8HyLyD9wk+ZQBsVBNOS5YNuM5n/XN/KW6lFJ1By7rLw3VKmrWGbZbezOkOK
         JhnpnHAhqF21zYgR+pNMWR4IOiROlZ2HsY11Rw79ZINs5bXlfLh3to0MCGJR4o3jolkG
         NrfE/uU/HWaNQo10ydwfIXFnZLoS6Gx1g9mmr4XWlLMODZ3rX/KeovtzdmQ1Iy3OCfB5
         z2jg3eeWi8Y6gBS0lhj/wsDhENP+b/dPQ7ngSx8hWCMoiWcX+RohBjl8PWxUY3K7GblM
         GKRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=rUEHhJXc7IUGp/9xpom9kdyD+1TduVj1LeXOHJgI0ms=;
        b=TrY7VB1ZBzo0vH1vB5FCE2mvci9YnWaT6UZxZDhINklXgCe+UpwnsoMiZzLd06N1Co
         so/E6PzPu2UZhrc0HhHLXp92r3wuv9ZABV+UIKCoVII/GxyCbEdx4YEiWQ0MkDtPvhMD
         42s/qaFvC0Q8k9zq7Tp1zpEyZ62IyPN1FMqy+qmFXEe2k1JugBOgC7ERdPZ9fiHR/VpS
         xBQGQZNfrzshLuw6n6Uufd15D+vEUhamWOdAFCkg+tYbM74Ne6rKjrx4ZuF0aWP9YxdR
         SfMwaHvxM4lPXfdASsgwXfAwuy64wXTiT9RGkxibrbRvEnpvoMMrXGrUTMUMgxj75K2s
         4k5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id q11si1419098ljg.2.2019.07.18.09.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jul 2019 09:20:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1ho98k-00084V-Td; Thu, 18 Jul 2019 19:20:19 +0300
Subject: Re: kasan: paging percpu + kasan causes a double fault
To: Dmitry Vyukov <dvyukov@google.com>, Dennis Zhou <dennis@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Tejun Heo <tj@kernel.org>,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <20190708150532.GB17098@dennisz-mbp>
 <CACT4Y+YevDd-y4Au33=mr-0-UQPy8NR0vmG8zSiCfmzx6gTB-w@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <912176db-f616-54cc-7665-94baa61ea11d@virtuozzo.com>
Date: Thu, 18 Jul 2019 19:20:21 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+YevDd-y4Au33=mr-0-UQPy8NR0vmG8zSiCfmzx6gTB-w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 7/18/19 6:51 PM, Dmitry Vyukov wrote:
> On Mon, Jul 8, 2019 at 5:05 PM Dennis Zhou <dennis@kernel.org> wrote:
>>
>> Hi Andrey, Alexander, and Dmitry,
>>
>> It was reported to me that when percpu is ran with param
>> percpu_alloc=page or the embed allocation scheme fails and falls back to
>> page that a double fault occurs.
>>
>> I don't know much about how kasan works, but a difference between the
>> two is that we manually reserve vm area via vm_area_register_early().
>> I guessed it had something to do with the stack canary or the irq_stack,
>> and manually mapped the shadow vm area with kasan_add_zero_shadow(), but
>> that didn't seem to do the trick.
>>
>> RIP resolves to the fixed_percpu_data declaration.
>>
>> Double fault below:
>> [    0.000000] PANIC: double fault, error_code: 0x0
>> [    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.2.0-rc7-00007-ge0afe6d4d12c-dirty #299
>> [    0.000000] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
>> [    0.000000] RIP: 0010:no_context+0x38/0x4b0
>> [    0.000000] Code: df 41 57 41 56 4c 8d bf 88 00 00 00 41 55 49 89 d5 41 54 49 89 f4 55 48 89 fd 4c8
>> [    0.000000] RSP: 0000:ffffc8ffffffff28 EFLAGS: 00010096
>> [    0.000000] RAX: dffffc0000000000 RBX: ffffc8ffffffff50 RCX: 000000000000000b
>> [    0.000000] RDX: fffff52000000030 RSI: 0000000000000003 RDI: ffffc90000000130
>> [    0.000000] RBP: ffffc900000000a8 R08: 0000000000000001 R09: 0000000000000000
>> [    0.000000] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000003
>> [    0.000000] R13: fffff52000000030 R14: 0000000000000000 R15: ffffc90000000130
>> [    0.000000] FS:  0000000000000000(0000) GS:ffffc90000000000(0000) knlGS:0000000000000000
>> [    0.000000] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> [    0.000000] CR2: ffffc8ffffffff18 CR3: 0000000002e0d001 CR4: 00000000000606b0
>> [    0.000000] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> [    0.000000] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> [    0.000000] Call Trace:
>> [    0.000000] Kernel panic - not syncing: Machine halted.
>> [    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.2.0-rc7-00007-ge0afe6d4d12c-dirty #299
>> [    0.000000] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
>> [    0.000000] Call Trace:
>> [    0.000000]  <#DF>
>> [    0.000000]  dump_stack+0x5b/0x90
>> [    0.000000]  panic+0x17e/0x36e
>> [    0.000000]  ? __warn_printk+0xdb/0xdb
>> [    0.000000]  ? spurious_kernel_fault_check+0x1a/0x60
>> [    0.000000]  df_debug+0x2e/0x39
>> [    0.000000]  do_double_fault+0x89/0xb0
>> [    0.000000]  double_fault+0x1e/0x30
>> [    0.000000] RIP: 0010:no_context+0x38/0x4b0
>> [    0.000000] Code: df 41 57 41 56 4c 8d bf 88 00 00 00 41 55 49 89 d5 41 54 49 89 f4 55 48 89 fd 4c8
>> [    0.000000] RSP: 0000:ffffc8ffffffff28 EFLAGS: 00010096
>> [    0.000000] RAX: dffffc0000000000 RBX: ffffc8ffffffff50 RCX: 000000000000000b
>> [    0.000000] RDX: fffff52000000030 RSI: 0000000000000003 RDI: ffffc90000000130
>> [    0.000000] RBP: ffffc900000000a8 R08: 0000000000000001 R09: 0000000000000000
>> [    0.000000] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000003
>> [ 0.000000] R13: fffff52000000030 R14: 0000000000000000 R15: ffffc90000000130
> 
> 
> Hi Dennis,
> 
> I don't have lots of useful info, but a naive question: could you stop
> using percpu_alloc=page with KASAN? That should resolve the problem :)
> We could even add a runtime check that will clearly say that this
> combintation does not work.
> 
> I see that setup_per_cpu_areas is called after kasan_init which is
> called from setup_arch. So KASAN should already map final shadow at
> that point.
> The only potential reason that I see is that setup_per_cpu_areas maps
> the percpu region at address that is not covered/expected by
> kasan_init. Where is page-based percpu is mapped? Is that covered by
> kasan_init?
> Otherwise, seeing the full stack trace of the fault may shed some light.
> 

percpu_alloc=page maps percpu areas into vmalloc, which don't have RW KASAN shadow mem.
irq stack are percpu thus we have GPF on attempt to poison stack redzones in irq.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/912176db-f616-54cc-7665-94baa61ea11d%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
