Return-Path: <kasan-dev+bncBAABBZP6VL4QKGQE7TXLKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id BED9723CB68
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 16:17:09 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id y11sf4477183ljm.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 07:17:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596637029; cv=pass;
        d=google.com; s=arc-20160816;
        b=TTXJmYZ6AkN+D35aFnpK3FIbaZ7caTcQfmbeVxdv5MEr47KyyvEfC/TKcSmiIQibuk
         2/pfCGbaIV7pmP+RirqodF4dllWLi/dAyaVTP56civz/3IRluWDGlbKRdhpksTI72zZe
         2uRlB7s8cQwZL4kuWQRr68YHQYmCb7FaP0YrvU0tQioNVa5SXF8wmerhup92r/65FCi7
         xZ2Y7LhmTBAuu189DZXGiFyZlAFSXok7JW+uUJ+GkQPjKg4QO8oNXPF9u2ThPEaeI7LQ
         Eax228RPSjSWpybg5Hom2P5edpMQdtaXG6mS94JntiUj9wwaq6C3n8BWPCo1feywUg5M
         QwlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=2Uy36T+eswbczXoNwtG7UnggwGJQ41vPBFLgtZf8HkA=;
        b=ossuMeih4pyOQzqT13B6C9d/ZoUHHkNlfUiRzuRX+CdsbzC7t50h9yefe3UhzmO2SD
         tHZnkaB4Hi+/uO3VnRRWrl6LhS5rPt4UtpDTl3FMZpbjy/dRSR8qn4nWO/9ezVfw7t5u
         r/VIC73fG9xywf4rQ8GQ4lXvEQxm2xVd4Rjn7e3rOYHMcQS4RG17CtdxSHvlmonZiIMn
         9bu/VnoKNd/yIk+2Z31fYQzucyApZGgRZIjVFRltVVE5ri/gGol6YUlxrSf+bhBaCXbG
         NhTng66bbf/oGnes+IhgHsUiQY3DpV0khblmX/5PuxGFgIayvZWX+KVcPOJNd7zMzS3d
         027Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2Uy36T+eswbczXoNwtG7UnggwGJQ41vPBFLgtZf8HkA=;
        b=OZtc/cQ8ehTVMjUM5EOeY7ygI1eFX7FOzpf2i82tlowN74sUgtauuK60n1I5OGGRCM
         DoopG5EPnX4uTrT4nJCGjBKrwwRLLAqI3qQHn/EOp+cjuaiaoZSUVfnkG0P+kH2LrW3K
         Nx/oLcjWzpOIX3AWvSodq0ihOBMK+1Td+aKmfduJYDnfrFjRQPinSP8+VXJp3/Y8fXTX
         xyuHKCjbywLP5PD24/iawY7EWR099I93wW0D5UCE0rN5DRwRrxDo3D7CqsB0OUxc13jq
         P5b/aOnV7p/siQwrdGQjFKF5/JKBg1bHhETQ3NTYnvbJH1cIwk6vtpMQuTjbtE/aMwJI
         Nv+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2Uy36T+eswbczXoNwtG7UnggwGJQ41vPBFLgtZf8HkA=;
        b=KoU3QVoSN0g8gyRFzQxfKWz6saF96JjrMCMkhPyuaF0ND6SKkPoiYs+0kY70m9VRGf
         dmxH+HnYZhO0oFRybN49vNKnEfaJein7doJxlm6XjIfQcsL1qLoKXP1seitgq+eHJjKU
         VuUignbTw1meEKhzF9d7ZIjzgYbuZ66t7Hzs4kns9kbUXO+rYW7+PyEHOK6RjcrI/XBR
         E/TsLHVM/VrOyyjqw2uQoI4pJ0PVcAx8W3wjMwEUD8x6/r4FIFNzDZWklrCRRLPw+Bnz
         PmTuWUqIattOoJhQq1lt9Ia/AZEr+xIHkc69y5hy1PCvq+aFAI1RJ+37UyB2zUp0ES88
         ViXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cLcz+deI7BeAx62Gfr0DoXb68YFKhh1BUiOcorVsgsioEfG2F
	ZZizJTtafZIvHAZl8ymr7w4=
X-Google-Smtp-Source: ABdhPJzWYyB30hnz4mPFNMmBVP6HJTrFTUw/9kqy7SxT11lJNz/D8jBpri7EvzwSQVU1PNbrGWJaxA==
X-Received: by 2002:a2e:9852:: with SMTP id e18mr1568458ljj.415.1596637029321;
        Wed, 05 Aug 2020 07:17:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a172:: with SMTP id u18ls491684ljl.7.gmail; Wed, 05 Aug
 2020 07:17:08 -0700 (PDT)
X-Received: by 2002:a05:651c:543:: with SMTP id q3mr1542462ljp.145.1596637028787;
        Wed, 05 Aug 2020 07:17:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596637028; cv=none;
        d=google.com; s=arc-20160816;
        b=fMMbyr2wb7m8H8Hl8ZBsJTZ/b2dP5hXkrz3j6nIuz7dOYvzBw6nmVgIINQHqXLe8uN
         iVZOlgkJuZaLu2mhT8TS8nCfGxU78KhNqofzVbDfj6fz83VM2f38qXNlNqaTj10dH0KQ
         77GdX+YWGrPAih9UPVi/SP05jzyAfalIUaxH8M8/dQDQxAsGYQzqLOpmzt9sczKF825c
         1RjjI5HWk0FgPbt/RckDAbKaw95hMmC2XNwPg4GCX3GPITaexfBSTZCE1hVrXNwOM01R
         pAY4gCBF9MWoCWyGBMkDnFNM0FABih3Y1YCGEYRBGa6xDFJKpMI596426bzZsXWLaZIa
         gsRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=gOM6MVZXM22BVPrIy44buJVAvcvrWRQExGBNljVYeYA=;
        b=wOcdLKclxihzLPkYi7BYbVuOOhShZvge6ldnuut0MQw57lBOgKJJD6bU3OqQ/0M2S9
         aaNv0ttj2QFhsh9B29ZnF7I/36Yj9iDAa002iEyx4bLUs/IyLhS2XehqfsWD2EnICmuS
         9GIfFKqUmUYdsouUpppOeGZpd+yK0RH0+LN1VehgyKgSPr/ZZxski2g7te9RRlPH4IRO
         XST0WMorSZq0wylzZ8k62Y8Js/xsswhBJiG6t/cm7HlSM5jXmrHu44iYXQ84woVdBf8e
         jWrQmIw2hjC+dRo9zxFLO1w3xe3TnJrnKjNqzYl7HcsxO/onqhR23cm44UyYxVRLTI0w
         bdtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id e2si111656ljg.8.2020.08.05.07.17.08
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Aug 2020 07:17:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id A4C6FB619;
	Wed,  5 Aug 2020 14:17:24 +0000 (UTC)
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
To: peterz@infradead.org, Marco Elver <elver@google.com>
Cc: bp@alien8.de, dave.hansen@linux.intel.com, fenghua.yu@intel.com,
 hpa@zytor.com, linux-kernel@vger.kernel.org, mingo@redhat.com,
 syzkaller-bugs@googlegroups.com, tglx@linutronix.de, tony.luck@intel.com,
 x86@kernel.org, yu-cheng.yu@intel.com, sdeep@vmware.com,
 virtualization@lists.linux-foundation.org, kasan-dev@googlegroups.com,
 syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <b4d46726-d343-f347-c044-06c6e815076a@suse.com>
Date: Wed, 5 Aug 2020 16:17:07 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200805141237.GS2674@hirez.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=jgross@suse.com
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

On 05.08.20 16:12, peterz@infradead.org wrote:
> On Wed, Aug 05, 2020 at 03:59:40PM +0200, Marco Elver wrote:
>> On Wed, Aug 05, 2020 at 03:42PM +0200, peterz@infradead.org wrote:
> 
>>> Shouldn't we __always_inline those? They're going to be really small.
>>
>> I can send a v2, and you can choose. For reference, though:
>>
>> 	ffffffff86271ee0 <arch_local_save_flags>:
>> 	ffffffff86271ee0:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
>> 	ffffffff86271ee5:       48 83 3d 43 87 e4 01    cmpq   $0x0,0x1e48743(%rip)        # ffffffff880ba630 <pv_ops+0x120>
>> 	ffffffff86271eec:       00
>> 	ffffffff86271eed:       74 0d                   je     ffffffff86271efc <arch_local_save_flags+0x1c>
>> 	ffffffff86271eef:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
>> 	ffffffff86271ef4:       ff 14 25 30 a6 0b 88    callq  *0xffffffff880ba630
>> 	ffffffff86271efb:       c3                      retq
>> 	ffffffff86271efc:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
>> 	ffffffff86271f01:       0f 0b                   ud2
> 
>> 	ffffffff86271a90 <arch_local_irq_restore>:
>> 	ffffffff86271a90:       53                      push   %rbx
>> 	ffffffff86271a91:       48 89 fb                mov    %rdi,%rbx
>> 	ffffffff86271a94:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
>> 	ffffffff86271a99:       48 83 3d 97 8b e4 01    cmpq   $0x0,0x1e48b97(%rip)        # ffffffff880ba638 <pv_ops+0x128>
>> 	ffffffff86271aa0:       00
>> 	ffffffff86271aa1:       74 11                   je     ffffffff86271ab4 <arch_local_irq_restore+0x24>
>> 	ffffffff86271aa3:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
>> 	ffffffff86271aa8:       48 89 df                mov    %rbx,%rdi
>> 	ffffffff86271aab:       ff 14 25 38 a6 0b 88    callq  *0xffffffff880ba638
>> 	ffffffff86271ab2:       5b                      pop    %rbx
>> 	ffffffff86271ab3:       c3                      retq
>> 	ffffffff86271ab4:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
>> 	ffffffff86271ab9:       0f 0b                   ud2
> 
> 
> Blergh, that's abysmall. In part I suspect because you have
> CONFIG_PARAVIRT_DEBUG, let me try and untangle that PV macro maze.
> 

Probably. I have found the following in my kernel:

fffffff81540a5f <arch_local_save_flags>:
ffffffff81540a5f:   ff 14 25 40 a4 23 82    callq  *0xffffffff8223a440
ffffffff81540a66:   c3                      retq


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b4d46726-d343-f347-c044-06c6e815076a%40suse.com.
