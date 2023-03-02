Return-Path: <kasan-dev+bncBC7PZX4C3UKBBCEGQSQAMGQEF6B7AXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ADBF6A8A09
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 21:11:53 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id e22-20020a05600c219600b003e000facbb1sf1753400wme.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 12:11:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677787913; cv=pass;
        d=google.com; s=arc-20160816;
        b=VfAbJcgpEH0w0VkOUoRV4CXEPTbwvjhtSZ5eVu4j8znGcaTCEHoPx4BK6GhT7FctEP
         UK8bh0PvyBAjM1HW1xjcqFrt5NuDJnbx+w6ipl3TNVsQmBgqbKOObJvyCObM8HWdHBZS
         XtJ08WUADn+F8uv/ycXNNLbFpHwwwAi76IEKEwHSBcBXO3Qjij1B25dHA72U+7U0ZFWG
         70RxcflOr37FX2qmcb2NIQMb330ZUTgGblijl7N0WgA37CFg1DI5/sE8n3kI4zEF802e
         Cg4/bbuprHA/1JBFQ2ipkn6fbVLXNjRLXEcYIHCNDO1oX4QzyyVkWRgAiRExcpl/9Bbv
         5baA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=z9UN1ZGL/EG2RCuJ5dHpnI82FQVYhLf2k/J28gZfN5Y=;
        b=jGtSf3GTXyIP3fCJNYOMcIS9pB9r94WZaXGB2mLj/fuQsyUL3mZsLaM8eKF291ZIXx
         vWTr4/oWvWfhnCcZbXbLIxMS/D4Q3XcEw5oCm2CgVEyovpb1Ko7BZknbSTc6dkGrcDw/
         52O5nHN+zNS/cqMyRhBdjjz0/yCXMmlhOsBaq9Gx90S/ukRPZqwGY99ChCtKUiewpOAE
         TJ69C0Mn8IAHWfDzA79C0IJgzcAqM2iQsMEzVYUzQsLzf/z0ZCs7EHwHYHxxSKPSLtK7
         ESs/Bwn7VGcjJqaTKwMkBLV2rR97AENm5LrCtIUaLK+EmiZrsyGvWMcciBmzVK7iizvW
         93UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z9UN1ZGL/EG2RCuJ5dHpnI82FQVYhLf2k/J28gZfN5Y=;
        b=s4X8zbwM/g5r/7231l3tIpu1q2yrcjt3ZxyjcfikX2bIJvA0pwQDK3IZD6mcspfrMl
         zSRYVRatpGDym8Y5v16iNWfizVxbm8K8C89/LgTumksL7Iud08xFhRBx8CUEiRAOH05v
         OJwy2f74M4Pb4VGhISI3hnkkTBsF1gKtTVsIvoCPsWsq05AjIKPQ1nKHvKEplIjxn4Lv
         bsoZBf64EKOEEEPPxzChB5gXlVoNXY11d1KPUJm5QQ9F5ZAP2vlQMAHows63U3BQs7sH
         HErgAASK6SKoJaDTeIy2u1IEX8+T9+nSbnkmaQh0KymuzBwXdU6Ejricqs5R6sRz9FG2
         g2TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z9UN1ZGL/EG2RCuJ5dHpnI82FQVYhLf2k/J28gZfN5Y=;
        b=PlR5rUWU2CLqh2JU6ky/DJ3imFVwC4A1z6G8kCdUZdQwC4npfv+r6sNdbRO67dbNl/
         raW/k3wyoAsRLJftiyIAXUso2JXF/4MCKB3v6fp2y4oCMG3PUbFOSrW38X8AOQYMLG6H
         48FC9Y2xRYDlLanjNdRH5ogJd0bnSx4j71I+ZNIf7DP94mNcwtm9SBZdGOCmCCM1z9rD
         YvOjjVZneK0DKBrl67i0MN5CMK8roMADiPVS2qpQAePkqV9CBLt1w8yFLDXIRBnDQ9+5
         8Ar30XbVQ0yBXPDankUeDsrKMdK8SHZ8QQO/+RX+9KF4NspDG3co4i68dk/yxWIYCIWo
         H0Ng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUl0YAcvz8WdBGz2sVoFBNK0IYhafxXv9VHzIm19+bVZa1PyozZ
	aAb8bg30BjoOYW0yNi3bZjo=
X-Google-Smtp-Source: AK7set/j28eCVWDikNhf0+NqQgl638YsvWpY85lDTPEbF6snTEuPBmibzh1gBloz5FI5PZ0D4nMngw==
X-Received: by 2002:a05:600c:a3a2:b0:3df:d852:ee05 with SMTP id hn34-20020a05600ca3a200b003dfd852ee05mr3224362wmb.0.1677787912734;
        Thu, 02 Mar 2023 12:11:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c01:b0:3dc:5300:3d83 with SMTP id
 j1-20020a05600c1c0100b003dc53003d83ls402221wms.0.-pod-control-gmail; Thu, 02
 Mar 2023 12:11:50 -0800 (PST)
X-Received: by 2002:a05:600c:450f:b0:3eb:29fe:7343 with SMTP id t15-20020a05600c450f00b003eb29fe7343mr7930660wmo.33.1677787910760;
        Thu, 02 Mar 2023 12:11:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677787910; cv=none;
        d=google.com; s=arc-20160816;
        b=u8Cv9gQhaowKZiTYQrLGSstrRgU+JnhxLa8tdaodBkL7jishEXr583gW9fnvhKURyg
         JHRKHEGnXjb16WKi9mj7aT3oTSvKeQEKYupKXiXVnebA6Y1Bsw57FePRdx73f8A+KcCo
         +lPXz+Mh7RpAt0Ljhq7LgzRALVdilJNVkt2hTH94keI+K/Ui2qXCxfpitslZLURtK3zb
         oKni886oiHg4+eYIkpAtvemD0BnsU3M2I8eaY/Y8KpaFtBJfcEa85A/o3V7EWBUZZL5B
         fUyedaD1zCx0N/pOtE9GWBUgeNjjGUavKliY7YgjlfX5/GdFLaWdUZIm2Ej+ZOx2SCEu
         41sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=SbBohJTUHFbxLItF8DMEZ2Gcl/FbymrP7CN8HMK7y54=;
        b=MLvBuQ6hQgS09a1pozkW+wIWaBqd92L9jL4Zq5krClFWd8bqy0LgQMoK0RcSrwp1VP
         OeKKrDqvdt2DBlUuh5UNX+zUbruy/aPgvxmVwhvDC+vlFi2p7KmS02sqGCX34jXkeG+r
         eWFq40Hp9P4irgN2QHyVprpjmmLB0sQ1YPoqNTQ7weVYz6ucChLaRygrCqcHcrMomh/N
         5cDdIp5gLA67t5NNr4TGYNw+O9hcWoElJ93Yo7Ctar/cVPOmfKXK71VAZ32445UHJ5v+
         Rf+d6wcGGPnCH1NZpmqrZce1RCpEC0cEL0srY/6RSL/gARBIsRErQfS0PU0cbcbQeSr/
         w9hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id n37-20020a05600c502500b003e1eddc40cfsi278775wmr.3.2023.03.02.12.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 02 Mar 2023 12:11:50 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
Received: (Authenticated sender: alex@ghiti.fr)
	by mail.gandi.net (Postfix) with ESMTPSA id C7F22240003;
	Thu,  2 Mar 2023 20:11:49 +0000 (UTC)
Message-ID: <067b7dda-8d3d-a26c-a0b1-bd6472a4b04d@ghiti.fr>
Date: Thu, 2 Mar 2023 21:11:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Subject: Re: RISC-V Linux kernel not booting up with KASAN enabled
Content-Language: en-US
To: Chathura Rajapaksha <chathura.abeyrathne.lk@gmail.com>
Cc: linux-riscv@lists.infradead.org,
 "dvyukov@google.com >> Dmitry Vyukov" <dvyukov@google.com>,
 kasan-dev@googlegroups.com
References: <CAD7mqryyz0PGHotBxvME7Ff4V0zLS+OcL8=9z4TakaKagPBdLw@mail.gmail.com>
 <789371c4-47fd-3de5-d6c0-bb36b2864796@ghiti.fr>
 <CAD7mqrzv-jr_o2U3Kz7vTgcsOYPKgwHW-L=ARAucAPPJgs4HCw@mail.gmail.com>
 <CAD7mqryDQCYyJ1gAmtMm8SASMWAQ4i103ptTb0f6Oda=tPY2=A@mail.gmail.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CAD7mqryDQCYyJ1gAmtMm8SASMWAQ4i103ptTb0f6Oda=tPY2=A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

+cc Dmitry and kasan-dev, in case they know about this but I did not=20
find anything related

On 3/2/23 19:01, Chathura Rajapaksha wrote:
> Hi Alex/All,
>
> Kernel is booting now but I get the following KASAN failure in the
> bootup itself.
> I didn't see this bug was reported before anywhere.
>
> [    0.000000] Memory: 63436K/129024K available (20385K kernel code,
> 7120K rwdata, 4096K rodata, 2138K init, 476K bss, 65588K reserved, 0K
> cma-reserved)
> [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [    0.000000] BUG: KASAN: stack-out-of-bounds in walk_stackframe+0x1b2/0=
x1e2
> [    0.000000] Read of size 8 at addr ffffffff81e07c40 by task swapper/0
> [    0.000000]
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
> 6.2.0-gae3419fbac84-dirty #7
> [    0.000000] Hardware name: riscv-virtio,qemu (DT)
> [    0.000000] Call Trace:
> [    0.000000] [<ffffffff8000ab9e>] walk_stackframe+0x0/0x1e2
> [    0.000000] [<ffffffff80108508>] init_param_lock+0x26/0x2a
> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> [    0.000000] [<ffffffff813d86e0>] dump_stack_lvl+0x22/0x36
> [    0.000000] [<ffffffff813bd17a>] print_report+0x198/0x4a8
> [    0.000000] [<ffffffff80108508>] init_param_lock+0x26/0x2a
> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> [    0.000000] [<ffffffff8023bd52>] kasan_report+0x9a/0xc8
> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> [    0.000000] [<ffffffff80108748>] stack_trace_save+0x88/0xa6
> [    0.000000] [<ffffffff801086bc>] filter_irq_stacks+0x8a/0x8e
> [    0.000000] [<ffffffff800b65e2>] devkmsg_read+0x3f8/0x3fc
> [    0.000000] [<ffffffff8023b2de>] kasan_save_stack+0x2c/0x56
> [    0.000000] [<ffffffff80108744>] stack_trace_save+0x84/0xa6
> [    0.000000] [<ffffffff8023b31a>] kasan_set_track+0x12/0x20
> [    0.000000] [<ffffffff8023b8f6>] __kasan_slab_alloc+0x58/0x5e
> [    0.000000] [<ffffffff8023aeae>] __kmem_cache_create+0x21e/0x39a
> [    0.000000] [<ffffffff8141623e>] create_boot_cache+0x70/0x9c
> [    0.000000] [<ffffffff8141b5f6>] kmem_cache_init+0x6c/0x11e
> [    0.000000] [<ffffffff8140125a>] mm_init+0xd8/0xfe
> [    0.000000] [<ffffffff8140145c>] start_kernel+0x190/0x3ca
> [    0.000000]
> [    0.000000] The buggy address belongs to stack of task swapper/0
> [    0.000000]  and is located at offset 0 in frame:
> [    0.000000]  stack_trace_save+0x0/0xa6
> [    0.000000]
> [    0.000000] This frame has 1 object:
> [    0.000000]  [32, 56) 'c'
> [    0.000000]
> [    0.000000] The buggy address belongs to the physical page:
> [    0.000000] page:(____ptrval____) refcount:1 mapcount:0
> mapping:0000000000000000 index:0x0 pfn:0x82007
> [    0.000000] flags: 0x1000(reserved|zone=3D0)
> [    0.000000] raw: 0000000000001000 ff60000007ca5090 ff60000007ca5090
> 0000000000000000
> [    0.000000] raw: 0000000000000000 0000000000000000 00000001ffffffff
> [    0.000000] page dumped because: kasan: bad access detected
> [    0.000000]
> [    0.000000] Memory state around the buggy address:
> [    0.000000]  ffffffff81e07b00: 00 00 00 00 00 00 00 00 00 00 00 00
> 00 00 00 00
> [    0.000000]  ffffffff81e07b80: 00 00 00 00 00 00 00 00 00 00 00 00
> 00 00 00 00
> [    0.000000] >ffffffff81e07c00: 00 00 00 00 00 00 00 00 f1 f1 f1 f1
> 00 00 00 f3
> [    0.000000]                                            ^
> [    0.000000]  ffffffff81e07c80: f3 f3 f3 f3 00 00 00 00 00 00 00 00
> 00 00 00 00
> [    0.000000]  ffffffff81e07d00: 00 00 00 00 00 00 00 00 00 00 00 00
> 00 00 00 00
> [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D


I was able to reproduce the exact same trace, I'll debug that tomorrow,=20
I hope it is a real bug :)

Thanks for the report Chatura,

Alex


>
> Best,
> Chath
>
> On Thu, Mar 2, 2023 at 11:25=E2=80=AFAM Chathura Rajapaksha
> <chathura.abeyrathne.lk@gmail.com> wrote:
>> Hi Alex,
>>
>> Thank you very much, kernel booted up with the patches you mentioned.
>> Bootup was pretty slow compared to before though (on a dev board).
>> I guess that is kind of expected with KASAN enabled.
>> Thanks again.
>>
>> Regards,
>> Chath
>>
>> On Thu, Mar 2, 2023 at 2:50=E2=80=AFAM Alexandre Ghiti <alex@ghiti.fr> w=
rote:
>>> Hi Chatura,
>>>
>>> On 3/2/23 04:13, Chathura Rajapaksha wrote:
>>>> Hi All,
>>>>
>>>> I observed that RISC-V Linux hangs when I enable KASAN.
>>>> Without KASAN it works fine with QEMU.
>>>> I am using the commit ae3419fbac845b4d3f3a9fae4cc80c68d82cdf6e
>>>>
>>>> When KASAN is enabled, QEMU hangs after OpenSBI prints.
>>>>
>>>> I noticed a similar issue was reported before in
>>>> https://lore.kernel.org/lkml/CACT4Y+ZmuOpyf_0vHTT4t3wkmJuW8Ezvcg7v6yDV=
d8YOViS=3DGA@mail.gmail.com/t/
>>>> But I believe I have the patch mentioned in that thread.
>>>
>>> I proposed a series that will be included in 6.3 regarding KASAN issues
>>> here: https://patchwork.kernel.org/project/linux-riscv/list/?series=3D7=
18458
>>>
>>> Can you give it a try and tell me if it works better?
>>>
>>> Thanks,
>>>
>>> Alex
>>>
>>>
>>>> My kernel config:
>>>> https://drive.google.com/file/d/1j9nU7f9MxCc_i-UHUCTvo7o6nDrcUz0w/view=
?usp=3Dsharing
>>>>
>>>> Best regards,
>>>> Chath
>>>>
>>>> _______________________________________________
>>>> linux-riscv mailing list
>>>> linux-riscv@lists.infradead.org
>>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/067b7dda-8d3d-a26c-a0b1-bd6472a4b04d%40ghiti.fr.
