Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBHWR77YAKGQEE5PHAXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F59C13D336
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 05:37:51 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id l1sf12572089qvu.13
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 20:37:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579149470; cv=pass;
        d=google.com; s=arc-20160816;
        b=dlxPLnJlWEuibszoJzRBE+Se9uZNygHMEfg0GFjOsPt143oRHXB/05VVraLw1ANUm3
         1NkXgntdNqCVPqV5zGWeuv7yN9AilXnsRfEVcR1UPykJor2KENQbOvWmn6L053UFIfLL
         EFVkMbNjTOoZiBcSY/fIB/l/1qa/b+vc2I2tQSNcXF32p5Clha2r4YqCC0yNCEjQT244
         9A7f6M/Ruu+83oqz1+eHjgSPPgiXQLTcv3ip+cFRfwX1RVuzeIbdy+nlfvkRj4ZmEHUl
         /Zos7pTVcwqJu0+uWTmlR9ilCr3KEPBEiNrnHfkPgb+CfpVm/iBbbmcj8DDxbb/23Pi4
         uwAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=rYuYQFk8IBtREd07kF1i3/6eEQ6pfLg1bM9Hud0jBEw=;
        b=b12CXw+5EBtBhtzBQv9+V2xHL6H2KKhpzTKa04gOuerw8m3FpyZV/kBW/0chMw/3MA
         Jy4Z4ko2pG7Du4x9JpzCiPkmuPtUMEVhQHvRvP3mFocLgbqQel84EjQCr8cpI3v3HqUz
         EgRp0uIVvZb3BFWLAwHFi/JiASROdAcbwuOsPGk840ccxvsESs/sbxVy07sRRlO0GIFc
         7nwfjD4dMfV36fvv6Jt34ob2/+3nRqC1FZSRLrXD/kEdKw6vN3FE9ybnt3tYNj9Sr9PA
         7+bk4DvQc4C2LI4qHLVEJt4eKEdhhRUSt7OTV8cg0JP2K5jZ4Efq0C8gYPLdiXu7Krfe
         xVPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=FmFuQEFR;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rYuYQFk8IBtREd07kF1i3/6eEQ6pfLg1bM9Hud0jBEw=;
        b=QbHpB+gQCBgITBTm+qJi2r4yPFqEJsr6+x4uPNil36QuCovoK9DYzVkDH7oLKcOR99
         TAw/FByDmjFO/MMubtOpVmZUZ48za3lDrQOZq65etCRMYPhcZHOq7xwkEHvPYY+wICgx
         CF5vagx25xG8YPcEZMbZl6ngz28yEPwXX+G9yuD46OfLMQBBDesol+i0BMTr3eshmf/F
         akycMckr1fKwAKJaw0ZcaYJB1njCOX242AT6sBO5I7Gcmj1U2l8zKiIpXKQP5X1pu7eG
         k5L267btVuQpZPKDxzuQtomXY5wLc2ieHRoKT4Oi3fxWibQUjZdst9/KaOQH5bFmM53z
         C8sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rYuYQFk8IBtREd07kF1i3/6eEQ6pfLg1bM9Hud0jBEw=;
        b=ra3cTtct18xV8A66E6WcC/4UKA0HoIt64dD23KgYQcbeEBujeXgJdbuZpuh6WsyYNS
         78L2BZsIx7BmnYSa9tx/S/1yCCiQULSEuNYR3N31geoCDV8VPb1UNplwko4U0c6N2+uo
         RXdzEBGHC6q4dM3z4UCDwYAyqv2JBcpFPK420s/J1b6IqeqVMzLGvg42njc07GfWyIOW
         MIsAs9bjX+mg7yqHeQ49janBI7wXWxZKXnJQa8arObwoCLHm0HSeezkC6i+ZqUcCb6qA
         Wi/0BRYUo0kOt/vdrgH+9w9o0awzvEvTx4JfyJl4QwE2htiXgr2zONv0TvEUPNfuldO0
         bSzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUGozopifWodsgV7E/YyAKCbVp/pjmMzw7brIQ7uRL5057Tqx14
	BdelZhnGiFoNgnfALt4yJ1Y=
X-Google-Smtp-Source: APXvYqyabsbfE+m5+RWL/b/5ORwgMQ1cn81sIVZ3pYegE4rg1PC00uqg82PuAAGbD/yjii+gmU9BVA==
X-Received: by 2002:a37:5fc2:: with SMTP id t185mr30528286qkb.271.1579149470176;
        Wed, 15 Jan 2020 20:37:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:47ca:: with SMTP id u193ls5024796qka.10.gmail; Wed, 15
 Jan 2020 20:37:49 -0800 (PST)
X-Received: by 2002:a05:620a:2010:: with SMTP id c16mr29504800qka.386.1579149469749;
        Wed, 15 Jan 2020 20:37:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579149469; cv=none;
        d=google.com; s=arc-20160816;
        b=lOLz3/1IgH87vNU1jeheIldAjI11X+Dqa8SH10pnJ1+Lzptu+jDFAEhodROjjRUuJK
         EhqAbd/lu6R/KMgmQ+/v/KFawVqFJOnCyHDnXY6ftSntT2RNd+8uQmHYL1y7/97uFSrL
         v+p69gHLvWtvlmp6eVCpvgYa6d7ZjNYBLsPeIlV+BAhtSf8PJ3ZCoTTGuWTTbwjxFbUN
         C97WtX9KcPm19SrrARjvnR29aUy2xfhd9d9G8OlXGTMNOkM/IyFZ69cQ5/NmrmFZOPSe
         cfANJvYhZfTaAErgco2deY8TVnk/NY5uh4qT+/S+tJc3uI5nh8ZIOzw+40wSf+YsjUg2
         AuDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=QyfMAGZrl4Hq8ZZCGma3ZFi+8xk6ybhLmqph1vhoS0Y=;
        b=Fmr+TR6q6cj3mw+keshb5MYVrWmIx4PF9ZBvsX4LAyucEhIUE0DTZPzSDHWomVVcyZ
         vGUTXm4QoOyPePUwpzOLGioyQhLGf0cS9HNEOF2szD1oLlffPFeQh/WO7B2nuSR5Bn6N
         kR3H8UfuCB7cmaHgTkyd8BLU0AT2AiZSnF2/YYLfhnmBGZYVOCNAW3z2+V+kj/KHhPmT
         IanlPjaHvwBKe73ASf4vFBLrZ5R0pgHR2nHGRYRv0YqKrWrLGM9jSMAgg+g2fdoZD6Se
         dtV7gkBktXEAGgeZqZ0cd91uLl2XYBPZrdnlGdrPd8DRRW75BDyAJumiPwUjgXYZqiNo
         Yg2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=FmFuQEFR;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id i53si985221qte.2.2020.01.15.20.37.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 20:37:49 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id y8so8503267qvk.6
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 20:37:49 -0800 (PST)
X-Received: by 2002:a0c:bd2c:: with SMTP id m44mr787302qvg.248.1579149469159;
        Wed, 15 Jan 2020 20:37:49 -0800 (PST)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id z6sm9300763qkz.101.2020.01.15.20.37.48
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 20:37:48 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.0 \(3608.40.2.2.4\))
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
From: Qian Cai <cai@lca.pw>
In-Reply-To: <B2717BA1-B964-4B0A-BE4F-5B244087B9E5@lca.pw>
Date: Wed, 15 Jan 2020 23:37:47 -0500
Cc: Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Dmitriy Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Peter Zijlstra <peterz@infradead.org>,
 Ingo Molnar <mingo@redhat.com>,
 Will Deacon <will@kernel.org>
Content-Transfer-Encoding: quoted-printable
Message-Id: <D8636F45-621D-4A9F-A7A7-3399450DDAF0@lca.pw>
References: <20200114124919.11891-1-elver@google.com>
 <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
 <CANpmjNP6+NTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q@mail.gmail.com>
 <20200115163754.GA2935@paulmck-ThinkPad-P72>
 <B2717BA1-B964-4B0A-BE4F-5B244087B9E5@lca.pw>
To: "Paul E. McKenney" <paulmck@kernel.org>
X-Mailer: Apple Mail (2.3608.40.2.2.4)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=FmFuQEFR;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jan 15, 2020, at 10:39 PM, Qian Cai <cai@lca.pw> wrote:
>=20
>=20
>=20
>> On Jan 15, 2020, at 11:37 AM, Paul E. McKenney <paulmck@kernel.org> wrot=
e:
>>=20
>> On Wed, Jan 15, 2020 at 05:26:55PM +0100, Marco Elver wrote:
>>> On Tue, 14 Jan 2020 at 18:24, Alexander Potapenko <glider@google.com> w=
rote:
>>>>=20
>>>>> --- a/kernel/kcsan/core.c
>>>>> +++ b/kernel/kcsan/core.c
>>>>> @@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, =
size_t size, int type)
>>>>>        *      detection point of view) to simply disable preemptions =
to ensure
>>>>>        *      as many tasks as possible run on other CPUs.
>>>>>        */
>>>>> -       local_irq_save(irq_flags);
>>>>> +       raw_local_irq_save(irq_flags);
>>>>=20
>>>> Please reflect the need to use raw_local_irq_save() in the comment.
>>>>=20
>>>>>=20
>>>>>       watchpoint =3D insert_watchpoint((unsigned long)ptr, size, is_w=
rite);
>>>>>       if (watchpoint =3D=3D NULL) {
>>>>> @@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, =
size_t size, int type)
>>>>>=20
>>>>>       kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>>>>> out_unlock:
>>>>> -       local_irq_restore(irq_flags);
>>>>> +       raw_local_irq_restore(irq_flags);
>>>>=20
>>>> Ditto
>>>=20
>>> Done. v2: http://lkml.kernel.org/r/20200115162512.70807-1-elver@google.=
com
>>=20
>> Alexander and Qian, could you please let me know if this fixes things
>> up for you?
>=20
> The lockdep warning is gone, so feel free to add,
>=20
> Tested-by: Qian Cai <cai@lca.pw>
>=20
> for that patch, but the system is still unable to boot due to spam of
> warnings due to incompatible with debug_pagealloc, debugobjects, so
> the warning rate limit does not help.

I set CONFIG_DEBUG_OBJECTS=3Dn to see how further it could go, but
the kernel is dead after those lines. Unable to boot any further.

=E2=80=A6
[  111.345991][  T789] Reported by Kernel Concurrency Sanitizer on:
[  111.373039][  T789] CPU: 44 PID: 789 Comm: systemd-udevd Not tainted 5.5=
.0-rc6-next-20200115+ #4
[  111.414596][  T789] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL23=
0a Gen9, BIOS U13 01/22/2018
[  111.459984][  T789] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[  111.554563][  T777] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[  111.590304][  T777] BUG: KCSAN: data-race in __change_page_attr / __chan=
ge_page_attr
[  111.626392][  T777]=20
[  111.636881][  T777] write to 0xffffffff9a19cde0 of 8 bytes by task 796 o=
n cpu 1:
[  111.671544][  T777]  __change_page_attr+0xe9c/0x1620
[  111.695067][  T777]  __change_page_attr_set_clr+0xde/0x4c0
[  111.722124][  T777]  __set_pages_p+0xcc/0x100
[  111.742644][  T777]  __kernel_map_pages+0x2e/0xdb
[  111.765379][  T777]  prep_new_page+0x87/0x1f0
[  111.785804][  T777]  get_page_from_freelist+0x1583/0x22b0
[  111.810633][  T777]  __alloc_pages_nodemask+0x1b1/0x450
[  111.835196][  T777]  alloc_pages_current+0xa6/0x120
[  111.858619][  T777]  __vmalloc_node_range+0x338/0x480
[  111.882253][  T777]  __vmalloc_node.constprop.29+0x70/0xb0
[  111.908550][  T777]  vmalloc+0x69/0x80
[  111.927150][  T777]  kernel_read_file+0x241/0x2b0
[  111.950372][  T777]  kernel_read_file_from_fd+0x56/0x90
[  111.976025][  T777]  __do_sys_finit_module+0xc7/0x190
[  111.999847][  T777]  __x64_sys_finit_module+0x4c/0x60
[  112.023326][  T777]  do_syscall_64+0x91/0xb47
[  112.043903][  T777]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
[  112.070954][  T777]=20
[  112.081261][  T777] read to 0xffffffff9a19cde0 of 8 bytes by task 777 on=
 cpu 16:
[  112.115510][  T777]  __change_page_attr+0xe81/0x1620
[  112.138564][  T777]  __change_page_attr_set_clr+0xde/0x4c0
[  112.164452][  T777]  __set_pages_p+0xcc/0x100
[  112.185228][  T777]  __kernel_map_pages+0x2e/0xdb
[  112.207122][  T777]  prep_new_page+0x87/0x1f0
[  112.227507][  T777]  get_page_from_freelist+0x1583/0x22b0
[  112.252947][  T777]  __alloc_pages_nodemask+0x1b1/0x450
[  112.277504][  T777]  alloc_pages_current+0xa6/0x120
[  112.300450][  T777]  alloc_slab_page+0x3b1/0x540
[  112.322039][  T777]  allocate_slab+0x70/0x660
[  112.342387][  T777]  new_slab+0x46/0x70
[  112.360102][  T777]  ___slab_alloc+0x4ad/0x7d0
[  112.380944][  T777]  __slab_alloc+0x43/0x70
[  112.400596][  T777]  kmem_cache_alloc+0x2c3/0x420
[  112.423674][  T777]  create_object+0x69/0x690
[  112.447347][  T777]  kmemleak_alloc+0x7d/0xb0
[  112.469100][  T777]  __kmalloc_track_caller+0x157/0x3c0
[  112.493548][  T777]  kstrdup+0x3d/0x70
[  112.510959][  T777]  mod_sysfs_setup+0x5e5/0xb10
[  112.532234][  T777]  load_module+0x2510/0x2b60
[  112.552985][  T777]  __do_sys_finit_module+0x14d/0x190
[  112.577212][  T777]  __x64_sys_finit_module+0x4c/0x60
[  112.601135][  T777]  do_syscall_64+0x91/0xb47
[  112.621690][  T777]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
[  112.648566][  T777]=20
[  112.659018][  T777] Reported by Kernel Concurrency Sanitizer on:
[  112.687603][  T777] CPU: 16 PID: 777 Comm: systemd-udevd Not tainted 5.5=
.0-rc6-next-20200115+ #4
[  112.729082][  T777] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL23=
0a Gen9, BIOS U13 01/22/2018
[  112.772563][  T777] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[  112.810304][  T364] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[  112.848145][  T364] BUG: KCSAN: data-race in __change_page_attr / __chan=
ge_page_attr
[  112.884579][  T364]=20
[  112.884586][  T364] read to 0xffffffff9a19cde0 of 8 bytes by task 789 on=
 cpu 12:
[  112.884595][  T364]  __change_page_attr+0xe81/0x1620
[  112.884602][  T364]  __change_page_attr_set_clr+0xde/0x4c0
[  112.884607][  T364]  __set_pages_p+0xcc/0x100
[  112.884612][  T364]  __kernel_map_pages+0x2e/0xdb
         [  112.884619][  T364]  prep_new_page+0x87/0x1f0
[  112.884627][  T364]  get_page_from_freelist+0x1583/0x22b0
[  112.884633][  T364]  __alloc_pages_nodemask+0x1b1/0x450
[  112.884640][  T364]  alloc_pages_vma+0x8a/0x2c0
[  112.884646][  T364]  wp_page_copy+0x100/0x930
Starting Show Pl[  112.884653][  T364]  do_wp_page+0x107/0x7b0
[  112.884660][  T364]  __handle_mm_fault+0xce6/0xd40
[  112.884667][  T364]  handle_mm_fault+0xfc/0x2f0
[  112.884677][  T364]  do_page_fault+0x263/0x6f9
ymouth Boot Screen...
perf: interrupt took too long (7468 > 7338), lowering kernel.perf_event_max=
_sample_rate to 26700
perf: interrupt took too long (9463 > 9335), lowering kernel.perf_event_max=
_sample_rate to 21100

>=20
> [   28.992752][  T394] Reported by Kernel Concurrency Sanitizer on:=20
> [   28.992752][  T394] CPU: 0 PID: 394 Comm: pgdatinit0 Not tainted 5.5.0=
-rc6-next-20200115+ #3=20
> [   28.992752][  T394] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL=
230a Gen9, BIOS U13 01/22/2018=20
> [   28.992752][  T394] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=20
> [   28.992752][  T394] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [   28.992752][  T394] BUG: KCSAN: data-race in __change_page_attr / __ch=
ange_page_attr=20
> [   28.992752][  T394] =20
> [   28.992752][  T394] read to 0xffffffffa01a6de0 of 8 bytes by task 395 =
on cpu 16:=20
> [   28.992752][  T394]  __change_page_attr+0xe81/0x1620=20
> [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0=20
> [   28.992752][  T394]  __set_pages_np+0xcc/0x100=20
> [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb=20
> [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730=20
> [   28.992752][  T394]  __free_pages+0x51/0x90=20
> [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0=20
> [   28.992752][  T394]  deferred_free_range+0x59/0x8f=20
> [   28.992752][  T394]  deferred_init_max21d=20
> [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1=20
> [   28.992752][  T394]  kthread+0x1e0/0x200=20
> [   28.992752][  T394]  ret_from_fork+0x3a/0x50=20
> [   28.992752][  T394] =20
> [   28.992752][  T394] write to 0xffffffffa01a6de0 of 8 bytes by task 394=
 on cpu 0:=20
> [   28.992752][  T394]  __change_page_attr+0xe9c/0x1620=20
> [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0=20
> [   28.992752][  T394]  __set_pages_np+0xcc/0x100=20
> [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb=20
> [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730=20
> [   28.992752][  T394]  __free_pages+0x51/0x90=20
> [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0=20
> [   28.992752][  T394]  deferred_free_range+0x59/0x8f=20
> [   28.992752][  T394]  deferred_init_maxorder+0x1d6/0x21d=20
> [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1=20
> [   28.992752][  T394]  kthread+0x1e0/0x200=20
> [   28.992752][  T394]  ret_from_fork+0x3a/0x50=20
>=20
>=20
> [   93.233621][  T349] Reported by Kernel Concurrency Sanitizer on:=20
> [   93.261902][  T349] CPU: 19 PID: 349 Comm: kworker/19:1 Not tainted 5.=
5.0-rc6-next-20200115+ #3=20
> [   93.302634][  T349] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL=
230a Gen9, BIOS U13 01/22/2018=20
> [   93.345413][  T349] Workqueue: memcg_kmem_cache memcg_kmem_cache_creat=
e_func=20
> [   93.378715][  T349] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [   93.416183][  T616] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [   93.453415][  T616] BUG: KCSAN: data-race in __debug_object_init / fil=
l_pool=20
> [   93.486775][  T616] =20
> [   93.497644][  T616] read to 0xffffffff9ff33b78 of 4 bytes by task 617 =
on cpu 12:=20
> [   93.534139][  T616]  fill_pool+0x38/0x700=20
> [   93.554913][  T616]  __debug_object_init+0x3f/0x900=20
> [   93.579459][  T616]  debug_object_init+0x39/0x50=20
> [   93.601952][  T616]  __init_work+0x3e/0x50=20
> [   93.620611][  T616]  memcg_kmem_get_cache+0x3c8/0x480=20
> [   93.643619][  T616]  slab_pre_alloc_hook+0x5d/0xa0=20
> [   93.665134][  T616]  __kmalloc_node+0x60/0x300=20
> [   93.685094][  T616]  kvmalloc_node+0x83/0xa0=20
> [   93.704235][  T616]  seq_read+0x57c/0x7a0=20
> [   93.722460][  T616]  proc_reg_read+0x11a/0x160=20
> [   93.743570][  T616]  __vfs_read+0x59/0xa0=20
> [   93.761660][  T616]  vfs_read+0xcf/0x1c0=20
> [   93.779269][  T616]  ksys_read+0x9d/0x130=20
> [   93.797267][  T616]  __x64_sys_read+0x4c/0x60=20
> [   93.817205][  T616]  do_syscall_64+0x91/0xb47=20
> [   93.837590][  T616]  entry_SYSCALL_64_after_hwframe+0x49/0xbe=20
> [   93.864425][  T616] =20
> [   93.874830][  T616] write to 0xffffffff9ff33b78 of 4 bytes by task 616=
 on cpu 61:=20
> [   93.908534][  T616]  __debug_object_init+0x6e5/0x900=20
> [   93.931018][  T616]  debug_object_activate+0x1fc/0x350=20
> [   93.954131][  T616]  call_rcu+0x4c/0x4e0=20
> [   93.971959][  T616]  put_object+0x6a/0x90=20
> [   93.989955][  T616]  __delete_object+0xb9/0xf0=20
> [   94.009996][  T616]  delete_object_full+0x2d/0x40=20
> [   94.031812][  T616]  kmemleak_free+0x5f/0x90=20
> [   94.054671][  T616]  slab_free_freelist_hook+0x124/0x1c0=20
> [   94.082027][  T616]  kmem_cache_free+0x10c/0x3a0=20
> [   94.103806][  T616]  vm_area_free+0x31/0x40=20
> [   94.124587][  T616]  remove_vma+0xb0/0xc0=20
> [   94.143484][  T616]  exit_mmap+0x14c/0x220=20
> [   94.163826][  T616]  mmput+0x10e/0x270=20
> [   94.181736][  T616]  flush_old_exec+0x572/0xfe0=20
> [   94.202760][  T616]  load_elf_binary+0x467/0x2180=20
> [   94.224819][  T616]  search_binary_handler+0xd8/0x2b0=20
> [   94.248735][  T616]  __do_execve_file+0xb61/0x1080=20
> [   94.270943][  T616]  __x64_sys_execve+0x5f/0x70=20
> [   94.292254][  T616]  do_syscall_64+0x91/0xb47=20
> [   94.312712][  T616]  entry_SYSCALL_64_after_hwframe+0x49/0xbe=20
>=20
> [  103.455945][   C22] Reported by Kernel Concurrency Sanitizer on:=20
> [  103.483032][   C22] CPU: 22 PID: 0 Comm: swapper/22 Not tainted 5.5.0-=
rc6-next-20200115+ #3=20
> [  103.520563][   C22] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL=
230a Gen9, BIOS U13 01/22/2018=20
> [  103.561771][   C22] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [  103.598005][   C41] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [  103.633820][   C41] BUG: KCSAN: data-race in intel_pstate_update_util =
/ intel_pstate_update_util=20
> [  103.673408][   C41] =20
> [  103.683214][   C41] read to 0xffffffffa9098a58 of 2 bytes by interrupt=
 on cpu 2:=20
> [  103.716645][   C41]  intel_pstate_update_util+0x580/0xb40=20
> [  103.740609][   C41]  cpufreq_update_util+0xb0/0x160=20
> [  103.762611][   C41]  update_blocked_averages+0x585/0x630=20
> [  103.786435][   C41]  run_rebalance_domains+0xd5/0x240=20
> [  103.812821][   C41]  __do_softirq+0xd9/0x57c=20
> [  103.834438][   C41]  irq_exit+0xa2/0xc0=20
> [  103.851773][   C41]  smp_apic_timer_interrupt+0x190/0x480=20
> [  103.876005][   C41]  apic_timer_interrupt+0xf/0x20=20
> [  103.897495][   C41]  cpuidle_enter_state+0x18a/0x9b0=20
> [  103.919324][   C41]  cpuidle_enter+0x69/0xc0=20
> [  103.938405][   C41]  call_cpuidle+0x23/0x40=20
> [  103.957152][   C41]  do_idle+0x248/0x280=20
> [  103.974728][   C41]  cpu_startup_entry+0x1d/0x1f=20
> [  103.995059][   C41]  start_secondary+0x1ad/0x230=20
> [  104.015920][   C41]  secondary_startup_64+0xb6/0xc0=20
> [  104.037376][   C41] =20
> [  104.047144][   C41] write to 0xffffffffa9098a59 of 1 bytes by interrup=
t on cpu 41:=20
> [  104.081113][   C41]  intel_pstate_update_util+0x4cf/0xb40=20
> [  104.105862][   C41]  cpufreq_update_util+0xb0/0x160=20
> [  104.127759][   C41]  update_load_avg+0x70e/0x800=20
> [  104.148400][   C41]  task_tick_fair+0x5c/0x680=20
> [  104.168325][   C41]  scheduler_tick+0xab/0x120=20
> [  104.188881][   C41]  update_process_times+0x44/0x60=20
> [  104.210811][   C41]  tick_sched_handle+0x4f/0xb0=20
> [  104.231137][   C41]  tick_sched_timer+0x45/0xc0=20
> [  104.251431][   C41]  __hrtimer_run_queues+0x243/0x800=20
> [  104.274362][   C41]  hrtimer_interrupt+0x1d4/0x3e0=20
> [  104.295860][   C41]  smp_apic_timer_interrupt+0x11d/0x480=20
> [  104.325136][   C41]  apic_timer_interrupt+0xf/0x20=20
> [  104.347864][   C41]  __kcsan_check_access+0x1a/0x120=20
> [  104.370100][   C41]  __read_once_size+0x1f/0xe0=20
> [  104.390064][   C41]  smp_call_function_many+0x4b0/0x5d0=20
> [  104.413591][   C41]  on_each_cpu+0x46/0x90=20
> [  104.431954][   C41]  flush_tlb_kernel_range+0x97/0xc0=20
> [  104.454702][   C41]  free_unmap_vmap_area+0xaa/0xe0=20
> [  104.476699][   C41]  remove_vm_area+0xf4/0x100=20
> [  104.496763][   C41]  __vunmap+0x10a/0x460=20
> [  104.514807][   C41]  __vfree+0x33/0x90=20
> [  104.531597][   C41]  vfree+0x47/0x80=20
> [  104.547600][   C41]  n_tty_close+0x56/0x80=20
> [  104.565988][   C41]  tty_ldisc_close+0x76/0xa0=20
> [  104.585912][   C41]  tty_ldisc_kill+0x51/0xa0=20
> [  104.605864][   C41]  tty_ldisc_release+0xf4/0x1a0=20
> [  104.627098][   C41]  tty_release_struct+0x23/0x60=20
> [  104.648268][   C41]  tty_release+0x673/0x9c0=20
> [  104.667517][   C41]  __fput+0x187/0x410=20
> [  104.684357][   C41]  ____fput+0x1e/0x30=20
> [  104.701542][   C41]  task_work_run+0xed/0x140=20
> [  104.721358][   C41]  do_syscall_64+0x803/0xb47=20
> [  104.740872][   C41]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
>=20
> [  136.745789][   C34] Reported by Kernel Concurrency Sanitizer on:=20
> [  136.774278][   C34] CPU: 34 PID: 0 Comm: swapper/34 Not tainted 5.5.0-=
rc6-next-20200115+ #3=20
> [  136.814948][   C34] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL=
230a Gen9, BIOS U13 01/22/2018=20
> [  136.861974][   C34] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [  136.911354][    T1] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=20
> [  136.948491][    T1] BUG: KCSAN: data-race in __debug_object_init / fil=
l_pool=20
> [  136.981645][    T1] =20
> [  136.992045][    T1] read to 0xffffffff9ff33b78 of 4 bytes by task 762 =
on cpu 25:=20
> [  137.026513][    T1]  fill_pool+0x38/0x700=20
> [  137.045575][    T1]  __debug_object_init+0x3f/0x900=20
> [  137.068826][    T1]  debug_object_activate+0x1fc/0x350=20
> [  137.093102][    T1]  call_rcu+0x4c/0x4e0=20
> [  137.111520][    T1]  __fput+0x23a/0x410=20
> [  137.129618][    T1]  ____fput+0x1e/0x30=20
> [  137.147627][    T1]  task_work_run+0xed/0x140=20
> [  137.168322][    T1]  do_syscall_64+0x803/0xb47=20
> [  137.188572][    T1]  entry_SYSCALL_64_after_hwframe+0x49/0xbe=20
> [  137.215309][    T1] =20
> [  137.225579][    T1] write to 0xffffffff9ff33b78 of 4 bytes by task 1 o=
n cpu 7:=20
> [  137.259867][    T1]  __debug_object_init+0x6e5/0x900=20
> [  137.283065][    T1]  debug_object_activate+0x1fc/0x350=20
> [  137.306988][    T1]  call_rcu+0x4c/0x4e0=20
> [  137.326804][    T1]  dentry_free+0x70/0xe0=20
> [  137.347208][    T1]  __dentry_kill+0x1db/0x300=20
> [  137.369468][    T1]  shrink_dentry_list+0x153/0x2e0=20
> [  137.393437][    T1]  shrink_dcache_parent+0x1ee/0x320=20
> [  137.417174][    T1]  d_invalidate+0x80/0x130=20
> [  137.437280][    T1]  proc_flush_task+0x14c/0x2b0=20
> [  137.459263][    T1]  release_task.part.21+0x156/0xb50=20
> [  137.483580][    T1]  wait_consider_task+0x17a8/0x1960=20
> [  137.507550][    T1]  do_wait+0x25b/0x560=20
> [  137.526175][    T1]  kernel_waitid+0x194/0x270=20
> [  137.547105][    T1]  __do_sys_waitid+0x18e/0x1e0=20
> [  137.568951][    T1]  __x64_sys_waitid+0x70/0x90=20
> [  137.590291][    T1]  do_syscall_64+0x91/0xb47=20
> [  137.610681][    T1]  entry_SYSCALL_64_after_hwframe+0x49/0xbe=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/D8636F45-621D-4A9F-A7A7-3399450DDAF0%40lca.pw.
