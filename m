Return-Path: <kasan-dev+bncBDTMJ55N44FBBSEO43BAMGQEYCWENTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 32FDEAE4B7A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 18:56:42 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553e00fa4ecsf2611268e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 09:56:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750697801; cv=pass;
        d=google.com; s=arc-20240605;
        b=efSyzMJcK/ZkkgE24sSJTX70ued4dm31S6ZgnrVHgQKArucI6Pd1ZUJLhVEoiLXmYh
         Y1kUMsH2uweNoqrxNzAy4AoehaLe6f3z64PGKPZZhEbS2OFbbGf4k1ekdgSlznll8s9Y
         ejpbLKFJ0AQRmpTm9f4BelVj8Ob3C4pe3q9/otZO6iU/b+Tz4c6ge4j8mfHzO2893jAp
         u1bj8PyBQufe+Mf1D72zC8scaYbJ02cTXHf7pbK1FUQ+Yty/uNNxZd61u3I5Zq+LFJlP
         BEIEvFTwToLv+stzaF/2YVABYG3p0GPmnDMHbqZ9stXxnxFxOmW2IlSolL683alPY+VM
         B2xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=uTZUg+oXLddAplesU0WIIYTjzX2zx7bMMtmkSBO+STI=;
        fh=etbMC8ekSC85VCHNmU4rve8z6xZv4dkmKX2Jnq+rhwU=;
        b=g3p5cDC33J93eQdmulZgBtHKQoYDeqnO5t7i+er+Swf7OuOJXWYxS5pfdGVw6+7G+m
         r2N2JRYnLAJnXeHfXO8ITv3+D8YL5+op36Y3t3Hzn1RmThRFOoCF+B83CQ7PSmPFLlyp
         eUIYZhVrRUm6GQeA/nxOgsgNPo34y3kqQglDj/93mCELNPd/JmYmJOzlA4KLX5n/IrnI
         jzfHU/INH/T/PKNkSt0nIRzNPtGh0cvF1mn6uRWRU3S3cyFYg+Jn7W1yC48uTp6q+7zu
         bibkH20qWevirxEiQGaA1YQxDDP71fCbl3mIbRON5hTtUGL91o6MQBSU9rE5ASHazg3O
         Occg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750697801; x=1751302601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uTZUg+oXLddAplesU0WIIYTjzX2zx7bMMtmkSBO+STI=;
        b=ox29WeQpLHfqIQXULSMW14uOmy5u/Wr7QpMU5+YENPKYI8PQG0xIpAb3/xkapkOJ0f
         OT6p+x/Vu3kgdhQxDuLlwsuDqMcA5VqOuCcq9yJksx5qJrkgfrILeq1SuRkmslvUM4Ts
         k4lM15If9TzNDY8nPLShp8MKvsETHBcyghO758sSAZ6S0qkH+3zVdy4Zo7uM8RboKfJh
         Rch5P0AqGZAu7VOdSlpqm7d2xH/FRf7aSdMRqtiKyspo2jZ4C1XkkoYGsF7V0mzK44Ib
         rELf7dSPqy/+mmnRTn4rnyY2D3uo+eHRgbgU2Ti/l3uJ7zBxwHmf8CR0WEfUOxPWQ/yn
         ilDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750697801; x=1751302601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uTZUg+oXLddAplesU0WIIYTjzX2zx7bMMtmkSBO+STI=;
        b=Xq75SfJgrET0L6x59VDbq+qyEDNJx/lnHL5+FxCIIHELhgSbE8D4FKkqLvnurDKzI9
         QwHRvuHsv5N+G955oILn/+pppc4GJ1/gWruDMEqZfbQqHoqb8tV9/U/hGYyZzl0r+Rhd
         kR5RXwKg7+VbemGPEISZFf39Ja4hcdvciwpzBxfia7zmSLLyZqGBT0X2H2wx0lveNmFZ
         4MsbGJJ2UkxQEWlroFrnACUtl0IR3X5Ua5Cw/yZTtjWgLfyh+fAsdPTgokkq3x8MOr5D
         ishjnVYYh5CgTeq00M8IIVFksrKbwbLYmy6oXXaLkJPpIFOcEfDKrP3VIkZ00qYmujjG
         WTDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKGE0n1NJCYLLDUhbIW5fB4GVY47JLHSFZqRHKEQ0ROtM99NqvC4in32BaYLe7bAbKkprJkw==@lfdr.de
X-Gm-Message-State: AOJu0Yxw5az3q0/eXu6Y04Zw6m8DS8JZwFiRL7cUIKEC/QXIS4WhJCB9
	8xRo5MnNd0NpKwLQV8Sg5qHUIR1OjJbGho8pm2XadiCBjYVqoDec5/SR
X-Google-Smtp-Source: AGHT+IElVbRgaFsx5rp3mMV7Esy7SiglE1jfQFzVa4Q9XUHgEr+gIM+0Oo6a1wbnIb5JwC0pp1SXMw==
X-Received: by 2002:ac2:51c4:0:b0:553:ac4c:2177 with SMTP id 2adb3069b0e04-553e3bc061emr4583790e87.20.1750697800922;
        Mon, 23 Jun 2025 09:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdqlC+orvQMwAlgYN6vhk2DRM1HUz2FsCJ1GcAwNpw3TA==
Received: by 2002:a05:6512:3d10:b0:553:d55b:4803 with SMTP id
 2adb3069b0e04-553db36965als944983e87.0.-pod-prod-04-eu; Mon, 23 Jun 2025
 09:56:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyQImQVxQf406IvxxGhy3PQh1J+1Gu38mJRx3PyKEzcwgYvJgF0KOynD3UR7QdTRYauJBA+IgKf8Y=@googlegroups.com
X-Received: by 2002:a05:6512:3b0b:b0:553:3945:82a7 with SMTP id 2adb3069b0e04-553e3ba76fbmr4396189e87.12.1750697797827;
        Mon, 23 Jun 2025 09:56:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750697797; cv=none;
        d=google.com; s=arc-20240605;
        b=J9Kdbxc1Y+1EH7Y8G7dHx1EGRDAKS8ghZIVd5wRnWRogHJRpBEPBYkFU3159v04EmB
         758VPLHBP+C3PIzudLnfxB3UqGlc+Aanip4oyUSxuPmiKeIJOjRZkImJ9F/kphUmfKCt
         y8GcEUIC+RMiCCTMlyc4vn4L5ZOoJSyLGiO5ecUCQI7iSrO1UpQR1vllFXZLi39WX6xo
         3U2Lz3jO1KeIG4eS47HFcg6gkDUPUMakI4Rv4mntf5sWbKEsm35XIzuwoCA75/ORMkfw
         wQaMNhAP8lEaydiB5txPtQm8R+4PGDLTcAUvKysmHh7J55SdAM5/UTeKn7bahX8ekJaj
         6shw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=EKkW4+XVrDVdyJMGMoOg/KRLZUDhgXliMkMQQ7T6pik=;
        fh=xDY0BUI8dUqw635+rHl8cdNnvlIIRUVVqFEbIMFoly4=;
        b=FkwmZ/AFpsPYs7dzw7vFwPHimF6uHO/Bfu2AgIF6yWn9A2oJWbDLJqgco0y3ejHuS7
         GlFk6kW5u5DdCdPebJUsHuIBtYOucXBrGFbfTyZ1oONKeLNyMj76gqrrrjyeU8V5D8b7
         lUYGqWweLenosGP9lECnNTWcTaJPzV0m0r5+iP7iTiuFn9/g/dWlP6EDzxx+Vy6cWFuX
         IwbawriBgsG/f7wO9id01BBEI1PmHtoAtWAALtVgcQleTYXrjKEPtxbIdxIgxwKNLlTL
         HY5+V72r8AlWuJCzJKkfMFLiBxW6DmFkvmU2HjXoguLTOreDfRPEpedxYLI6+3ieXDc1
         ViwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f50.google.com (mail-ej1-f50.google.com. [209.85.218.50])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e41c1aa9si141224e87.9.2025.06.23.09.56.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jun 2025 09:56:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as permitted sender) client-ip=209.85.218.50;
Received: by mail-ej1-f50.google.com with SMTP id a640c23a62f3a-ad93ff9f714so777739066b.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Jun 2025 09:56:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDMk0ASrTQ0m9X4rFoMZfWRtIDcU8duGhAI3nSx84WUrmUgGBp1Rvvomf46wZzvfcTp+vpkli9dD4=@googlegroups.com
X-Gm-Gg: ASbGncsqGv3DuxpxvD0LprkOZcTZnQH+KAdQlrlzYHyzHPMSauxzc9lWfbV7Pyq+Ww7
	WAb3bVhLN8WJNevYLQMfOKHramw2hkQzSaXPleWNW/8AkPgFrsQ1nrogqD7UQnnRKKnqHRWQT6Q
	ynhnzAb0ZPKoI2srKaF5q9nphf6jSpVAHKXJAtJvPnngd37qZf4YqrsXPk30MTtZq421FG7iwKz
	iaaODRxfxJu92hV+i6zcXNWlhmlBLReiQfMoLNk1yYKpuzAa76gEyFoda7oHXaTufYKYTcjJdDb
	FtDeqKBx7uMVHWVeRPbbINcLKawGXDaZG2T2ULZXz+i5QuV79yLyWw==
X-Received: by 2002:a17:907:3d09:b0:ae0:a684:2594 with SMTP id a640c23a62f3a-ae0a684278bmr38731066b.0.1750697796691;
        Mon, 23 Jun 2025 09:56:36 -0700 (PDT)
Received: from gmail.com ([2a03:2880:30ff:71::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae06aa5ff34sm549543666b.40.2025.06.23.09.56.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jun 2025 09:56:36 -0700 (PDT)
Date: Mon, 23 Jun 2025 09:56:33 -0700
From: Breno Leitao <leitao@debian.org>
To: Catalin Marinas <catalin.marinas@arm.com>, andreyknvl@gmail.com
Cc: Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, will@kernel.org,
	song@kernel.org, mark.rutland@arm.com, usamaarif642@gmail.com,
	Ard Biesheuvel <ardb@kernel.org>, rmikey@meta.com
Subject: Re: arm64: BUG: KASAN: invalid-access in arch_stack_walk
Message-ID: <aFmHQbpwX4WnR/5p@gmail.com>
References: <aFVVEgD0236LdrL6@gmail.com>
 <CA+fCnZfzHOFjVo43UZK8H6h3j=OHjfF13oFJvT0P-SM84Oc4qQ@mail.gmail.com>
 <aFlA1tXXUEBZP1NH@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aFlA1tXXUEBZP1NH@arm.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

On Mon, Jun 23, 2025 at 12:56:06PM +0100, Catalin Marinas wrote:
> On Sun, Jun 22, 2025 at 02:57:16PM +0200, Andrey Konovalov wrote:
> > On Fri, Jun 20, 2025 at 2:33=E2=80=AFPM Breno Leitao <leitao@debian.org=
> wrote:
> > > I'm encountering a KASAN warning during aarch64 boot and I am struggl=
ing
> > > to determine the cause. I haven't come across any reports about this =
on
> > > the mailing list so far, so I'm sharing this early in case others are
> > > seeing it too.
> > >
> > > This issue occurs both on Linus's upstream branch and in the 6.15 fin=
al
> > > release. The stack trace below is from 6.15 final. I haven't started
> > > bisecting yet, but that's my next step.
> > >
> > > Here are a few details about the problem:
> > >
> > > 1) it happen on my kernel boots on a aarch64 host
> > > 2) The lines do not match the code very well, and I am not sure why. =
It
> > >    seems it is offset by two lines. The stack is based on commit
> > >    0ff41df1cb26 ("Linux 6.15")
> > > 3) My config is at https://pastebin.com/ye46bEK9
> > >
> > >
> > >         [  235.831690] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > >         [  235.861238] BUG: KASAN: invalid-access in arch_stack_walk =
(arch/arm64/kernel/stacktrace.c:346 arch/arm64/kernel/stacktrace.c:387)
> > >         [  235.887206] Write of size 96 at addr a5ff80008ae8fb80 by t=
ask kworker/u288:26/3666
> > >         [  235.918139] Pointer tag: [a5], memory tag: [00]
> > >         [  235.942722] Workqueue: efi_rts_wq efi_call_rts
> > >         [  235.942732] Call trace:
> > >         [  235.942734] show_stack (arch/arm64/kernel/stacktrace.c:468=
) (C)
> > >         [  235.942741] dump_stack_lvl (lib/dump_stack.c:123)
> > >         [  235.942748] print_report (mm/kasan/report.c:409 mm/kasan/r=
eport.c:521)
> > >         [  235.942755] kasan_report (mm/kasan/report.c:636)
> > >         [  235.942759] kasan_check_range (mm/kasan/sw_tags.c:85)
> > >         [  235.942764] memset (mm/kasan/shadow.c:53)
> > >         [  235.942769] arch_stack_walk (arch/arm64/kernel/stacktrace.=
c:346 arch/arm64/kernel/stacktrace.c:387)
> > >         [  235.942773] return_address (arch/arm64/kernel/return_addre=
ss.c:44)
> > >         [  235.942778] trace_hardirqs_off.part.0 (kernel/trace/trace_=
preemptirq.c:95)
> > >         [  235.942784] trace_hardirqs_off_finish (kernel/trace/trace_=
preemptirq.c:98)
> > >         [  235.942789] enter_from_kernel_mode (arch/arm64/kernel/entr=
y-common.c:62)
> > >         [  235.942794] el1_interrupt (arch/arm64/kernel/entry-common.=
c:559 arch/arm64/kernel/entry-common.c:575)
> > >         [  235.942799] el1h_64_irq_handler (arch/arm64/kernel/entry-c=
ommon.c:581)
> > >         [  235.942804] el1h_64_irq (arch/arm64/kernel/entry.S:596)
> > >         [  235.942809]  0x3c52ff1ecc (P)
> > >         [  235.942825]  0x3c52ff0ed4
> > >         [  235.942829]  0x3c52f902d0
> > >         [  235.942833]  0x3c52f953e8
> > >         [  235.942837] __efi_rt_asm_wrapper (arch/arm64/kernel/efi-rt=
-wrapper.S:49)
> > >         [  235.942843] efi_call_rts (drivers/firmware/efi/runtime-wra=
ppers.c:269)
> > >         [  235.942848] process_one_work (./arch/arm64/include/asm/jum=
p_label.h:36 ./include/trace/events/workqueue.h:110 kernel/workqueue.c:3243=
)
> > >         [  235.942854] worker_thread (kernel/workqueue.c:3313 kernel/=
workqueue.c:3400)
> > >         [  235.942858] kthread (kernel/kthread.c:464)
> > >         [  235.942863] ret_from_fork (arch/arm64/kernel/entry.S:863)
> > >
> > >         [  236.436924] The buggy address belongs to the virtual mappi=
ng at
> > >         [a5ff80008ae80000, a5ff80008aea0000) created by:
> > >         arm64_efi_rt_init (arch/arm64/kernel/efi.c:219)
> > >
> > >         [  236.506959] The buggy address belongs to the physical page=
:
> > >         [  236.529724] page: refcount:1 mapcount:0 mapping:0000000000=
000000 index:0x0 pfn:0x12682
> > >         [  236.562077] flags: 0x17fffd6c0000000(node=3D0|zone=3D2|las=
tcpupid=3D0x1ffff|kasantag=3D0x5b)
> > >         [  236.593722] raw: 017fffd6c0000000 0000000000000000 dead000=
000000122 0000000000000000
> > >         [  236.625365] raw: 0000000000000000 0000000000000000 0000000=
1ffffffff 0000000000000000
> > >         [  236.657004] page dumped because: kasan: bad access detecte=
d
> > >
> > >         [  236.685828] Memory state around the buggy address:
> > >         [  236.705390]  ffff80008ae8f900: 00 00 00 00 00 a5 a5 a5 a5 =
00 00 00 00 00 a5 a5
> > >         [  236.734899]  ffff80008ae8fa00: a5 a5 a5 00 00 00 00 00 00 =
a5 a5 a5 a5 a5 00 a5
> > >         [  236.764409] >ffff80008ae8fb00: 00 a5 a5 a5 00 a5 a5 a5 a5 =
a5 a5 00 a5 a5 a5 00
> > >         [  236.793918]                                               =
      ^
> > >         [  236.818810]  ffff80008ae8fc00: a7 a5 a5 a5 a5 a5 a5 a5 a5 =
00 a5 00 a5 a5 a5 a5
> > >         [  236.848321]  ffff80008ae8fd00: a5 a5 a5 a5 00 a5 00 a5 a5 =
a5 a5 a5 a5 a5 a5 a5
> > >         [  236.877828] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> >=20
> > Looks like the memory allocated/mapped in arm64_efi_rt_init() is
> > tagged by __vmalloc_node(). And this memory then gets used as a
> > (irq-related? EFI-related?) stack. And having the SP register tagged
> > breaks SW_TAGS instrumentation AFAIR [1], which is likely what
> > produces this report.
> >=20
> > Adding kasan_reset_tag() to arm64_efi_rt_init() should likely fix
> > this; similar to what we have in arch_alloc_vmap_stack(). Or should we
> > make arm64_efi_rt_init() just call arch_alloc_vmap_stack()?
>=20
> In theory, we can still disable the vmap stack, so we either fall back
> to something else or require that EFI runtime depends on VMAP_STACK.
> We can do like init_sdei_stacks(), just bail out if VMAP_STACK is
> disabled.

Thanks for the feedback and suggestions. Are we talking about a patch
that looks like the following:

	Author: Breno Leitao <leitao@debian.org>
	Date:   Mon Jun 23 09:46:54 2025 -0700

	arm64: Use arch_alloc_vmap_stack for EFI runtime stack allocation
=09
	Refactor vmap stack allocation by moving the CONFIG_VMAP_STACK check
	from BUILD_BUG_ON to a runtime return of NULL if the config is not set.
	The side effect of this is that _init_sdei_stack() might NOT fail in
	build time if _VMAP_STACK, but in runtime. It shifts error
	detection from compile-time to runtime
=09
	Then, reuse arch_alloc_vmap_stack() to allocate the ACPI stack
	memory in the arm64_efi_rt_init().
=09
	Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
	Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
	Signed-off-by: Breno Leitao <leitao@debian.org>

	diff --git a/arch/arm64/include/asm/vmap_stack.h b/arch/arm64/include/asm/=
vmap_stack.h
	index 20873099c035c..8380af4507d01 100644
	--- a/arch/arm64/include/asm/vmap_stack.h
	+++ b/arch/arm64/include/asm/vmap_stack.h
	@@ -19,7 +19,8 @@ static inline unsigned long *arch_alloc_vmap_stack(size_=
t stack_size, int node)
	{
		void *p;
=09
	-	BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));
	+	if (!IS_ENABLED(CONFIG_VMAP_STACK))
	+		return NULL;
=09
		p =3D __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
				__builtin_return_address(0));
	diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
	index 3857fd7ee8d46..6c371b158b99f 100644
	--- a/arch/arm64/kernel/efi.c
	+++ b/arch/arm64/kernel/efi.c
	@@ -15,6 +15,7 @@
=09
	#include <asm/efi.h>
	#include <asm/stacktrace.h>
	+#include <asm/vmap_stack.h>
=09
	static bool region_is_misaligned(const efi_memory_desc_t *md)
	{
	@@ -214,9 +215,8 @@ static int __init arm64_efi_rt_init(void)
		if (!efi_enabled(EFI_RUNTIME_SERVICES))
			return 0;
=09
	-	p =3D __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
	-			   NUMA_NO_NODE, &&l);
	-l:	if (!p) {
	+	p =3D arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);
	+	if (!p) {
			pr_warn("Failed to allocate EFI runtime stack\n");
			clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
			return -ENOMEM;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
FmHQbpwX4WnR/5p%40gmail.com.
