Return-Path: <kasan-dev+bncBC6JD5V23ENBBL5UTKAAMGQE2ZSFZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 54DC22FB424
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 09:37:04 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id i82sf19515327qke.19
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 00:37:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611045423; cv=pass;
        d=google.com; s=arc-20160816;
        b=z7Oh0XattePkcl7sPyV2iwrRQ1NpDrG5C9whKqUgofeqyLjUmeaxgV2Y1xp3Jx40wo
         mNBoWLr7gGazUmk1lN06B8kXIirBTwScbh4rszWM6fJRogiKTrjmE3QYGvjLkTP6plmI
         8Vgwryfnsb1bscPmS34VRfBP0EB0s6oCQSvllH/5MdOpxT80ePlOyDSt7jMs/XtRXH9/
         D7YZ812W9D9ZXvIkkw1rcJj35mwZZQAQrhdwLySpXE5ULfjAySF3C6k1P5RAXYj4KC8b
         rQopGtehWWTxQg55Z1yjJbWcIbh3kA5WeF7Mv0I+YS9qXr9csLYX/8GFMmZzfWCtFEQG
         pnTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=zc5XtZ8QyS/NrqnZH65HvqdjEMr8095EpP5xhTU5Nyk=;
        b=dwCX5VSkT3BiMdF3DD0TFJ2UrtkXhHVLXWFnTu44EA9wxrjfH5Fep8sts3frYuEdAF
         /KX3CE2gkmz1VxQlNVXZx6dpSime2q6fT523lqPGk3RfCo/+FHfq0cCptc7A8/SpUFvz
         6yQ2gh6v+erP6iP9WZDFoW2ZPYj7ZAUL58doutQP/fugHiMtzKbRZ+ctHjdAWB1N0yO1
         IbKRKQbi94o2iI+Q5cxSnRcd832M/X3PmjKkhCqibqyDjraOdtjngJVQ6rMp7euHEaTB
         WqeIcRw9eaj7ZQPxFqWcqWNaNYuKhyCve3p6U0KpgmIdS2/zJqT+K249bNtJlRl2RxTG
         9NrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qFZfASgQ;
       spf=pass (google.com: domain of krzk@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=krzk@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zc5XtZ8QyS/NrqnZH65HvqdjEMr8095EpP5xhTU5Nyk=;
        b=T05gm9tSfsFaEynHHKcc2GBPhoqhDdqJ8+nefUEZyNy6LIIt0X8EgFAktj6JbRoMaB
         JXJLDDeVo2aX1SyoYaJ8xjoUB+ITHqwGo+3t8+7+zJaspyLCEQ8N9iI3hEadMCWWFfvm
         7zwzvUJZEmk7HlvEp3nmYXmiLepqi8+RuMy9W8JZLpXoMXctEWNycEId8yrbuzJwu1hM
         oKowBuFScKxab7zmOw9xMvzoV/qJfEuIFtYcl2wnfXOuwPiZLsMuZnUQJ6YkuJdeDVtI
         S1lF7u0nR6C+Y2eRFw8iZmwo/dLNBbkaofAXudvcVtzzTOJiC5B4rK7dLOfZRQMFTkIE
         FFAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zc5XtZ8QyS/NrqnZH65HvqdjEMr8095EpP5xhTU5Nyk=;
        b=k5F49WW4rhjcBe0jxr/k7g+3STn8jlaRXOyamuaHor/GP4Vj3yzkKmBgupCoirx0A9
         VkrnkqqfI3FoJn40Mn9S2llkS/s7SWRD8DIC8lT8HwTUst03JgkB2TMWqzeUj7RSdL5o
         g9h9Njs3zZcMinUtP+8zvCgF40nJQEXvPgXs3NQl4TIXbcNGYn1pgoC+uI4/r3XkOXk7
         aOoEpwM9u7t7l0xKVNaLEktW2Qi2YvgEXYf38H9Ah619jBCzY6TnaaNEmgEomNndlbDq
         XaqZvBzWA361xVk030I7dVw0EeBrmMo/Yt/TeR7JP+iTp3z65zM9OiSmzvceFIurXWWG
         bLMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DTozO6Fu7fSlbuRBxs+2TEOElZaCl26lgsdKQribajQPK97O3
	lEqfNswLkIh5opcU0neHQ/M=
X-Google-Smtp-Source: ABdhPJy9YhtH9PJML6gYqueoYXvjs/BtV54I3I5C2jDa+fR1UqbHHraxMy4/PA92HOYgcvBQKh+1tw==
X-Received: by 2002:ac8:118c:: with SMTP id d12mr3295560qtj.262.1611045423102;
        Tue, 19 Jan 2021 00:37:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1001:: with SMTP id z1ls4506086qti.4.gmail; Tue, 19 Jan
 2021 00:37:02 -0800 (PST)
X-Received: by 2002:aed:2666:: with SMTP id z93mr3160766qtc.319.1611045422694;
        Tue, 19 Jan 2021 00:37:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611045422; cv=none;
        d=google.com; s=arc-20160816;
        b=edud3xQodb1wjSmnc6ZKienFr5m11ECYNm90g+g0KO8CcbJYqScskRqZlDinAzd5Rm
         XziiCouwIU560i0Pqd6BCaIHZoSCAfnmloAEiMsqKSYOUBVbYCvIgwf9ustN+QyQmnTl
         80b/1MXdpsnarpZfBhC8BW11kSW+kJlpN5BzEZliXUwYLj7hMX7rQQayiKfQGKZ9/zQt
         Fejmdt75iiF8ymqRhoYvDFDeQoIyNlBVK1h6P0UTenMevGszSCC7XxwVfhK1NTKg8PZV
         PHDX/eJrHm9lMuPW85WE4CcQhNmY69VexgJ9Uhh5FtOlXd9l4YViOcElzzSXF3pT2xul
         8LZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OEekYL1Psn6FyFt0vwyimb32gZ96dS/txgVXPts+PLs=;
        b=MQHu95l6raQDmJDpQ/H48hiuCyNHWu/cm0oSUNky5tHttbl7xkxKl/oT0T9nmMDKeo
         SKQHD7VdCx6QH6q5N9gcLJ7F/ekMMNUumch/6hJOsfD0/iC7+3E9CQMAzZn3fnczkksZ
         Igk4elJ5Gohsr+oNnHMoG6AT2lRkgTVi1nuBrTcC9fN5OG93m5E5irpTfRdM8x1ihEAa
         Cr9ykPyHGi98A66r2U4Vsxtd3kQASvqZ/LAwMee9UwYLbhGKi5wEGd6eGTKvhppS5cfE
         3+WwGmuoA8+Nqu3sKgnKRPW0dbWAN9lXISdox93JjeublIkgSqkXolKEOfPiDHD3025K
         xt8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qFZfASgQ;
       spf=pass (google.com: domain of krzk@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=krzk@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p6si2184051qti.1.2021.01.19.00.37.02
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 00:37:02 -0800 (PST)
Received-SPF: pass (google.com: domain of krzk@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 22BF923135;
	Tue, 19 Jan 2021 08:37:01 +0000 (UTC)
Received: by mail-ed1-f41.google.com with SMTP id s11so13202841edd.5;
        Tue, 19 Jan 2021 00:37:01 -0800 (PST)
X-Received: by 2002:a05:6402:160f:: with SMTP id f15mr2517992edv.348.1611045419534;
 Tue, 19 Jan 2021 00:36:59 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
In-Reply-To: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
From: Krzysztof Kozlowski <krzk@kernel.org>
Date: Tue, 19 Jan 2021 09:36:47 +0100
X-Gmail-Original-Message-ID: <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
Message-ID: <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linus Walleij <linus.walleij@linaro.org>, liu.hailong6@zte.com.cn, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: krzk@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qFZfASgQ;       spf=pass
 (google.com: domain of krzk@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=krzk@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, 18 Jan 2021 at 17:31, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> Hello Arm maintainers,
>
> We are considering setting up an Arm 32-bit instance on syzbot for
> continuous testing using qemu emulation and I have several questions
> related to that.
>
> 1. Is there interest in this on your end?

Sure, the more, the better.

> What git tree/branch should
> be used for testing (contains latest development and is regularly
> updated with fixes)?

Depends on your testing capabilities, whether you can deal with every
sub-maintainer's tree. 0-day kernel robot tests everything possible
and this allows each submaintanier to early receive feedback about his
tree. It can be around 30 Git trees, though... If you want only few, I
would start with:
 - https://git.kernel.org/pub/scm/linux/kernel/git/soc/soc.git/
 - linux-next
 - and Russell's for-next
(http://git.armlinux.org.uk/cgit/linux-arm.git/log/?h=for-next)

> 2. I see KASAN has just become supported for Arm, which is very
> useful, but I can't boot a kernel with KASAN enabled. I am using
> v5.11-rc4 and this config without KASAN boots fine:
> https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt

Maybe try first with a kernel based on vexpress defconfig. Yours looks
closer to multi_v7 which enables a lot of stuff also as modules and
this by itself brought up few issues (mostly with order of probes).

You could also try other QEMU machine (I don't know many of them, some
time ago I was using exynos defconfig on smdkc210, but without KASAN).

> using the following qemu command line:
> qemu-system-arm \
>   -machine vexpress-a15 -cpu max -smp 2 -m 2G \
>   -device virtio-blk-device,drive=hd0 \
>   -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
>   -kernel arch/arm/boot/zImage \
>   -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \
>   -nographic \
>   -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
> virtio-net-device,netdev=net0 \
>   -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
> oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"
>
> However, when I enable KASAN and get this config:
> https://gist.githubusercontent.com/dvyukov/a7e3edd35cc39a1b69b11530c7d2e7ac/raw/7cbda88085d3ccd11227224a1c9964ccb8484d4e/gistfile1.txt
>
> kernel does not boot, qemu only prints the following output and then silence:
> pulseaudio: set_sink_input_volume() failed
> pulseaudio: Reason: Invalid argument
> pulseaudio: set_sink_input_mute() failed
> pulseaudio: Reason: Invalid argument
>
> What am I doing wrong?

No clue but I just tried KASAN on my ARMv7 Exynos5422 board (real
hardware) and it works (although kernel log appeared with a bigger
delay):

[    0.000000] Booting Linux on physical CPU 0x100
[    0.000000] Linux version
5.11.0-rc3-next-20210115-00001-g77140600eeec (kozik@kozik-lap)
(arm-linux-gnueabi-gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld
(GNU Binutils for Ubuntu) 2.34) #144 SMP PREEMPT Tue Jan 19 09:23:24
CET 2021
[    0.000000] CPU: ARMv7 Processor [410fc073] revision 3 (ARMv7), cr=10c5387d
...
[    0.000000] kasan: Truncating shadow for memory block at
0x40000000-0xbea00000 to lowmem region at 0x70000000
[    0.000000] kasan: Mapping kernel virtual memory block:
c0000000-f0000000 at shadow: b7000000-bd000000
[    0.000000] kasan: Mapping kernel virtual memory block:
bf000000-c0000000 at shadow: b6e00000-b7000000
[    0.000000] kasan: Kernel address sanitizer initialized

Best regards,
Krzysztof

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJKOXPejytZtHL8LeD-_5qq7iXz%2BVUwgvdPhnANMeQCJ59b3-Q%40mail.gmail.com.
