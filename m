Return-Path: <kasan-dev+bncBDV37XP3XYDRBFO5TKAAMGQEAC5DMHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 31D832FB519
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:04:07 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id 137sf12864895pfw.4
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:04:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611050645; cv=pass;
        d=google.com; s=arc-20160816;
        b=mffkhbtAwqbc95iQrTtBL6rp2bT1G5I7U9wgwHFV2IdBQed49KyCECbMf7FPOB70e/
         eLMRHY94ywuJVeEXnMoqnxyHF4qrL++HBIQKxQuxcPhti0AE82kcLMY0O4gyDC2s+NJP
         04MjSwk4Y/M+nu1ymW1PqssbAIhnVGIDcpzKqifYxK+CyDYbD17e8nI8Yj0De2IK39nF
         iRO04UD2Il13t29TbdPEaCulOStvagIdP86onRLMDzW2+VXPQYLR+BZsPMu2CBaCGwRk
         /GvrYzBMp6h0Tr8RwgiBsqqwmWCA44x+JhMT6+aA6vuAlKtNQSfDHXFYzxKg0CsOByLR
         0MoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hKSvT3bGt/8tp6+DnL14Q3SgZ8ag9jhPg7pGZ8BTAtU=;
        b=Md2i0I+wJbvJGO3hAV48O5AQqL71qtsZNSbOyzAknpevaWbZ9+W++afQu4MImnJxyf
         JaHsK/As1viAyQxCUHeEqr6pXvEnYIqaWWmHFiieNyfZZp1hUZ/KMCJ0f5bclAvYjKxt
         T5pFjo3qtGVuB6X1AihKxc3iPHGH9Fi0AI9UsZ1UP8AnCMcUrJaB9F1MzkbTkUM06TBc
         X93/SE1pTTw5n2nj+Y+Eownw/JhcvDhe7/2MyLSiGWh7ZVUPhGQPeO8bJ1lK5lO2ziEt
         3ZEEH69cG5WDFWUGqlciRf3r5O5hhOJd97PdYm+lWpCn4KJSl12VHvvyxhd6ju3oe02P
         5xGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hKSvT3bGt/8tp6+DnL14Q3SgZ8ag9jhPg7pGZ8BTAtU=;
        b=K6IF1muTXTxNr0jxKk0TYP29dD1KWWx07P1VwsmOLoLzRnRwc+d4XPRK1D4oOp4P8o
         0H+fa1M0k2lVpWqqXjyKD+eN39gewMm0Eus7qLYSk/nSgFNQA8+1aIyMkb5i39Fr65x7
         ccDd8P9/FEpaH5C81zCfHwO/OcG9Ic2gt1lWCn9y/gXEmxvWGf079Mh1AleSSfOfjLfV
         PAN3LbXmxRP5JQ4asrcTHnHQ2f6BucF8DabYI/MPWr+FxxIokfBhwQhjsrFL1neHm5qP
         0ej3JMd3bfLms6ZF4EpXnQ5ebFj5y3Ea6nWMJtUHel3yIQO1Et6kGejCC6aEUDcEoms3
         hlFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hKSvT3bGt/8tp6+DnL14Q3SgZ8ag9jhPg7pGZ8BTAtU=;
        b=dsFr+uJTPq9T2z/0cKaiI87huPwDcWVuql7RMPvBGkVzUZOkLhvL+qVmk43Rky7Bk/
         X7Cq3jJ3MoSuo2RI2jQcPcZdMPAwyt82pVkgMMldNvyTyXETnwTt1hgG59uGGpaKKJnK
         BQzrogzoelsSS7n2kbFPwVrNBqXQbH+rlmlgw+mFBp2J9t0ROilJpV5qjt5WA63AXUwq
         /o/IFiCJJj0Nnq5M/g6Lzh/AQ4btH9eFF/swIgQ7zkKGjbK3kDCrsy8H+jLcB2dWer+I
         2YkLRdX8OOuyVRMRNep5HBaGneFIjaa6V31mwM7Ud4MSURTyR5f4cdfmdGmM0C7pQOFC
         wWZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Zwo2KNV2D/LPjDv8VtS86lttvsfbPuqnHy9n2g4RIfXq+ym9U
	3UwfqM/pWIfT+d71+GZmkl8=
X-Google-Smtp-Source: ABdhPJypd9Cduf6ls+zgVrY+GBaI19emxLYAZxcCuztKmwg+OahnKuNBgForgY4N7UqEKlsyo5tkAQ==
X-Received: by 2002:a17:90a:5509:: with SMTP id b9mr4538187pji.230.1611050645516;
        Tue, 19 Jan 2021 02:04:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5312:: with SMTP id h18ls2480184pgb.9.gmail; Tue, 19 Jan
 2021 02:04:05 -0800 (PST)
X-Received: by 2002:a62:87c9:0:b029:1a5:9d56:7e24 with SMTP id i192-20020a6287c90000b02901a59d567e24mr3313904pfe.56.1611050644938;
        Tue, 19 Jan 2021 02:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611050644; cv=none;
        d=google.com; s=arc-20160816;
        b=nQfMaFY660IDnvVW2JzKs/weU0ruu8Goe2EakaZqTHnFmAgpYasAW2Vq1tAie/E2Q2
         ihADRn3YmvtiSCmrlojQUAH9ZL9sgdlO/GwMcdZqggL2TsSzvHhu+9Howqd29m3KVy54
         tn2wUPANcc/IJuK0H9TPUFRh7mlSJSIWiL5sBlep/7uvBUzFI+bBR5lndNjVJ7hYSlR7
         /kao45iDitUw++f9CdDfhocpM2tUl7eIngjaMx6QXZBxyARDHc+MmEAI8z9b1/krQc93
         3U0A8i90tIR8P8JR+3mdAkLkYYE6zAHBKidpHe5dex1QMbyiWJuWxIA9bIMQHziCjRd7
         +GFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=6cSYoRtH87hXzWSOTjyIaYKbj6E3G3aqBSK2w82VGCA=;
        b=RjjnydiXWqgeJankPd6GivNut/WjNMpw2FCHyDUXBhaoYZhvDLxRlEXWMH12wTfFD/
         +W4c6uvsIPFq/2ows9HmKU8s2glf08Jc7FspHX14G5y/z2mX42MIYUZvrcdt0NFPNWLt
         3hQh0df+KwPedXn6CjlE8esv22Cy5vCCb1KX5yPPsVV1wsAyfTcAgNHebGIG4yBZq3/m
         6iF5dbt1W7LF9/mykrbzBbQCV5BaBE8YO27xIn0Am3wlrk+GMUaVQZy/qBkjtPK1exUC
         9nzKU1qNuGsL4bV8VNU/co3sNMbp1joChyUD5JoMCnKIhDYKWSQykf8OhaF2JbzhO3BF
         fCpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q15si1663004pfs.1.2021.01.19.02.04.04;
        Tue, 19 Jan 2021 02:04:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0E0301FB;
	Tue, 19 Jan 2021 02:04:04 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.250])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D814E3F66E;
	Tue, 19 Jan 2021 02:04:01 -0800 (PST)
Date: Tue, 19 Jan 2021 10:03:55 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linus Walleij <linus.walleij@linaro.org>, liu.hailong6@zte.com.cn,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzkaller <syzkaller@googlegroups.com>,
	Krzysztof Kozlowski <krzk@kernel.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119100355.GA21435@C02TD0UTHF1T.local>
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 18, 2021 at 05:31:36PM +0100, 'Dmitry Vyukov' via syzkaller wrote:
> 2. I see KASAN has just become supported for Arm, which is very
> useful, but I can't boot a kernel with KASAN enabled. I am using
> v5.11-rc4 and this config without KASAN boots fine:
> https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt
> using the following qemu command line:
> qemu-system-arm \
>   -machine vexpress-a15 -cpu max -smp 2 -m 2G \

It might be best to use `-machine virt` here instead; that way QEMU
won't need to emulate any of the real vexpress HW, and the kernel won't
need to waste any time poking it.

IIUC with that, you also wouldn't need to provide a DTB explicitly as
QEMU will generate one...

>   -device virtio-blk-device,drive=hd0 \
>   -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
>   -kernel arch/arm/boot/zImage \
>   -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \

... so this line could go, too.

>   -nographic \
>   -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
> virtio-net-device,netdev=net0 \
>   -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
> oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"

[...]

> 3. CONFIG_KCOV does not seem to fully work.
> It seems to work except for when the kernel crashes, and that's the
> most interesting scenario for us. When the kernel crashes for other
> reasons, crash handlers re-crashe in KCOV making all crashes
> unactionable and indistinguishable.
> Here are some samples (search for __sanitizer_cov_trace):
> https://gist.githubusercontent.com/dvyukov/c8a7ff1c00a5223c5143fd90073f5bc4/raw/c0f4ac7fd7faad7253843584fed8620ac6006338/gistfile1.txt

Most of those are all small offsets from 0, which suggests an offset is
being added to a NULL pointer somewhere, which I suspect means
task_struct::kcov_area is NULL. We could hack-in a check for that, and
see if that's the case (though I can't see how from a quick scan of the
kcov code).

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119100355.GA21435%40C02TD0UTHF1T.local.
