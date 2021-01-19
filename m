Return-Path: <kasan-dev+bncBCMIZB7QWENRBRXLTKAAMGQE4VQRBNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id A84292FB561
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:34:47 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id b62sf15205626ybg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:34:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611052486; cv=pass;
        d=google.com; s=arc-20160816;
        b=snPv8CjOlmCfs6cg4oSVIP+nCUMlfvgoBfC2KVHo/ZHnfQ9xyEDT9Ru7yT+OICHgsg
         v7RTA2p7ZlXCRA8m/VqYoLF4ujCaU1jTbawhY5Yx3ve+wJzlcBjWh8bDWqSMPl1s0SUc
         ftw1Y9F+ZpLV402dDs6cwCJ+mqGEsDyYa5Qwu2AhWQm/hexx5EW8QC6OorNvc+GAD1aq
         iW+CXK2mbfuFIoHCPBgOv0HUsK/yWfS5Mia9xmmPpQmWSPk+1A0YGIJGMs6SRM+DER8D
         PNja6dwfI1ZqzewKK26v6+bIItWmf+F4S2cbZtE0SuGOvnIeSS2Bl5duEGk/xZB5r+bA
         OpZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i/Hm/CydBNpwTUTqEhPSR0QFxjgTEIbnaDayHacMOZU=;
        b=bRnE5m+ZfwNoCS0Jeeb7lYFDXMSKnj/x7GnLN3a72+s2otcChZcto5BYkNGkDPKZZd
         tYWyWsn05iAumlLAiEQsZj0l5RGaNymdSfcXOD7a8tqxEtiGYoV7S4hAAM0UExy+NQF3
         aKaH8hULwMKznLAA0rWBjsEFL9uvLI3DfhFURXMhvw7yuhLtyQ8pY1N0ZNOyA7COhRRK
         ekoAz1+VxVGY+gswNrc6zcCUm3nZ/orEGAsYJcU6Z3QkkSe6sPvGO+y7bfCQElSS0UZW
         GQYKldTNhJSM9GGgnrsqnyToPWOsGc4f2Jru83a6MzoClgLM5MaBEgLnqVX+qojdqFxM
         5JMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BXidqSOo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i/Hm/CydBNpwTUTqEhPSR0QFxjgTEIbnaDayHacMOZU=;
        b=WeDK96vU3zxwltmhuNaf171LLjxk2d+mmK2pnx0fvbPNTruig/j0N35WtO4DQMD5hA
         vt0WcjGm9mvfnMnmUC3Psh6kDg1e65oQW5BhoJrd7AEiUBr+rYXPHTMIa70yjr01Qtsh
         cMCOiDEPOf1578bsfs1a1cKzrv4sNkA6WdyEY6xJcdGzSDlGaHreCtlBRbRSHZxidRbi
         cLMDeN2akZdd34yfmHRZexpcHO/U+M5OXSKd+zGbVm01SmVxmhIZqI3Pj/k/+LEFeONP
         bifNy2of+Xwnt3jECd6VNvvYGNn4QMJoQA89eWTgQVKBqxyhwNLqDqIsHzU8e7M5KRw+
         Ddgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i/Hm/CydBNpwTUTqEhPSR0QFxjgTEIbnaDayHacMOZU=;
        b=a9J0qKuelowA/+B4vXK2dla4o/ggqxCp6t1A7r+XcEnpvG9cy3D2PXBbTYnPRBZjFP
         u2B7pTNInZ9Sk6JqJWMF3qovfdiDw6pmv83lgiIkAePLaQD5RZTSgwPmmrdFdeCMOQBy
         6RRGkGEud91p19kmcv6nQYZE5xXrCGhPIGoXk4o0ZeOvXp1cGSmeZXZzqpUTDbWGSZTx
         Oz7Gj82yqWGGw0BszPlBaGqwnJiVJUPbMCEmDNzKpN2LU+oZ/vW1SjgzvSZxoUnnUkfo
         be905K85SKLmmgqAw5bOoY0c5I1WTnGHkbIkrEPKWutwGhgWFiEu06hzdJM+56QZT+6Y
         +z1w==
X-Gm-Message-State: AOAM532aDHHqjpClg4/fAZNuHz8L0XyJ/Gbwh7qmq2chg82yXWJDkQ/q
	dcDSdlU97Gqg2JaKkptGEfQ=
X-Google-Smtp-Source: ABdhPJxT4f3GRArRNthoESuzWS/uXQpaygXU8mS9qzkg9FZjG6/xV4bPpxIGnKw4rXgbrfnM9L5t5w==
X-Received: by 2002:a05:6902:210:: with SMTP id j16mr5025877ybs.122.1611052486509;
        Tue, 19 Jan 2021 02:34:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8188:: with SMTP id p8ls4015790ybk.6.gmail; Tue, 19 Jan
 2021 02:34:46 -0800 (PST)
X-Received: by 2002:a25:2407:: with SMTP id k7mr5241325ybk.282.1611052486088;
        Tue, 19 Jan 2021 02:34:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611052486; cv=none;
        d=google.com; s=arc-20160816;
        b=vLTrJrUivd3r3CkBRGjGvqqf6G5xwWfIrGfTHppoI9YscpkR/ScIIiuWk2dGLeXGS7
         XblPFn9gRydZoNw46vmS3af+Iblgc+wYkDMvZuoYnF+YOHBJzhhTHhvy6qV8QIGWMTfF
         zCwo2hn2NpAHjRTKfR8CTRWO77XnQs9YXxBlVhpyn03O3DOXfFQj60RxMWX5b9MPOt5m
         7PHv1tamQc9qNXKYQcDdT5g+gRhU8WGQVE+w89mL3PMCLFDeQRMOtXQaheOzfjjkrWbv
         tz/sSgfEphwMZN9EKTaxYpIoqjXhTzpWCNfAFHALAxyxwMppRaGGbK2siGdNlROoqpvj
         jhcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h3iQBw02U3HK4o1t6TxZRf77V1pC/EfgMTHkB2XUWaY=;
        b=CGp3lp1bm9w1NkXjI+tF1UT3kEbmmjhPF7uO7LfDZL/QE013ayIJZINkgQmLgNMjWJ
         wA1BFbWkJm0bQO2E/zJKmLo8Q65hB0rWUMGCFYaH8VkN/ZjhRz3xwlXNPLwxJ6pJ+KYl
         dS2n+f0q7mMzmYUBznx209739Fj1C+P8UJlOJ0lSsluj1Oce1sH1Hx807xzIp5wjk11N
         YDAlcBGOKgv4ZVNVIlL36NP9I2a9i1RBa/qLMR1UThYj70RMuCwR2f5Cq6EpX+6o/MiK
         Z9w+Ebik28vrcZZH8YkAHPRq54bjA30E2ify8sUlJIvpGdaIYvNjSijV33msfLMpw8kp
         JiEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BXidqSOo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id x13si168698ybk.3.2021.01.19.02.34.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:34:46 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id j18so8870993qvu.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:34:46 -0800 (PST)
X-Received: by 2002:a0c:99c8:: with SMTP id y8mr3423970qve.35.1611052485553;
 Tue, 19 Jan 2021 02:34:45 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <20210119100355.GA21435@C02TD0UTHF1T.local>
In-Reply-To: <20210119100355.GA21435@C02TD0UTHF1T.local>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 11:34:33 +0100
Message-ID: <CACT4Y+aPPz-gf2VyZ6cXLeeajLyrWQi66xyr2aA8ZCS1ZruTSg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Mark Rutland <mark.rutland@arm.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linus Walleij <linus.walleij@linaro.org>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	syzkaller <syzkaller@googlegroups.com>, Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BXidqSOo;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Jan 19, 2021 at 11:04 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Dmitry,
>
> On Mon, Jan 18, 2021 at 05:31:36PM +0100, 'Dmitry Vyukov' via syzkaller wrote:
> > 2. I see KASAN has just become supported for Arm, which is very
> > useful, but I can't boot a kernel with KASAN enabled. I am using
> > v5.11-rc4 and this config without KASAN boots fine:
> > https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt
> > using the following qemu command line:
> > qemu-system-arm \
> >   -machine vexpress-a15 -cpu max -smp 2 -m 2G \
>
> It might be best to use `-machine virt` here instead; that way QEMU
> won't need to emulate any of the real vexpress HW, and the kernel won't
> need to waste any time poking it.

Hi Mark,

The whole point of setting up an Arm instance is getting as much
coverage we can't get on x86_64 instances as possible. The instance
will use qemu emulation (extremely slow) and limited capacity.
I see some drivers and associated hardware support as one of the main
such areas. That's why I tried to use vexpress-a15. And it boots
without KASAN, so presumably it can be used in general.


> IIUC with that, you also wouldn't need to provide a DTB explicitly as
> QEMU will generate one...
>
> >   -device virtio-blk-device,drive=hd0 \
> >   -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
> >   -kernel arch/arm/boot/zImage \
> >   -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \
>
> ... so this line could go, too.
>
> >   -nographic \
> >   -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
> > virtio-net-device,netdev=net0 \
> >   -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
> > oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"
>
> [...]
>
> > 3. CONFIG_KCOV does not seem to fully work.
> > It seems to work except for when the kernel crashes, and that's the
> > most interesting scenario for us. When the kernel crashes for other
> > reasons, crash handlers re-crashe in KCOV making all crashes
> > unactionable and indistinguishable.
> > Here are some samples (search for __sanitizer_cov_trace):
> > https://gist.githubusercontent.com/dvyukov/c8a7ff1c00a5223c5143fd90073f5bc4/raw/c0f4ac7fd7faad7253843584fed8620ac6006338/gistfile1.txt
>
> Most of those are all small offsets from 0, which suggests an offset is
> being added to a NULL pointer somewhere, which I suspect means
> task_struct::kcov_area is NULL. We could hack-in a check for that, and
> see if that's the case (though I can't see how from a quick scan of the
> kcov code).

My first guess would be is that current itself if NULL. Accesses to
current->kcov* are well tested on other arches, including using KCOV
in interrupts, etc.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaPPz-gf2VyZ6cXLeeajLyrWQi66xyr2aA8ZCS1ZruTSg%40mail.gmail.com.
