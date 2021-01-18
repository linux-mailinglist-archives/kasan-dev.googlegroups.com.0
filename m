Return-Path: <kasan-dev+bncBCMIZB7QWENRB5HPS2AAMGQEXG7J3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 46AA72FA641
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 17:31:50 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id l8sf191765pjf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 08:31:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610987509; cv=pass;
        d=google.com; s=arc-20160816;
        b=SkDqZkM89ydb8P6nGu/qfwdGFdkExT9f4/UQfRl9hJZGzRjRpc+46hrycdzHIUwz33
         Y5kzCmdLkXf7li+zCPyYLmdNKz4dBvajGz2ku8j5s6JNeLHIeabvoKO9tDiipXBt31Nd
         8idE/o1ilCktre0zX/maW5NgW3CEgj0wtF1D4IkHc6NSFoFWMoUxGlcGwz5LX2unshwR
         JYSbI/kf5xKQSfq9+D3CzvEfNGPJU5aG839o8hcuN2Ytm5i3VhN4bXu22hID7fqWdHgS
         v/wlb1gYsIdPN/A6UtAZ7ebZsVcqDJqAMz54JbFjYBOpVt6rNdkaDkX00ZgjIGDF/sy6
         WBLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:mime-version:dkim-signature;
        bh=TITc462fDo6bT0HwjkjBrPec0KnCXjQFpnjw86CXva4=;
        b=GiHjYGIIhaaZ05z+cjdd7cm3DghfKBsGF05YSdIOb7vImwuModoTZgrPCWVxSUdsdH
         oi+eZeSxBblQN6HaoEayzZgnn/lkspJePxx4qaHzsrdAA104WNIK4v5dV2colyM0Oml2
         fdlhrrk6yKxVBJwu/4y7slxCX65j6+tkcQ18AFYia1lqF4hgTCdC+/Z+3Rc30MouJkXZ
         9ocs/QsrFbDLy8tO6WlqG3SYYSi9upjatvdPeQ3uxnB2XrPJA3CUx7OEVdqanFeI/BIr
         bjXsAtV2aP5R5/D3ZMW2jQD/ZdYSobICxVMLOpnYqII6qOfCmzuP2X+2FGgF1X2GIyz4
         ty8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VMADvLQX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TITc462fDo6bT0HwjkjBrPec0KnCXjQFpnjw86CXva4=;
        b=CSV76Dk1teq/0U+VjCdEjvkhxzD81tdA82THDYDFU5yvR4WXaLPIMBe7HmJSos7yxS
         Q1vImSkyBnwnfeBrprjTy2Lbbo+9QWx4seLZWOB6hytrkpVKfPazpgZXUWpIc4LloThO
         nMews/mtsl9a0bDP4J2Azc+IrBq6XmR5nDEwk7i3Wg4WS48XEKJo9SfnWgNXZArR1W40
         +isTJTzTTf2Faqzb4XpAayPRwsr1V7oYh6yJFOD8HA0JqhUk6W8p5BxmkB7YmV3jM913
         Hzz7dRoRXAV1tBNQfiF9GKJXCGEtxAx38koGqyuDzeJg9s4oLoxuYuZwViGxp03lSKxi
         2arQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TITc462fDo6bT0HwjkjBrPec0KnCXjQFpnjw86CXva4=;
        b=T0YiNmhtv6kch1A1CjmjYEBDY7ulNXCe4qkdYsd6NBusJNtIsQBc1elYp4ZTc+k91X
         VDbFe5HPOnXqOmwK+Q0OHPHohZVHXidBDf6sBQNO5wp2jfy6hag8BqbmfJN+kiFsUv+Z
         3zSZcRaHlWr5DGLCLRLAu3bEobdUiGD+oZrylhGa/ylclbTf6PHutWJipBeZasy8srKq
         QcERNOODKebR27JfRfmJOFb5pjm0cotE9hjmoyBVJjMK69zA7ng/r1y7CH9EqqRfLwS1
         /RZas0mGS71ko2mz6T/J8/SLBMNyu2JU3Muhw2VWryeznRSZgybamY4gsnfx2x4zXPTI
         RIAQ==
X-Gm-Message-State: AOAM532rPfUn258EPFMADspfDT2r9/F91hmzUlqiqc7ZhypGSwnINtMo
	byR4UJkKxULY/NoF8GFNd0o=
X-Google-Smtp-Source: ABdhPJw9TFBPZX6QJeDZstYQBLfK2t243GANnj3Fx8diQKFesN770J7WtKAkuC0f9CFTHmHlsRjWdA==
X-Received: by 2002:a17:90a:bd13:: with SMTP id y19mr121415pjr.24.1610987509006;
        Mon, 18 Jan 2021 08:31:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5290:: with SMTP id w16ls817490pjh.2.canary-gmail;
 Mon, 18 Jan 2021 08:31:48 -0800 (PST)
X-Received: by 2002:a17:90b:602:: with SMTP id gb2mr91782pjb.170.1610987508499;
        Mon, 18 Jan 2021 08:31:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610987508; cv=none;
        d=google.com; s=arc-20160816;
        b=P/Lc8zJGPACJ9+OW/04BKRRs2PxSCDN9M1J3ZTqWHwir6qdupdB0+hr1uJPCEj/mE8
         D/LuHDo1cjouCAt/ajzLYvrd6tH7M2tQ1KX5qW/maXXVUCTtQLWPae3UKXtZZa+DAa3H
         i3GRnVwcjUv+rNV9ssRJZGOhvTVOWFDKfsWnZV+GTmmtxZhpTqRmkjav+o03ux+QGluG
         CuO6r+khbjVkgUIp6SCJOADk10KlbCU9Hj7eYMqgicYHmXPw/hDvjIMqlRtVMNmk3B+I
         izZTMEEoi6E7pANvU5PFBC+83gWvnLXMLjxEYuy5/y46FhaStXlk/KDv4BXRQ7id0VeF
         D5Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Vc5iUj8Lf7LlRmVi9npWH3SZikYvU8sokovMVtv3diU=;
        b=SamfZfWmyBtzTjfflaXH0Ty1GvvGrZgHUp+o3n8vnOROpwCQg8hTu0qXuirr5BLldk
         88XjVl5cM8Fpa3uUmYmjmcd0AN5Igs6jD+Q7K17x0fgJnAiAlgSXhNmDwWm85VCTJHHK
         3QsEmWnBr7vz/6SHTNojt2hWzhSHqVje5U8zx4idktJho9EufT65JuF/8xatI2uKEzMN
         szzQimWE8EYBsr1boQEfm7Syq9lI4dCC9tLLB59vatAiBF927L8Jsreuyjz5GBAB7KCG
         85isSW6YYhp3MJHDqGl3WQd6xK6uuDgz6+HcMdkadKAKB4ydeSfCwTVlZs+FPEiGul1z
         oCwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VMADvLQX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id r142si1204150pfr.0.2021.01.18.08.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 08:31:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id v3so9352953qtw.4
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 08:31:48 -0800 (PST)
X-Received: by 2002:aed:2f06:: with SMTP id l6mr440749qtd.66.1610987507380;
 Mon, 18 Jan 2021 08:31:47 -0800 (PST)
MIME-Version: 1.0
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Jan 2021 17:31:36 +0100
Message-ID: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
Subject: Arm + KASAN + syzbot
To: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linus Walleij <linus.walleij@linaro.org>, liu.hailong6@zte.com.cn, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	syzkaller <syzkaller@googlegroups.com>, Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VMADvLQX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833
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

Hello Arm maintainers,

We are considering setting up an Arm 32-bit instance on syzbot for
continuous testing using qemu emulation and I have several questions
related to that.

1. Is there interest in this on your end? What git tree/branch should
be used for testing (contains latest development and is regularly
updated with fixes)?

2. I see KASAN has just become supported for Arm, which is very
useful, but I can't boot a kernel with KASAN enabled. I am using
v5.11-rc4 and this config without KASAN boots fine:
https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt
using the following qemu command line:
qemu-system-arm \
  -machine vexpress-a15 -cpu max -smp 2 -m 2G \
  -device virtio-blk-device,drive=hd0 \
  -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
  -kernel arch/arm/boot/zImage \
  -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \
  -nographic \
  -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
virtio-net-device,netdev=net0 \
  -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"

However, when I enable KASAN and get this config:
https://gist.githubusercontent.com/dvyukov/a7e3edd35cc39a1b69b11530c7d2e7ac/raw/7cbda88085d3ccd11227224a1c9964ccb8484d4e/gistfile1.txt

kernel does not boot, qemu only prints the following output and then silence:
pulseaudio: set_sink_input_volume() failed
pulseaudio: Reason: Invalid argument
pulseaudio: set_sink_input_mute() failed
pulseaudio: Reason: Invalid argument

What am I doing wrong?

3. CONFIG_KCOV does not seem to fully work.
It seems to work except for when the kernel crashes, and that's the
most interesting scenario for us. When the kernel crashes for other
reasons, crash handlers re-crashe in KCOV making all crashes
unactionable and indistinguishable.
Here are some samples (search for __sanitizer_cov_trace):
https://gist.githubusercontent.com/dvyukov/c8a7ff1c00a5223c5143fd90073f5bc4/raw/c0f4ac7fd7faad7253843584fed8620ac6006338/gistfile1.txt
Perhaps some additional Makefiles in arch/arm need KCOV_INSTRUMENT :=
n to fix this.
And LKDTM can be used for testing:
https://www.kernel.org/doc/html/latest/fault-injection/provoke-crashes.html

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g%40mail.gmail.com.
