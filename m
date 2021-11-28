Return-Path: <kasan-dev+bncBDRZHGH43YJRBKNBROGQMGQEPXUQHKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FAF446029E
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Nov 2021 01:43:22 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id k9-20020a056e02156900b002a1acf9a52dsf9154992ilu.15
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Nov 2021 16:43:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638060201; cv=pass;
        d=google.com; s=arc-20160816;
        b=bppLETj2zSqHQEq8mpHoZhNzItrTqYkqGm2yp9BsEUTbSGlZJXhQabirX5TRtt6cmU
         8k1iLxTJeJBIfthquH7udCbfVqhW1K+7nc0M/VP1GPAEHFHsqkHq7sNDhLyQ9sJ2wlCj
         pGRrV1MYxy1Qw08DE4gr8ccYCb6pQFvEq0vandpMvesKNogPTw6T+1QLHCs5lVmEGL2c
         VkqPMWb1/WBrTi0Cpe4Mjw6CD0h8vnGeLGoVxBVUmrJmaYFV7ZpymcarIe/85MC3yxGM
         /uLPWZDpYlwWKHa7XgssFXN1AcEsKr3iOgjbJHaigJJHHyYnVa5IWmFlj5bCzZBsutWE
         +WQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=qmMOEArvFURGN+LnPciUgUDkbAcDusEVGSdwtIwdRko=;
        b=DYu4xHYs89Ig4jOCTvV6WdwTDAca3BoehZTxJimu75S4QHR0df21c3EAL3CpVRCAtR
         1fgor0UdblJL/V9Lvrw0o5UvnfAmeIyB3/tYaonTAbTJcfRqIJXH//5sfJf/z1VqR4VO
         LHWJeW1o9l/tGw/1qPUOwY+K8pwmErwcYuyynxSiFzR9Pk3Vf89xmKTva2gNUFu+tfjG
         jqRim9hhMuX2MiSgDPipfYCGsrSTCiFugjmdx3dxHrq/DuBvy59CFpwdjQKvdatmO6fO
         I+NNuMESXbCjDjohxwYLaCVdFj6WaQeOQ0TH4rD7HUhoioBcbZOku70blNW9w/+npK6q
         Jzyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oiJkbRrQ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qmMOEArvFURGN+LnPciUgUDkbAcDusEVGSdwtIwdRko=;
        b=cma9esAhZbUOk2JAhMZuXpZXXuemvL8NE62J6RLVOSzl+hglgRaXxX+GlMKd1Yqwmr
         KDUF3r+FQcq9ADE+B7WCDHYpSnbjlt5vMmY2LfvGVlPf/XuXluIaACIvQ43JmQ83Tmfn
         a/IyWpOF+eF19bv0/23DbvNrog5WvaS9yPjTbtuA0Hzz42mZ1+5STK0rWHjWDm3hU9Hj
         BZc9S6XAEwN+ILgiyEQSZH33wvNPgItKz5tdVhPaPGkVQLE5VofXOnEYCEQRFJNSmpC5
         3GO67ttPLCqK1MKJCRhhSsEyS/WGQaCUELHD6092K4K76KuL5Dg91NmLnaWcXdGd/4KR
         D2yg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qmMOEArvFURGN+LnPciUgUDkbAcDusEVGSdwtIwdRko=;
        b=ejTl/6rTAMW++CBHMgONCDPMbrw04fHi5706RJQQSicLDKdfiZbXP8XkTsyLsn88UP
         ffNy95Eh+JxixAqc4McRUHLoFerJRIkEdGcTaP+HdiF70qeZY2DVkETAemq7Xe+qSxPk
         UUAV0yfvZQxab7mDxGNsAdRbqlHyntZJScgtl8LUWCv9tLTYnQXNHticOGhRXGx92uix
         z8YaMWQQY0FbS+b+zNGz4fPv2lFV8xPVVukwjBiwdGENK6anZ0a0V8ufzvcqoifl2Nck
         WvfnUU+FbXX5j1yHocfJycbw2WPLSYd080UxEH5gPnpyieAoKV8SA47Zv87PsEhEzx9t
         VCng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qmMOEArvFURGN+LnPciUgUDkbAcDusEVGSdwtIwdRko=;
        b=ouhIVhjZSi43L9lXHAprdLrxFI8JBmrDClF9Ar6WevzGMWCI0Kqj63pm0eK4zxFBmv
         XQsJiBtmGVFG6oB9gzF1skOQ0b8ik+2kfhxBqLdtLKHQEe+U4dTBCj5D99oI3pn5+VjG
         5f6wMqsEB1YkHVH0hFRP6v2x7wpz3bd/SCttVqxOzP5U2xTLdABez+TYBAaC+7Xc/ct0
         p53Gg2udXGA1GsrgxHSN3QShLW6uFyY6luCvtjbfN9HWDepWluuKrMinTBoCXepC+vyv
         JjOqKjo4q0c/ZFTW8pOGSEv4Yy/SsHWK4IOSpmepueFLdj5Z6dAefTtkAiE99EoY1VsQ
         3Gcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ptHK5CHQtgFX7sfBwcZS6ORolv5kBufir9e6xncUWbxAGReWU
	lLDtKC9U3fAYK0OaKjepVT0=
X-Google-Smtp-Source: ABdhPJz6iR1gJS+/F9at/LRoZvue2cDx4dPhT8IcbgcXmK+hSp10KTiIiSM6DWUJkgcnRCPf18kfVg==
X-Received: by 2002:a05:6e02:1c85:: with SMTP id w5mr15682300ill.288.1638060201524;
        Sat, 27 Nov 2021 16:43:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1492:: with SMTP id a18ls1008648iow.5.gmail; Sat,
 27 Nov 2021 16:43:20 -0800 (PST)
X-Received: by 2002:a05:6602:1581:: with SMTP id e1mr48555570iow.64.1638060200530;
        Sat, 27 Nov 2021 16:43:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638060200; cv=none;
        d=google.com; s=arc-20160816;
        b=DRVXYVl5LLv9WRF5NSzza9ipKrsUkS2/ozlu82Y9NDYUP5+dIbEhNCO00bADb/61Cj
         MBmFo5okNPwTaCyeSSDV59HPGbyQnUW1bh2ekt09HRPpEpsbj0t9uty93GmlJzSF70GS
         ZBxgY6cIEYE6PLyi1BhblZRwXsiZT4hTeKAMT2hbhM4C7I4LTdUaZa1ZLvAIhxaMh9Yf
         DUZRGz9ZYuXCUB/xy188KB9njYCSX05vAn3icXXnLX0CIrgBZT8wEBnKTlfyuJY1T4bu
         A7G2/BlITbEGhnOlcdyXCQg3ymCxDJSDv3KERSJFvJB00UI0xcBvYXgy57jK1d+Glqke
         cn1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=1SEnnhSDtFX7zCcC2R4UoBpLdS3gZaSbU/hF2We3+T4=;
        b=vTnNIyemxofhHF3wy0QWWj6A+xC1FpzMByj6BiM5Z8/5aYIWLhfS1X+s8BDo4apRTO
         nhfuHkkJ1GvhmoA29/WOHArQo50czSZ7vvufPIFAgGwUoVLxxLZqo2i3m49zUCPxb2wa
         6r8T/uc2o5BsP93tVxHQvlwVSj7iOmcgD9ykJrKVjjEVs5PE6tMKeXCyhFnkKyCz1pW7
         kgkPl0kjKRzfR6P6WWciOsJq2dsKGdVgZnkDQVdDsyg6ZU4MUqV9Fb4jrs3LQPiTSVvE
         kom7pLRtmJ6fESOPjfKjqxarlZ4+0zeTw7w1HmjyzpmuYy3ewulSnGibV4p4QRjJv3Gn
         +/rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oiJkbRrQ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id l7si47338ilh.5.2021.11.27.16.43.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 27 Nov 2021 16:43:20 -0800 (PST)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id 15so3913197ilq.2
        for <kasan-dev@googlegroups.com>; Sat, 27 Nov 2021 16:43:20 -0800 (PST)
X-Received: by 2002:a92:da0f:: with SMTP id z15mr44768055ilm.151.1638060200327;
 Sat, 27 Nov 2021 16:43:20 -0800 (PST)
MIME-Version: 1.0
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sun, 28 Nov 2021 01:43:09 +0100
Message-ID: <CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A@mail.gmail.com>
Subject: KASAN Arm: global-out-of-bounds in load_module
To: kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-kernel <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oiJkbRrQ;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi KASAN / Arm folks,

I noticed in our CI that inserting and removing a module, and then
inserting it again, e.g.:

    insmod bcm2835_thermal.ko
    rmmod bcm2835_thermal.ko
    insmod bcm2835_thermal.ko

deterministically triggers the report below in v5.16-rc2. I also tried
it on v5.12 to see if it was a recent thing, but same story.

I could find this other report from May, which may be related:
https://lore.kernel.org/lkml/20210510202653.gjvqsxacw3hcxfvr@pengutronix.de/

Cheers,
Miguel

BUG: KASAN: global-out-of-bounds in load_module+0x1b98/0x33b0
Write of size 16384 at addr bf000000 by task busybox/17

CPU: 0 PID: 17 Comm: busybox Not tainted 5.15.0 #7
Hardware name: Generic DT based system
[<c010f968>] (unwind_backtrace) from [<c010c6f8>] (show_stack+0x10/0x14)
[<c010c6f8>] (show_stack) from [<c0210734>]
(print_address_description+0x58/0x384)
[<c0210734>] (print_address_description) from [<c0210cc8>]
(kasan_report+0x168/0x1fc)
[<c0210cc8>] (kasan_report) from [<c0211230>] (kasan_check_range+0x260/0x2a8)
[<c0211230>] (kasan_check_range) from [<c0211c68>] (memset+0x20/0x44)
[<c0211c68>] (memset) from [<c019d21c>] (load_module+0x1b98/0x33b0)
[<c019d21c>] (load_module) from [<c0199f88>] (sys_init_module+0x198/0x1ac)
[<c0199f88>] (sys_init_module) from [<c0100060>] (ret_fast_syscall+0x0/0x48)
Exception stack(0xc113ffa8 to 0xc113fff0)
ffa0:                   00000000 00002a98 00098038 00002a98 00081483 00093f88
ffc0: 00000000 00002a98 00000000 00000080 00000001 b66ffef0 00081483 000815c7
ffe0: b66ffbd8 b66ffbc8 000207f5 00011cc2


Memory state around the buggy address:
 bf001200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 bf001280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>bf001300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f9 f9
                                                     ^
 bf001380: 00 00 07 f9 f9 f9 f9 f9 00 00 00 00 00 00 00 00
 bf001400: 00 00 f9 f9 f9 f9 f9 f9 00 00 04 f9 f9 f9 f9 f9

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A%40mail.gmail.com.
