Return-Path: <kasan-dev+bncBC72VC6I3MMBBLNGZCDAMGQEUXOXSRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id DB6163B0A8D
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 18:43:26 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id k13-20020a9f30cd0000b029025e3e26edb8sf6645753uab.9
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 09:43:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624380205; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWxaAtllU0vIsrWdkBfrhS5Gf4ghnUEm9RuIGHAqJ+ewjnL43faxieMSRGQ659OgSq
         gpgJrulPjxRlcye2hvwHNIjTViqAT53DH1EijSXNgh+O8NTeQyEc1lA6PTA/IET2XBmb
         aF3p+25xrVtqwuKn1D0lIL9x6t3l5hnzWB4H0v+ONARID55/Kn0ZFFVpvC8gg02g48/a
         gUo24HJp+mOD0aaB37grfJWwN+YHN8gOI6acV+I1PrjRYxTc6c1xqIb3BYn/IPxJd2Lf
         scEIpeMKayRfTZ19qn3GZVdTgLnuffEOBatlYfy9UOBOKZOyh/aMaefG4/TuRnQQJAhd
         tyEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=tKSizUTFDaKFdrRW3sE9sMhucZBC8GUHQ+kzG/wCjXU=;
        b=rPz4cC8QMF1/NRUicwkHwThvaxsap+MN93ib7t5vGBa2GUyFJWx8nThVMIVEc2SIY8
         hYNwTKYZbKeetu9i7btuuK1Ra778WytLDQbQjJa3F00vxdSKNBsAVAsYIDLalY5RKrdC
         hCPAp/+d6Vd2LYIxocLB7SlGO5PgMulIdOSPnJNUwI9Pn67UsNQDU0fASQslCPD55oXR
         2RTLDlmJWputmV6c/caZZQBYQjmW7VwBahtzBlvYPkYa+Q3J/iAsbWPfzW6i1IELe25g
         5dQEbZZE7BY46Ni9i301gTmnZPtCQKCw2tBBeJXnUgwzMM9yl94c1Fxg/YQJQ1mm5wGm
         3R8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Umxe35Uw;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tKSizUTFDaKFdrRW3sE9sMhucZBC8GUHQ+kzG/wCjXU=;
        b=cIxdPvV6df1+f8X1nIjsasaJTQO3o6PeTrmKWPG7bhOKXFn3IrlTssz0E2FI5CejPh
         IflTb8RfgYDcJYKQAMxJ7RWzJAmgNq2MUBg0PpvVMwKSxenq89nUeCBK0AEWv5MHEzqf
         /fusoF6z1pofLiWhrkHlz74uOjdK7qN1va2erJ1KDo7WYoz6JdLVSuicDyLBNtR5sLSS
         4dTC+Y4v5LyGls2PQKilFDy/fXn7/gmWhiE2/d+L99iNugUmRWyPa0sdJG2eVZEJLuJk
         2WjiQ7PemFg/bSXSqHZkpMXQHiA2HSVkuP0nYF7hWvQ/X2DXt159rSXKPQjTlE1HN+vv
         YfoQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tKSizUTFDaKFdrRW3sE9sMhucZBC8GUHQ+kzG/wCjXU=;
        b=Pq2U8HcefiN5iIcAC170uE3S7mC2X9gw4TR5SW9bmoqFYsbljOmE9hhKhsgWpUULpG
         CB3pQIb7Y6ZMhR3hWE+lukZg21ULfdnZQq/2PHXFt7Hj0CB3F4nFcHprLjCmVxBVvbqL
         uL3gKqweQTCNxxr2OJvmD664SEMQmPG6yawTZk+pVFozsR2JHm4Mbn7uBNZg7Ge8GRKz
         f93KLMV2f2KM64fWQMgoVbcXvljMyUy6LcqLlm+cMyQZi8sRDOt8sBi5H5WgLHnmze2X
         U9VjO+u7VdACUQKHMIEez2zl3gItRE+SONcLCAyHa3nl/ou/Np/2T87DMptL+vY1owSJ
         g+lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tKSizUTFDaKFdrRW3sE9sMhucZBC8GUHQ+kzG/wCjXU=;
        b=c9GZgUG9BEYYWOpwWB0wPfEvhZEo/qrZIUqHs1d7ftu6a2bfNSEGKRRP1/1FYTTkpM
         jJo5VQYV4WBGDxprAJTNwS/HME1N1R2SebkJoeyZ4jvrHkC73twjEbkP86vQ1cdEvWNK
         bnAQvfgSjg4ivynHWVF5o5stNDetHdSksLUX/+/5NNQjOFzLs/5q/csjHbydeqlP4HdL
         EK4VyMbbj6a/1ng7+9WWfjnS7UPlp9xERYUQ+hFcZh9OFDUR7LYUxt8NsSnXV3Z6DASO
         dYIjTukmOoLbHfVrej4cqMKwjEyyL8b6i1/R6jRG9LOrOwin6vtXR+s/gmdfG+bXko+z
         8H6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/QRnWx0S+F64u49glyb+Dc/3F9BYcQiozSvW0y717hdrkbT91
	83Vww0lOj1g0hCIPBX0Todk=
X-Google-Smtp-Source: ABdhPJzBeK82OujdJUjJJbheJIAFVjnobxmpYuo3qM3Bj/o/z8fJC2J3O7M7aQ2XneYxIyIgTCpEUQ==
X-Received: by 2002:a9f:31b1:: with SMTP id v46mr4780984uad.22.1624380205670;
        Tue, 22 Jun 2021 09:43:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2fc3:: with SMTP id v186ls1342970vsv.10.gmail; Tue, 22
 Jun 2021 09:43:25 -0700 (PDT)
X-Received: by 2002:a67:ad07:: with SMTP id t7mr23712667vsl.22.1624380205242;
        Tue, 22 Jun 2021 09:43:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624380205; cv=none;
        d=google.com; s=arc-20160816;
        b=rIQb+QTG8OYbIhsR7u10CtLAaiVbKhdWY/C6/lNGfmojs2fn2nJQmUy90EDLfVdfEm
         TJDBo5VJZ7Nfq0MFebIrA8M89sdrqpG/Mfy+gMADizeMEmC1F1f0Gz5Z2iyGCOlpctrk
         3JMoo7Ra4M2t7yM9T+90bz119q9hPQIHtCrN7kxj5dfFLdQ9m2PiwWy1S87ibTm+uybo
         iEE8ktPg8h5Ugq/4P3ZuesWOc2NqMa7Gs7gTA5401vrJXsPkTZffXRTgFYKlkeoewck/
         tx7ACNIPhKU5l9lG6k90yx2iHCjnfVyxiilZxXZnk0OXUTxYWz9EcGJHY90JFnUReMoe
         P5FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=vxFrkh6PfJNY2iqd2AHDe5xeAdZHifSt7a5NfrAQdks=;
        b=RgzGaqFWBLYyMd+PVfgawPNRVs6EWqii7VAZhxhLwusjsTQcIUylRFgLmfOYMKrSGZ
         WvgkSq3AFgz5I172XXNujksbfbGYPQ4RtZ4C3jWD6mG5xMulZqojLI4lGyNiUn1wLc3A
         h8M0V7YuMuXfZEWWo1d80ALMZRPZtbwtB84p9yz1DNZ6dCDrHvClKle4mbUJI63bd1nO
         UbFGHLGP78pzFm5O+jbFGybIiq5XQ7Beye8IYqaNEld2lCEJEE5n/IpNXXUjus5lGw2k
         527/cV8RaU9JfTWDx4fjuxJrzCgzCVi4kkTvhNz++e4vOTqQA8R2pTarEAmUHo3UdkUV
         LK/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Umxe35Uw;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe29.google.com (mail-vs1-xe29.google.com. [2607:f8b0:4864:20::e29])
        by gmr-mx.google.com with ESMTPS id g20si237709vso.1.2021.06.22.09.43.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 09:43:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) client-ip=2607:f8b0:4864:20::e29;
Received: by mail-vs1-xe29.google.com with SMTP id z15so11597072vsn.13
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 09:43:25 -0700 (PDT)
X-Received: by 2002:a05:6102:ed6:: with SMTP id m22mr10980416vst.60.1624380204705;
 Tue, 22 Jun 2021 09:43:24 -0700 (PDT)
MIME-Version: 1.0
From: jim.cromie@gmail.com
Date: Tue, 22 Jun 2021 10:42:58 -0600
Message-ID: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
Subject: KCSAN BUG report on p9_client_cb / p9_client_rpc
To: kasan-dev@googlegroups.com, v9fs-developer@lists.sourceforge.net
Cc: LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jim.cromie@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Umxe35Uw;       spf=pass
 (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29
 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

I got this on rc7 + my hacks ( not near p9 )
ISTM someone here will know what it means.
If theres anything else i can do to help,
(configs, drop my patches and retry)
 please let me know



[   14.904783] ==================================================================
[   14.905848] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
[   14.906769]
[   14.907040] write to 0xffff888005eb0360 of 4 bytes by interrupt on cpu 0:
[   14.907989]  p9_client_cb+0x1a/0x100
[   14.908485]  req_done+0xd3/0x130
[   14.908931]  vring_interrupt+0xac/0x130
[   14.909460]  __handle_irq_event_percpu+0x64/0x260
[   14.910095]  handle_irq_event+0x93/0x120
[   14.910637]  handle_edge_irq+0x123/0x400
[   14.911156]  __common_interrupt+0x3e/0xa0
[   14.911723]  common_interrupt+0x7e/0xa0
[   14.912270]  asm_common_interrupt+0x1e/0x40
[   14.912816]  native_safe_halt+0xe/0x10
[   14.913350]  default_idle+0xa/0x10
[   14.913801]  default_idle_call+0x38/0xc0
[   14.914361]  do_idle+0x1e7/0x270
[   14.914840]  cpu_startup_entry+0x19/0x20
[   14.915436]  rest_init+0xd0/0xd2
[   14.915878]  arch_call_rest_init+0xa/0x11
[   14.916428]  start_kernel+0xacb/0xadd
[   14.916927]  secondary_startup_64_no_verify+0xc2/0xcb
[   14.917613]
[   14.917819] read to 0xffff888005eb0360 of 4 bytes by task 261 on cpu 1:
[   14.918764]  p9_client_rpc+0x1cf/0x860
[   14.919340]  p9_client_walk+0xcf/0x350
[   14.919857]  v9fs_file_open+0x16c/0x340
[   14.920411]  do_dentry_open+0x298/0x6a0
[   14.920980]  vfs_open+0x58/0x60
[   14.921475]  path_openat+0x1130/0x1860
[   14.922126]  do_filp_open+0x116/0x1f0
[   14.922731]  do_sys_openat2+0x91/0x190
[   14.923267]  __x64_sys_openat+0x9b/0xd0
[   14.923790]  do_syscall_64+0x42/0x80
[   14.924295]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   14.924955]
[   14.925159] Reported by Kernel Concurrency Sanitizer on:
[   14.925899] CPU: 1 PID: 261 Comm: ip Not tainted
5.13.0-rc7-dd7i-00036-gb82eaba47adf-dirty #121
[   14.927094] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014
[   14.928292] ==================================================================
virtme-init: console is ttyS0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P%3DTrGDVXE2ktQ%40mail.gmail.com.
