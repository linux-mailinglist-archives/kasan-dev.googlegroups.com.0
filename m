Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOM64DZAKGQETWRE6EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 20C3B1727FD
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:30 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id q123sf212968qkb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829369; cv=pass;
        d=google.com; s=arc-20160816;
        b=YNSgHYwbkwiAoBxHpgc0LK6uIr3fiFcwZ25GYboRWkAae5TDevy+6ao3kc0Z2IqMaX
         FvwMhf2AQQgTcAquxePcc7bnAlBTPrjWNEWJrf5GFWmaS7vJGybkfHv51NYtluD0oEVs
         oXozg7/0XC5KRr/LU0/x+CYYyXV2vvNxZVHQP+6ihBeiyqszrxI/vajjHrEbRCS1SpuM
         Lrh05d0PGoKg7CBUNQVe2YIGlKpEFtmZtIfsuzMPHhCeS3PkaC5htlEXz4/8zz8cCcc3
         9+uSjAm/mxE7lG3SbAw9DJfPzbzrPSYnL6A3n2sGrOj01ix4PCW82H1Rkb3zBWiVuGgF
         vrVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1P8Lu4yuNrZs3kpWH7B9c56kH6MpG/Ehv+V7gazbgbY=;
        b=P7x7miwwpUMqgykJ0UQLGTWj3JAHyb8Yfy7plzj7tN4Pe6nCwLib9qBOiQxq7kp4Qy
         rxeH2Cx01XRMHeqDC7Yqch0DthDgJ7fQsAx9ur78gMVZsAX6Puirsuj08ZWrz5fq6Tr2
         iytmViywfjps+GNeBHLqhNq3Y7fV5FvNlM/fz/ZMbNKALPvgzeAERmHvoXbKysBUvzSM
         e0SbZRvuT4tMLlvUj1OURoQ8Jx755Nyx7BHRuy7XbH3zBYNdZXbTBZ8Dd/AWB/az+9EE
         d0327vnFwjkY5PxixDnL5Oz81LE7+iASVRbXJhA4vEBwQu63kOCoxV7CAZTUZIbkm0wh
         dDlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=M2bJFwGR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1P8Lu4yuNrZs3kpWH7B9c56kH6MpG/Ehv+V7gazbgbY=;
        b=gVap2G9S5/ShbACSUAnpi200FDYMm28QsqZnRp9pkjP5KSsrvijk4vK2XtU2WGn5Lo
         MZqhUHlMKzs19PAdpuotwDPIohOTIoxT9tfNdvB1n+PZO9X+f4/qG3IL7I+Wsuc0oY4d
         HHGSi5Uyrp0ojmcjTHva0MOFN4E4lxOVwysI06ep+KAwxigqHLEU01vjBdS9aiS+uB1t
         Ru5eOfI5SbZOtJHibaNoRNYIBCsx9STtFZTWTMJMb18DsFccZZ7V+XMwk44FjLS3s1jd
         IUm8cVcIwwAhxyNG8n2mSOrOFrff3F2uiGYV3Sn0IM5DqxtZZxkRCFYcPcvb8GuNOqML
         dgcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1P8Lu4yuNrZs3kpWH7B9c56kH6MpG/Ehv+V7gazbgbY=;
        b=nzQktCMw3gIJtTA/03sf6NjJzgCWe/k5h0WJjihB6FrTH7X361tgNSJo2paP9vbB/9
         pG/3HM2WP1PsRRwhH7jHTA74629AQTcIM6YdC1wYwYPIG7/ifFPC6JFBSsCeI+9d9JBF
         QRr9G5PotjUzuuBVYCLbKvj+o09Osu5jYih/rDkL02lGI3AHEjAaZH+H+lKsgRJtb75p
         U/Wmuhm4u63hgkwNmLWv8wCx0w5ZalODsKpE25HGHRvuM9GwUjP0z2IOQhpHOixeasIx
         jlZEMbwUu9kLp3UNW0GqnzlLpPo6swLACKHtlmUfo5Ihp6DKSoxTbFv4IHZzRjqugL3J
         Ry8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWnO8FzcV67s7pMfbEHqj2zfFFHd6DhyBcBUx0lRVYFSalAzPWb
	71A8egqjc5zFC2q8uDDftpM=
X-Google-Smtp-Source: APXvYqwAuBX54FI2t9VODdaiwjzj3KbJbZ7pMwOuM+IEz+OGWXx2W1ALo/uM0R6D4ynngf60SEMmPg==
X-Received: by 2002:a37:7f03:: with SMTP id a3mr784363qkd.121.1582829369212;
        Thu, 27 Feb 2020 10:49:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2e1:: with SMTP id a1ls50014qko.11.gmail; Thu, 27
 Feb 2020 10:49:28 -0800 (PST)
X-Received: by 2002:a05:620a:2239:: with SMTP id n25mr748740qkh.147.1582829368868;
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829368; cv=none;
        d=google.com; s=arc-20160816;
        b=bV2NbAjqMvv4ALB7dArFpqF2RsS+HfXDezP0xFXVTF8AqcaXdD8Dx9q/FC+mlhnfkA
         4CnCaNwJqW8V5wKzA5IBP67D4ZLG4VxRtV78MZscF/9kKvw85eH6nQrGlNRsF3QkbOGK
         u/skVLCAQ3QheaOVMKy9PMSNx2FwokofMMjo6Mf6aTmlzkX8SC5Rwc1VY/RigL+jlwb9
         9eqUKo2m3Vp6YgBnvBHgiARSQXVRkO+azX+9pooCpT+lPfRt4WyokebLzHHB6ETGcwdS
         69mGEeFigFfD4MOLCoGjK8QYhODiOdnCjUw468u7Gyx5PeVB8yisjj8d8f+/j3ajT3Px
         VR0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=uio9MFsHXugpSMEN2c2VbCCKbgwswLA7MQ9KMJphrpM=;
        b=ltsERrPEoxhiVxMcjZLRIxj/cZBrNIhKro3+5c6ybUq7gBR6F2NM9ME9/GWB8w/DY2
         ZLLJ9TeVLotq8BJQMD+EShGe5mdIIdNrINTRgjwrz0uaozkojmKfYtsFcB/3eCUucSaR
         oAYtCw6ilNAEIFktDWucTdNpS51tKkCsk+sICZrr7Mijzwnhxc/6sXD9WzFBNxyYgvVg
         XUm/EtprwTsjEbZ5sSy+J6ArqSDurVySIGKmuVb+L9gCgdsxYO4AbXUc+bOwW1WHUyzh
         hdqHCuDmgYaJpNoLy/QFGRhWa9MgrZpfiY6iPJFVDWadoywklZyoxO7ztljCvkZy7lsr
         IEIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=M2bJFwGR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id w10si21247qtn.1.2020.02.27.10.49.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id 2so267733pfg.12
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:28 -0800 (PST)
X-Received: by 2002:a62:e414:: with SMTP id r20mr371760pfh.154.1582829368003;
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h3sm8314321pfr.15.2020.02.27.10.49.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:26 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v4 0/6] ubsan: Split out bounds checker
Date: Thu, 27 Feb 2020 10:49:15 -0800
Message-Id: <20200227184921.30215-1-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=M2bJFwGR;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

This splits out the bounds checker so it can be individually used. This
is enabled in Android and hopefully for syzbot. Includes LKDTM tests for
behavioral corner-cases (beyond just the bounds checker), and adjusts
ubsan and kasan slightly for correct panic handling.

-Kees

v4:
 - use hyphenated bug class names (andreyknvl)
 - add Acks
v3: https://lore.kernel.org/lkml/20200116012321.26254-1-keescook@chromium.org
v2: https://lore.kernel.org/lkml/20191121181519.28637-1-keescook@chromium.org
v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org


Kees Cook (6):
  ubsan: Add trap instrumentation option
  ubsan: Split "bounds" checker from other options
  lkdtm/bugs: Add arithmetic overflow and array bounds checks
  ubsan: Check panic_on_warn
  kasan: Unset panic_on_warn before calling panic()
  ubsan: Include bug type in report header

 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 lib/Kconfig.ubsan          | 49 +++++++++++++++++++++----
 lib/Makefile               |  2 +
 lib/ubsan.c                | 47 +++++++++++++-----------
 mm/kasan/report.c          | 10 ++++-
 scripts/Makefile.ubsan     | 16 ++++++--
 8 files changed, 172 insertions(+), 33 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-1-keescook%40chromium.org.
