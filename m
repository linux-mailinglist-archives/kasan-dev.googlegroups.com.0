Return-Path: <kasan-dev+bncBAABBTGR6DWAKGQE5MRVIRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 00D1DCF276
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 08:12:30 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id a144sf14498125ywe.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 23:12:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570515148; cv=pass;
        d=google.com; s=arc-20160816;
        b=TjCw9ybi01rlxxScYWHzPkna/HlskFLG8HMLnsl1x7324CbbRFEpjLxYCh1tBPUgAL
         26EGQo3kYv67mEc/bNt54b94NB5nHhvCkV+pkhC78HxJhTFvdyjk6MkZPzpgzapIk8Gm
         uf/FTnfpi5BvU6PWdqjJHaJl7vV97bU930U5rXGF9fB+w9v+UQ/eFbAOrPk3kfpFqk89
         RrC4AnN2/bCVEO8lmRDRhLQ2MrysOiV04IooMgE3JuQKxmyuAT2Uo6SstBgzzl7KOxiz
         LYxarX4pIMP15jDxOJg3ExmOZc1jarBkPOmUD7GqEsdz1lZr5paMV1NJ0R7He50xAyGq
         bINw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BVfSd+9OQuVy5MBk33t89qs+su6wn8SFXvTcK6r/XLs=;
        b=Pxq/+EC3q94UsGBuHGY70tQLU660UxcIeIkGWxzn8E0h4BznQGANEuPJBudHDibFJK
         3qx/nhzuydQDE7Gd2UCgDZq9CPW9/d6VpS+vq5mZrXzpomGn/sUPq27yKi0vIakRJMJt
         Gin6FDaVOOCJxVET1KQqWRSef9GXfH9CkMRv15Dfg0TerOxEH25ewOTpYY+5YXfokBn8
         hyBthJqjF6UT3zjOfsU6io16fShio3fox9ggQeVM0WtPARcezMinoAyrrr1kmJgQUk8F
         jdcnW2/TzOvjmFJWjW5RmTCi4LsA+kiurbgLxQZEW7h1gAvXGcu0DFsMeX9kiU9PVH/Q
         xTBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BVfSd+9OQuVy5MBk33t89qs+su6wn8SFXvTcK6r/XLs=;
        b=f3v4+WTn+aDjYnjdofElsLawcz0aVNqHuqZEWHxR7/P7r/TnDE5uRaYk1OBgIkx9fO
         Yzf9P2/kclMbroCwokXsrzrOw2Bkymu4VzqLSwd3uZq44vzdsO0oHzIVQSCWmRcXCy/W
         jcPtuvA7IFlt3bYLSsZFXKdwhHpYZILh5ywqD4PSaJd2nGgUjUHpP9clmzaAC1Mnm71n
         bIR49SbMZTnE55T9TtenfxJ7Ew9I2t6T1BtFe8nwTaZOkcrzjuamrndbSYuYbX3VnQHN
         Xf9jdqtbcjg55LL0KI4p6TrFJ7Ma+V8qmMGFwyStXQyOdoBiuJjGDQXe/Rrot7T/Pgo3
         4cgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BVfSd+9OQuVy5MBk33t89qs+su6wn8SFXvTcK6r/XLs=;
        b=Jzsh2WPacLJOV6Ls5MtXe+rUGCrzRN6eeH4k84ox4zJiH0XuNND0LhriQ9nCV1Q6NF
         kGZyC+WaztuZJ/fRpY35ghPF8euuS1H06qvMLcJgp+YlPO0QUz+EsjScuvHUlweUtzYH
         zSAntfCmfZC7M0CyeWvu1WxuKj0+/3UKWAcr/44KCHrA4CY9A5HyYox6FrPbHQCbRpNX
         1sNm0ksYqW/62Qqy18iN0PZhb9fBDnD+f6/20bFjgdylbxCajU9JCW1BPzTNlBso3jlV
         BWTObEofCzKW+xcGXk1fiz3AUJ0DP3rdbB7OHtZ3pZpxSZtkB8xeR0z9Lyn4m7cKWFa5
         RqXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUXGw75r20uU5l9XJoqu/eeICA7taAjL2cN5BGWDxeuNUUxImx0
	Ze+IwV89VrI6UY/ZrAdf4q4=
X-Google-Smtp-Source: APXvYqygx6+l3j9PFUWeLwFFX/THPxasYHDxZgCaNNxQISSfY5Yl/V60t9CWxCexlmBRkVSE+U/x4w==
X-Received: by 2002:a25:e4c7:: with SMTP id b190mr12634528ybh.310.1570515148608;
        Mon, 07 Oct 2019 23:12:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:30d2:: with SMTP id w201ls397312yww.14.gmail; Mon, 07
 Oct 2019 23:12:28 -0700 (PDT)
X-Received: by 2002:a81:55cf:: with SMTP id j198mr24255060ywb.128.1570515148100;
        Mon, 07 Oct 2019 23:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570515148; cv=none;
        d=google.com; s=arc-20160816;
        b=eD10FrPPiKdSOFoxizAhHmCgwvPOcH/CjgItiqDdgaM7Z18btw2bewlQI/nkWKcvCo
         WhfLq0CggsuH4Kiiwzgx/PLGwkapjtyWRx+jEFcmEvP2dt41wvho/gKQHSiOyn/1hOz/
         W8X8/XZ1a+m+DENU2opr7ecLAiefv3k/0yZBEsEYILkgJZhQFHM7vEA2Q/GEvabq75Xx
         d4Qs1rzy01PqJpAAI40cXRkr3H63JbPskVmb1eIlVfx5nHdxP/AwcsiXdBtbqm9FqzSP
         h4NCrv0q1gM7+RanPdms/toxmyTTiUcHDeN/1AFkOUM24rqt9+9DThC7VAdHz1UIvr2l
         Fz3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=fiOz620LpNFZf765tEIIdVO483qEUotF+Iy2UM5EmkA=;
        b=RkHhk0TheJG7agEav94a5zUT0QVqK+qT4/38nn5PopRowVEKerZJmZ/+3uYg2zqPdD
         ShNfp/cF98kp32GVi6ekkV1p1E/0lXUeJOOMUP3gFXHR7ACDz0aHzdnnR1SLFS6po3IF
         70484iXQc4pfM8TDVStjR7A1BZv07QlLhulj2y9SZJWDlZognEZwqbiKjuhHrXZvhi3N
         f/yx5DF8wSnOntE2E8Jg/Z9AkaxdHGTZaBN1QTW/f1BqI3F8qCEUsZkouYsfxsRoBCO8
         xV5urY18vyjdAo1poOrcfkpCiWE7JxJ2Z7TSLj0O+uH0Aa+k6RsnrfNBYNITSQElFkWb
         JOBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id t73si1420195ybi.4.2019.10.07.23.12.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 23:12:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x985u7EV075289;
	Tue, 8 Oct 2019 13:56:07 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Tue, 8 Oct 2019
 14:11:59 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
        <alexios.zavras@intel.com>, <allison@lohutok.net>,
        <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-doc@vger.kernel.org>,
        <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v3 0/3] KASAN support for RISC-V
Date: Tue, 8 Oct 2019 14:11:50 +0800
Message-ID: <cover.1570514544.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x985u7EV075289
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

KASAN is an important runtime memory debugging feature in linux kernel
which can detect use-after-free and out-of-bounds problems.

Changes in v2:
  - Remove the porting of memmove and exclude the check instead.
  - Fix some code noted by Christoph Hellwig

Changes in v3:
  - Update the KASAN documentation to mention that riscv is supported.

Nick Hu (3):
  kasan: Archs don't check memmove if not support it.
  riscv: Add KASAN support
  kasan: Add riscv to KASAN documentation.

 Documentation/dev-tools/kasan.rst   |   4 +-
 arch/riscv/Kconfig                  |   1 +
 arch/riscv/include/asm/kasan.h      |  27 ++++++++
 arch/riscv/include/asm/pgtable-64.h |   5 ++
 arch/riscv/include/asm/string.h     |   9 +++
 arch/riscv/kernel/head.S            |   3 +
 arch/riscv/kernel/riscv_ksyms.c     |   2 +
 arch/riscv/kernel/setup.c           |   5 ++
 arch/riscv/kernel/vmlinux.lds.S     |   1 +
 arch/riscv/lib/memcpy.S             |   5 +-
 arch/riscv/lib/memset.S             |   5 +-
 arch/riscv/mm/Makefile              |   6 ++
 arch/riscv/mm/kasan_init.c          | 104 ++++++++++++++++++++++++++++
 mm/kasan/common.c                   |   2 +
 14 files changed, 173 insertions(+), 6 deletions(-)
 create mode 100644 arch/riscv/include/asm/kasan.h
 create mode 100644 arch/riscv/mm/kasan_init.c

-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1570514544.git.nickhu%40andestech.com.
