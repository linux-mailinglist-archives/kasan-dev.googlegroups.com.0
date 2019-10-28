Return-Path: <kasan-dev+bncBAABBZFK3HWQKGQEMTUN2QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4636FE6AE0
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 03:41:42 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id g144sf4384530vkf.8
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Oct 2019 19:41:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572230501; cv=pass;
        d=google.com; s=arc-20160816;
        b=NoWu6U8byrXgjske7HPSSjOXNNZHBXfJFbd2eUNqNv8DilTVwEXMXo+QsRgeD1674k
         9WkB2e9JB6a+hLdDENH5o3Kt8BrFCd7QS9WPJZfM1sU6sSBOXBbQu1YfsXZX8+unEcmB
         K0RZDyLTPLazfvZ9xfcAL0vTng/a1Vwu9/JNow6k6RjILtcCp72t/vObhDBWwAo0ptiP
         OnyjtScdWfWWEvQDWIb1dk4CbVsNW8pBQHPbg7UVBm9xfeEAZusHKJlMWrAg1QXLtXEc
         aCQNfrjb0YSFiPZcsdEqdLYKXWyFUOtmvflR7H4lFBbWsPzk5x4KVDUFDLlEGPfbGxwo
         3A1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FuOIor2Q80m2omgjUIYHWXd7+naEJ0/wIGYj2EUHENA=;
        b=WS2Nq30ErsR7RlrbTDvs7w+Vc4cL4hUgs4K0E1rTABmRuYf3C8dQJDtaS1TbJ0hzip
         XSPmsx7uGmssWcXq2YGbqnF6VxW06l45YsqUeV43P2Io5HeiutEG4HS35MlsMwBmLaWc
         X1so0xo1jpvYpm+p+HpusGll8n6lDMBCQGJ3TU/ZIg5Y6joTE/pTwnPuo4jezoK4RxQd
         H80WrTCpUYePxW5HMLKEnWSmdn35tSmTu3GnEWqYwCcLvPotgZmLfxqME8XWt6z/X9Ad
         JBanB/10min/Isz3/asC5mDLwbFBwJjo37mvEsSsttyPx1kq7m0D5OHYXHOU2wc0Dlv+
         0w2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FuOIor2Q80m2omgjUIYHWXd7+naEJ0/wIGYj2EUHENA=;
        b=PBtMybeKpfiI5FAQ+FvQHuBfdj8QT1xqhAFLuoIQGAvTcaseTQ/ZjRhyBtOc3l7+7G
         Bg4iwFnwEEhbG82+Gs1qivzHuImqk3rTgx2fvzuBHZEe+W6TGIWGXOeCvtsD6i+1YvuT
         XioABHJYCBm9A7D+gsKhEKnDUzAXgdIxmCpSjb4zJoJaRaiCwtUKXv1HGpHqFN1UpMZJ
         zUDnTA7xiHaqhM0PyBZ+/6gpVJGWfa0jO8Eb15Fyi5C8+CbXvUwSM54gg5JOX2TtnMps
         4qsQt4Pvmkt7gE8nITm+XE/sBfWPIvgNxtPc4juyXo0pdgGW6o4X/gF/i5ky9hEFyiUK
         hapw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FuOIor2Q80m2omgjUIYHWXd7+naEJ0/wIGYj2EUHENA=;
        b=oiAZz4hXaWxatRIpjX5+8WOCHNWfqfjrFN5NlTaejNLlJ+QrB3qMIsyLLl1Yh3KCHA
         BD6Th8x2R84+EmhiofXgpH9Mo5gN21qt1SS6wBP0cf9LEY5/FPPXK7xreUXuWHVB9bem
         alRlAvqFmzv+EKx7ojE8qssH0qbTATnL3/hQr5SNASmoMeA8RordblBk0OX/+oUJisr1
         x7NXQv0kTzVUauNmgXTdzpG5LXZSDavZGW78OMi4NR2z9/lvq0te4ndO3xRmqRoPNlDt
         xrb4A83wKnDFfvJZGOQViXaZ/X0RSb0zeqpVp4UDFrrbMlH/RcKjjMY9Vd7bf9G79uCO
         dc7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUMl+BbQSsZQ8/8Lpn/xdNBwqwaVlz3UylV4yVpjAG8wwkHFZAX
	iEOjbTfy/85XDVjA4sW+EHc=
X-Google-Smtp-Source: APXvYqw9PF7IXmhfPvb9CogOzo2JTgtEFk6MFrr6n0LQ1Gix/esdkrJGtKr3u1npBzvqrkYwLGgOMQ==
X-Received: by 2002:ab0:2a8c:: with SMTP id h12mr4314104uar.91.1572230500975;
        Sun, 27 Oct 2019 19:41:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3e05:: with SMTP id o5ls783173uai.5.gmail; Sun, 27 Oct
 2019 19:41:40 -0700 (PDT)
X-Received: by 2002:ab0:4ea9:: with SMTP id l41mr7198328uah.76.1572230500634;
        Sun, 27 Oct 2019 19:41:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572230500; cv=none;
        d=google.com; s=arc-20160816;
        b=UOfOmVANZ7Y22JlFPgX9+uj6sXb7ctUcLl/6VNZFOiwXGhWsFm6kRRYEkWOArMpmAd
         0WC00EBjwes15ebRAT7jA62Xg6/TITXgQ0WvKg8ogd3DBV86+fYJL1sRG7TQr0q4pRGY
         yESFwqOb6i76R4ivGTFM56NKC3j+LdkXN8Jj+ApHfU9A3aGFuiJ/BpCs7BLdCxkTWPmG
         BSnc1RDRlPWysKQ+mU9LVYwJ/PeFLLlwPS453vJFNrfgW3XO4K2mtFIyDoRLDZHTNCBC
         l4ypPEtDPrwCus30jLkog7jLFVKRZ5nFj6SOqHYHomZMkXXe3zyznFYg0/4mv8yUUnZy
         rCTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=f2SFir8BqXs3ytqw9iPZ/wUEvsaN2FfJduhjtNkbqpk=;
        b=R01GO34VB5SRqA7wN3Rw2E7eZrclbzvb32AC7jlK1/SF4ajVOlPs5cRcwyS0we1hEB
         5rMlvEGZcRnjglqjTsWWG7gKkIe4gXCWtVDvhVsjG9q/R3qRmyoZ/dvzdmd80LSsrDEt
         aiSJ/O90gB2UUQH7Q4OjygAMurUkQ0neShASmsnza2d7n5ijvyNMD2V0pEhQ/NTvJuj0
         bj1Sq6i3cUgfQvaclZuXV0hCaGbaj7A/lOck8LaHjxVONt5Z1cjT9QJnWo6QdpJBKfp7
         I4c8cbRxLf2wNgO/ZB74HRLTbb9GC8gGpyo69l2rMmnT6O3IztOygpS4ifvi+c2Umx2C
         GPYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id v4si579832vka.3.2019.10.27.19.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Oct 2019 19:41:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9S2Ns1u087163;
	Mon, 28 Oct 2019 10:23:54 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Mon, 28 Oct 2019
 10:41:22 +0800
From: Nick Hu <nickhu@andestech.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <corbet@lwn.net>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <alankao@andestech.com>,
        <Anup.Patel@wdc.com>, <atish.patra@wdc.com>,
        <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
        <linux-kernel@vger.kernel.org>, <linux-riscv@lists.infradead.org>,
        <linux-mm@kvack.org>, <green.hu@gmail.com>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v4 0/3] KASAN support for RISC-V
Date: Mon, 28 Oct 2019 10:40:58 +0800
Message-ID: <20191028024101.26655-1-nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9S2Ns1u087163
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

KASAN is an important runtime memory debugging feature in linux kernel which can
detect use-after-free and out-of-bounds problems.

Changes in v2:
  - Remove the porting of memmove and exclude the check instead.
  - Fix some code noted by Christoph Hellwig

Changes in v3:
  - Update the KASAN documentation to mention that riscv is supported.

Changes in v4:
  - Correct the commit log
  - Fix the bug reported by Greentime Hu

Nick Hu (3):
  kasan: No KASAN's memmove check if archs don't have it.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191028024101.26655-1-nickhu%40andestech.com.
