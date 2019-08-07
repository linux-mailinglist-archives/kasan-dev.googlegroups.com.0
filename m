Return-Path: <kasan-dev+bncBAABBFPXVHVAKGQEN5G72DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id A7E768458B
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 09:19:50 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id p193sf38743221vkd.7
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 00:19:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565162389; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lz41q4iAygMbMmlf3fve6fYwVnuQLRLeZHnbbW39HQ+20Hd1SWF9LDEgAWH9FxXazN
         +osor799bUd4FO+DOar5jwMEWbGSOuf6jK9yh5vFnkZcvvQiKnOsMQoi0T+VWQSZ78So
         ertYGHTt9VnnxRJd2iyiu1/UOXEDl7kFgxJOD78PFJSXi2HifhZUSbkj+dNidE0rSCqJ
         O1iK7kH5QH6bv4gFnEzPow7yuXmwyc1wEfOs9Kgw5mXBobD5FHmkfKrKWcktcn2aTrRT
         LkyKNsDgdPm9PvTZfN0RUnK5THb0Kb2Hdw+PfMDaeWSC27y4U/GdxV6Zm+kP0XHaONgQ
         2T4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+M4eHTK8qe52DZAsIx4AW5sZKzyg46zSA5KfGqn4ocs=;
        b=m4g0ETiXs6aT5EVnV5Yyo4E8/s895irMhamZULF6bekWPVjuLq1xCjxchYInDp7Fzm
         T4YMOqgrlE5fiM/TGFgwxn7gcjMr+YkUl3TKdDvoZiDtX7c3K/fnS3lfVFTiwxtKRiq3
         oP4I3s6Wir9pzo1lkAczmrU6/TJ6ILRxTrIMHe6D6qSCBkkJ9SQY2PP68FOcC1qvyuan
         EwSA/RL6o1LygkM3VSY1SL613YMnJRLTKUjge5FxovIkzwG8cqjn40EKWB/5avx3OpVO
         XF6ULakKOapmmSHnZu1VtrenenZjGvRQSKAVcVrOg94qa63mwkrZlaRp+F3LtEgJOUZr
         j1jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+M4eHTK8qe52DZAsIx4AW5sZKzyg46zSA5KfGqn4ocs=;
        b=szuPDnrEt9wxqxJVMRv8EL176Y0EkxeXtOR9Z4UiMMHxX4OLTkL6hXu6VIo5+VznFp
         JRgwOleM03UM1OKDSVKmypTrGtU1oLevxwtLcgZsBTvFHMWZpo0z8ai6KEdrmpilovpL
         htJV4QdoLy0qSO7Wr2EuRgLfuxb3NE8YozDKsYwcdOlirBLa7EAPKCBtQ5oDfNtALe+J
         uJTqvauLIAjcTy1PoAcq+4NTgxRPJbqVN89HKR+kdV0Lsl6Z1onn0gO/jNhtIY5bJoV1
         G6JHwQ/ZS1xexkcUFPl87P5yQV3m1D8a6UqpceJMJWElBh5T3gsVWXHoOcFsLshRxX0u
         jGpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+M4eHTK8qe52DZAsIx4AW5sZKzyg46zSA5KfGqn4ocs=;
        b=SIITA3HLEr5XedHiZI1VAeyNOBu5ubYMiXaRucxOsosfsYhNMGZ0uQ3xVGv1rd6kvC
         4cTZ/xyqBY4HH0ClzDZedOu9XpDIPfM2O9lL/RmnPecwbGRxiQe522ZsYfTkX7uv58j1
         T5NjvyIS9jIl4LcyU+adknUx5T3h8jK4jujFtnlSPIC2dl5/XnZaTj5Hs9oJInNAnpHc
         RdaDxpIHUCs1SWqvYLma0xe4B8WvAUBaES5aMfHKylo4m70NFzLPC0YZsMocdi5wDza0
         yfaqWxXoJEOHsRT+7hmFdwT4OD5vlQjRtb/LRZR+bVQaql/lVLub79LcZo0gAkvogxp+
         1xZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXtcFE9ob04KyZ2ch1jjhdT3pLyFNI8QKiIpDI8B2+vC/24Puk0
	oYfByW0ErSqCRzg7iCQzjww=
X-Google-Smtp-Source: APXvYqyJfSBRXS3hI7/VvbkaSGjPf5xJWUoRz2jdvunu1y0xRIUwC+u2MUKqlbkr3Ibj5//kWeFCWg==
X-Received: by 2002:a67:7d13:: with SMTP id y19mr4921472vsc.232.1565162389332;
        Wed, 07 Aug 2019 00:19:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7a41:: with SMTP id v62ls11320255vsc.6.gmail; Wed, 07
 Aug 2019 00:19:49 -0700 (PDT)
X-Received: by 2002:a67:f495:: with SMTP id o21mr4934493vsn.54.1565162389183;
        Wed, 07 Aug 2019 00:19:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565162389; cv=none;
        d=google.com; s=arc-20160816;
        b=nWbySFvniEH3MJLhsJ/KPol5AcdARmnl90qz/BJM8INsFxcZaZQkUvGcu8vImK15z/
         Mzoczawf5G1Qq+9aqMrHwp99ca5kmjtLoZIyXPDTn4I9Sh/5YBEtI3mqRiy80qm6/sae
         H7N7Y7dxWmqYeKfghsWXB6wPe+odIF2JDGto4UO5F5B9wHQ6Ui2aC/CdZhcaNwEA5icj
         gy2i231oGXqZLnq6JYBY9vp3dTscqjigoA7gL7RYo4x0SE7QYO7wNEpCQdXXZCBvsJYI
         qx+1nZ320zO3O9tuLFn5I/1ojxWxUU6QXIXnxahM3X4ARJx/elSHFFZHechQLkwV50hM
         SQow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=uW05hAgVYpGgQ1X271yyEo47Mr7cileauVQyzV1GAyU=;
        b=Yiv2WWPkecZheooscKr/2J4RwfHeWudG3tSYFVuGMtoNttyPYXbzObfzdpaVkjjHKx
         9JHMQWxrGH0s8aMJbPIP6a+4b6siHxEHxV1h19Mq9UpMthogHWjRH80SoGFT/NhwGYhN
         pCX9PdaUgKKhNnPQPWBpUYRNKnqVc5HuHHrQt8I0rg4Pmqcb0D/yVL+qh2AtYkEZeDhy
         xSBNGWUP7/tyHEaJokT8wA3ggUgYVJ3HAP9WiiTcfnWjAibOS6Y4bmMF7CEsWv/iyobN
         UcU933uvr1xdiT+JpRWtmDpnC+WiDxQQgsWSzqxjOxGeulYtj6Z0/+58FXLloUMkI+14
         fGag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id e126si4782811vkg.5.2019.08.07.00.19.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 00:19:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7778Nlw027022;
	Wed, 7 Aug 2019 15:08:23 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 7 Aug 2019
 15:19:21 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <green.hu@gmail.com>, <deanbo422@gmail.com>,
        <tglx@linutronix.de>, <linux-riscv@lists.infradead.org>,
        <linux-kernel@vger.kernel.org>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <Anup.Patel@wdc.com>,
        <gregkh@linuxfoundation.org>, <alexios.zavras@intel.com>,
        <atish.patra@wdc.com>, <zong@andestech.com>,
        <kasan-dev@googlegroups.com>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH 0/2] KASAN support for RISC-V
Date: Wed, 7 Aug 2019 15:19:13 +0800
Message-ID: <cover.1565161957.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7778Nlw027022
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

KASAN is an important runtime memory debugging feature
in linux kernel which can detect use-after-free and out-of-
bounds problems.

There are two patches in this letter:
1. Porting the memmove string operation.
2. Porting the feature KASAN.

Nick Hu (2):
  riscv: Add memmove string operation.
  riscv: Add KASAN support

 arch/riscv/Kconfig                  |    2 +
 arch/riscv/include/asm/kasan.h      |   26 +++++++++
 arch/riscv/include/asm/pgtable-64.h |    5 ++
 arch/riscv/include/asm/string.h     |   10 ++++
 arch/riscv/kernel/head.S            |    3 +
 arch/riscv/kernel/riscv_ksyms.c     |    4 ++
 arch/riscv/kernel/setup.c           |    9 +++
 arch/riscv/kernel/vmlinux.lds.S     |    1 +
 arch/riscv/lib/Makefile             |    1 +
 arch/riscv/lib/memcpy.S             |    5 +-
 arch/riscv/lib/memmove.S            |   64 ++++++++++++++++++++++
 arch/riscv/lib/memset.S             |    5 +-
 arch/riscv/mm/Makefile              |    6 ++
 arch/riscv/mm/kasan_init.c          |  102 +++++++++++++++++++++++++++++++++++
 14 files changed, 239 insertions(+), 4 deletions(-)
 create mode 100644 arch/riscv/include/asm/kasan.h
 create mode 100644 arch/riscv/lib/memmove.S
 create mode 100644 arch/riscv/mm/kasan_init.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1565161957.git.nickhu%40andestech.com.
