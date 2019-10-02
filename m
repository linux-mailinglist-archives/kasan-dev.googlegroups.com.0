Return-Path: <kasan-dev+bncBAABBQ4B2HWAKGQEI4W2DII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 09683C4798
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 08:16:37 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id c24sf11969379pfi.8
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 23:16:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569996995; cv=pass;
        d=google.com; s=arc-20160816;
        b=DKqw0VOP43fZN/YutX4rMvoo0AVGoyvMKvw6RazatKuaFN+Juv37FuGMx6+rCsNyYt
         6kKnPSCWHDAdp4cmg+0urvJL/os9tOlHynf5RrmuJ1U69Gwa2zsUzVMl/K2k/Zww3rSm
         iFEHIIC5aytaVx69TLX8BI6bADigxvYznwy8jUAnGfgo6PAUfIU7MS12eK7L8Ug0hBC9
         bWWXQnaijrOURmvG/45Z4NQ6uUFnGuMAEBJAiiKjVuRnDAvPT4+udneCZ1uts1+auRuK
         mLoyxquASv88cop0Zu53ENRxHh5pyoNsDuy8hOlURgliO1GmnsFRB6jqsjDAKedQ5JEV
         GU8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Ph54M3Klk4xfKAlh6OiBZBzXMHUoRkI1Mc8Wm7JKTZY=;
        b=k1SYjwXenb7VBKZEyK1ybuQ7ZfgUiM3mevM8zvgu3XOZLYoc7OPnWdUee59C4vnvlN
         tj5jCO3eRk66l+YZAYHa3qIyA4bsKozFguJd/DEjcZRVjHXeMpNczURUK61W4Z8BpRVC
         w6lKK8NqQsHmrYpQMCTnUQsYBthIBmu6fTRa4lOT0JY9cFLKyKhE7HJj/IcY22OLBmH1
         rtHfDFkykAo8OCgLIqybuk/8Jsa4RD2c9XMPljRCiFmqWPR0o8a36GMV93Y0YwWfsyKE
         jJ/i32vWu95wd1Z99i0av3u+uGLz73kTUsO82Cwy14GDMeEO5ICWkz75RpjiK38W3row
         3OyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ph54M3Klk4xfKAlh6OiBZBzXMHUoRkI1Mc8Wm7JKTZY=;
        b=B+ZDyJI0BbD8PZjkuXBojYubm2enV7CSP8xcMvFa4O7OU46/WapeDAAyKm8EgMk9bN
         j+XVRQCa5rmezOKqUDGYu3tOUPRr2J3+WfQhcD6rbIDf49pRJiKkV533s9I3Qn6fkajN
         zQlwnLW8hofkQZMw4nHDbPUqeIfbVmn9i7DRWEyV/BZLFppmI5BQbyKqqTgP7Ol5ZBmX
         SuAfuKZFZElqjE2dykzu4ZxExLHPkrvb2rmtjuz+Fr28pWWT6zMjrgVxNYS1xsdqlFyO
         K40x3W1BdDI7nBfZmLcc6GD61hOSB9WVceSPNZsTRmsIK1Bk4T+dksETH23gg2XxKkxG
         AxXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ph54M3Klk4xfKAlh6OiBZBzXMHUoRkI1Mc8Wm7JKTZY=;
        b=OsAtg8+/h1sAJJnzT3Z+7tiRcGskB/SWg3gSj7S+yB3IamGE5FUXzdU18B1ezXn4Xi
         Wf8/mJPsoJWuFafJpi0LFtnrUhvZteEAbBA2IjpNfPrxvnzmuGsoV4/ISBeYpFh2hlpV
         GXbOpIwDQuciVC85IdhBUroCleXOo9BB1/2n4Xbcpa3kfm4jNtks3KpanYeIdSzunLe6
         VG5JYfhsu940elk2iSTEKbOitW6iQ9WLK5nAj6bJvqA4fnztCqxKBmQZf+evBi1c49+B
         XgHSwHeZPwSBoi1bjgeCfSWOMiNvVKjqSbiD8NBxIGgiG/Y4qKrLFFl8/zhLNXAo4ox+
         4mYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU3zPBYjtskOmbdQUI3JDd42yn4Tcp4gK52smnWYL3P1E7cWxBV
	fRWcOIlYepo7yWjTN+ZsjKY=
X-Google-Smtp-Source: APXvYqx+4YpSeb+DvJfu7OpJTfibLeCAXBJRrJ8HhfcNxbjNHSEW381ABEfamHM1lU7zQDD+VgjfjA==
X-Received: by 2002:a62:1955:: with SMTP id 82mr2703414pfz.256.1569996995643;
        Tue, 01 Oct 2019 23:16:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:80d1:: with SMTP id a17ls357408pfn.7.gmail; Tue, 01 Oct
 2019 23:16:35 -0700 (PDT)
X-Received: by 2002:a62:684:: with SMTP id 126mr2757998pfg.104.1569996995300;
        Tue, 01 Oct 2019 23:16:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569996995; cv=none;
        d=google.com; s=arc-20160816;
        b=gmwK5b0ZVDr3uuLJc75Iu6ZYDfPhkSUMifqMfjkxs0KRCdxvhlm/+Zmz8Ikyu+x04N
         h3GcECP3er7K7jaMbZYeAek3v/EW9SVg9UyqdXl8mXpiKiDcrrIiDf3NUcHinB6lbhGD
         Ju0UGDdnPO0UXjOoX2vLaD51glolzINCEtbfw4TA80H/Z+4HCE7Uf2g4FaqC6sQea0nj
         HicL4yvCZbd/GQr1EGl72xsL9GeO7fGWR64Q7HCy6qgbl5nx1KhK/4/YY7XD+DgEfHi1
         QVJOpcHQ7zyApybjGhbu/iQT5jw/2s32lF54XBEBnrer9/E7AEY0Edsq27AL/GR5S9T/
         YiXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=aA8Qq9jewBxt+//w19/0JAmIsXIjUAFSLoTLx8dLCTo=;
        b=zzysocktvWxPkDApPBc4E7VEhQaPdeLsNioCJcNf2eEj3MGXG4asImDDA5KJIPgT3B
         ov/vVW8LKQzu0S5bt2GeHICscT+C/Nr73/GTYCrERpL1Gw8mlwjAM92KzmLCL6uWWAu8
         Ptb59QjTAIcvbwpXd0q9GROL06BLwBO+ureNACMZVlpT8YUubPrV3g/FlMz9Fcl2R13R
         8NMaHWV8GZB2nqvi5W6ll+gSYBdqdGdu+JwPXNWaTmxNc3ThC4vp89f4R/R7iWKs4RqG
         3bKPVgOPo35imK1ewdYWOGUl3FEmbCVNLtZfs3mwmYxVoMzOnbfXc3ap5KjGJPcOb1dG
         ARhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id l1si179456pjr.2.2019.10.01.23.16.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 23:16:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9260iVl065604;
	Wed, 2 Oct 2019 14:00:44 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 2 Oct 2019
 14:16:11 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <alexios.zavras@intel.com>,
        <allison@lohutok.net>, <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-riscv@lists.infradead.org>,
        <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v2 0/2] KASAN support for RISC-V
Date: Wed, 2 Oct 2019 14:16:03 +0800
Message-ID: <cover.1569995450.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9260iVl065604
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
which can detect use-after-free and out-of- bounds problems.

Changes in v2:
  - Remove the porting of memmove and exclude the check instead.
  - Fix some code noted by Christoph Hellwig

Nick Hu (2):
  kasan: Archs don't check memmove if not support it.
  riscv: Add KASAN support

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
 13 files changed, 171 insertions(+), 4 deletions(-)
 create mode 100644 arch/riscv/include/asm/kasan.h
 create mode 100644 arch/riscv/mm/kasan_init.c

-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1569995450.git.nickhu%40andestech.com.
