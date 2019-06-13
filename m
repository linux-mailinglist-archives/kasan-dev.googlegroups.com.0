Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJEFRHUAKGQEHAMJF7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id AF7A1435ED
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:33:41 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id f1sf14394180pfb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:33:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560429220; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXcIMV3qKLmAD0G92xbC7kQKRPBkULCZQ3w8tRQXQjQH3LUY7WZtERe06U+fzS5dXJ
         tBmDs/1NqKqx7ygPN9inK2PUzWxJRgjrbEfepzKUe6HCy9OqjR6zindZxNH0lebmuSdX
         Mon1yi4hglKqGpneKdZnQVZkAlMlYjIuhVEwsBkaqeTIPvgB6yGvfXSJ4cRLO/xpdbz9
         tU95cW/Tsf+6C/HB3a4D/Llux5AqgOw6/G1BJ9sgI6F7v+vT8HkYAdZmGIEoEtZwuGkP
         koaSZSezevSxzlXFCwnK5wGgyjvtmhI9STUrKFTEa1qHW4ucEuJaj4XdRFN2a2jEfMJ9
         i2DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Fpxo/roeKHFp7hbnhYibF1A3TfTB4xJ4U4cOBsgILOE=;
        b=Qk1HnO4MRyZICWWnrSx61DBKpf4JZ33FzdrtAwIEJJNq3sjZ1buZEp4PFfGSHVCyDQ
         vfDPs3jeURh/jBXGdby2g6Hp7Wn5h+ZAKMYQRsTfoOvJHSLuW516s/kSKvbLeVi0+gdt
         +riJTl2PtQJpXoLQ13GTW+G441Ds4Cz3fx+oW1kmv5jPsqdLuzhm2FF1X7OAYSDHm1G4
         G+wg/WyM7BsxSURBvP+Ec/7c0dtYQ6dLC04OGEyOeUJ3UYDSW6JEjuVlRtVxhpujvBjs
         H0vlM2RrmMPTHfOuAzh2aNBnKrj2Vdh9GSwLAvyDn3+vA1VSip/3kpYxPAkReo0Ns0FS
         qUJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vMwEtqzM;
       spf=pass (google.com: domain of 3okicxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3okICXQUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Fpxo/roeKHFp7hbnhYibF1A3TfTB4xJ4U4cOBsgILOE=;
        b=H7n9xF9odu+vQWPC+ha2/NR7Wbd9k3BKlnxxBYRS3R//n4S931TOWATMCmGH/Pc7xt
         yB4GiNrImzdU2AmGhm29ObpByKG7htCSggNb2Pb5TXnG6nW5OXPPTGDw6RyB2pCvc9/1
         MSfx9FfrpOlPt7LgbRW4280KptgfeDSIQSgIKn52HptK0qnq9n1+RjCtNYHGi8MMxAVV
         nkP/Vfg9QPKb8n0t7bpfFwwsE50ZFIM2SrQ67qxq9rFD/Nk0gV7Fce2GL/YuKGZx8vgj
         qCiYJJok9TzFlNeuEXofchWnYmjc6EpJmHUdmMqO1rpPGAuyVCoiaIxLBE4VNoiPItCO
         Tu+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fpxo/roeKHFp7hbnhYibF1A3TfTB4xJ4U4cOBsgILOE=;
        b=cvLCaJafkhyQEOqgPBaYuaZu85i3uSwILoxZXlbOKqmBxAs38xwmrH0+vs+5V4p4xn
         JS1o5u/wrJeTScJFe5a8BBFK9tCBW22l4h1s335drSVb4drD22Y0Yrx1rs4aYjtw6v72
         8QQ7kKZ8x7ok0hZM35Nri79Q6aMHV0DN/K8xuiKg+z0ttvSgo9f4I/uKCFusZSbRX4Za
         5pb+ISqYuXue+/OcbBA2P9pBdBDvSVcQiDPtdome6Ift5SgnDdQ/LqnGoB0wxL92J4c0
         cpEqCJGw95CViOU7r8gDZF+2mYZTDBdgbMI6kBdWpP8ZJ6Vusb3UF4i67Px0htyMqlzm
         AwDA==
X-Gm-Message-State: APjAAAW8CBkgsbmeVPQFvZt2ltzCWN50dSQ4cbU/YDBiBfAVXRlXZaTT
	gJlRxXn/m5jY1PcH6hdex10=
X-Google-Smtp-Source: APXvYqyLn0TvKhOxUu2F8mTTIKNlgXcbRn6VuWD5CRwqFnd3NtGi2Hl5UWeruSVYnGHVM5lW60dWGw==
X-Received: by 2002:a63:224a:: with SMTP id t10mr21545276pgm.289.1560429220119;
        Thu, 13 Jun 2019 05:33:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9112:: with SMTP id 18ls872505pfh.0.gmail; Thu, 13 Jun
 2019 05:33:39 -0700 (PDT)
X-Received: by 2002:a63:c903:: with SMTP id o3mr18963592pgg.295.1560429219683;
        Thu, 13 Jun 2019 05:33:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560429219; cv=none;
        d=google.com; s=arc-20160816;
        b=q7vcON4yUU8p6SAEXX6bpva/vi1cqIpl37FT6GC9nv5cbhdjbkwFZIMNmm8rEmUAGE
         UwNO8gYj73w0h4rmnxqdyvmv1bvZ6nSDM30g7Q5Bly3X2Omi63K5FZRQWEvWDtmYajfb
         W+kLmnepnLcwcpIghnOv23XsxfwljRzKauZSzSSqja/3xszW37U6MRjVIe7ieyWpM/ks
         xu4uD+4U74eXUwFNrzni8awwtscZJviUFFtgWfyIBamPjr4HC5M6rbSZ5IhwkqjVaLI+
         rBeTK9e3YP2jU5YBAcqt/XbXoBotIEHpvBitG6czd8NNbQgxDSIBOPxbVtV9/5a5epdP
         fjNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hR/rel8D4gBiToxcZ/kWhC4zY96wRtLwSvBkxQ4V8Fg=;
        b=ctNvMu0RuxGKD2hTxQG9LJ5eAfjofHyH1bazh6umPzX4Z7kZy+cz21ENgkKXxS2jS1
         KHk+bl9XT6ybVTMs8IjbE/ApcPHj9lWUf6nzGyfxkxvtWFo4TcmQu3scAk7FZGe2s/1S
         NFFtxfroIaNNSiD+cmSN9Psr27J7w2snRXdHiLOM87pEINZauFTHwMBhjqxsbUfOpEwo
         GqYXgOax3uuXnIMcUpmV1pb0wOKpY6Utj16ko+1IkJv5xhlf62j82E2QGPv0tl280k1x
         2QKT+doPfyy+a812L9lT6fUvqX0chWpLyYJr9vL3uGv+D9aRKGa2+d8aTrmdrmCu8pLp
         8LXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vMwEtqzM;
       spf=pass (google.com: domain of 3okicxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3okICXQUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id d6si70311pfm.4.2019.06.13.05.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:33:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3okicxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id s9so17314652qtn.14
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 05:33:39 -0700 (PDT)
X-Received: by 2002:a0c:888a:: with SMTP id 10mr3409777qvn.0.1560429218725;
 Thu, 13 Jun 2019 05:33:38 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:30:25 +0200
Message-Id: <20190613123028.179447-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v4 0/3] Bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vMwEtqzM;       spf=pass
 (google.com: domain of 3okicxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3okICXQUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Previous version:
http://lkml.kernel.org/r/20190531150828.157832-1-elver@google.com

* This version only changes lib/test_kasan.c.
* Remaining files are identical to v3.

Marco Elver (3):
  lib/test_kasan: Add bitops tests
  x86: Use static_cpu_has in uaccess region to avoid instrumentation
  asm-generic, x86: Add bitops instrumentation for KASAN

 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/ia32/ia32_signal.c               |   2 +-
 arch/x86/include/asm/bitops.h             | 189 ++++------------
 arch/x86/kernel/signal.c                  |   2 +-
 include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
 lib/test_kasan.c                          |  82 ++++++-
 6 files changed, 383 insertions(+), 157 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

-- 
2.22.0.rc2.383.gf4fbbf30c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613123028.179447-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
