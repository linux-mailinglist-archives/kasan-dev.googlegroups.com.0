Return-Path: <kasan-dev+bncBAABBL735SIQMGQE6BIMFEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id BDC504E5549
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 16:33:03 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id x3-20020a05651c104300b00247ebe980b7sf729597ljm.11
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648049583; cv=pass;
        d=google.com; s=arc-20160816;
        b=t2O/mzFSo+i8f0jTuP82rQLS8nT91SiGspb857o9Jp61UdDFzCS6uMYf8Xlntey3YE
         AoMuQRzOHRC5T55CT2PSv1n4n7HbJJVry9PlCPEWUVFatml5Oywc55NGnYhswVu8ze8S
         P6kdsh0JrL7NFHoGl8mnouzlAsDYrjlYneLcgH40+JFu+y+DOT7S4jKgD7RqGKzr4o9Y
         egITRnEihcoBk9XjNWIgGfn7AiYi5CEDovUVe1tgZfPX+LTyTN70q/vupAFrIXOL4PaZ
         aTXMuq6IAgEmVSSRM391lP3IegMCxg49kT7mWYBm2GOuuxTLn8qDNIIQZIvhwnI+JS5h
         24/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=iPpsFm8fD8cAxabBkRNMdhY8z+7zwZKMPoTOFBJPrgk=;
        b=hm1mwuotVnU9Ig9rSA3IpZDqHyFNxzBl0m+ZGOev9eilf5Jume+k0DGncxZp+b65vK
         kJ5/woYnpNuRHpo4qIj4CZyZ2mGu4wxmf3ZD41h+vvfnu3pV2uiraLPfe/gnmJ1xg815
         nOGoQ3eJJFeFq01/4W+xV+yXSd8lzJ7DSPsRfVMacHGMI1CyZfRCpUV5xzyolto1JSTn
         tiNF7aNB1neWYEd7en1VThrM6auJQ3tjxQHtWFcBgANqV+gez9f1SScTwnb2BVEhc0Yv
         J8dCLO6wxYuDfzxBE/S2wsW95lyujU0yvYq8xK5UR18M0yIeNYAb/KweBA85lPKACNeQ
         Ga6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nNAzpZbK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPpsFm8fD8cAxabBkRNMdhY8z+7zwZKMPoTOFBJPrgk=;
        b=JpnWtbaGhQP03TA0mVyljkwrBDIM/FPz9OeUNDtXthBGwRAnuBTioGM+FAkBXbvnTV
         RJKygjUEZMrcSRDNFc7r0dCeJPLpRvLeZZWf8U2ohFqbhdQhwLTXZw1Qlo7GUjOYCKeF
         46Jx5wEqTljiFZIQNzYLFApYsIC5X6qWhCy1gJdRyTm3ZvW59dD2rz6inXMQDWKlc+87
         dkerrm+lj8Cku2coDcmjs4gIQrorDBuonR1FqFTig9aoubQjLvgbfQ7Oj70s1W/LUix/
         71IFDzGzPEJ0wqCVMD8OGppgvuskoh1GL2irBQi2kPfwl0LekmvqSgCreIly8Vc297hb
         TRhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iPpsFm8fD8cAxabBkRNMdhY8z+7zwZKMPoTOFBJPrgk=;
        b=70kj1H+kXI/ku4jVkWBh5ZXLi/t9RP2rNJrDYx/8p+JYG2QCN+FxBMvCjnkD8C4NHB
         qtJGArb2gTN7yryT2gEYi/pvu9wbKq1CvFqsniI+hIW1Qpt3B69MZpzjiDr24VPSYdI3
         7g1l6T6tZOsWucT7/Z6VbI7uxmlPUs4OxXLJYlHNfKTrAdVse4ZrTmEIsMc7x64pWodZ
         elNcz8o6UaFFNnnPpQDeOItbE6hKFXG+bc6BOY6Vfj27CtQT91r5VNmqffrm3/xE9VLV
         2dOlkS4T675Pk447Z0XsJ/MSaszRAQzyO4djAK+vXqolvs4Kcaw4M7qXaNvOCEUYK+cM
         2Jrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532aOBVG+BCxZX5c40OBem4X0LS3gA0U9ksoUcuQ470BN28m/vtq
	19++E+Y3xzy6Z6A6rVkfCGQ=
X-Google-Smtp-Source: ABdhPJwa7aLI7UQ8tgCgNmqcb6srGEzCwpHB3IjfUt2YTqwGSVT2drdhHRnHMcSEDkWrjSW4IrdEmA==
X-Received: by 2002:a2e:9119:0:b0:247:e306:1379 with SMTP id m25-20020a2e9119000000b00247e3061379mr416488ljg.361.1648049583208;
        Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:892:b0:249:a5b7:d97e with SMTP id
 d18-20020a05651c089200b00249a5b7d97els410620ljq.10.gmail; Wed, 23 Mar 2022
 08:33:02 -0700 (PDT)
X-Received: by 2002:a2e:5754:0:b0:247:fc9d:5d6b with SMTP id r20-20020a2e5754000000b00247fc9d5d6bmr468697ljd.294.1648049582389;
        Wed, 23 Mar 2022 08:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648049582; cv=none;
        d=google.com; s=arc-20160816;
        b=eidudEkCSuFg+hVX+KkoNg2HFgmK5x3L1PahbQPljt6IQy8JS/MKFKYKr7efebNanv
         MBGrWjp/lOUDMJX84uRQmkqaUOnxFJlxLglvI1kFEUXB19+f/QsHdcYmUiZt4m61BKIt
         mWU3Rhyq34eVmSuxSQ/LR4uQAY3VCuPVFOFVqLdweRdcOp3Hd1LI9z97iq2bP8K90zYk
         f2TgLvBTXbgE8dzxv5QYNQ22FWxvDijVQnxeNfM3zEPTl3lIhGo0NYym7FiEUxhcRU02
         XOgt9r1DOdfdCX/SUUACKAS4gKASn/179oUN6jgL62JOx2AvqWWjKecC9Jt7zMEnt5vB
         rtAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=aF3Mslkri/nAJdWJHWopR/qwkkYDeoi5D+QsOOTejFE=;
        b=Y95U9pZpE9JhUzGW2h7hfXEftONPdAoAZPW6A7JOnrx4ebGQ0pV28xVhoUfX2PwFAy
         SRrdXgU8Kw7fK41K5Q/JIETxLIytLXY6MlYIHvEmPEZPSiWQgbydPzTgcw1bOOTwIslV
         C1pz4lomQcDBxR2q3kxU9l/AcMwIZTaWGZkutDzoO3lzyJK/twsT6Ddbk8GhZzBRxJlh
         9j4h9PPpGly6gtngB9QQ0qhqA2ZFgxjZ/NPiMHYrI2J0ReU0WehPTGuWCQEz6oZAFZUD
         URDLrnQgkX9FwB987GdIs7vP9mB93oWblrbE6ofTMSqS2fCZDJ8/c3kMWgoCSKpS47rS
         EMbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nNAzpZbK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id z19-20020a195e53000000b0044a11f487a1si19133lfi.11.2022.03.23.08.33.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 23 Mar 2022 08:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack traces from Shadow Call Stack
Date: Wed, 23 Mar 2022 16:32:51 +0100
Message-Id: <cover.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nNAzpZbK;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

kasan, arm64, scs, stacktrace: collect stack traces from Shadow Call Stack

Currently, KASAN always uses the normal stack trace collection routines,
which rely on the unwinder, when saving alloc and free stack traces.

Instead of invoking the unwinder, collect the stack trace by copying
frames from the Shadow Call Stack whenever it is enabled. This reduces
boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.

Stack staces are collected from the Shadow Call Stack via a new
stack_trace_save_shadow() interface.

Note that the frame of the interrupted function is not included into
the stack trace, as it is not yet saved on the SCS when an interrupt
happens.

---

To deal with this last thing, we could save the interrupted frame address
in another per-CPU variable. I'll look into implementing this for v3.

I decided to postpone the changes to stack depot that avoid copying
frames twice until a planned upcoming update for stack depot.

Changes v1->v2:
- Provide a kernel-wide stack_trace_save_shadow() interface for collecting
  stack traces from shadow stack.
- Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
- Get SCS pointer from x18, as per-task value is meant to save the SCS
  value on CPU switches.
- Collect stack frames from SDEI and IRQ contexts.

Andrey Konovalov (4):
  stacktrace: add interface based on shadow call stack
  arm64, scs: save scs_sp values per-cpu when switching stacks
  arm64: implement stack_trace_save_shadow
  kasan: use stack_trace_save_shadow

 arch/Kconfig                       |  6 +++
 arch/arm64/Kconfig                 |  1 +
 arch/arm64/include/asm/assembler.h | 12 +++++
 arch/arm64/include/asm/scs.h       | 13 ++++-
 arch/arm64/kernel/entry.S          | 28 ++++++++--
 arch/arm64/kernel/irq.c            |  4 +-
 arch/arm64/kernel/sdei.c           |  5 +-
 arch/arm64/kernel/stacktrace.c     | 83 ++++++++++++++++++++++++++++++
 include/linux/stacktrace.h         | 15 ++++++
 kernel/stacktrace.c                | 21 ++++++++
 mm/kasan/common.c                  |  9 ++--
 11 files changed, 183 insertions(+), 14 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1648049113.git.andreyknvl%40google.com.
