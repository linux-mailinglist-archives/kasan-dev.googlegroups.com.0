Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVNRVXCAMGQE4CZHNUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B926B1709B
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:51:50 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-455f79a2a16sf9368985e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:51:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962710; cv=pass;
        d=google.com; s=arc-20240605;
        b=h8gH2s+2wKWHsmAngOwsCjhSkuDunfY6RChIcEWVqaPu0oHjaIUHKUEpgmPhbOhL9R
         E55kqXm+PlJRvW+HoRqD7Ty9kKUwq60IjElngerGbJZdD2sXRtV2BV/yXgwZap2DwyQy
         XimKPiDJVREiQOxPyi0O0B9pOXSq/IZtXgZkHakln/4/YLIWJRjCuFlKccxHWpZhwOFr
         J/T/EpL9dNwA9yjAg7ARJO67YuNKdX4wCh303dfE8cc37n2PR5sSSPly/p6zTl3XjDKy
         RSjVJhsie/BQkd1tI7f4hPj6QpZSA6NTl7a8R60Qii82GpOMhQEZUnGwabxHqefsHIva
         mAGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SXfITbkOHZ/u30hRpc14bYZXJrLfzDVJk7ZD3y3oUwU=;
        fh=f1QmcWxEwvxAw/q/kkRoDB9fkSB2N/MqyyTgLUon3WU=;
        b=LBFBnDISf/zpn6LUjyXDKa0WK9YdP7oix7qzI/YWYFwPlNJcC68v+zLHhjWH8e6c1q
         RJW2+RyEGg4y3+uVmw8CCeJ9Vua3hOl9x5syjEDXN+allRoRRqJK0r8AVtaOte5g3X3o
         x+ujoNqKta07rOPKEliFcfwqzeYZUQRdzEi9Vy0vbI+46NatWhpoRqlTZUMHWDHCbzXe
         sWXhf9h3LJ+/b11buPBDo/BpJJMTi04OltlPAcWWwNYFFGDp1BQytH4eMZxM/U9zhI0D
         FG6hQRU6XQABgrrW6XKxis6h0cRPvePVx/lgnawaJv6GJlRTM295PDNZx3DS0BDRDZ9u
         aHGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p36PvnFa;
       spf=pass (google.com: domain of 30lilaaykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30liLaAYKCfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962710; x=1754567510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SXfITbkOHZ/u30hRpc14bYZXJrLfzDVJk7ZD3y3oUwU=;
        b=KHQoQZO4x+PHSitxbXyTsXdjLJ6gcVF/5coLxcCsYOnxwgTOKrfjGVRXT78zGP59tr
         HKNWM7N/ArpgHrwYSEfswF/MMIXayTdFLPaVr7lbICptcvdUBRzZBd0z0oh7WnkzGcNK
         iN93vO+B5z/FocUasg+ZBp2Wu8TztA3Q8xeBhQAztbXYSZjn573V42Pm33OtmN3ZTHA7
         0C97Mzt/SWfBH7MXdaS/x9L1+8WTX2FBvwHuQX/QWch2Rz61KqYlpIsDZ2WCHtJ8mKSj
         dCg8ozSYlfCf4QKbqmiGqE5dVClsKaaCCbSe6oLfNvBjPlsLATjtcr1PqmkRPhTi8Qtv
         Y3OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962710; x=1754567510;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SXfITbkOHZ/u30hRpc14bYZXJrLfzDVJk7ZD3y3oUwU=;
        b=ANACfqg4q8baORepn1e6Q7LoTSoXbtII9HmC/+WJ00PSQ4t85N1l61/VCBL2ONt497
         XC4SL2WcOgnnjeBHLGh6ifinc1pm/G/Vv+u1S6cLgOJucZS9Pxiu4N4XdtNI+s9Drco7
         N/AUOZaWJI6g073OM0/XuQsFON1p/8d4dsr3eqEBcOPKyW1fLYdNF7zu01348fGyMiXc
         tx4OXVJPmXqbQLbhnLPv0P7gQmB1yrTYWmCIsfenz7Mr32YZQ/0mXRWqhqSuQffOarj8
         Q4KLQSdBgqia3tGQuRtdi4lrqbUhiti6VIu+OFuKaYdaBLmhziPzZ3/OHvW/xKOn0WLI
         h4mg==
X-Forwarded-Encrypted: i=2; AJvYcCWCNy0LJcSKBP0KxSmcbfq0Cj+mFTXYeM72iEyXVpxMDEOTXYuS9A7IQF0dZwCTG/kyxM9+yg==@lfdr.de
X-Gm-Message-State: AOJu0Ywjkkn6DvBi5m0TrV3TZSsK1fjD0M8fiA8SsCzS9K6iG3zculE+
	a87bQ5k+M25Q8k5ofQRt4x73xj/a2p0PanaWbvjlgwae+hXBQGVwrF9O
X-Google-Smtp-Source: AGHT+IHuZG0bjLDomvkRQmOq71X4Jwp087BrxJyhzL/C3WCUodllrNgVc/n+YfGizAvDp6q2/qNxTA==
X-Received: by 2002:a05:600c:530c:b0:455:ed0f:e8d4 with SMTP id 5b1f17b1804b1-45892b9dfd4mr76448865e9.10.1753962709837;
        Thu, 31 Jul 2025 04:51:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdV5oS82NSzHqdVmIYp8DD/VkKt/xEIyKlAwsSkDJwN3A==
Received: by 2002:a05:600c:4588:b0:455:1744:2c98 with SMTP id
 5b1f17b1804b1-4589eaf0db7ls6324905e9.1.-pod-prod-02-eu; Thu, 31 Jul 2025
 04:51:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXE5wlV/Ya/AtPB6BMuEI7VTYvhhRZV4eodcrB0iAD3dh8mH8+TerrPlzokfPA0A9vzMwSe71TxYvg=@googlegroups.com
X-Received: by 2002:a05:6000:4312:b0:3b7:968b:7f81 with SMTP id ffacd0b85a97d-3b7968b81d1mr4531788f8f.24.1753962707035;
        Thu, 31 Jul 2025 04:51:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962707; cv=none;
        d=google.com; s=arc-20240605;
        b=YGHTY6Q5tmV/HsQjf3sNkASU16K3ahc+rSKiWxBD2H5vmrxuHUUv7hVBaDwF2XXYCY
         GP2OyxcR/O0d5rshyVuun2FjNyGRih7tSPE97VacaIDNKmekjzZhHwV/Jbx3hcageZ3n
         zF4a934ogMTHLGig3CS0FKigpr/MI70z5ZzfRexDbY6k0RARC+rgMtNLsOr/FJ99J830
         2TvWlgoYYSUYq5c1Xu9/MPBtiJ7S62hmqrvXDvQ6ek/7xjUMYsBu/P3rt14bMA8DluSb
         g2ovM1QGuozluwv3V18tRQnt77WvdYEQYzxeSCECV50dDDKpOGd/nbhagfKUreB4Me9j
         uMFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=CXQg+XdaYsLX77wN5kdKJjw9/5umyLhAylJtIjXw9j0=;
        fh=eTX0yydmx7m4jLEsyPY8UbbUNhyipSTGQAFR65SXi2o=;
        b=Mk6uGuat+xtmnfs2VNCzMdEfsd4jOVdAUq3sxrpfSWb9Uje/b2rAJCYjybeuYvczTI
         qAzxgpiB/MCoDGJocYhZbfVNvJ5yhrOclkOLBF5u1CTWkrgt/arFHU9HT1HrRlAHskgu
         Ut6LsiwXb7hbiBTwAdziuEszTB+0KSLj1K8BaQ8eJihpxrNJDQj2vo4rrpMKHuN6xk9N
         LuHOKqvMowrfeKouSVYtqnYX61Aw6mzkuN1VOXh2ogD6X/DhXegFoGSvQyCu9EVH6KAO
         VgSSZ6QCH3e613Yyj7IVMqbXJfzX3H3cm11qSVAwX9ToxY73olhnaSlAtIREzJhh1Whu
         FoVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p36PvnFa;
       spf=pass (google.com: domain of 30lilaaykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30liLaAYKCfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45895377d6esi1056395e9.1.2025.07.31.04.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:51:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30lilaaykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3b7807a33faso158469f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:51:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcMv5wKvA/u6/eTREHfdfvlCLE8j5O6n+9au77yCR2CbJPTz1QHkytX5hMTV6IHvPKH6EKEPRziWk=@googlegroups.com
X-Received: from wrbfy8.prod.google.com ([2002:a05:6000:2d88:b0:3b7:8d84:e97])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:3101:b0:3a4:dfc2:bb60
 with SMTP id ffacd0b85a97d-3b794fd3f6cmr5156251f8f.26.1753962706607; Thu, 31
 Jul 2025 04:51:46 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:30 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-2-glider@google.com>
Subject: [PATCH v4 01/10] x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p36PvnFa;       spf=pass
 (google.com: domain of 30lilaaykcfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30liLaAYKCfsjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

sched_clock() appears to be called from interrupts, producing spurious
coverage, as reported by CONFIG_KCOV_SELFTEST:

  RIP: 0010:__sanitizer_cov_trace_pc_guard+0x66/0xe0 kernel/kcov.c:288
  ...
   fault_in_kernel_space+0x17/0x70 arch/x86/mm/fault.c:1119
   handle_page_fault arch/x86/mm/fault.c:1477
   exc_page_fault+0x56/0x110 arch/x86/mm/fault.c:1538
   asm_exc_page_fault+0x26/0x30 ./arch/x86/include/asm/idtentry.h:623
  RIP: 0010:__sanitizer_cov_trace_pc_guard+0x66/0xe0 kernel/kcov.c:288
  ...
   sched_clock+0x12/0x70 arch/x86/kernel/tsc.c:284
   __lock_pin_lock kernel/locking/lockdep.c:5628
   lock_pin_lock+0xd7/0x180 kernel/locking/lockdep.c:5959
   rq_pin_lock kernel/sched/sched.h:1761
   rq_lock kernel/sched/sched.h:1838
   __schedule+0x3a8/0x4b70 kernel/sched/core.c:6691
   preempt_schedule_irq+0xbf/0x160 kernel/sched/core.c:7090
   irqentry_exit+0x6f/0x90 kernel/entry/common.c:354
   asm_sysvec_reschedule_ipi+0x1a/0x20 ./arch/x86/include/asm/idtentry.h:707
  RIP: 0010:selftest+0x26/0x60 kernel/kcov.c:1223
  ...
   kcov_init+0x81/0xa0 kernel/kcov.c:1252
   do_one_initcall+0x2e1/0x910
   do_initcall_level+0xff/0x160 init/main.c:1319
   do_initcalls+0x4a/0xa0 init/main.c:1335
   kernel_init_freeable+0x448/0x610 init/main.c:1567
   kernel_init+0x24/0x230 init/main.c:1457
   ret_from_fork+0x60/0x90 arch/x86/kernel/process.c:153
   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
   </TASK>

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Ica191d73bf5601b31e893d6e517b91be983e986a
---
 arch/x86/kernel/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 0d2a6d953be91..ca134ce03eea9 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -43,6 +43,8 @@ KCOV_INSTRUMENT_dumpstack_$(BITS).o			:= n
 KCOV_INSTRUMENT_unwind_orc.o				:= n
 KCOV_INSTRUMENT_unwind_frame.o				:= n
 KCOV_INSTRUMENT_unwind_guess.o				:= n
+# Avoid instrumenting code that produces spurious coverage in interrupts.
+KCOV_INSTRUMENT_tsc.o					:= n
 
 CFLAGS_head32.o := -fno-stack-protector
 CFLAGS_head64.o := -fno-stack-protector
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-2-glider%40google.com.
