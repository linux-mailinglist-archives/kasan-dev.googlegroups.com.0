Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMM46XBAMGQEFM4TMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 80765AE9F2A
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:13 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-32ac7176fc6sf4037221fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945330; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kp+uKEU4+e/7xM7SFUefvEMaS6K4UzS/X+BhdTwuM3lNk0I/eH0XhlKWVuiLzWktrD
         23fyH8hX9XYBXi0YaYPIsEF1tgh1zq9sB1tXYsX00yUIC/yzRe8NCbpsKEJfyv/9XNkw
         bSMpYuokq7PsTRn0CsfMu81oLb3+K8+4JnKR4Q3d5/57A+RTFQbNqOT/TFzkOfXNdbH8
         lhGMhHNiVUHrv7dCr1te/qhaIDbkFtzHSL6l38+G4j4RZvHPHAriYekyy2Pe+R8PiBWt
         oR6JqyPUsbhGD4b+1hQN3RKxUTWBlxmDEXJkmUbB89aRv94HKEqB/zV7YJGcqWOfYmVI
         HewQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3PDW+UnJnZdrgEQnGpsURmziobSFZglZXJxCGPD1yOY=;
        fh=SEGPNbWc5Mk0vukOILwIlhK1SNfXavYL9whhjQwsW4A=;
        b=ftCirDc5tQ45xuWS/gWBH5+WLvECSx2KXkdIQbzyFxcfqWM7ihz71A7xGLJAkRMJn6
         lXGcCLYKtylxDe0q6ipADOPGUt7vAs1R9By5IXMyZKeeREt4D8m7MU6DHoOwgD6wAFoI
         +gJbYz/LuA2ktQ8HyDs6VuFgsxTMYW7aGNLcB+RCv6Ezrk70+uzkgFdRIq8OnQrItQJG
         lDweR/AUwepKkx00Ko0vVfM0EkP34zm3xQAAPkvv4eJYIjyx/V/xaNdVBrsyUZk9Dcc+
         aY2Bfi3VOxbhjrjDo7qi7AEuFSjIopotzAOisVVKAQZt+v5m+wTqJCPZt9EJt1H3z+Ef
         6MTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=l5BLkaDr;
       spf=pass (google.com: domain of 3lk5daaykcyktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Lk5daAYKCYktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945330; x=1751550130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3PDW+UnJnZdrgEQnGpsURmziobSFZglZXJxCGPD1yOY=;
        b=AIqK/3pQK96H13o2NqSDYNMYY7Q61+FUdGTPBmYG/xVT/D18DP++a0DO/xUHKOZtH2
         QxCJOa+vy0SexDJrz/GVQJrxd2XB7sM9yRoThiilaZEUhvbcxxFB8OR5Bhh7XUXRdvyg
         P1F4zUx9L58xVKk5Kvuul/efwE3RXs8nrWk2PHxD9fiKGfqEOijB0NuIRUrC28Gld+2J
         alVY4b1ww7uhXlRDd1WTgdp/hZiA0m31KHfDmpQOJK/uXRDOB992lDkNM/u+kfoG+GUX
         lpqVfcjRv2YMC/ofJUNHXq3Ey2m7zwI8KIcVrpDuUY63pmUqTlj/BY1GKNXrDIHIWj3H
         4EXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945330; x=1751550130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3PDW+UnJnZdrgEQnGpsURmziobSFZglZXJxCGPD1yOY=;
        b=iYwpYusg3YpNnS59HTMkpYLrgbUw5SWreV9LPNNn//M+12/43+kEeLbl2dlpz5QvLn
         JftvXj1sEaRmOgmM1AgILIrQbaQeustodeo4WjKLBJ3dEXMK1HRtqQ/5GW/QxzHibC+n
         rS8AFfTMsRW2mSM3PDn+4pKOe2AD3Otb1yLBGWLIu0R59DltizYVykH+qtQ6qJCeYpsj
         OwPU1jdUauD015r1S96LhVHJngg4UULIlibW43XqnX3a9Rfb8golEb79rRiYAufWlYDk
         JrHZtrgIPwoLPxgmUY7dPd/uLFZo8g1SWm3dfOVNf3opT2uUDZrhtttkcQdtrgRGUPYm
         1qBg==
X-Forwarded-Encrypted: i=2; AJvYcCUZ+VUB/Q0YFQt4hR5yeDoTkM1Wtk9uGGV3CELi1SHRrX0vL9G+875vQCejIBMHD8muG2icNQ==@lfdr.de
X-Gm-Message-State: AOJu0YxTVVpPYkP+QXOq2xvZ6AWflxkYjNuKaE6KYTlwXhdp65WTV+4r
	JUIlPnyib/Ew1Mry4ETzkXUjzNrikyNXZ0evOb4ZFrvJYafmFEcp2oUs
X-Google-Smtp-Source: AGHT+IG4lA7WgaXxRAFO+H4KZ1oz+FDu9xyfg967xEf7u4qy4vxsmFkCBf8mgD+oToao6tauevnCEg==
X-Received: by 2002:a2e:9402:0:b0:32b:7ddd:275f with SMTP id 38308e7fff4ca-32cc6560c74mr19157911fa.30.1750945330262;
        Thu, 26 Jun 2025 06:42:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc9vfcdLqaJZ8M/sOHUwuf5sJQ0fVGIe3hLehxviiNdhQ==
Received: by 2002:a05:651c:302:b0:32b:7db5:4bf9 with SMTP id
 38308e7fff4ca-32cd044497fls1649801fa.2.-pod-prod-06-eu; Thu, 26 Jun 2025
 06:42:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDJFj710HRdmovi8w0yb0M5xWlD0zyhbJTARoxHpqThX6ywpaFcT135fJUXdwrZxsRJ2c9RFQxnFs=@googlegroups.com
X-Received: by 2002:ac2:4e07:0:b0:550:e527:886f with SMTP id 2adb3069b0e04-554fdf650a8mr2623442e87.51.1750945327301;
        Thu, 26 Jun 2025 06:42:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945327; cv=none;
        d=google.com; s=arc-20240605;
        b=SVKB8WNiDeRlIZ5sG2A+0+ZRluYhQl9RoPC+peD9qKCG4+pK7yY7UNO2HLnjzBFXQ/
         42stZEAJGjdRMOAQ1Km29pRtpxpM57+wj2Ba8JVmQaWQyL9IT60U6jt00kIQchTIyOw1
         0Th8o2EEoBywVYRdfXgKnZHNFPkQGdPUBhvuzeXT4cQMdzoDVntH/yKrdZJCaabMldFA
         tPXBrFm1OEbJCLsih4E0u+UrRmCOKiSXncEOhkKIWv7S7iPeCV2AoPYK99BVezeHwI/y
         0WpBeFb/CgWxOPQjO9//GDNq3alr88cVHNkBfv54EGx6LC1bsiWmWmytaNZ5QPhznD7w
         rtTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KgRyE+5ZFAr6FW9KaXMYIeYZG6lVPAbPaVY2rL2tJCY=;
        fh=0G4iJqBoqD4RNqUJUWNsJpY44X+VSkW/k5Eprwl1CDE=;
        b=hh6hgv5bZr1VgGjk1SCt/OBUWBiqyPd8xWo2PhBE5pYKbB2o8klSnxrT9xwHgRMR+r
         QY36g3x1Pea76plx1jPAxRRpDOvBU1re1GT+QH8M+WfpUd/BFGSHDXxUdaeAng4rjs8Q
         71otQRsLOzQ0DIK6+QZa1APbqFW7Yqm5p+3xji/ATmGlHo6FLpC6wKv8Cnj5jtSY5fFM
         3gi5psH2aHLjBRF6CRp0ZAZvqgY0SvIWUnUpmSlt7au8sCCAyx/DgnzvMmFOe08aFcpE
         IzZxZ0yQo1Q2uqjDpJdJmtEO8ZdBaAT1JJF9zsnFuKXHFKAEkhrSy8+f+57dM7gMJl/N
         oa7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=l5BLkaDr;
       spf=pass (google.com: domain of 3lk5daaykcyktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Lk5daAYKCYktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b0f0374si1311e87.0.2025.06.26.06.42.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lk5daaykcyktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4535ad64d30so7381915e9.3
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrwcJvAGjCvYuFHqkeRXL4t4XxfEExQkkLBnJy8nvcMAHVKPtnhmxEsdt8jjqkrE7tf53sBsgfpH8=@googlegroups.com
X-Received: from wmth13.prod.google.com ([2002:a05:600c:8b6d:b0:44f:f406:f4f2])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:6f18:0:b0:3a5:8a68:b823
 with SMTP id ffacd0b85a97d-3a6ed60755dmr5704580f8f.23.1750945326673; Thu, 26
 Jun 2025 06:42:06 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:48 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-2-glider@google.com>
Subject: [PATCH v2 01/11] x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
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
 header.i=@google.com header.s=20230601 header.b=l5BLkaDr;       spf=pass
 (google.com: domain of 3lk5daaykcyktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Lk5daAYKCYktyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com;
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
 arch/x86/kernel/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 84cfa179802c3..c08626d348c85 100644
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
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-2-glider%40google.com.
