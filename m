Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCVNT3CAMGQETRGGPXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D0DEB13E35
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:04 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-455e9e09afesf16228655e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716364; cv=pass;
        d=google.com; s=arc-20240605;
        b=gxF/XSIqzGHasofZhOMdO4E9PZryrCGmpwk+p8a6RB/pK9ZEIMAa4x0FtXW8RSsCos
         YstFYjrtGETS50lTxqzQ7Mk9SeBkwlw887cCXdrIqTo1Z30fRnfxBFomzFNlZk0VzxDd
         yYqLrWqMoJs0VkKph2P/GvVyXAoyPgEhl1bELCan4EkoNo8xMUaNEVNRa1fikpExaiJe
         ltGxWdrt6v/aEUdPpIgZ4ymt99UxMj2AyBwlZVmyU3ZhVARv+8PBwcylAdDJqMnAggYR
         F+q8jEbqBZ64ygpfhgBYzeHur1ywzMGMUfjivCzz1gVns9lIGudRhWtSch7ONF5X550W
         qgfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Pgw/pgFZBGwEyZdj2vzFpVtAB0f/M1uctanukXy2k94=;
        fh=GECKBZe7EevIJd7/XC00b4Q3k7EPS6BRDr2L2DHTz0E=;
        b=gqb0Ak53cwnr9LqAXPj61jr4M2TEGKhYzdlttwdMiAIxGiJnkZFK00ALXbIg04/ow9
         aXtVeuLkOtr7/VJ1JH0GMX/6k6S2XXMGyayVniRnt2HMS+1qG3oTsZfhJ+xRCll+/CYT
         SV2TIHAVoextZbv5FOEYq7cnm2Qy8ZoJLsQJpEvXChFHz6wCKVB24yrkWLvA/S+pS3WT
         +fWJzeiM/X0QKpgYNhJxVrFOXNoJdf9DAjuzLXiA2RngQHYPQ8b720QzfUsBgEAbYEx4
         uPAr6F4KjMjsvUKf8LslSiQdHK3CmtWrBBV9T/Mvil+4ioIIhtvaASo8aZF0nqToqj7H
         xciw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Won9HPo9;
       spf=pass (google.com: domain of 3h5ahaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3h5aHaAYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716364; x=1754321164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Pgw/pgFZBGwEyZdj2vzFpVtAB0f/M1uctanukXy2k94=;
        b=CNNZjB3yiKcshjUI7bo8N6DyZUPFE1K21kwgNcSKYBr5+s6ZnpKwbWEXYfCYqWPChE
         IMC072XRegMiUItwpmtl/zMvvRyBb99HxdY0ON6fDESbMwIJfezGh/r29+AfieHbcSur
         bEveSN74M4ISVcy1BT7SsC2SdOI6mXB+DIGlERU98oEgj7p8pkdF8Im8eIsiyAquZIeu
         AGLEsPE+fblfRGZtGfH1gS2IswJAr90RnON5ENKZWeTSRCZL4TFHcRK8Yq7msmif0Fmw
         Vlj2w5ODhA2uCFcDMLFW9gWHFVdKctvCY8U6yQVgQrep4Gtg22SQ39vmky+kA9z+iknQ
         G1zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716364; x=1754321164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pgw/pgFZBGwEyZdj2vzFpVtAB0f/M1uctanukXy2k94=;
        b=fMbXM7Y3O6J92a7L+DctLUNnWEobPA+tS8KRrbCDIFIqdpO6hMKigxOhukj6nQ0Ykx
         tMjfxwxuVUs07tbinH/PDwOig0Bnl0HkigWU5JCgpyjXVxfukQjy0S7IWXZJ1vjRVfXr
         XDK4SEojSrh7OCIOoT9be+7TC2JM+SVOsunzsMCpcdIzwOUkmCrqYxPwNgWWVCwRyyq8
         hWq8VypnVVy61j78YsVCMddbX+2N7TKa14qvRU6xdqWaEGiMQfZ+7dZr/fxDFjB/o74k
         x+jIG1PZSiLOQg6g3UAx9Zaay94U3Fdk3MvFZxrmtBVz66yUnnmlDPQvn4YT/AjMizh5
         1OdA==
X-Forwarded-Encrypted: i=2; AJvYcCWlA5+3mmcISspSsMKuwkPY2LCfyzmIhnaHi4If3swf7K67FKe2VpBBCox6bigIBrEQwgkKrQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyb1zYm6BDlpqcFQzQZuYiVGPYTi72iqk6n7RwX0ltZs6h3KsWP
	ccRfHcdD2uxER5BiTY7kWxw0NzPb3KDNR1f7BUYXNHZ3ChVCljnNo1UQ
X-Google-Smtp-Source: AGHT+IF2P0J8apx2MeXXst7+UEc2KHCF8SowFCwe7XBqQjASwbt52V7MK7MYnO0nTqpTBbMXiJkMng==
X-Received: by 2002:a05:600c:528a:b0:43d:563:6fef with SMTP id 5b1f17b1804b1-45877445e90mr89961865e9.21.1753716363332;
        Mon, 28 Jul 2025 08:26:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfiViQxZ60X9qf9t8Nd4wBGG8+VdBSK6s16vbGePiYnwA==
Received: by 2002:a05:600c:a086:b0:455:f866:3c0e with SMTP id
 5b1f17b1804b1-4587631d750ls16011825e9.1.-pod-prod-06-eu; Mon, 28 Jul 2025
 08:26:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEJAL/DlmIHFFZDOPrK5X672/e0GvbmdA26484RQlC8kyKa2EmeQEdVw9Z2lkSxwehoCvHNvMeko4=@googlegroups.com
X-Received: by 2002:a5d:5f53:0:b0:3a4:dfc2:bb60 with SMTP id ffacd0b85a97d-3b776603426mr8964544f8f.26.1753716360540;
        Mon, 28 Jul 2025 08:26:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716360; cv=none;
        d=google.com; s=arc-20240605;
        b=BmC4Zhu/f58pWtD1g4qi4O1x2b+NcNkm0Q85M6lbBYyCZNuV9IHo2bnG+gjCB9XC8p
         yjZq7/G47JgZJw1tOijzhjVzgVH/KaC9OTUSxiYoP8gIQomAHreM/pVjNEn15bk3td1e
         STdJ0bUkGRQmsMjr3WLPuS3M5QYsum91RTDARQxgtLUb1UPtizzH2vguqjLEfJCsPovA
         HbANPW5ml3V8gLAfD2gHsNuTd/rwVo1lK82E5BtBRn6K1dOAIbF8MRbt9wMkUgvaFEBP
         +7h+59kV1ySZ+ZBSemm4uuf3mMpsyncDnWAMzINhSa+BybAN06lu2Egu2LThUiOha4Lu
         P2iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hA2z1o4ZKLpPx/4s7kZhiOi+XbhOvD8L3886s5YuSNo=;
        fh=np+0aXi0CchQbnMbeFBgdswrtWFo8r9/Jsc49woyTqo=;
        b=H+2XcEcxj+NU0kCjDVJyVMarwLZNWJI8RR/BOenw4epqQgP25NRSgVQZiuDcz6O8gq
         UicnOTdZJa+20jelDLLskd3MJpAiLy6/PcmEQE0Kues2qcsMz06J4Zmh9BkPwE/ik+5U
         fjo8zbqFLOuQ6y4EuNIR+rFH61Fo7wc0HypvOOEO4rmzNENNXqywzX6zVFV5SviYewVo
         uujLODtxfy5wcACkwCvrq1Tt9g7Bm+OKHTOCp6nOStC9vjWRZ6+GDa/5A+A79XdPY6kJ
         Dbc4KqoK3PMbWS3HYees7A31Gusfj1PUoRFwFWBBp+4r9KLH6EoiBGpkfss+toBgrN5F
         of6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Won9HPo9;
       spf=pass (google.com: domain of 3h5ahaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3h5aHaAYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b778edb62asi181113f8f.3.2025.07.28.08.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h5ahaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3a4f3796779so2540116f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUehLSn4A9UMq3Aj1lhyf7Uggd5C2iadpjK1O2fj/UxS1c8EjCH+5+W4Di2E++r3oQCNUZSsPfBI70=@googlegroups.com
X-Received: from wrur18.prod.google.com ([2002:a05:6000:1b92:b0:3a3:6eeb:2a27])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:230d:b0:3b7:8d71:9657
 with SMTP id ffacd0b85a97d-3b78d71968amr446780f8f.28.1753716359829; Mon, 28
 Jul 2025 08:25:59 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:39 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-2-glider@google.com>
Subject: [PATCH v3 01/10] x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
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
 header.i=@google.com header.s=20230601 header.b=Won9HPo9;       spf=pass
 (google.com: domain of 3h5ahaaykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3h5aHaAYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
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
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-2-glider%40google.com.
