Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLGD5SBAMGQEAODFTHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AEFDA347711
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:33 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id x20sf1105324qvd.21
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585132; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSTFwK7RKpEmJtRYVjJJlvE7PTAQktq5DuVJu8fPKv3Sc7ulCDrSIVF4bI5STZ/F/d
         SdPnoEN1Vlzgg/HvYefqg6gPzyq3IfxmuG4D+n5VfGvj9rJWaYoLhBFDIS9AVOpyBoMC
         hh7MgvaQJ+wzZc1AN8TQ2xfOJE9TNUWr2azkbquBaRQueW6GHstUtx7ae63kQq2XO57k
         tTRErhsW1Y9IT2Eq8zwrsJNBB9bYVkSlSrX0LX1Q7BrfuT25XlS9VIzEszkFC7v08Q2a
         mvqPHe9X7NG+rTgAwjOvj8bSF5i+3T1QYfqo/KZ0Ysx/L9OyS6DGADuvMGyMwVGLGcXe
         mJZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wsW4KxF7xKZBVFVEOdgyhaGCofjg8QSgdY7Klb0sDOo=;
        b=isVrfS6uonpaPfD3Jj9kaCK+cQ/geAmsd37/bHNdLgx5nyeVvM24yqWLDyfRhSnRYc
         Jjl1tcskdVQxmNqhaRG5woy4eNW+VnVdO6DbivRWa4ZI9ltziz2YOXYIIsHOScLy5I8y
         NzhnAUuy8otelaRopMVOm+IquMGMFieDfBoYz+06rMB9XtoQmgITpAugGfECIDRyaRbf
         QcmpZrMsw2+QEl4hWFwbl68XLzEJ37E3bOFe5Jg+VpHRVlQsuV3pX82cILI5LtLoftM7
         PrL9dVFBbjYfPUuQU9Ylt4OXVs1EjY+3jBsEtwvBvMxoVXhiG+oZOXK/8wDtaDyWHEV/
         VgaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S2DUvLHr;
       spf=pass (google.com: domain of 3qyfbyaukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qyFbYAUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wsW4KxF7xKZBVFVEOdgyhaGCofjg8QSgdY7Klb0sDOo=;
        b=mtrHeWx9FfyfrjwHaGAURz2EoSXGdmh74Rqrjf5e/Yw/V/CnBVSRtJ4uq+p/aft1d5
         7qLZrguZVWiZdXJI12jTd1F52/AzxwrhnNFt+D1wQ7a4vOWrZ6Fvu1K/MErR+zs42Rph
         GQyz5I5Rmuh9No3Rvu/nJ48XfxEDja53z1vZO+n2Hratz/Y47FhKmbOfeBqv0YhjKJvL
         /80ftrwdow7JiJTLE2jGuRsfM3n1dHbHm85BbJ1S3j09Ks5Rmeba8rKW40/DzpZDXw1P
         A1b6Gzrxnej9fntesnF+ktPVuxOmtkTAWyRzD++mB1XjMraXFFcsOFo37KfSfmPZC2RB
         121Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wsW4KxF7xKZBVFVEOdgyhaGCofjg8QSgdY7Klb0sDOo=;
        b=Fe9qx60nNbEqzfNXJoyhZ6CAJDzBm39P7kkI2HAqIGKJWGJ7AFX+0QbYyityCCRh+C
         TP/maoSRuYL8ytrlVqYnI/HSAdQSOLbU1kCTxNIiBYdaKatj1Z8MAKZmc7LG/Y0axoMx
         eG2Q9lSsMmtYboVbIyBLPKa44nZ2t/z2IAtvdURLx9NYFUayB47TjCuVgtesqxXoT+EZ
         D4/M4GJV/dUFrYEFTsDt+gkpKkbMvQwSa83TPEEgMFlqlT/QNvkCfXlKWgJEqSi5KZVT
         F7YWjdXeoR9Ruavh/xiR9GcOBF7BjK94yS6atSqDb5Jg7lT8JjWrd/eU2QGeI26iAoqT
         k7Tw==
X-Gm-Message-State: AOAM530ubH0iYErhkZNvHb5eCQvLBjHNvM8QJeyA8kdejahc2QHsmSUz
	T+S0/DFW+Qjh2OpAVNjfDiA=
X-Google-Smtp-Source: ABdhPJwnx2Z4VLoXPEP9izVda5Ar19h1WVJf36Rgfyj7hP1AShv+dTCBqbBdt5nqadz1o68FcR5oOg==
X-Received: by 2002:ad4:4431:: with SMTP id e17mr2503940qvt.37.1616585132602;
        Wed, 24 Mar 2021 04:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4f10:: with SMTP id b16ls617474qte.7.gmail; Wed, 24 Mar
 2021 04:25:32 -0700 (PDT)
X-Received: by 2002:ac8:695a:: with SMTP id n26mr2477392qtr.20.1616585132124;
        Wed, 24 Mar 2021 04:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585132; cv=none;
        d=google.com; s=arc-20160816;
        b=lseH96GbjA/Juzn2dx7+BvZt7eyBFFnX/1jlIKEHshoEzoiC2iXXKRKtayeTcE6DKu
         jakQGmN7VKfElmwHebGujzUTOWHGEhLEq7xYs3uZAJBX7ioQcPa0hN5wZmX+2mQA945i
         GGFFy0CPOMQpxLKERya0fshc9Aq8clr7ZEOfFZwvVb2pTUQDuZEShsN2cvjUolIoin5k
         drFQq08VD1+rEPjGWzzqtypzp14WMqnyVj+ArsImVCK3ph9FvyoupOlI37bxdRfrirzf
         oKhvDIsXuSJw0LtXI8LrYH76yUORJyUUoKpbs/3BDXvQSwwvrgG2Oib+g/S7+WJqS9BS
         IpMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=b4Q2ZglVTkOzHkjXlOYZwcAGDS9zw6a0ARZ6VBAohd0=;
        b=jHghkJlYiFP2Mxz4cZ06FbEpjnDfBo77tzqYjngScCMp8zmJ7yYzDihEHVMOFc4fEX
         9n995BfJylai0zTVC925HbBJIHCqo3IQX+zrYC7S+kua9tNuu0LzKkS0k1JtvdmyT/I/
         /aZ4uW7FZpIN5abSju8xE2CjluSCssIlAv7M9LlvnHlloodMdHXyHsRF/WkfU50DDrMu
         IZcTT+YO/O6QNJLHE//cFdUlzCr0oTFWtxno4Q5QnUBSSjuX/IJRHRRKPz9q3q+GRl1m
         ULC3oJoLK6mcLClpUDxUi3SOgEU4IPPOkCNTngfNPiILipvG+KN2NWfDNsAFxuMOtrWy
         MSbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S2DUvLHr;
       spf=pass (google.com: domain of 3qyfbyaukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qyFbYAUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id b4si140056qkh.2.2021.03.24.04.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qyfbyaukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 130so1353096qkm.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:ad4:540a:: with SMTP id f10mr2342906qvt.26.1616585131695;
 Wed, 24 Mar 2021 04:25:31 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:57 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-6-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 05/11] signal: Introduce TRAP_PERF si_code and si_perf to siginfo
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org, Geert Uytterhoeven <geert@linux-m68k.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S2DUvLHr;       spf=pass
 (google.com: domain of 3qyfbyaukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qyFbYAUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

Introduces the TRAP_PERF si_code, and associated siginfo_t field
si_perf. These will be used by the perf event subsystem to send signals
(if requested) to the task where an event occurred.

Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/m68k/kernel/signal.c          |  3 +++
 arch/x86/kernel/signal_compat.c    |  5 ++++-
 fs/signalfd.c                      |  4 ++++
 include/linux/compat.h             |  2 ++
 include/linux/signal.h             |  1 +
 include/uapi/asm-generic/siginfo.h |  6 +++++-
 include/uapi/linux/signalfd.h      |  4 +++-
 kernel/signal.c                    | 11 +++++++++++
 8 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/arch/m68k/kernel/signal.c b/arch/m68k/kernel/signal.c
index 349570f16a78..a4b7ee1df211 100644
--- a/arch/m68k/kernel/signal.c
+++ b/arch/m68k/kernel/signal.c
@@ -622,6 +622,9 @@ static inline void siginfo_build_tests(void)
 	/* _sigfault._addr_pkey */
 	BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x12);
 
+	/* _sigfault._perf */
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x10);
+
 	/* _sigpoll */
 	BUILD_BUG_ON(offsetof(siginfo_t, si_band)   != 0x0c);
 	BUILD_BUG_ON(offsetof(siginfo_t, si_fd)     != 0x10);
diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
index a5330ff498f0..0e5d0a7e203b 100644
--- a/arch/x86/kernel/signal_compat.c
+++ b/arch/x86/kernel/signal_compat.c
@@ -29,7 +29,7 @@ static inline void signal_compat_build_tests(void)
 	BUILD_BUG_ON(NSIGFPE  != 15);
 	BUILD_BUG_ON(NSIGSEGV != 9);
 	BUILD_BUG_ON(NSIGBUS  != 5);
-	BUILD_BUG_ON(NSIGTRAP != 5);
+	BUILD_BUG_ON(NSIGTRAP != 6);
 	BUILD_BUG_ON(NSIGCHLD != 6);
 	BUILD_BUG_ON(NSIGSYS  != 2);
 
@@ -138,6 +138,9 @@ static inline void signal_compat_build_tests(void)
 	BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x20);
 	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_pkey) != 0x14);
 
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x18);
+	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf) != 0x10);
+
 	CHECK_CSI_OFFSET(_sigpoll);
 	CHECK_CSI_SIZE  (_sigpoll, 2*sizeof(int));
 	CHECK_SI_SIZE   (_sigpoll, 4*sizeof(int));
diff --git a/fs/signalfd.c b/fs/signalfd.c
index 456046e15873..040a1142915f 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -134,6 +134,10 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 #endif
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
+	case SIL_PERF_EVENT:
+		new.ssi_addr = (long) kinfo->si_addr;
+		new.ssi_perf = kinfo->si_perf;
+		break;
 	case SIL_CHLD:
 		new.ssi_pid    = kinfo->si_pid;
 		new.ssi_uid    = kinfo->si_uid;
diff --git a/include/linux/compat.h b/include/linux/compat.h
index 6e65be753603..c8821d966812 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -236,6 +236,8 @@ typedef struct compat_siginfo {
 					char _dummy_pkey[__COMPAT_ADDR_BND_PKEY_PAD];
 					u32 _pkey;
 				} _addr_pkey;
+				/* used when si_code=TRAP_PERF */
+				compat_u64 _perf;
 			};
 		} _sigfault;
 
diff --git a/include/linux/signal.h b/include/linux/signal.h
index 205526c4003a..1e98548d7cf6 100644
--- a/include/linux/signal.h
+++ b/include/linux/signal.h
@@ -43,6 +43,7 @@ enum siginfo_layout {
 	SIL_FAULT_MCEERR,
 	SIL_FAULT_BNDERR,
 	SIL_FAULT_PKUERR,
+	SIL_PERF_EVENT,
 	SIL_CHLD,
 	SIL_RT,
 	SIL_SYS,
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index d2597000407a..d0bb9125c853 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -91,6 +91,8 @@ union __sifields {
 				char _dummy_pkey[__ADDR_BND_PKEY_PAD];
 				__u32 _pkey;
 			} _addr_pkey;
+			/* used when si_code=TRAP_PERF */
+			__u64 _perf;
 		};
 	} _sigfault;
 
@@ -155,6 +157,7 @@ typedef struct siginfo {
 #define si_lower	_sifields._sigfault._addr_bnd._lower
 #define si_upper	_sifields._sigfault._addr_bnd._upper
 #define si_pkey		_sifields._sigfault._addr_pkey._pkey
+#define si_perf		_sifields._sigfault._perf
 #define si_band		_sifields._sigpoll._band
 #define si_fd		_sifields._sigpoll._fd
 #define si_call_addr	_sifields._sigsys._call_addr
@@ -253,7 +256,8 @@ typedef struct siginfo {
 #define TRAP_BRANCH     3	/* process taken branch trap */
 #define TRAP_HWBKPT     4	/* hardware breakpoint/watchpoint */
 #define TRAP_UNK	5	/* undiagnosed trap */
-#define NSIGTRAP	5
+#define TRAP_PERF	6	/* perf event with sigtrap=1 */
+#define NSIGTRAP	6
 
 /*
  * There is an additional set of SIGTRAP si_codes used by ptrace
diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
index 83429a05b698..7e333042c7e3 100644
--- a/include/uapi/linux/signalfd.h
+++ b/include/uapi/linux/signalfd.h
@@ -39,6 +39,8 @@ struct signalfd_siginfo {
 	__s32 ssi_syscall;
 	__u64 ssi_call_addr;
 	__u32 ssi_arch;
+	__u32 __pad3;
+	__u64 ssi_perf;
 
 	/*
 	 * Pad strcture to 128 bytes. Remember to update the
@@ -49,7 +51,7 @@ struct signalfd_siginfo {
 	 * comes out of a read(2) and we really don't want to have
 	 * a compat on read(2).
 	 */
-	__u8 __pad[28];
+	__u8 __pad[16];
 };
 
 
diff --git a/kernel/signal.c b/kernel/signal.c
index f2a1b898da29..f9351217d391 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1203,6 +1203,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_PERF_EVENT:
 	case SIL_SYS:
 		ret = false;
 		break;
@@ -2535,6 +2536,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_PERF_EVENT:
 		ksig->info.si_addr = arch_untagged_si_addr(
 			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
 		break;
@@ -3337,6 +3339,10 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 #endif
 		to->si_pkey = from->si_pkey;
 		break;
+	case SIL_PERF_EVENT:
+		to->si_addr = ptr_to_compat(from->si_addr);
+		to->si_perf = from->si_perf;
+		break;
 	case SIL_CHLD:
 		to->si_pid = from->si_pid;
 		to->si_uid = from->si_uid;
@@ -3417,6 +3423,10 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 #endif
 		to->si_pkey = from->si_pkey;
 		break;
+	case SIL_PERF_EVENT:
+		to->si_addr = compat_ptr(from->si_addr);
+		to->si_perf = from->si_perf;
+		break;
 	case SIL_CHLD:
 		to->si_pid    = from->si_pid;
 		to->si_uid    = from->si_uid;
@@ -4597,6 +4607,7 @@ static inline void siginfo_buildtime_checks(void)
 	CHECK_OFFSET(si_lower);
 	CHECK_OFFSET(si_upper);
 	CHECK_OFFSET(si_pkey);
+	CHECK_OFFSET(si_perf);
 
 	/* sigpoll */
 	CHECK_OFFSET(si_band);
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-6-elver%40google.com.
