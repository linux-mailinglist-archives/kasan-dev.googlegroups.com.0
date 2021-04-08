Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSVZXOBQMGQEPBHJE7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 35C9A3580BD
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:36:59 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id n21sf653619ejl.11
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:36:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878219; cv=pass;
        d=google.com; s=arc-20160816;
        b=SGMOFkGsr9QdBgPRvuM6GAqgwaZW/r0k7c3xmQvr26xz1VrEd53RS8ka1QqxsvoX1o
         yC0F3JNhJ3FhK98cr3M5SrkvxVJWQAcZ/Js8JoKKifak1DLseXlDXUaEcqoaafypv9FP
         AH+d1KVRQ+4XXwztATKUh9viEpKd6+xpz7tHYFx4skBfBMpwrgCPdSEMATj0Dcl9uCeq
         6AC6kPIlqPvssTfWaSL6Zbpcaz01IPQOTitzahKW3G8mSaVq9YVu96gIMA/ry1Mil4NN
         pPqDESWhT3CshKCvlL8AXoEbk49AFpe8/gEMy0hW2jtGma6+0x0cUh+te9TMANTDeaVj
         UY0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4lNV7LBWN0uw2q35uN7OPwMNYwHS3NaRtT0It4od+3w=;
        b=Y+UqqWF4OWtxLM3yjSnEXWUKA/wqhuqIoV+OWGp5nW3bbYcaXlVoPt/kzu6siX0+RO
         piXX+q56z2+Tp23N+u7pepDM7pz/cr8aiidN60BP5fSdeNUP+r0Fx6W3vcacPr1B5gpP
         HByoYAeCrwvhi2qidKPLs9gtHtnxXAvGmGKXT/ngbD2YO0IetFt+0rS32Yyie8KUrVe8
         g3EliewNUaF5FsIVYWXawg4I4NPI/Lg6/BHdgLQEeGNyHPtpUDNHBqoe/yp9B0Lsm1s7
         IUHq4aRYBLHmUcZqYkOVYTepAmNLuZrgL9esN+qLqc9bBuD7l+H86lyrln8vwUIByVy6
         f9wA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Se424GbY;
       spf=pass (google.com: domain of 3ydxuyaukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ydxuYAUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4lNV7LBWN0uw2q35uN7OPwMNYwHS3NaRtT0It4od+3w=;
        b=g7QMQ2Uj8aIo/Bg4lbP+G6Z3B+YSIK9NBMs5gO4wviX9+Cy3HzoKR2Ckdvmv6X3yo4
         tM6GKyDm4gp2KrfCq+6OH0wZsuZZDMYA22PWY9egnhhw6Ga41QDGYA1IwKcHDbFiT2Y0
         dH3rsF70O6cXKg61ankOqU9ZRFJcMijrHScdD4uvZ/CV/LxzVQmwAwydC3BAy06AdshD
         wufTLUf6yFRLt63Km1Bg1aExdxzX3JMAccCJ4ZLz2XzkP2/ZlKSYijWpmppQkWMs6ioK
         vXjdkyG7v3CBH5aXFdnaxOheIarzqo2HpTdyPhyWio4Myqv0Twwvoi+H2TamQ4D3HiYR
         7CPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4lNV7LBWN0uw2q35uN7OPwMNYwHS3NaRtT0It4od+3w=;
        b=TcNQu+5DuWzi0F6vNJh5PtCwKQxvH3YY08e59g6Mld0yU3JcFTdzUVGvEJc4n8OSzH
         gdcGvfsHci6Qb5Q6rbltV3IElLHjVInqMmrECKZT1tI+W5Ij77KGdoK4uOJkd+2We+dx
         GWhvSLw33FK7ClWuJ50bQXwmzyU9t022yeb2+QhA8tfa5eQDNqQWMcodIcnqQcB++EpM
         wo6hezvq78gqFrswnoE22+IVqzmY1MhXN9VgP/ybPc9D2HFyT2+oBEaXBWHhIAUgf44L
         nXYNm+2hbCfgVbzhq3oT81KEuVYKqkDFBjlnMlD7iWcPMmmq9qSu0P3cQyNt4pumRM/I
         y+lQ==
X-Gm-Message-State: AOAM532ylTCnIJlRsm0zQQLF7T5zuQg+HBzvYAKX2u3pwbCuliZGkm51
	RbNA1j0DcPfbPfD405YFw/w=
X-Google-Smtp-Source: ABdhPJzW+ESTqW4OAuHYNy1xzri75T0JNOGWi5myNPT7zcmR9tUAS5q9/jGqX36yrluW44eI48zTaw==
X-Received: by 2002:a17:906:3e97:: with SMTP id a23mr9486852ejj.440.1617878218983;
        Thu, 08 Apr 2021 03:36:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:22c9:: with SMTP id q9ls2924070eja.11.gmail; Thu, 08
 Apr 2021 03:36:58 -0700 (PDT)
X-Received: by 2002:a17:906:94ca:: with SMTP id d10mr9264803ejy.107.1617878218029;
        Thu, 08 Apr 2021 03:36:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878218; cv=none;
        d=google.com; s=arc-20160816;
        b=rY1UkkrncCYkCT8LpVAqvdAd1MISWM1QCe4NG3qSIRWN27+cjQRtibeVSsPi58uQ+/
         OR4kvK31FBrwFa7MHQG5OoElj7OG2vHCF1XRT5C9LHOT7VW/gtcfOenYghNcAz3f8eAa
         GKtfn1vRnypTVFrcJu0fYp+L0WoZ1+n82qx70QNkBvnC7nieDAK89yodVqFahOwul2pT
         ez0JfhMJf+wx1jypByNZ+Oj25fhJY6jmLuVlCkBJGi/YTmNw7sIfPVz8b6XcQeywI15p
         FcDYUPjC3ovYG5QHJuu/EuHnMMeJeUjacjPALyNZ2xXNiiiXyh9EB7qGbKsKPf0OhO/d
         k/SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=v9gUyO4WlGopcl8m0bUjiNb99+c1BypULZulubgrE/E=;
        b=GWHSTIppzld9rMhq2XR4+apdgPEcQnDT4Txx7dtI50RmeoBRNyxqG6YcF1Htk+jc9X
         tEekpWG7iN4X+/I1cOJakkO3bglxSEa7z2cBAncQT0d/jfFnLQtvHff5RNQ2165k3HJr
         FeVv8XHg7o/PWZP+yV66XqeI+PjrbUpqS8vIS+vOzJZdzDsczwJvwbkfI/AGQsVjaHp/
         O9IYOZMa42eP4nkj5+aFmHnNHMU6DXb2hmwHfqaWjBVkcNit9hSgc6EO7kvEvIz14LVM
         38zLuGbQuczdRHELogFut7bKkX+OAiEJrBzqBZk4Bvj7uxKadXa25M0xgLIRj3NFZyic
         dI+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Se424GbY;
       spf=pass (google.com: domain of 3ydxuyaukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ydxuYAUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id m18si2827420edd.5.2021.04.08.03.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:36:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ydxuyaukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u37so118906wmp.8
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:36:58 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a1c:87:: with SMTP id 129mr2114476wma.112.1617878217643;
 Thu, 08 Apr 2021 03:36:57 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:36:00 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-6-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf to siginfo
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org, Geert Uytterhoeven <geert@linux-m68k.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Se424GbY;       spf=pass
 (google.com: domain of 3ydxuyaukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ydxuYAUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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
index f2718350bf4b..7061e4957650 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1199,6 +1199,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_PERF_EVENT:
 	case SIL_SYS:
 		ret = false;
 		break;
@@ -2531,6 +2532,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_PERF_EVENT:
 		ksig->info.si_addr = arch_untagged_si_addr(
 			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
 		break;
@@ -3341,6 +3343,10 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
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
@@ -3421,6 +3427,10 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
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
@@ -4601,6 +4611,7 @@ static inline void siginfo_buildtime_checks(void)
 	CHECK_OFFSET(si_lower);
 	CHECK_OFFSET(si_upper);
 	CHECK_OFFSET(si_pkey);
+	CHECK_OFFSET(si_perf);
 
 	/* sigpoll */
 	CHECK_OFFSET(si_band);
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-6-elver%40google.com.
