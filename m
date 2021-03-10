Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6GEUKBAMGQEBFFGUHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CD563333A42
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:42:01 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 97sf10809278otm.11
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:42:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372920; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cvj8FuTIgU3KnkOQCIrbHBAB/hj2UQxsMU7fF8VADHKfaEh/XLAxUa26P2oO06omt6
         xkJPbFOwWYkohCxViELHkyMJU5bb3OL2zBf4YO81+3V8TmbfQ00gkZo4wgDYlMl6tFvs
         k21Yz9j14yO/8+aVhNk+ZlS0mY71mjpq7oa0e0uA7K0DSCoU+dL6YjcDgEPe1qnNKb1+
         x1uxvIPxEE6+eJHbnvUIGJpaJyc5S27eh8A/Pms55XVBQbLrZT8hnjPpc8PNJYbI6GN8
         JMbpjgHyZ72xNQaczVTwtEapSMDjkUQOCyXz3TIjnv4Dae6aGW/lfPe5dLU1Axa6EeVF
         AOJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=nZDm2htyJJL/0phAprVDvpDQHgJLKZG1gpMqE+TrJAU=;
        b=KaHSR0EIlgUi6YeAh6c6jd/xfdeXJxq+AR/fdQ3PwrpT8quy4eBzbObwlZivS3DWgp
         ql2uRgdVVyhHKKSudH9e7MXdXFIo9ZYmVHgEXtw7taiNPdE5YqOlScuvBY4+Xg6MT3P9
         hw3yqW+20qy4Y1T4j0RCguMYVxgLw1jge5dYaJ8Lca5yQaGrhkjM6Z3Oi4EWG+7tajau
         apy7RTOs+ghaixSRT2z7pkhirEhclup6L26ewsecZcVFp3Dk+vg2cSHq00yOfs/wrLSI
         /wWm2jN8VBK+eWWlrqqmvWr5R8zFsgs9B04UvP2aMy9l77WivN30vmBgqzhKGGFRC4Yy
         pW3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hl7F9vqa;
       spf=pass (google.com: domain of 3d6jiyaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3d6JIYAUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZDm2htyJJL/0phAprVDvpDQHgJLKZG1gpMqE+TrJAU=;
        b=dPW1CN8bYUgMX7RrSK+eAHiwlk1eaa1aD8Y+9/p9x3KFzaNYuCp1o4xNRo4EwCZd/h
         yK3pTz80etyvSbiIDB+SDQY2yTCynGd3q5lYO6VeeX+LsoQFb2gF+gyZIs1Mh0zxFFBt
         HXd5Zy/pVwqwpiUH95LOZfWo3M/D5VgUDtP1mKd/Dd3CHq3Dqn/FEGx6tQ2ZGUh1YhjT
         MsoQebt5YpzoNtgM2FN/8UfRrn3KrbowXGlKsXE/fe/9Lb6U2CzktfznR94KYZyIoLwm
         qctWAv9UpXrItwKnsIUfHJf5jJgNuoM6MrOdvjIlOaePg71h66w5r52kE6FzHd52j3KM
         39RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZDm2htyJJL/0phAprVDvpDQHgJLKZG1gpMqE+TrJAU=;
        b=aGCX5+LlZZaZlMni30zM8Ghra0mHoIeXn9AzFz5Huzb6s1hHy4RQY7Bgmlw87qnanq
         7C8M7wwe2DOyIHx81yea3lY4mkU2u4rynwrcc63REA4pXNh27K7Yg6Jh+jzUgZNa7CtH
         KtcxwR3BxbAi/90bjrIMxYv50I1P/6PZ+tTrBbcXnE3XT5+ZD+u11ay3fupr7UW5cZZt
         cY3S1S/bzOqTvo/kU2iXUI5eAtyA9n1+J/tcy6wYH7vQOwHxK3ZjTuLy+FqdKa+Ncqj8
         j+LGrG6L0FBw5uYesdbN79p1PIPzvirOo7qWcihu6d9/iGRJjM8+K1X7RbMex8YCzceb
         06Vg==
X-Gm-Message-State: AOAM5319WpPlQOMgib0JKpbEijcGL32HiOX1Ne+ORhh1nGnoFrRu7aJ9
	AxiHtdChLyRanck/Hhp3gBM=
X-Google-Smtp-Source: ABdhPJwDieRHCR3H32OIcBNd4iIZXuFuMAvVTYSGCypJjq/Jj4EilHhk+Og8Mopnq584KWzcr9zc5w==
X-Received: by 2002:a9d:200e:: with SMTP id n14mr2083021ota.130.1615372920697;
        Wed, 10 Mar 2021 02:42:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4390:: with SMTP id u16ls388583oiv.9.gmail; Wed, 10 Mar
 2021 02:42:00 -0800 (PST)
X-Received: by 2002:a05:6808:1442:: with SMTP id x2mr1935148oiv.74.1615372920347;
        Wed, 10 Mar 2021 02:42:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372920; cv=none;
        d=google.com; s=arc-20160816;
        b=YyAOuonVE1YHTuAR0kCxIiwRMAzAU4NRW5SaoNpe8bQiwKx+18zkza87o2QHG3yzdX
         Xe5euMBJmMNTVV1iO9Wk3r1d4kKjzTfCjhbOsWL+PSUtAh14lVgI+nIevWbWiHXvyBA6
         mgeTaNMMiOjjhRthOhNlvKUXRxUbGZ9FeU71/wC+koeLJ/q5jBiN/GhnmXuJWPmWUS7N
         xmYj0+j/UmW8Glqgqz7hDKynJKBNTkG6NbFK+p+m/vfOMZ5rfa3TbDnpD8Qv50qYfSAG
         PxXfCqAo2b5UbmpmB51WppWYdVPG09b9brJ3D51d2YzLhQgiUqma/MOWi+gWXCGnlTcE
         Qraw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=TJtkCAibz7hjjm1jVaTeeVhou55l9X9TvLV9OEul/NU=;
        b=gZHf/PBqWEFPQoPCMqsYSqLoqTsVqQPt2t4BrSSsAFE3aLpFrxfCXNsSRoais2ryh4
         knblgLvLfxrImUwXwqGO0f3//LXWA2QI55sR9feeQhlHsrQYljyEexNSiXPnpms1ndu8
         3NzLXdHNdT3nw5PUYKvmt190unpq6iG3opt70xm+cyDSz4TPBkiZf2aH54Hc1NI6owaK
         5jWIlzaUKATanYF4B40HAQbbg01FLHsU5YGZXM8CEdXMpVrk5WKQ0s4fjRmK9ZS1nxXj
         cc/new2n2BWolpPueBYDg5kr+HF2lRLglNZ1QPMmmrL2w7N88m1lpBDxz5CfS5EU8ags
         JGlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hl7F9vqa;
       spf=pass (google.com: domain of 3d6jiyaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3d6JIYAUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v4si1622091oiv.4.2021.03.10.02.42.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:42:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3d6jiyaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id j2so7183858qtv.10
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:42:00 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:a05:6214:90b:: with SMTP id
 dj11mr2130953qvb.52.1615372919806; Wed, 10 Mar 2021 02:41:59 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:35 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-5-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 4/8] signal: Introduce TRAP_PERF si_code and si_perf to siginfo
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
 header.i=@google.com header.s=20161025 header.b=Hl7F9vqa;       spf=pass
 (google.com: domain of 3d6jiyaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3d6JIYAUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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
index ba4d1ef39a9e..f68351825e5e 100644
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
@@ -3333,6 +3335,10 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
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
@@ -3413,6 +3419,10 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
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
@@ -4593,6 +4603,7 @@ static inline void siginfo_buildtime_checks(void)
 	CHECK_OFFSET(si_lower);
 	CHECK_OFFSET(si_upper);
 	CHECK_OFFSET(si_pkey);
+	CHECK_OFFSET(si_perf);
 
 	/* sigpoll */
 	CHECK_OFFSET(si_band);
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-5-elver%40google.com.
