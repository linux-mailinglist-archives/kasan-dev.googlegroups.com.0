Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCVF2SAQMGQEITKO4EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A92FD322C6B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:34:51 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 7sf6270534otu.19
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:34:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614090890; cv=pass;
        d=google.com; s=arc-20160816;
        b=sgqG98W8Z/md3HVYHaGsP2j7bUTZpHnASQ3TQlXICZ1UF7Y2CQsr52y5JCpMR8KJh9
         nyYKsUDLiHx2BY12sVvy6ZLup5X6uLlE0SeUcO86IyAsTeWPugjlbdb8VOl4+6rTSbXv
         fbQ1EksTcznPhZNyBcVzaftJqV8eIb3tQywKoizBQgWtXNkN+L1GqY9uak7K90U3O0FP
         /QZnglpGKawzrGDrRuBFF0epVgMvuoXitHwXKUpIzEO/yK8LAfy2mafATiQ449oqCzkw
         ZRgEaVGcNoeQkxuZIpIK2FCSl+hRfmFaP61Vsnrajp4d8nO8D+psaOkxLdCk7v96uYJC
         VXew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yCKn7qfRW3YYYfDwnx/HG0ajNZeUPZQ6S4ZbvvLBguY=;
        b=hEhbMqaHf+zRlMRF6m9DGM0aad9xz2P4UghG9Sqpj4QyESHidk6GQt4VbV95M1Jvag
         p+k6bUiQg84SSMX+d2wTLDx/THtpdAuHnSD8gwI/pgmwf9/4Hjw79mppjthP/Lq38DIx
         gp9xQ1nQsXtiEF5zfwdS+zz+1XkFYA1Q+LMI6kf/DzdrndgXWMRSyuTw4sgdU2VZM42S
         CzaSg3XplaGNhstI96C+BOthBYcmJLrDaxSwr4F/TtFhkeLmqCKue2dZbVHlcHlKGVps
         RwMhzXNj11F0PtNR+/LR2+sUMAaziBjtyLy1cHkDlhru8aVjyeM30pB36KzKb/z9outk
         IgdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AOwWMdBQ;
       spf=pass (google.com: domain of 3iri1yaukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3iRI1YAUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yCKn7qfRW3YYYfDwnx/HG0ajNZeUPZQ6S4ZbvvLBguY=;
        b=R0U8c/6SCYEKbQ/n0w2sde9f8kApq0byRcIO+GGjWoXUylGUDIoCkFYkF8VhfspJkx
         7IJU+P6FV7Yk62ha/1jK/l63eCdKc6AiJakfWPtdREEu4wy8IOqFQfdsSfazA/XF6Kvw
         lvU/5sVPjbhxv0NsAIvu6Uii92nc0WTaLBQ1elfioPE1YMB/J4XWqPXaEW88b+cWTuiS
         kzxLwnGxhkIbTfOw2uNUAX3mehgRoI16DLojZm/BSZk0h9k7ffGg6UFD5GmMRodopiJ8
         HtSjZ3Hr1W+0mAFWdrgkbHCoe8KpbYkVfdW1DQj/mZEOXGxsBTvmgHLv3PGEPPSFPjYu
         vBhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yCKn7qfRW3YYYfDwnx/HG0ajNZeUPZQ6S4ZbvvLBguY=;
        b=rY+8UwQQKIlq1TG/GlgVzqowMj4MkPDVjpe6hQooIOeUWNhiyOUvDBFrJYOXCWruaE
         eW7Z6rn48rSwNreCI6/lEORcpfMAo0DAYOJAeAKKl/Ph13T/8juUqGh6vNgT415+WV1V
         V6WXDB8ATpGZi+Pn1UbxToq/DN3b1u2M4TQE2NpCifEYRzKvfJGJFmFHTrDI6gtYcljP
         7TjXXRdhoX5iFdHIlk+WHH9LJ+hDri8v30IpQL7TB8dMEGIxkow1OivVk7X1jFB+1lKn
         kcCtg5P16Dolp+otAYoCKQUxSlIbzIvnBU+llfjtU0bS/otcVYicWqRlfH33W6y1Yc+N
         NwFQ==
X-Gm-Message-State: AOAM5334vyZHsp1zzaH22ZcRgRABFPULteHU5VGOA5lnavFpP9DHRNTB
	9LUUTMZbxMNndPuosvMkgQg=
X-Google-Smtp-Source: ABdhPJzqAjh10uYBAAC4hLCTI6u3TvUxMYYCZl2iNmo8CJHNasjWyq8rjD1WDZtANW9ofeFHjutNiQ==
X-Received: by 2002:a9d:17e1:: with SMTP id j88mr18926941otj.22.1614090890528;
        Tue, 23 Feb 2021 06:34:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1482:: with SMTP id e2ls255959oiw.4.gmail; Tue, 23
 Feb 2021 06:34:50 -0800 (PST)
X-Received: by 2002:aca:2b07:: with SMTP id i7mr509603oik.146.1614090890129;
        Tue, 23 Feb 2021 06:34:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614090890; cv=none;
        d=google.com; s=arc-20160816;
        b=l2e0xF5s33jqMwQMPXmqUrrwy8ZLIK4Wvgjv6HUW3u5ug5ym76XiWp0efPeygsNltm
         WaR5RJQLDwWJdx5uH6urW5EcxMgkpJFoGyUXzIs0ZYkfqUho8jmofsnKjzoOFJpCjzx/
         2M2ZIn9/u4tUiM1GQnafY1N65fYwoEF9zke9dSRYMVhsFjJZ6vDBQrkasqBZpN82DnkB
         aU5iba4AwMsOXPPxLRhHeCX49mDjzgusOL7X6DGdzfxFKLZVLiMLLGPCo+JmMJUQmRd0
         wY2qdWx0kA/8zt14tfT0zo/Lw0xyjPqZtayBotUoCXfpiDcT0jIeIeOYDuLGu6qSt3Xd
         jDZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=c07W/N7UYuxP8d3WxqLOZLQNcQmHUhhwBq0FOrgMOE0=;
        b=Cq4fa0EXnzhJSOvARpkU3d2iSPA+gHCZFebUDNZuAuxtviw4yFIBmx7gKrNry2LsaL
         wqUOoGQG/lspI0/P/COu+elbKWgpLpRO1zVpATRLHymLEWCOz476G/DLs1Mhdtfl1t4M
         vdZKRYne75y2GaOIybWKzoVwqs+15ngHSjWtTu7ZFNj76g5D1b4WqIqxr2kXHRU7i1Ks
         wtE019Y7SawtjXgYEqhSDWjNDhU9btJ3cRcR4KNpIB6k9UuOw3OLyAMUafiSDZdWhFM/
         GVqo0jw/KF7zHqpMNcem0vbkcG1gav9CbUMV0vpoJ+LIwEuaiTbO2yeZDcxXgvqyhN2A
         0wPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AOwWMdBQ;
       spf=pass (google.com: domain of 3iri1yaukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3iRI1YAUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id o21si1719719otk.4.2021.02.23.06.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:34:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3iri1yaukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k4so10131235qvf.8
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:34:50 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:855b:f924:6e71:3d5d])
 (user=elver job=sendgmr) by 2002:ad4:47ca:: with SMTP id p10mr2137828qvw.32.1614090889585;
 Tue, 23 Feb 2021 06:34:49 -0800 (PST)
Date: Tue, 23 Feb 2021 15:34:24 +0100
In-Reply-To: <20210223143426.2412737-1-elver@google.com>
Message-Id: <20210223143426.2412737-3-elver@google.com>
Mime-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH RFC 2/4] signal: Introduce TRAP_PERF si_code and si_perf to siginfo
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-m68k@lists.linux-m68k.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AOwWMdBQ;       spf=pass
 (google.com: domain of 3iri1yaukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3iRI1YAUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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
index 5ad8566534e7..943c98782634 100644
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
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223143426.2412737-3-elver%40google.com.
