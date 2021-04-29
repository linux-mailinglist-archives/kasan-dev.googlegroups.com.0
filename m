Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRGJVGCAMGQEHHW2GFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 54C3036E63B
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 09:48:21 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id o4-20020a05651c0504b02900bef5ae012asf14957628ljp.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 00:48:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619682501; cv=pass;
        d=google.com; s=arc-20160816;
        b=lyajHR2i4Mw0IYj94v2lui2TJH2hKOga9zCmt0mOLT+0ay1AZQQD7kuepgD1VagV3Q
         8ZtagH8vDVHsGWOUz2Fzz0XiOKcU40ey+CH42cqFM5+LVihQgtCAd1BP3AwvU5y5CU6Z
         yGEM7qsZJO4WClkeOLMJm6EQDZi06j4k0f1VIVk3i6SrZi6PksDb/GkUDlc+Vr+f++Bi
         16B/89VGNWu9IS/IC+8z7p3HOtFUOGz1/a2qyX60DbSExg320MSIcPxrlldO/4dJjQgS
         6OkaTXnY359JE9tYyWSgrGcjAXo54F6s42P1kpesypzPwBhYpxvLxFiMz+RNOMMlm8Ps
         7FOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=FitdsZPnsot4RKrymPJcaniDNeQ1KtIm4k9rczpXoKI=;
        b=xFQ/OvXEZAjJHD6aLQY7fK4ZhHHsehoXPjKWF2b+lbaNtfqn8HPqTe1Qj/V8k8mdht
         V1OOmOGnl+H6EMd4e76L5CCQjpd3oPkcOv9IRvkLg8LZMYMLT6HMZ8tOa0HSH6nGJ7L4
         HWxmtSDPJvo15QM5s7ju9lDmIRF12BsrzoeAbJlIHqxvZToiYmvO7kkp1zlAbgE53X3D
         EvdNXLsaI6jdG0hZyb0Eu/lBeCcEaUPBuqofwTqUIy5Yr35Ub/J+uRMia/I95sbOHvv7
         GGHohlgDqCfGUaedlXVQar4ZOm2/948JbtzVI74JK6cM0931M35fBtymGVh3kJkW9Emg
         891w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JcIUqcHr;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FitdsZPnsot4RKrymPJcaniDNeQ1KtIm4k9rczpXoKI=;
        b=Khs9DXsHIlsc4H2pJOBYX905O5H1JY2AlWSnbATzHbLJwVN298O3ArwfZstMIAsyO/
         +4qi8YYbXIf0GJTYyTcrMUfX9w455qyyTJsJNmAMlHAj6u0LT4NCdKjhXqyL6GCE+6yj
         FDLJVQ98ofV+O0NCfgxwPnxKgqx5r2xPoft9vr/V50kj/bY4i0uHkTq8syCmhj435jFb
         sJBr796pWpfSzS//+GVQVHkqvLA5oHKSX81k14JU7wVa2HWVhHsIVh2C4Oh8d+YMxnUI
         ksg7PH739RTk6+Kgn4FUi6vCF05ZKzZYoWNahIOiEvBA9reff1z4jX9j3+tJ41dUltSQ
         /67A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FitdsZPnsot4RKrymPJcaniDNeQ1KtIm4k9rczpXoKI=;
        b=eyG56WvOX4bErbAbTj3UsPMtyXyX1hl2qZx3yoxZIuhfkNIyEqLzi9i9b9s+JVm8G9
         p2NykooeE9sJ2+SiIaeOCocBRN7aETKzPKTLMeBcpiZxu+V+IU9SDQ9+zDTKb3KsOCUt
         9uEb1pz5yyX8kC80WumkTUs8QG9DGnC94IExcE3C8pZRRiKluT2ayIFT72qJ1OtXCeVB
         AzGuW9NT5RgFlFsmnCyA7E8HUexxOgkvVA9BwTKOwsxI1WwERoumb8deKxOTWrlW5YrH
         x3sr96CUUFT17SlJbqLVSkjD6Qs9XtUy2Kbs2yt8TpzujK+DqmcfgW1NBqE2n2QbZ03H
         gqBA==
X-Gm-Message-State: AOAM531I1OzKmC/o6uRehYwqU4rl0TqBv4KgXnkTQFgVKSyInxTzUoqV
	KbDMGz4JPDnW+oJ/YFq8nf4=
X-Google-Smtp-Source: ABdhPJw6CJPTycv/uVVvtDHIGEzl57vPWYMeGzw9vjNBNdDFNqoPqzOfHPl34m5D1bA/LeGRmA3bYg==
X-Received: by 2002:a2e:a374:: with SMTP id i20mr23888258ljn.481.1619682500899;
        Thu, 29 Apr 2021 00:48:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls809369lff.3.gmail; Thu, 29
 Apr 2021 00:48:19 -0700 (PDT)
X-Received: by 2002:a19:e309:: with SMTP id a9mr23337276lfh.222.1619682499685;
        Thu, 29 Apr 2021 00:48:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619682499; cv=none;
        d=google.com; s=arc-20160816;
        b=r2PhadDLci5rMsTmQK8jYuD9Ujo/6l70qmXd0t+ROf+M2nvLjHNZc1ahUhtcHVMXVJ
         6zEZ25g68tQV9zjij9RjNi3kU8otz7R41LvKM4Lcwj8y48JOYSY0i/HSKJ6gY7gpzAgr
         3+iJqi7ugZRVicKmP51SeMeyJoP45zrOg3Bqzfl9vmq8jVPZXBxlsKimS/eadjM23uSG
         /diqr3LBMOWNeveGOmGbXk+RqRkoMVoLYY89ECmTWoRw8PK4bJ2ZpvDPJTdKwXa1q/s0
         BMvmNVFkX57RNLa/C3SxDGPP7iUz//H6cCEZzDKx3D3eXRJoQzzkn8mDaf9F0qu6eu1N
         NCAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=BpYrN5HcmOywbaw+z2lQkv5C1/K+LRrq5c9nfbi+Y18=;
        b=psoFZoLF6QPJy2dNJfXbKzOKGqnTOImxTYsyd8PZ56auYg6Gw2kTYbF/RCkjMaoGo2
         7ie7eXRIOIEHw7VUu4a7qe+/OTfsuZpFkn/CmNegRZbfhMzuqesNG0ZKLSkaTh2O+LTl
         8qFNyy/8V3ZZiN+VH+AEbg5yC6jYPwAb8VUYfKyeUULx5Zjl3W5yWxvwdmStMn+az+8e
         c+cxw6ODUModb2Z+P+dZawniCkk0IXO12ts2pd5X1gQ8tLfiDJPLBLTi+D1apuaMQ0CQ
         Sf7W8DVlKzrA0OCLUCr6T4AnFwtUuOtX4OhiSQgS78VnICDGErrN0YVcOdliSB/biSQ9
         5RsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JcIUqcHr;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id b12si73066lfb.3.2021.04.29.00.48.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Apr 2021 00:48:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id n2so12592379wrm.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Apr 2021 00:48:19 -0700 (PDT)
X-Received: by 2002:a5d:610d:: with SMTP id v13mr11811010wrt.173.1619682499142;
        Thu, 29 Apr 2021 00:48:19 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:fdf0:ddee:bee4:b3ce])
        by smtp.gmail.com with ESMTPSA id m81sm2571110wmf.26.2021.04.29.00.48.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Apr 2021 00:48:18 -0700 (PDT)
Date: Thu, 29 Apr 2021 09:48:12 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Arnd Bergmann <arnd@arndb.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, sparclinux@vger.kernel.org,
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-api@vger.kernel.org, kasan-dev@googlegroups.com
Subject: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
Message-ID: <YIpkvGrBFGlB5vNj@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JcIUqcHr;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Hello,  Eric,

By inspecting the logs I've seen that about 3 years ago there had been a
number of siginfo_t cleanups. This included moving si_addr_lsb:

	b68a68d3dcc1 ("signal: Move addr_lsb into the _sigfault union for clarity")
	859d880cf544 ("signal: Correct the offset of si_pkey in struct siginfo")
 	8420f71943ae ("signal: Correct the offset of si_pkey and si_lower in struct siginfo on m68k")

In an ideal world, we could just have si_addr + the union in _sigfault,
but it seems there are more corner cases. :-/

The reason I've stumbled upon this is that I wanted to add the just
merged si_perf [1] field to glibc. But what I noticed is that glibc's
definition and ours are vastly different around si_addr_lsb, si_lower,
si_upper, and si_pkey.

[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=42dec9a936e7696bea1f27d3c5a0068cd9aa95fd

In our current definition of siginfo_t, si_addr_lsb is placed into the
same union as si_lower, si_upper, and si_pkey (and now si_perf). From
the logs I see that si_lower, si_upper, and si_pkey are padded because
si_addr_lsb used to be outside the union, which goes back to
"signal: Move addr_lsb into the _sigfault union for clarity".

Since then, si_addr_lsb must also be pointer-aligned, because the union
containing it must be pointer-aligned (because si_upper, si_lower). On
all architectures where si_addr_lsb is right after si_addr, this is
perfectly fine, because si_addr itself is a pointer...

... except for the anomaly that are 64-bit architectures that define
__ARCH_SI_TRAPNO and want that 'int si_trapno'. Like, for example
sparc64, which means siginfo_t's ABI has been subtly broken on sparc64
since v4.16.

The following static asserts illustrate this:

--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -556,3 +556,37 @@ void do_notify_resume(struct pt_regs *regs, unsigned long orig_i0, unsigned long
 	user_enter();
 }
 
+static_assert(offsetof(siginfo_t, si_signo)	== 0);
+static_assert(offsetof(siginfo_t, si_errno)	== 4);
+static_assert(offsetof(siginfo_t, si_code)	== 8);
+static_assert(offsetof(siginfo_t, si_pid)	== 16);
+static_assert(offsetof(siginfo_t, si_uid)	== 20);
+static_assert(offsetof(siginfo_t, si_tid)	== 16);
+static_assert(offsetof(siginfo_t, si_overrun)	== 20);
+static_assert(offsetof(siginfo_t, si_status)	== 24);
+static_assert(offsetof(siginfo_t, si_utime)	== 32);
+static_assert(offsetof(siginfo_t, si_stime)	== 40);
+static_assert(offsetof(siginfo_t, si_value)	== 24);
+static_assert(offsetof(siginfo_t, si_int)	== 24);
+static_assert(offsetof(siginfo_t, si_ptr)	== 24);
+static_assert(offsetof(siginfo_t, si_addr)	== 16);
+static_assert(offsetof(siginfo_t, si_trapno)	== 24);
+#if 1 /* Correct offsets, obtained from v4.14 */
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 28);
+static_assert(offsetof(siginfo_t, si_lower)	== 32);
+static_assert(offsetof(siginfo_t, si_upper)	== 40);
+static_assert(offsetof(siginfo_t, si_pkey)	== 32);
+#else /* Current offsets, as of v4.16 */
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 32);
+static_assert(offsetof(siginfo_t, si_lower)	== 40);
+static_assert(offsetof(siginfo_t, si_upper)	== 48);
+static_assert(offsetof(siginfo_t, si_pkey)	== 40);
+#endif
+static_assert(offsetof(siginfo_t, si_band)	== 16);
+static_assert(offsetof(siginfo_t, si_fd)	== 20);

---

Granted, nobody seems to have noticed because I don't even know if these
fields have use on sparc64. But I don't yet see this as justification to
leave things as-is...

The collateral damage of this, and the acute problem that I'm having is
defining si_perf in a sort-of readable and portable way in siginfo_t
definitions that live outside the kernel, where sparc64 does not yet
have broken si_addr_lsb. And the same difficulty applies to the kernel
if we want to unbreak sparc64, while not wanting to move si_perf for
other architectures.

There are 2 options I see to solve this:

1. Make things simple again. We could just revert the change moving
   si_addr_lsb into the union, and sadly accept we'll have to live with
   that legacy "design" mistake. (si_perf stays in the union, but will
   unfortunately change its offset for all architectures... this one-off
   move might be ok because it's new.)

2. Add special cases to retain si_addr_lsb in the union on architectures
   that do not have __ARCH_SI_TRAPNO (the majority). I have added a
   draft patch that would do this below (with some refactoring so that
   it remains sort-of readable), as an experiment to see how complicated
   this gets.

Option (1) means we'll forever be wasting the space where si_addr_lsb
lives (including the padding). It'd also mean we'd move si_perf for
_all_ architectures -- this might be acceptable, given there is no
stable release with it yet -- the fix just needs to be merged before the
release of v5.13! It is the simpler option though -- and I don't know if
we need all this complexity.

Option (2) perhaps results in better space utilization. Maybe that's
better long-term if we worry about space in some rather distant future
-- where we need those 8 bytes on 64-bit architectures to not exceed 128
bytes. This option, however, doesn't just make us carry this complexity
forever, but also forces it onto everyone else, like glibc and other
libcs (including those in other languages with C FFIs) which have their
own definition of siginfo_t.

Which option do you prefer? Are there better options?

Many thanks,
-- Marco

------ >8 ------

Option #2 draft:

diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index a0eec62c825d..150ee27b1423 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -556,3 +556,37 @@ void do_notify_resume(struct pt_regs *regs, unsigned long orig_i0, unsigned long
 	user_enter();
 }
 
+/*
+ * Compile-time assertions for siginfo_t offsets. Unlike other architectures,
+ * sparc64 is special, because it requires si_trapno (int), and the following
+ * si_addr_lsb (short) need not be word aligned. Accidental changes around the
+ * offset of si_addr_lsb and the following fields would only be caught here.
+ */
+static_assert(offsetof(siginfo_t, si_signo)	== 0);
+static_assert(offsetof(siginfo_t, si_errno)	== 4);
+static_assert(offsetof(siginfo_t, si_code)	== 8);
+static_assert(offsetof(siginfo_t, si_pid)	== 16);
+static_assert(offsetof(siginfo_t, si_uid)	== 20);
+static_assert(offsetof(siginfo_t, si_tid)	== 16);
+static_assert(offsetof(siginfo_t, si_overrun)	== 20);
+static_assert(offsetof(siginfo_t, si_status)	== 24);
+static_assert(offsetof(siginfo_t, si_utime)	== 32);
+static_assert(offsetof(siginfo_t, si_stime)	== 40);
+static_assert(offsetof(siginfo_t, si_value)	== 24);
+static_assert(offsetof(siginfo_t, si_int)	== 24);
+static_assert(offsetof(siginfo_t, si_ptr)	== 24);
+static_assert(offsetof(siginfo_t, si_addr)	== 16);
+static_assert(offsetof(siginfo_t, si_trapno)	== 24);
+#if 1 /* Correct offsets, obtained from v4.14 */
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 28);
+static_assert(offsetof(siginfo_t, si_lower)	== 32);
+static_assert(offsetof(siginfo_t, si_upper)	== 40);
+static_assert(offsetof(siginfo_t, si_pkey)	== 32);
+#else /* Current offsets, as of v4.16 */
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 32);
+static_assert(offsetof(siginfo_t, si_lower)	== 40);
+static_assert(offsetof(siginfo_t, si_upper)	== 48);
+static_assert(offsetof(siginfo_t, si_pkey)	== 40);
+#endif
+static_assert(offsetof(siginfo_t, si_band)	== 16);
+static_assert(offsetof(siginfo_t, si_fd)	== 20);
diff --git a/include/linux/compat.h b/include/linux/compat.h
index f0d2dd35d408..5ea9f9c748dd 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -158,6 +158,31 @@ typedef union compat_sigval {
 	compat_uptr_t	sival_ptr;
 } compat_sigval_t;
 
+struct __compat_sigfault_addin {
+#ifdef __ARCH_SI_TRAPNO
+	int _trapno;	/* TRAP # which caused the signal */
+#endif
+	/*
+	 * used when si_code=BUS_MCEERR_AR or
+	 * used when si_code=BUS_MCEERR_AO
+	 */
+	short int _addr_lsb;	/* Valid LSB of the reported address. */
+
+/* See include/asm-generic/uapi/siginfo.h */
+#ifdef __ARCH_SI_TRAPNO
+#	define __COMPAT_SIGFAULT_ADDIN_FIXED struct __compat_sigfault_addin _addin;
+#	define __COMPAT_SIGFAULT_ADDIN_UNION
+#	define __COMPAT_SIGFAULT_LEGACY_UNION_PAD
+#else
+#	define __COMPAT_SIGFAULT_ADDIN_FIXED
+#	define __COMPAT_SIGFAULT_ADDIN_UNION struct __compat_sigfault_addin _addin;
+#	define __COMPAT_SIGFAULT_LEGACY_UNION_PAD				\
+		char _unused[__alignof__(compat_uptr_t) < sizeof(short) ?       \
+				   sizeof(short) :				\
+				   __alignof__(compat_uptr_t)];
+#endif
+};
+
 typedef struct compat_siginfo {
 	int si_signo;
 #ifndef __ARCH_HAS_SWAPPED_SIGINFO
@@ -214,26 +239,18 @@ typedef struct compat_siginfo {
 		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
 		struct {
 			compat_uptr_t _addr;	/* faulting insn/memory ref. */
-#ifdef __ARCH_SI_TRAPNO
-			int _trapno;	/* TRAP # which caused the signal */
-#endif
-#define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
-				     sizeof(short) : __alignof__(compat_uptr_t))
+			__COMPAT_SIGFAULT_ADDIN_FIXED
 			union {
-				/*
-				 * used when si_code=BUS_MCEERR_AR or
-				 * used when si_code=BUS_MCEERR_AO
-				 */
-				short int _addr_lsb;	/* Valid LSB of the reported address. */
+				__COMPAT_SIGFAULT_ADDIN_UNION
 				/* used when si_code=SEGV_BNDERR */
 				struct {
-					char _dummy_bnd[__COMPAT_ADDR_BND_PKEY_PAD];
+					__COMPAT_SIGFAULT_LEGACY_UNION_PAD
 					compat_uptr_t _lower;
 					compat_uptr_t _upper;
 				} _addr_bnd;
 				/* used when si_code=SEGV_PKUERR */
 				struct {
-					char _dummy_pkey[__COMPAT_ADDR_BND_PKEY_PAD];
+					__COMPAT_SIGFAULT_LEGACY_UNION_PAD
 					u32 _pkey;
 				} _addr_pkey;
 				/* used when si_code=TRAP_PERF */
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 03d6f6d2c1fe..f1c1a0300ac8 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -29,6 +29,45 @@ typedef union sigval {
 #define __ARCH_SI_ATTRIBUTES
 #endif
 
+/*
+ * The _sigfault portion of __sifields after si_addr varies depending on
+ * architecture; capture these rules here.
+ */
+struct __sifields_sigfault_addin {
+#ifdef __ARCH_SI_TRAPNO
+	int _trapno;	/* TRAP # which caused the signal */
+#endif
+	/*
+	 * used when si_code=BUS_MCEERR_AR or
+	 * used when si_code=BUS_MCEERR_AO
+	 */
+	short _addr_lsb; /* LSB of the reported address */
+
+#if defined(__ARCH_SI_TRAPNO)
+/*
+ * If we have si_trapno between si_addr and si_addr_lsb, we cannot safely move
+ * it inside the union due to alignment of si_trapno+si_addr_lsb vs. the union.
+ */
+#	define __SI_SIGFAULT_ADDIN_FIXED struct __sifields_sigfault_addin _addin;
+#	define __SI_SIGFAULT_ADDIN_UNION
+#	define __SI_SIGFAULT_LEGACY_UNION_PAD
+#else
+/*
+ * Safe to move si_addr_lsb inside the union. We will benefit from better space
+ * usage for new fields added to the union.
+ *
+ * Fields that were added after si_addr_lsb, before it become part of the union,
+ * require padding to retain the ABI. New fields do not require padding.
+ */
+#	define __SI_SIGFAULT_ADDIN_FIXED
+#	define __SI_SIGFAULT_ADDIN_UNION struct __sifields_sigfault_addin _addin;
+#	define __SI_SIGFAULT_LEGACY_UNION_PAD				\
+		char _unused[__alignof__(void *) < sizeof(short) ?	\
+					   sizeof(short) :		\
+					   __alignof__(void *)];
+#endif
+};
+
 union __sifields {
 	/* kill() */
 	struct {
@@ -63,32 +102,23 @@ union __sifields {
 	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
 	struct {
 		void __user *_addr; /* faulting insn/memory ref. */
-#ifdef __ARCH_SI_TRAPNO
-		int _trapno;	/* TRAP # which caused the signal */
-#endif
 #ifdef __ia64__
 		int _imm;		/* immediate value for "break" */
 		unsigned int _flags;	/* see ia64 si_flags */
 		unsigned long _isr;	/* isr */
 #endif
-
-#define __ADDR_BND_PKEY_PAD  (__alignof__(void *) < sizeof(short) ? \
-			      sizeof(short) : __alignof__(void *))
+		__SI_SIGFAULT_ADDIN_FIXED
 		union {
-			/*
-			 * used when si_code=BUS_MCEERR_AR or
-			 * used when si_code=BUS_MCEERR_AO
-			 */
-			short _addr_lsb; /* LSB of the reported address */
+			__SI_SIGFAULT_ADDIN_UNION
 			/* used when si_code=SEGV_BNDERR */
 			struct {
-				char _dummy_bnd[__ADDR_BND_PKEY_PAD];
+				__SI_SIGFAULT_LEGACY_UNION_PAD
 				void __user *_lower;
 				void __user *_upper;
 			} _addr_bnd;
 			/* used when si_code=SEGV_PKUERR */
 			struct {
-				char _dummy_pkey[__ADDR_BND_PKEY_PAD];
+				__SI_SIGFAULT_LEGACY_UNION_PAD
 				__u32 _pkey;
 			} _addr_pkey;
 			/* used when si_code=TRAP_PERF */
@@ -151,9 +181,9 @@ typedef struct siginfo {
 #define si_ptr		_sifields._rt._sigval.sival_ptr
 #define si_addr		_sifields._sigfault._addr
 #ifdef __ARCH_SI_TRAPNO
-#define si_trapno	_sifields._sigfault._trapno
+#define si_trapno	_sifields._sigfault._addin._trapno
 #endif
-#define si_addr_lsb	_sifields._sigfault._addr_lsb
+#define si_addr_lsb	_sifields._sigfault._addin._addr_lsb
 #define si_lower	_sifields._sigfault._addr_bnd._lower
 #define si_upper	_sifields._sigfault._addr_bnd._upper
 #define si_pkey		_sifields._sigfault._addr_pkey._pkey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YIpkvGrBFGlB5vNj%40elver.google.com.
