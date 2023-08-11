Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJND3GTAMGQEH2KDIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 177047792D6
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 17:20:07 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1bdaa9d66a3sf2137235ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 08:20:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691767205; cv=pass;
        d=google.com; s=arc-20160816;
        b=KN3/+oq6JfhLkN5ITdCesto9iDiyeC65IRdeSpu1wWjZaCefRK/AlOW09brtTq2O2m
         92cr4/14EJGTYDfCpi0YVDymGa2NMS1BxJuh8hgqhmv5X40iEO2BPesfkbNw1woVo9Ys
         pdJM4ulNwZ+oeFS7bfAcTvYGxP6CeETyOb5pTenud5XtR0KcicGFkVgElW+zhxaEVp5V
         e6YTi6nFJ1YGQAbLbvzKj14+tt+UILgsnC9cZhA+r6/J8lvKE8CzjQwLFNvt17WAOsTQ
         Sg0Ga1sDOJASn7XpEPSvwSwl54f6nQwHMSlnLBBk8FelH4L5F1ej9rALDHFXh0Uw7uyb
         o8mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ts/x97BHLtmMGKdwM1dGAXkM/8dkJKdnJzcfPvPPOaU=;
        fh=qzUwxS9h9GHZXLKRdSveNA0UW/h6SdpMH03X1Oyv03c=;
        b=freneki1cXEQmZC1BIF3th8CeNz65i7ijBvsNSsVBPU1GrPjJPFEyo5hrK9lWxqvIW
         Et0XLvGwFRxSwoDYHAE/kv+eVTEj+JP1TAzecADnJoYC1cAgibI531iS5MpVg3HDR+yJ
         bZ215hk8swbzHfsawEp8rNYhXNktKEBVrEv2qe1lEEN9arLQfQwAx6SXp7k2V+yOapGq
         emWjeQWHrjJMsI0yKcF2roVY+1GyfgyMB8uUcJLon+9Keg5UxOrHOo5XXHK0VeyqpqHT
         sXJdBLGirYOikHr+u3rlVmSeyup3XrjBsTtMqm3pnGxUn/xbofG6/3Y6k/BplHbOl7Af
         u2Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=0RjpBwJr;
       spf=pass (google.com: domain of 3o1hwzaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3o1HWZAUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691767205; x=1692372005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ts/x97BHLtmMGKdwM1dGAXkM/8dkJKdnJzcfPvPPOaU=;
        b=O4ynoZfDcrw4bIZluExhxJCjHWDLQ1mJAR6TVyAk5wIB6kWnNJiaEz90xxZLNShNQ5
         p0xrNLpCX4ClUa096Rv05G3rxFuweSSm4bwtUF+tIfuTWDCObm8Pwl5x5wWW3dqvDXeF
         et+Dkk8ndGtIYIb28caw7U8TK95OR3sTbjDHJiGDKvn3aqS7yRyCQotjjGn7Zu8IPKdc
         XT8bp/b0AGltBCKPjQlcoOSLAIhD6HISzqkSQfAoCN++vyOzIGmGsK6J0RGtg/YxkhrJ
         O3jFYW+lCZl3JxSaUtuWSirx89d+7rVx+Pf4Z128Q1RvZWu1asSu/LtvbbUxMSFRdJdn
         DGNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691767205; x=1692372005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ts/x97BHLtmMGKdwM1dGAXkM/8dkJKdnJzcfPvPPOaU=;
        b=PAN2fmfhkz0aWk8fvUxRbbHLvwLBreLBtpK0uVTH4r7R3oQ/qT9+dUwmE9/7cwjLth
         +wmpjKyVsOsYkWvs5R8ISqwiEk7GArwKX8grgo46o5OT53yFRfEjvT12t+eF6wTIEbKA
         BVgJ/ybdqdXkhIkjwlgwv8jkQ0bpUjztJv40Xm7Zlp7IaaTIOHQuZu10WkpQ1Q+yZMby
         P74XgTBTDo0o3N6spBRTbJiHm63dRD+t+If4sZkc1n1Iw8b/22MHXYTu1RSS9oqu0owv
         sdxfvMgkb/FSAkc77sM+z1RhEo+VhRdggKgIRIobuGX1HRSRJCKQKC15I5/c8gkc6u34
         pKhw==
X-Gm-Message-State: AOJu0YxYBGkxDVbtRBHFtjC5zfWLORZC3ZLkYquXO6pzC2pzBtJ6TV84
	8j6j2JQF7BFCdKInQQpXfBU=
X-Google-Smtp-Source: AGHT+IFiv/o/JvxuEeLsGZTFFa3DupXwywfX4JgY23SEWsZns5VpdF4IyfsAGRR2SQg73C3FW81YBQ==
X-Received: by 2002:a17:903:41cd:b0:1b0:26c0:757d with SMTP id u13-20020a17090341cd00b001b026c0757dmr284059ple.22.1691767205364;
        Fri, 11 Aug 2023 08:20:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9f4e:0:b0:686:a110:9519 with SMTP id h14-20020aa79f4e000000b00686a1109519ls1723870pfr.0.-pod-prod-09-us;
 Fri, 11 Aug 2023 08:20:04 -0700 (PDT)
X-Received: by 2002:a05:6a00:8c7:b0:67a:8f2a:2cb2 with SMTP id s7-20020a056a0008c700b0067a8f2a2cb2mr2366083pfu.20.1691767204234;
        Fri, 11 Aug 2023 08:20:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691767204; cv=none;
        d=google.com; s=arc-20160816;
        b=WYqRFZh//IfX7fRpsChZyW1W+NFbe7BhKCs1wup+03aY4GHXEIskqi58bLU/HJTMob
         ZopMpyfKpFkttbZ71DtEw1BLAR4Eg/OF49YtxIiXEqKNIGGNUkVuWXNcQUhTgigAMCUU
         kO+gKM4Lxxeb39NdRlo/A1h6sSFN6h9Sw2YaMpKLw2PswNcxr8p3v3GchvdlKy8fys8/
         By1h0DWq2Sfl9tSCqhsLmkQUiBnvicLslIOr5Azk1JeXGWNmv+O4JPluiI9kZmITHi09
         Am4l481pqc7lNXJqy9OAwmJsULAyQmm3S7JZveAHarHywYHuWy0w3r2osu8YmafNW6ro
         iwug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rS381it9UYEeasrqdhU1KJ8J8i5NBjxji31IXhusmao=;
        fh=xh/g7dNJbwYr9WVB3rCguj1R0VLL65UcAaOvl7LeWOQ=;
        b=dWAqa3VNBaPpMPQ3aZd5KgSiPCGjhU6Dtbps+pLA6ID1OLcQgsfozQ746IYrXJElpn
         8WF6ESUuHBb3V7zOy/Ff7UBmMJr6ZaKwBRleEW4DlrhHlVyeQ1b6oeL8Zsno48KG2pwS
         +cKw67F5wizVbypWnY3DZ6zcb8FjXL9B/RMKxPMkYPDw0+hgaPMPU2It2qkFDIaRbO7i
         Bl1e72PO5XY4jkyvbxWKjTm5no7VlI31nCoJxbmdnlTqphMNfEuY7sGlCJC1DMljSv3e
         2mAzxCIDH0x47SXL13VLpbVc4RS1wFtV5GW85vwcLlTmwxRx/vvkhMFkjxILt5UiKbJC
         ZV5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=0RjpBwJr;
       spf=pass (google.com: domain of 3o1hwzaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3o1HWZAUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id cq9-20020a056a00330900b00681f56016b9si254230pfb.4.2023.08.11.08.20.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 08:20:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o1hwzaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-589cd098d24so3055987b3.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 08:20:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8dc0:5176:6fda:46a0])
 (user=elver job=sendgmr) by 2002:a05:690c:709:b0:57a:118a:f31 with SMTP id
 bs9-20020a05690c070900b0057a118a0f31mr45931ywb.7.1691767203457; Fri, 11 Aug
 2023 08:20:03 -0700 (PDT)
Date: Fri, 11 Aug 2023 17:18:40 +0200
In-Reply-To: <20230811151847.1594958-1-elver@google.com>
Mime-Version: 1.0
References: <20230811151847.1594958-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.694.ge786442a9b-goog
Message-ID: <20230811151847.1594958-3-elver@google.com>
Subject: [PATCH v4 3/4] list: Introduce CONFIG_LIST_HARDENED
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Paul Moore <paul@paul-moore.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org, 
	llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=0RjpBwJr;       spf=pass
 (google.com: domain of 3o1hwzaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3o1HWZAUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Numerous production kernel configs (see [1, 2]) are choosing to enable
CONFIG_DEBUG_LIST, which is also being recommended by KSPP for hardened
configs [3]. The motivation behind this is that the option can be used
as a security hardening feature (e.g. CVE-2019-2215 and CVE-2019-2025
are mitigated by the option [4]).

The feature has never been designed with performance in mind, yet common
list manipulation is happening across hot paths all over the kernel.

Introduce CONFIG_LIST_HARDENED, which performs list pointer checking
inline, and only upon list corruption calls the reporting slow path.

To generate optimal machine code with CONFIG_LIST_HARDENED:

  1. Elide checking for pointer values which upon dereference would
     result in an immediate access fault (i.e. minimal hardening
     checks).  The trade-off is lower-quality error reports.

  2. Use the __preserve_most function attribute (available with Clang,
     but not yet with GCC) to minimize the code footprint for calling
     the reporting slow path. As a result, function size of callers is
     reduced by avoiding saving registers before calling the rarely
     called reporting slow path.

     Note that all TUs in lib/Makefile already disable function tracing,
     including list_debug.c, and __preserve_most's implied notrace has
     no effect in this case.

  3. Because the inline checks are a subset of the full set of checks in
     __list_*_valid_or_report(), always return false if the inline
     checks failed.  This avoids redundant compare and conditional
     branch right after return from the slow path.

As a side-effect of the checks being inline, if the compiler can prove
some condition to always be true, it can completely elide some checks.

Since DEBUG_LIST is functionally a superset of LIST_HARDENED, the
Kconfig variables are changed to reflect that: DEBUG_LIST selects
LIST_HARDENED, whereas LIST_HARDENED itself has no dependency on
DEBUG_LIST.

Running netperf with CONFIG_LIST_HARDENED (using a Clang compiler with
"preserve_most") shows throughput improvements, in my case of ~7% on
average (up to 20-30% on some test cases).

Link: https://r.android.com/1266735 [1]
Link: https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/blob/main/config [2]
Link: https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings [3]
Link: https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html [4]
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename to CONFIG_LIST_HARDENED, which can independently be selected
  from CONFIG_DEBUG_LIST.
* LKDTM test should just check CONFIG_LIST_HARDENED (which is also
  implied by DEBUG_LIST).
* Comment word smithing.

v3:
* Rename ___list_*_valid() to __list_*_valid_or_report().
* More comments.

v2:
* Note that lib/Makefile disables function tracing for everything and
  __preserve_most's implied notrace is a noop here.
---
 arch/arm64/kvm/hyp/nvhe/Makefile     |  2 +-
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  2 +
 drivers/misc/lkdtm/bugs.c            |  4 +-
 include/linux/list.h                 | 64 +++++++++++++++++++++++++---
 lib/Kconfig.debug                    |  9 +++-
 lib/Makefile                         |  2 +-
 lib/list_debug.c                     |  5 ++-
 security/Kconfig.hardening           | 13 ++++++
 8 files changed, 88 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Makefile
index 9ddc025e4b86..2250253a6429 100644
--- a/arch/arm64/kvm/hyp/nvhe/Makefile
+++ b/arch/arm64/kvm/hyp/nvhe/Makefile
@@ -25,7 +25,7 @@ hyp-obj-y := timer-sr.o sysreg-sr.o debug-sr.o switch.o tlb.o hyp-init.o host.o
 	 cache.o setup.o mm.o mem_protect.o sys_regs.o pkvm.o stacktrace.o ffa.o
 hyp-obj-y += ../vgic-v3-sr.o ../aarch32.o ../vgic-v2-cpuif-proxy.o ../entry.o \
 	 ../fpsimd.o ../hyp-entry.o ../exception.o ../pgtable.o
-hyp-obj-$(CONFIG_DEBUG_LIST) += list_debug.o
+hyp-obj-$(CONFIG_LIST_HARDENED) += list_debug.o
 hyp-obj-y += $(lib-objs)
 
 ##
diff --git a/arch/arm64/kvm/hyp/nvhe/list_debug.c b/arch/arm64/kvm/hyp/nvhe/list_debug.c
index 16266a939a4c..46a2d4f2b3c6 100644
--- a/arch/arm64/kvm/hyp/nvhe/list_debug.c
+++ b/arch/arm64/kvm/hyp/nvhe/list_debug.c
@@ -26,6 +26,7 @@ static inline __must_check bool nvhe_check_data_corruption(bool v)
 
 /* The predicates checked here are taken from lib/list_debug.c. */
 
+__list_valid_slowpath
 bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 				struct list_head *next)
 {
@@ -37,6 +38,7 @@ bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 	return true;
 }
 
+__list_valid_slowpath
 bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
diff --git a/drivers/misc/lkdtm/bugs.c b/drivers/misc/lkdtm/bugs.c
index 3c95600ab2f7..963b4dee6a7d 100644
--- a/drivers/misc/lkdtm/bugs.c
+++ b/drivers/misc/lkdtm/bugs.c
@@ -393,7 +393,7 @@ static void lkdtm_CORRUPT_LIST_ADD(void)
 		pr_err("Overwrite did not happen, but no BUG?!\n");
 	else {
 		pr_err("list_add() corruption not detected!\n");
-		pr_expected_config(CONFIG_DEBUG_LIST);
+		pr_expected_config(CONFIG_LIST_HARDENED);
 	}
 }
 
@@ -420,7 +420,7 @@ static void lkdtm_CORRUPT_LIST_DEL(void)
 		pr_err("Overwrite did not happen, but no BUG?!\n");
 	else {
 		pr_err("list_del() corruption not detected!\n");
-		pr_expected_config(CONFIG_DEBUG_LIST);
+		pr_expected_config(CONFIG_LIST_HARDENED);
 	}
 }
 
diff --git a/include/linux/list.h b/include/linux/list.h
index 130c6a1bb45c..164b4d0e9d2a 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -38,39 +38,91 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 	WRITE_ONCE(list->prev, list);
 }
 
+#ifdef CONFIG_LIST_HARDENED
+
 #ifdef CONFIG_DEBUG_LIST
+# define __list_valid_slowpath
+#else
+# define __list_valid_slowpath __cold __preserve_most
+#endif
+
 /*
  * Performs the full set of list corruption checks before __list_add().
  * On list corruption reports a warning, and returns false.
  */
-extern bool __list_add_valid_or_report(struct list_head *new,
-				       struct list_head *prev,
-				       struct list_head *next);
+extern bool __list_valid_slowpath __list_add_valid_or_report(struct list_head *new,
+							     struct list_head *prev,
+							     struct list_head *next);
 
 /*
  * Performs list corruption checks before __list_add(). Returns false if a
  * corruption is detected, true otherwise.
+ *
+ * With CONFIG_LIST_HARDENED only, performs minimal list integrity checking
+ * inline to catch non-faulting corruptions, and only if a corruption is
+ * detected calls the reporting function __list_add_valid_or_report().
  */
 static __always_inline bool __list_add_valid(struct list_head *new,
 					     struct list_head *prev,
 					     struct list_head *next)
 {
-	return __list_add_valid_or_report(new, prev, next);
+	bool ret = true;
+
+	if (!IS_ENABLED(CONFIG_DEBUG_LIST)) {
+		/*
+		 * With the hardening version, elide checking if next and prev
+		 * are NULL, since the immediate dereference of them below would
+		 * result in a fault if NULL.
+		 *
+		 * With the reduced set of checks, we can afford to inline the
+		 * checks, which also gives the compiler a chance to elide some
+		 * of them completely if they can be proven at compile-time. If
+		 * one of the pre-conditions does not hold, the slow-path will
+		 * show a report which pre-condition failed.
+		 */
+		if (likely(next->prev == prev && prev->next == next && new != prev && new != next))
+			return true;
+		ret = false;
+	}
+
+	ret &= __list_add_valid_or_report(new, prev, next);
+	return ret;
 }
 
 /*
  * Performs the full set of list corruption checks before __list_del_entry().
  * On list corruption reports a warning, and returns false.
  */
-extern bool __list_del_entry_valid_or_report(struct list_head *entry);
+extern bool __list_valid_slowpath __list_del_entry_valid_or_report(struct list_head *entry);
 
 /*
  * Performs list corruption checks before __list_del_entry(). Returns false if a
  * corruption is detected, true otherwise.
+ *
+ * With CONFIG_LIST_HARDENED only, performs minimal list integrity checking
+ * inline to catch non-faulting corruptions, and only if a corruption is
+ * detected calls the reporting function __list_del_entry_valid_or_report().
  */
 static __always_inline bool __list_del_entry_valid(struct list_head *entry)
 {
-	return __list_del_entry_valid_or_report(entry);
+	bool ret = true;
+
+	if (!IS_ENABLED(CONFIG_DEBUG_LIST)) {
+		struct list_head *prev = entry->prev;
+		struct list_head *next = entry->next;
+
+		/*
+		 * With the hardening version, elide checking if next and prev
+		 * are NULL, LIST_POISON1 or LIST_POISON2, since the immediate
+		 * dereference of them below would result in a fault.
+		 */
+		if (likely(prev->next == entry && next->prev == entry))
+			return true;
+		ret = false;
+	}
+
+	ret &= __list_del_entry_valid_or_report(entry);
+	return ret;
 }
 #else
 static inline bool __list_add_valid(struct list_head *new,
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index fbc89baf7de6..c38745ad46eb 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1674,9 +1674,14 @@ menu "Debug kernel data structures"
 config DEBUG_LIST
 	bool "Debug linked list manipulation"
 	depends on DEBUG_KERNEL || BUG_ON_DATA_CORRUPTION
+	select LIST_HARDENED
 	help
-	  Enable this to turn on extended checks in the linked-list
-	  walking routines.
+	  Enable this to turn on extended checks in the linked-list walking
+	  routines.
+
+	  This option trades better quality error reports for performance, and
+	  is more suitable for kernel debugging. If you care about performance,
+	  you should only enable CONFIG_LIST_HARDENED instead.
 
 	  If unsure, say N.
 
diff --git a/lib/Makefile b/lib/Makefile
index 1ffae65bb7ee..d1397785ec16 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -167,7 +167,7 @@ obj-$(CONFIG_BTREE) += btree.o
 obj-$(CONFIG_INTERVAL_TREE) += interval_tree.o
 obj-$(CONFIG_ASSOCIATIVE_ARRAY) += assoc_array.o
 obj-$(CONFIG_DEBUG_PREEMPT) += smp_processor_id.o
-obj-$(CONFIG_DEBUG_LIST) += list_debug.o
+obj-$(CONFIG_LIST_HARDENED) += list_debug.o
 obj-$(CONFIG_DEBUG_OBJECTS) += debugobjects.o
 
 obj-$(CONFIG_BITREVERSE) += bitrev.o
diff --git a/lib/list_debug.c b/lib/list_debug.c
index 2def33b1491f..db602417febf 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -2,7 +2,8 @@
  * Copyright 2006, Red Hat, Inc., Dave Jones
  * Released under the General Public License (GPL).
  *
- * This file contains the linked list validation for DEBUG_LIST.
+ * This file contains the linked list validation and error reporting for
+ * LIST_HARDENED and DEBUG_LIST.
  */
 
 #include <linux/export.h>
@@ -17,6 +18,7 @@
  * attempt).
  */
 
+__list_valid_slowpath
 bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 				struct list_head *next)
 {
@@ -39,6 +41,7 @@ bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 }
 EXPORT_SYMBOL(__list_add_valid_or_report);
 
+__list_valid_slowpath
 bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 0f295961e773..ffc3c702b461 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -279,6 +279,19 @@ config ZERO_CALL_USED_REGS
 
 endmenu
 
+menu "Hardening of kernel data structures"
+
+config LIST_HARDENED
+	bool "Check integrity of linked list manipulation"
+	help
+	  Minimal integrity checking in the linked-list manipulation routines
+	  to catch memory corruptions that are not guaranteed to result in an
+	  immediate access fault.
+
+	  If unsure, say N.
+
+endmenu
+
 config CC_HAS_RANDSTRUCT
 	def_bool $(cc-option,-frandomize-layout-seed-file=/dev/null)
 	# Randstruct was first added in Clang 15, but it isn't safe to use until
-- 
2.41.0.694.ge786442a9b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230811151847.1594958-3-elver%40google.com.
