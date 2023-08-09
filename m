Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCOGZWTAMGQETEYK27Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 054987756BE
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Aug 2023 11:57:31 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-4fe6141914csf4319435e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Aug 2023 02:57:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691575050; cv=pass;
        d=google.com; s=arc-20160816;
        b=nABK61xbMIMQZKxDeECr0t/EJ9sVjg9oJ4k0ylQ6Q1ljFMgGU273pYf14Pewll+uPw
         89DkO9N92ILAYh6dldpWR5UXzTjv9DKRFrWw2hoknXj1A2mMNlbcsfNMyQDNv58m1wg0
         jEEgUWVTrSJmhNir/eAlTPhyGB/GelltAV+K44eEcGf79J2TyzMDrdFEMlhJ8gFMmsUA
         LLqaKoInEnyv0y7d4L9Gp6Z7gf51iq/rSMz9fQzEpV82h5Tnbd1Y8K/gC/OB+9rNQr/u
         ENnd6vwdM10Ma1vk7bSUq2MgoZl1U5CFyGDmRGnJrj8M/rb9WbLrjluBB66HN0AOs/bc
         U+yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xcNgqFanWbIc2RKOOElZWF2nc/VZs49wyrSgaw5sAXQ=;
        fh=cwzY8x7dDHilKeHMNJDjnqowd6448fHrWFIOQtERjqU=;
        b=QS1c28E2piSEgxDqLIAYTgF2jXffx1lBQyxbLS+NpbgH8DBwLoAuZVmUtBmzvU55wt
         A284SjX74jpHhLWFyUnlaT0ev9STZRbNU8wvhQMyH0X0N6lNZJLub3HWhw14NrzTPdw/
         rdiYskm+2VyK4A3rIOt1X4acJDUBNxjv6rkiIQZyvwRfrZtbLtLhiCZkr/XzjaV3fldT
         s3y4x+dfuafcDrs2dT5vV/FpDQw38qhaMD2JCOY50JM2ZJ5EkxwUbcob4fc31P1wIsLE
         //bHm8xeyQcWvdmklWXn6xA052J9OOhvCNdQ9RPR8jQCVKBnTDFIzOracTTqG7bIYNwG
         nIjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="zrFX/lyu";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691575050; x=1692179850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xcNgqFanWbIc2RKOOElZWF2nc/VZs49wyrSgaw5sAXQ=;
        b=K5T6JgGaP4aUWW+OcNKsz5tB/89cyXHu1nXOp/IgQQmvFQr0F4kP39q5pU0UokvXAw
         +bYU1zRakyHQ+EpG+buIGbVqNXtwTcoWoTuiOoFwLyqJ1M4y8Iz96Ch05t6vnYccPYJi
         h9UsJmD+SYKmlUZLcDn15AhAV+ptzNpXUCPSKak2YdTGx2DpTZD8cWQ8cFHuaagUYmL0
         LHE11L4cz51gM52OcPu+FdC4/ac5M1quZKCmnK+/2PX19rjOhl07rMG4Aur2uX8Hc2dT
         e/OEfg4eZ5Xz9gxlg4jtVuFfC9/DO1BkVU6mmThqB1UrbiwfEwg2VxAnh2kO8OEYdftM
         KDfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691575050; x=1692179850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xcNgqFanWbIc2RKOOElZWF2nc/VZs49wyrSgaw5sAXQ=;
        b=ILLsC6JATPHdQ21/yA2WpLljNhmrLf8NKwxqHdY1mHjNhjH+gw7eupnfw3SOI7vGwP
         K2j06hIf+Ip7K6sD/WgBrENZEQ4t9xAatTddXMsrS1QYbYtrgy4L6dKmjLufpGAT/aYr
         Ta69iJNN7DuYbLiBvXRkZPOZ7+yqQyHqNKwa099VNEPBznm4Uz7LR+IQbmmjc5WMBmP2
         lABDFflRNKxDjg+pIno56ynrmkyXqJDTjRwHhZ+DIXrjmIC+EhIsMO8Ib9XsdHYy/TkX
         m3VkQ4o/ZtFn+81+YuW6JejYbeQgN1O+MOeIqOSZXOVZUQMzKebp22w1zNK0bwtPcYmy
         R8BQ==
X-Gm-Message-State: AOJu0YwjPKmskqBoJyXFcbAP0a66pI4dHcLDHS6eJjFLooFjASPa+qOH
	TkurKtvwA99WLw60k29/+10=
X-Google-Smtp-Source: AGHT+IHcCOxshgcSgiWkBTmORoSOwNL/s7upQOZxnT5bnurAb03+YRfZ29dvKr0DPBU3mj7X1grm2g==
X-Received: by 2002:ac2:5e2f:0:b0:4fb:8948:2b8e with SMTP id o15-20020ac25e2f000000b004fb89482b8emr1357862lfg.8.1691575049602;
        Wed, 09 Aug 2023 02:57:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4649:0:b0:4fe:3cb9:db1f with SMTP id s9-20020ac24649000000b004fe3cb9db1fls1795536lfo.1.-pod-prod-09-eu;
 Wed, 09 Aug 2023 02:57:27 -0700 (PDT)
X-Received: by 2002:a05:6512:1048:b0:4f8:651f:9bbe with SMTP id c8-20020a056512104800b004f8651f9bbemr2016239lfb.54.1691575047499;
        Wed, 09 Aug 2023 02:57:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691575047; cv=none;
        d=google.com; s=arc-20160816;
        b=hQtwXFQ7GX6sJjwzvbWM2w4jpjoSB1lt/0j3OrM/jsjCssUg4MhIjBKp1s6RCJtMFi
         O9G4wb7qVUz1KXKycZDyaF65Psme6pYuCYRVaVapT7r9keCS6FSE5FE7QgKcm9BtsXNf
         RGL5sw1bloNX69kipboZnA0fKQPwlud5l9yhfbeEpT7J92ropvCudYKZkMVL2lgilFbb
         cj3u6NDtwRboMJWQEXl24qPRagmzaj2TvHcwa6JK8l8rTYqKgl7CHi4iA4WsZXH5RJx5
         maXuvd8lyQuCZK7zH/G210vxkHJr6qfPdLcHkoGqwfK7u4rEXpFsDP6XAWlDrqLjta8W
         yTQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/rmEnk1g8Unm9TjBDd1nYGxjvPpnWaZtUFtYH71EmO0=;
        fh=OhVD7+5q5gV7DhBXNYxg3SR/gDmJhPIj0bBm5u8U3nw=;
        b=YuueHB/Kab+WlnjnewE/Lnf+eShGfureh5iy/5MIwomaM86KI3Tpd+atZw7Qxi1YcN
         xj0JfwQjzczS85IDaVSoO55FfMBclJw+SlCJx+PbBLidYtw6R2VLJdzR4/Gzim7PhUJw
         Pq1kTObsFHc4GJAi6dm+/KPj45iC/fdxzIsGluB99U8p9cUj9Rf1+oEiXOVMxOs71m9N
         +uKvNTF4sm1Lp4eBDiYulX6TisvdatiLbOKx6UgKu7S+dPxs6hucVdboK15M1podzcfE
         lNA+csawMFGt/EvsWJK1+r8obI32muyKaylqh/UDewqwQ0MBsDvGFGqHhizRW7Cce93q
         Surw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="zrFX/lyu";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id qf9-20020a1709077f0900b0099c3ca79cd6si1198278ejc.2.2023.08.09.02.57.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Aug 2023 02:57:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-3fe5c0e587eso28066905e9.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Aug 2023 02:57:27 -0700 (PDT)
X-Received: by 2002:a05:600c:210:b0:3fe:ad3:b066 with SMTP id 16-20020a05600c021000b003fe0ad3b066mr1884370wmi.41.1691575046903;
        Wed, 09 Aug 2023 02:57:26 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:9ce0:327a:6e5a:3533])
        by smtp.gmail.com with ESMTPSA id h18-20020a1ccc12000000b003fbd9e390e1sm1479988wmb.47.2023.08.09.02.57.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Aug 2023 02:57:25 -0700 (PDT)
Date: Wed, 9 Aug 2023 11:57:19 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v3 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
Message-ID: <ZNNi/4L1mD8XPNix@elver.google.com>
References: <20230808102049.465864-1-elver@google.com>
 <20230808102049.465864-3-elver@google.com>
 <202308081424.1DC7AA4AE3@keescook>
 <CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A@mail.gmail.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="zrFX/lyu";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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

On Wed, Aug 09, 2023 at 09:35AM +0200, Marco Elver wrote:

> > I'd really like to get away from calling this "DEBUG", since it's used
> > more for hardening (CONFIG_LIST_HARDENED?). Will Deacon spent some time
> > making this better a while back, but the series never landed. Do you
> > have a bit of time to look through it?
> >
> > https://github.com/KSPP/linux/issues/10
> > https://lore.kernel.org/lkml/20200324153643.15527-1-will@kernel.org/
> 
> I'm fine renaming this one. But there are other issues that Will's
> series solves, which I don't want this series to depend on. We can try
> to sort them out separately.
> 
> The main problem here is that DEBUG_LIST has been designed to be
> friendly for debugging (incl. checking poison values and NULL). Some
> kernel devs may still want that, but for production use is pointless
> and wasteful.
> 
> So what I can propose is to introduce CONFIG_LIST_HARDENED that
> doesn't depend on CONFIG_DEBUG_LIST, but instead selects it, because
> we still use that code to produce a report.

How about the below?

We'll add CONFIG_HARDEN_LIST (in Kconfig.hardening), which is
independent of CONFIG_DEBUG_LIST. For the implementation it selects
DEBUG_LIST, but irrelevant for users.

This will get us the best of both worlds: a version for hardening that
should remain as fast as possible, and one for debugging with better
reports.

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Thu, 27 Jul 2023 22:19:02 +0200
Subject: [PATCH v4 3/3] list: Introduce CONFIG_HARDEN_LIST

Numerous production kernel configs (see [1, 2]) are choosing to enable
CONFIG_DEBUG_LIST, which is also being recommended by KSPP for hardened
configs [3]. The motivation behind this is that the option can be used
as a security hardening feature (e.g. CVE-2019-2215 and CVE-2019-2025
are mitigated by the option [4]).

The feature has never been designed with performance in mind, yet common
list manipulation is happening across hot paths all over the kernel.

Introduce CONFIG_HARDEN_LIST, which performs list pointer checking
inline, and only upon list corruption calls the reporting slow path.

To generate optimal machine code with CONFIG_HARDEN_LIST:

  1. Elide checking for pointer values which upon dereference would
     result in an immediate access fault -- therefore "minimal" checks.
     The trade-off is lower-quality error reports.

  2. Use the newly introduced __preserve_most function attribute
     (available with Clang, but not yet with GCC) to minimize the code
     footprint for calling the reporting slow path. As a result,
     function size of callers is reduced by avoiding saving registers
     before calling the rarely called reporting slow path.

     Note that all TUs in lib/Makefile already disable function tracing,
     including list_debug.c, and __preserve_most's implied notrace has
     no effect in this case.

  3. Because the inline checks are a subset of the full set of checks in
     __list_*_valid_or_report(), always return false if the inline
     checks failed.  This avoids redundant compare and conditional
     branch right after return from the slow path.

As a side-effect of the checks being inline, if the compiler can prove
some condition to always be true, it can completely elide some checks.

Running netperf with CONFIG_HARDEN_LIST (using a Clang compiler with
"preserve_most") shows throughput improvements, in my case of ~7% on
average (up to 20-30% on some test cases).

Link: https://r.android.com/1266735 [1]
Link: https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/blob/main/config [2]
Link: https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings [3]
Link: https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html [4]
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename to CONFIG_HARDEN_LIST, which can independently be selected from
  CONFIG_DEBUG_LIST.

v3:
* Rename ___list_*_valid() to __list_*_valid_or_report().
* More comments.

v2:
* Note that lib/Makefile disables function tracing for everything and
  __preserve_most's implied notrace is a noop here.
---
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  2 +
 include/linux/list.h                 | 64 +++++++++++++++++++++++++---
 lib/Kconfig.debug                    | 12 ++++--
 lib/list_debug.c                     |  2 +
 security/Kconfig.hardening           | 14 ++++++
 5 files changed, 84 insertions(+), 10 deletions(-)

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
diff --git a/include/linux/list.h b/include/linux/list.h
index 130c6a1bb45c..1c7f70b7cc7a 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -39,38 +39,90 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 }
 
 #ifdef CONFIG_DEBUG_LIST
+
+#ifdef CONFIG_HARDEN_LIST
+# define __list_valid_slowpath __cold __preserve_most
+#else
+# define __list_valid_slowpath
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
+ * With CONFIG_HARDEN_LIST set, performs minimal list integrity checking (that
+ * do not result in a fault) inline, and only if a corruption is detected calls
+ * the reporting function __list_add_valid_or_report().
  */
 static __always_inline bool __list_add_valid(struct list_head *new,
 					     struct list_head *prev,
 					     struct list_head *next)
 {
-	return __list_add_valid_or_report(new, prev, next);
+	bool ret = true;
+
+	if (IS_ENABLED(CONFIG_HARDEN_LIST)) {
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
+ * With CONFIG_HARDEN_LIST set, performs minimal list integrity checking (that
+ * do not result in a fault) inline, and only if a corruption is detected calls
+ * the reporting function __list_del_entry_valid_or_report().
  */
 static __always_inline bool __list_del_entry_valid(struct list_head *entry)
 {
-	return __list_del_entry_valid_or_report(entry);
+	bool ret = true;
+
+	if (IS_ENABLED(CONFIG_HARDEN_LIST)) {
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
index fbc89baf7de6..6b0de78fb2da 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1672,11 +1672,15 @@ config HAVE_DEBUG_BUGVERBOSE
 menu "Debug kernel data structures"
 
 config DEBUG_LIST
-	bool "Debug linked list manipulation"
-	depends on DEBUG_KERNEL || BUG_ON_DATA_CORRUPTION
+	bool "Debug linked list manipulation" if !HARDEN_LIST
+	depends on DEBUG_KERNEL || BUG_ON_DATA_CORRUPTION || HARDEN_LIST
 	help
-	  Enable this to turn on extended checks in the linked-list
-	  walking routines.
+	  Enable this to turn on extended checks in the linked-list walking
+	  routines.
+
+	  If you care about performance, you should enable CONFIG_HARDEN_LIST
+	  instead.  This option alone trades better quality error reports for
+	  worse performance, and is more suitable for debugging.
 
 	  If unsure, say N.
 
diff --git a/lib/list_debug.c b/lib/list_debug.c
index 2def33b1491f..0ff547910dd0 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -17,6 +17,7 @@
  * attempt).
  */
 
+__list_valid_slowpath
 bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 				struct list_head *next)
 {
@@ -39,6 +40,7 @@ bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
 }
 EXPORT_SYMBOL(__list_add_valid_or_report);
 
+__list_valid_slowpath
 bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 0f295961e773..a8aef895f13d 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -279,6 +279,20 @@ config ZERO_CALL_USED_REGS
 
 endmenu
 
+menu "Hardening of kernel data structures"
+
+config HARDEN_LIST
+	bool "Check integrity of linked list manipulation"
+	select DEBUG_LIST
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
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNNi/4L1mD8XPNix%40elver.google.com.
