Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLP7Z2TAMGQETV52H4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E78D877652B
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Aug 2023 18:32:46 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-31400956ce8sf25909f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Aug 2023 09:32:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691598766; cv=pass;
        d=google.com; s=arc-20160816;
        b=EIuFmhWL9zKFLJcGOv3DR48yqPYLoNBwfSN7t1Y3ALL+9UUi/ki0OdRAvs4fsuuCF7
         KOd0QWJ+cKXyPx0K5bzs/nTakWbDsztqIrrM6Mdb6qOhfxYoSfKq7LuIeFTuV5sfSUyJ
         DFWWAt7rq07KzWr8tYPxqrJVk9Qia8brY4fwnK19YbK/lDDLiwBg/gbKfeJocI8T7ORY
         xSoMcdNG/YAZN+d04NGA5EJWyWkKwvKfY0asMFlYLjlqBdkTI3r86vJOrckCgnr4TqFZ
         WFoC0Y3bwbwql8+wb9Wz12H1Lkj2Seh0KCKjbUL1RCAWeHJL9heaphyeEa3n/3voGtej
         MvWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9fLP1w2dfkREFILIFuDQUprlTcclvg590LYizSfbgF4=;
        fh=eVGcyMNUaZKF9nc8V+EFfIBBM67ampZUt82bcT6UxHI=;
        b=U/QNmgCAyVZmKjkmofveBFvHU1OKMOjs8kb7hGgfZlP57tsMHFwRAgN8s9rTErLXUV
         j9/1J8vyMeXsyugTq8khR+ZirCcUNdSVqOZocEnxmrnxLun2w9cg4cvEtQV/bEyoi9O3
         RM2X2bEUgq6vOvbELptONQFosSerOVKHwUvZTHAZwDoCpbohfD8HegITS+y4ZYwzBiYT
         DweZ50saIX0kbCSCgR0UlPiDEeNqQAS1LM5Hymcc6oSZdxXf41cS+J/QjY+4eMrIAE6Q
         EWwzD3d+iFmzlpw4/4Kw7AH8QCm8JODMhlAJYMw+21rHqEl4pgKMUCCgkfKd+Srv9CgS
         TfTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="LbvtTy/F";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691598766; x=1692203566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9fLP1w2dfkREFILIFuDQUprlTcclvg590LYizSfbgF4=;
        b=beaB0hKJnZrKJde0+dT9Hl54lb1wBk35rCdkDK0dB3P0uAM1b1fJPdrATDmt9ugoDK
         bdPWvK3Hqxh7+BXocduNZ89T9Rws1ZMlpg/bTvSvwpKKuQLvEux+jmOExtqD4PlYYUY4
         mNu0LqJB6d/wWUuYYbR28xuM1lNN9bxL4nbqmMzyCk9Luvl5V5pS5DtNVjgC+/5yhEr+
         B9WPp1DtzgYsqkZzuzJET14YvbdDRx+UQNIA3C5XtkjgQWxpebkWp0MKUcX6ZmK78SeZ
         TT/5HK9y9+gq5UmcbCLC9IYTir/q1T3CqSJ4zczXZJ/6cWax2iiwLWnFwtJ2B/JLHx8L
         O7pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691598766; x=1692203566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9fLP1w2dfkREFILIFuDQUprlTcclvg590LYizSfbgF4=;
        b=bBl+XanEwwTvmbUlFACB/Gv/PXnUG8fQ8vTYJj0kNsAB61ij1+dXJ+wKyEDuCvUaMo
         CVaTRiPdbZgq7bkJ3gKyj0TmJkSyfwbwOIbEehN9WFWcrSJeldSm5ICePNA6VLWDPDLR
         OeXYnPGqzwfrwbXTJImEiZMLIi71glOQCccpDfdWvja/ZuCTacEd0ZURL7QlcqS6SHoY
         v8E9f81ijKMnD0U95KhNh2xCmKJX2gXwVlHJTeVYu5dzQoxvkW7G1oamKh+w4Pt49lUv
         SGDlDNHY7CTdWUGG1NleznM4+oPNA8nlN2fNHzEWCtxmPki/YSOkzpicNS3xPioTJZPf
         bZEg==
X-Gm-Message-State: AOJu0YyizIgfW2pwDS+ojIIPq+RZ3RiJThGmLNZnXnyIJrrZggmUXNcL
	Uf91qsRi5auiN/fHHvbZmh4=
X-Google-Smtp-Source: AGHT+IFBK6nMna4w5Z8c3F7I70zJR0DfVS7iy90ESQ30gNscUqcJWJYACjJWUNDyWa48c0w4GPBrVQ==
X-Received: by 2002:adf:f9d1:0:b0:317:5ddb:a8bf with SMTP id w17-20020adff9d1000000b003175ddba8bfmr2033030wrr.29.1691598765849;
        Wed, 09 Aug 2023 09:32:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c6:0:b0:317:79ec:7a0 with SMTP id k6-20020adfe3c6000000b0031779ec07a0ls1616214wrm.1.-pod-prod-04-eu;
 Wed, 09 Aug 2023 09:32:44 -0700 (PDT)
X-Received: by 2002:a05:600c:20f:b0:3fe:3b8e:1cba with SMTP id 15-20020a05600c020f00b003fe3b8e1cbamr2531754wmi.6.1691598763938;
        Wed, 09 Aug 2023 09:32:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691598763; cv=none;
        d=google.com; s=arc-20160816;
        b=sHAjKQmMUTIbQgugGvIcLu1oLLHHKpVyu6A9R3dEUM3mJRe5gtwxm+Lx1ZG5IWV6PM
         xCOkKMqrCsnGRW1xOojRUPb+cGffUWIWgBKq68ZvMBmT+h8rfsYUcKMz3q9gGPKYBISh
         4N0RTYkDHeRDRB6SYMmVbEyT57OwvUYAOk1gKlqwoLzy4vN6GMW2r19auFj+D0BKReOS
         FsMExUT/SWtCmgSKdvD8pORvPYjVyPG1xhNkXE4wy/yI4VnBAF8pYhQjHd0eHww+T3l+
         oDWbsht/0FmXfPcQ/VLCwJgKE+5xCfPob1dEdevnC2zss/XgWs/vLM9GPeTyDuf4MCqH
         S+JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fUKdVS5/N5qQkJwAZJURTrzizTk+EoulthkFub9h71Q=;
        fh=Evykoaj+4jw1Ymb3gI1cJJBKSfl3YZXsVdzXmHnGR94=;
        b=R0qcE7a23aoorUf2IEPptY1026GcNQS9vat8kBgSSUP9z4UUm/njvcw7Ks/ppKSPNX
         rTDs4qPHhRse+RInDOulwd1963nGyOxDR9H9E87hhUSZQO5rtWXUkOSHmhc1t8QLcESu
         oum6aq3aYnbjtueI5sUbtD4RNtkK4D7hVfyo4z4XzNfvnXiRoKBUpsaITsuxPXNiTw5l
         /ifaIcPXThz4YHr3WSS4ypZ7/29q2zhhnlFNSYhFYY11XPMIun/e68KHy2Fh0L486leb
         PalAM1P0vrPcFsiHcJ3N9ByhiAwTPu8QNyNRh+yi4GkNBgsZg8ZKwyGZ5+8fxzzV1QgA
         vovg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="LbvtTy/F";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id az26-20020adfe19a000000b0031596f8eeebsi1026549wrb.7.2023.08.09.09.32.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Aug 2023 09:32:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-31781e15a0cso49043f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 09 Aug 2023 09:32:43 -0700 (PDT)
X-Received: by 2002:adf:ea4d:0:b0:317:9537:d73f with SMTP id j13-20020adfea4d000000b003179537d73fmr2324254wrn.30.1691598763235;
        Wed, 09 Aug 2023 09:32:43 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:9ce0:327a:6e5a:3533])
        by smtp.gmail.com with ESMTPSA id d10-20020adffd8a000000b003143ba62cf4sm17138365wrr.86.2023.08.09.09.32.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Aug 2023 09:32:42 -0700 (PDT)
Date: Wed, 9 Aug 2023 18:32:37 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>, Marc Zyngier <maz@kernel.org>,
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
Message-ID: <ZNO/pf/pH5jJAZI0@elver.google.com>
References: <20230808102049.465864-1-elver@google.com>
 <20230808102049.465864-3-elver@google.com>
 <202308081424.1DC7AA4AE3@keescook>
 <CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A@mail.gmail.com>
 <ZNNi/4L1mD8XPNix@elver.google.com>
 <20230809113021.63e5ef66@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230809113021.63e5ef66@gandalf.local.home>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="LbvtTy/F";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Wed, Aug 09, 2023 at 11:30AM -0400, Steven Rostedt wrote:
[...]
> 
> I would actually prefer DEBUG_LIST to select HARDEN_LIST and not the other
> way around. It logically doesn't make sense that HARDEN_LIST would select
> DEBUG_LIST. That is, I could by default want HARDEN_LIST always on, but not
> DEBUG_LIST (because who knows, it may add other features I don't want). But
> then, I may have stumbled over something and want more info, and enable
> DEBUG_LIST (while still having HARDEN_LIST) enabled.
> 
> I think you are looking at this from an implementation perspective and not
> the normal developer one.
> 
[...]
> 
> That is, if DEBUG_LIST is enabled, we always call the
> __list_add_valid_or_report(), but if only HARDEN_LIST is enabled, then we
> do the shortcut.

Good point - I think this is better. See below tentative v4.

Kees: Does that also look more like what you had in mind?

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Thu, 27 Jul 2023 22:19:02 +0200
Subject: [PATCH] list: Introduce CONFIG_HARDEN_LIST

Numerous production kernel configs (see [1, 2]) are choosing to enable
CONFIG_DEBUG_LIST, which is also being recommended by KSPP for hardened
configs [3]. The motivation behind this is that the option can be used
as a security hardening feature (e.g. CVE-2019-2215 and CVE-2019-2025
are mitigated by the option [4]).

The feature has never been designed with performance in mind, yet common
list manipulation is happening across hot paths all over the kernel.

Introduce CONFIG_HARDEN_LIST, which performs list pointer checking
inline, and only upon list corruption calls the reporting slow path.

Since DEBUG_LIST is functionally a superset of HARDEN_LIST, the Kconfig
variables are designed to reflect that: DEBUG_LIST selects HARDEN_LIST,
whereas HARDEN_LIST itself has no dependency on DEBUG_LIST.

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
 arch/arm64/kvm/hyp/nvhe/Makefile     |  2 +-
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  2 +
 include/linux/list.h                 | 64 +++++++++++++++++++++++++---
 lib/Kconfig.debug                    |  9 +++-
 lib/Makefile                         |  2 +-
 lib/list_debug.c                     |  5 ++-
 security/Kconfig.hardening           | 13 ++++++
 7 files changed, 86 insertions(+), 11 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Makefile
index 9ddc025e4b86..c89c85a41ac4 100644
--- a/arch/arm64/kvm/hyp/nvhe/Makefile
+++ b/arch/arm64/kvm/hyp/nvhe/Makefile
@@ -25,7 +25,7 @@ hyp-obj-y := timer-sr.o sysreg-sr.o debug-sr.o switch.o tlb.o hyp-init.o host.o
 	 cache.o setup.o mm.o mem_protect.o sys_regs.o pkvm.o stacktrace.o ffa.o
 hyp-obj-y += ../vgic-v3-sr.o ../aarch32.o ../vgic-v2-cpuif-proxy.o ../entry.o \
 	 ../fpsimd.o ../hyp-entry.o ../exception.o ../pgtable.o
-hyp-obj-$(CONFIG_DEBUG_LIST) += list_debug.o
+hyp-obj-$(CONFIG_HARDEN_LIST) += list_debug.o
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
diff --git a/include/linux/list.h b/include/linux/list.h
index 130c6a1bb45c..ef899c27c68b 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -38,39 +38,91 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 	WRITE_ONCE(list->prev, list);
 }
 
+#ifdef CONFIG_HARDEN_LIST
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
+ * With CONFIG_HARDEN_LIST only, performs minimal list integrity checking (that
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
+ * With CONFIG_HARDEN_LIST only, performs minimal list integrity checking (that
+ * do not result in a fault) inline, and only if a corruption is detected calls
+ * the reporting function __list_del_entry_valid_or_report().
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
index fbc89baf7de6..9e38956d6f50 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1674,9 +1674,14 @@ menu "Debug kernel data structures"
 config DEBUG_LIST
 	bool "Debug linked list manipulation"
 	depends on DEBUG_KERNEL || BUG_ON_DATA_CORRUPTION
+	select HARDEN_LIST
 	help
-	  Enable this to turn on extended checks in the linked-list
-	  walking routines.
+	  Enable this to turn on extended checks in the linked-list walking
+	  routines.
+
+	  This option trades better quality error reports for performance, and
+	  is more suitable for kernel debugging. If you care about performance,
+	  you should only enable CONFIG_HARDEN_LIST instead.
 
 	  If unsure, say N.
 
diff --git a/lib/Makefile b/lib/Makefile
index 42d307ade225..a7ebc9090f04 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -161,7 +161,7 @@ obj-$(CONFIG_BTREE) += btree.o
 obj-$(CONFIG_INTERVAL_TREE) += interval_tree.o
 obj-$(CONFIG_ASSOCIATIVE_ARRAY) += assoc_array.o
 obj-$(CONFIG_DEBUG_PREEMPT) += smp_processor_id.o
-obj-$(CONFIG_DEBUG_LIST) += list_debug.o
+obj-$(CONFIG_HARDEN_LIST) += list_debug.o
 obj-$(CONFIG_DEBUG_OBJECTS) += debugobjects.o
 
 obj-$(CONFIG_BITREVERSE) += bitrev.o
diff --git a/lib/list_debug.c b/lib/list_debug.c
index 2def33b1491f..38ddc7c01eab 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -2,7 +2,8 @@
  * Copyright 2006, Red Hat, Inc., Dave Jones
  * Released under the General Public License (GPL).
  *
- * This file contains the linked list validation for DEBUG_LIST.
+ * This file contains the linked list validation and error reporting for
+ * HARDEN_LIST and DEBUG_LIST.
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
index 0f295961e773..19aa2b7d2f64 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -279,6 +279,19 @@ config ZERO_CALL_USED_REGS
 
 endmenu
 
+menu "Hardening of kernel data structures"
+
+config HARDEN_LIST
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
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNO/pf/pH5jJAZI0%40elver.google.com.
