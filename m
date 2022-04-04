Return-Path: <kasan-dev+bncBC7OBJGL2MHBBINFVOJAMGQEZVWTF6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DCA64F13A2
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Apr 2022 13:12:34 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id i64-20020adf90c6000000b00203f2b5e090sf1626295wri.9
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Apr 2022 04:12:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649070754; cv=pass;
        d=google.com; s=arc-20160816;
        b=mAoclDzBdfi46R7ni6bmb1hG7g/luNk+x83VCfnR6oJWwgCZ7XuT5rJEv0MNT1Ucgn
         Dhpd1L71X9YSSWALGmG/Eoe4VRoUGfGH8eIkuXCfQzS0paU7MUc3N9Pup6eMPO3I1/Kf
         9qISzAMnONO0YMiREfCYjaAXhYpXPpP3l7de1hTup+ibdLyyWQtE9ppw1Y92pKhVNltg
         R7MaH7MwmkvwLlRQF2l56F1JmyqfxRkMsJ0STIUwKLIC8ygaa1YdbpB30G41rTTz1JA9
         HVKc9n2sRniQ534Y91XCIxKRyw9o4fS/zT1rKGYAo70K2BZbqztbVpyE6CTEKWxIPF8H
         OiXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=VS4M7Qlwq0MWz3c76trWIVFijJuqbsMNruYW+F+6QBE=;
        b=OH4QhYKly5w2JMu4RyUhucj9c8m/Es7uu2aziTxAKRGTlcaiyiYI6UeyHBopkKcTTz
         eN7D/pHHEZRXszy/Zt8sIhP/Hj8Hm+fJ5coYswvJhILRlMpOwgd1Vvf0eOGA9M9YLiRC
         l855TQbp31QyxbtUFiTuxDbaMLrm+ASXc7LIHaBONezxUYTd4twDc/ENR8PTxtC0dJ0I
         TxEa9E1wghTvAsR5VLOiD6g3Z6Iyq5VakK/pNSo5uDVT+pmY7aoAOrLONv2o/IeF1n8r
         F3RrkzyHIGV6F+G/BRM3Ke4C9+DMoALoVvGuI1GQdFFiWX688L+nMfZzJ1nglygXzYb7
         PzRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K24G7ugH;
       spf=pass (google.com: domain of 3onjkygukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3oNJKYgUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VS4M7Qlwq0MWz3c76trWIVFijJuqbsMNruYW+F+6QBE=;
        b=SO+GUWTFRCKnyHIw8P5WC6dMxhuLwwcG0Y478cDV6BMDUs/jlKjh7TLD+9zVDRoGUC
         wR8SK6T6BjOY1XJLMnRrBm5Atkgbtvv0IPIUuNpoitgAs8WCOE6iI0DfnqCFYQpxUn3K
         /9mscbZ8esVLZjV3WNq8dF3819y1fA+Ggn3g2sPfK4VgiJNMhjFGOJiWgFHLK6aoeZNv
         0zo6vkR2mmVsJtWVMPhRY5sEJuEvY3ibXSHNoPktfbeu+YOM9D/vL0B28mGItTLAbm4O
         SNy2yWXRRFbSgZmFbIX7r5V0fi+peXFa0vyQvIM8uNWoOi4qgvaNC+20VYfUCqvo9Xjv
         JkdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VS4M7Qlwq0MWz3c76trWIVFijJuqbsMNruYW+F+6QBE=;
        b=I9oeCWIy7ZTK9fPx8CLUZmftMYU5844PyEvbRgyYYPsvnQrxCVnSZp/5miVgwkqMtz
         Qlm6Q1rgPsTUOnIkkKHSEScc0RcHER9jpRaHlkpMd+EV32pfKPCStP+3mQsr6tQ6RlHt
         vvWnlqz0nLOKkmuEJaZHjBXwfqi9g6NVlAO4lYR3SXedSngNT1w3FjeQ8O73bjXzPiFb
         9IqXX90WhNCjxchnyWSDDKwQOvzJJl7odyPursPzfU0dbWsliCkIj7M/vyyA+AMa58YZ
         06ODXhb4SreVwxCMPSn8wZqsYnnzcfTOrxK5GRZqHaygrO4xu4frM753LeJpajFjBOM9
         P8mw==
X-Gm-Message-State: AOAM531SkO9kRnvNpKv2udddpodF0n3qR6P3Oz+mU2XFwhiDdBDoxhrY
	E+NwG/2CZWSPMFjykV9dPsc=
X-Google-Smtp-Source: ABdhPJxVeBV+c9OqDP6mByqfa4jeBv2pUETtdh2/ZawhwWpskEptxctAADk2/21FSuJ6Ew+I0RBdxA==
X-Received: by 2002:a05:600c:3495:b0:38e:6f95:e97 with SMTP id a21-20020a05600c349500b0038e6f950e97mr5293465wmq.60.1649070754138;
        Mon, 04 Apr 2022 04:12:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f950:0:b0:205:dbf5:72d8 with SMTP id q16-20020adff950000000b00205dbf572d8ls1574466wrr.0.gmail;
 Mon, 04 Apr 2022 04:12:33 -0700 (PDT)
X-Received: by 2002:a05:6000:1288:b0:205:9907:9f6f with SMTP id f8-20020a056000128800b0020599079f6fmr16431255wrx.399.1649070753136;
        Mon, 04 Apr 2022 04:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649070753; cv=none;
        d=google.com; s=arc-20160816;
        b=Xgf9X30l10V9JD88CZTY3atlOMxTJGEqKeEyx7pmjsgbIDNWRN7UMmxkinGvpdsByw
         eJmtjHq4jJjzRuPH7rq8gDwaeEww/2J6EEC+p3q7t96qON3onToMMCSmEtuZnmsNTyEa
         PWOTudjeWQ74aL5Vg5otpRHtsAV0jPPFLUsMK2bTBHC5X4bT+yBF0SzURqyQgh26o1ez
         ZGoIj5El9oHX92AhWwYhZWbPwt9X/WiUbU2MRfd90C8Xd5ixDvjQZ/G2WURo0CvetMoE
         Jtsh3GN6EOxD0PelxnPReA2ReySM9WM+EcoXqejJl7Kk6LustUTOGISUBJadl59A8c0/
         rFuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=uhLLYDnsUK5GPlq+K1PIEo3r9jI08L/J2t2NRzzrt3o=;
        b=jQfaJ07zB6Sq4T3qDss/AO/1m9C/IgzEzvatmS4tNdPCvTO1/RHQrUcdHnJ64mRiGI
         Nrv2OvMppieTGelVY0L+1TqyRBH1nzT2HLZwhsD7MidccC5JMy1/w6p+8/DQ2xHp6eNb
         uZr7K0b4CE79kPTPDPmXeFSPLxIcOlir1MMbN5kb3TOQiW60CmF+azO1t03nePBkDnJv
         yH6vE9aqT9aD79/PQP0KztiFzlw2RAwFVbaCYb5xMI/gAzZpD+rozctQ0Znxwo0GL2yC
         T1REqWOEXfxFNQPGJ5aQDaj/HJxiVxBrvI/R3WfHb3iskBieEdXE4gvXM4nQPaj8THZ5
         ey2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K24G7ugH;
       spf=pass (google.com: domain of 3onjkygukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3oNJKYgUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id d10-20020a05600c34ca00b0038cac42709csi495034wmq.1.2022.04.04.04.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Apr 2022 04:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3onjkygukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qb5-20020a1709077e8500b006e7f59d3cc0so826258ejc.15
        for <kasan-dev@googlegroups.com>; Mon, 04 Apr 2022 04:12:33 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:8bc1:e5e5:97b1:783])
 (user=elver job=sendgmr) by 2002:a17:907:1b09:b0:6d8:faa8:4a06 with SMTP id
 mp9-20020a1709071b0900b006d8faa84a06mr10090795ejc.701.1649070752716; Mon, 04
 Apr 2022 04:12:32 -0700 (PDT)
Date: Mon,  4 Apr 2022 13:12:04 +0200
Message-Id: <20220404111204.935357-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.1094.g7c7d902a7c-goog
Subject: [PATCH] signal: Deliver SIGTRAP on perf event asynchronously if blocked
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-m68k@lists.linux-m68k.org, 
	sparclinux@vger.kernel.org, linux-arch@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K24G7ugH;       spf=pass
 (google.com: domain of 3onjkygukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3oNJKYgUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

With SIGTRAP on perf events, we have encountered termination of
processes due to user space attempting to block delivery of SIGTRAP.
Consider this case:

    <set up SIGTRAP on a perf event>
    ...
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGTRAP | <and others>);
    sigprocmask(SIG_BLOCK, &s, ...);
    ...
    <perf event triggers>

When the perf event triggers, while SIGTRAP is blocked, force_sig_perf()
will force the signal, but revert back to the default handler, thus
terminating the task.

This makes sense for error conditions, but not so much for explicitly
requested monitoring. However, the expectation is still that signals
generated by perf events are synchronous, which will no longer be the
case if the signal is blocked and delivered later.

To give user space the ability to clearly distinguish synchronous from
asynchronous signals, introduce siginfo_t::si_perf_flags and
TRAP_PERF_FLAG_ASYNC (opted for flags in case more binary information is
required in future).

The resolution to the problem is then to (a) no longer force the signal
(avoiding the terminations), but (b) tell user space via si_perf_flags
if the signal was synchronous or not, so that such signals can be
handled differently (e.g. let user space decide to ignore or consider
the data imprecise).

The alternative of making the kernel ignore SIGTRAP on perf events if
the signal is blocked may work for some usecases, but likely causes
issues in others that then have to revert back to interception of
sigprocmask() (which we want to avoid). [ A concrete example: when using
breakpoint perf events to track data-flow, in a region of code where
signals are blocked, data-flow can no longer be tracked accurately.
When a relevant asynchronous signal is received after unblocking the
signal, the data-flow tracking logic needs to know its state is
imprecise. ]

Link: https://lore.kernel.org/all/Yjmn%2FkVblV3TdoAq@elver.google.com/
Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/arm/kernel/signal.c           |  1 +
 arch/arm64/kernel/signal.c         |  1 +
 arch/arm64/kernel/signal32.c       |  1 +
 arch/m68k/kernel/signal.c          |  1 +
 arch/sparc/kernel/signal32.c       |  1 +
 arch/sparc/kernel/signal_64.c      |  1 +
 arch/x86/kernel/signal_compat.c    |  2 ++
 include/linux/compat.h             |  1 +
 include/linux/sched/signal.h       |  2 +-
 include/uapi/asm-generic/siginfo.h |  7 +++++++
 kernel/events/core.c               |  4 ++--
 kernel/signal.c                    | 18 ++++++++++++++++--
 12 files changed, 35 insertions(+), 5 deletions(-)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index 459abc5d1819..ea128e32e8ca 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -708,6 +708,7 @@ static_assert(offsetof(siginfo_t, si_upper)	== 0x18);
 static_assert(offsetof(siginfo_t, si_pkey)	== 0x14);
 static_assert(offsetof(siginfo_t, si_perf_data)	== 0x10);
 static_assert(offsetof(siginfo_t, si_perf_type)	== 0x14);
+static_assert(offsetof(siginfo_t, si_perf_flags) == 0x18);
 static_assert(offsetof(siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x10);
 static_assert(offsetof(siginfo_t, si_call_addr)	== 0x0c);
diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
index 4a4122ef6f39..41b5d9d3672a 100644
--- a/arch/arm64/kernel/signal.c
+++ b/arch/arm64/kernel/signal.c
@@ -1011,6 +1011,7 @@ static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
 static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
 static_assert(offsetof(siginfo_t, si_perf_data)	== 0x18);
 static_assert(offsetof(siginfo_t, si_perf_type)	== 0x20);
+static_assert(offsetof(siginfo_t, si_perf_flags) == 0x24);
 static_assert(offsetof(siginfo_t, si_band)	== 0x10);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x18);
 static_assert(offsetof(siginfo_t, si_call_addr)	== 0x10);
diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
index d984282b979f..4700f8522d27 100644
--- a/arch/arm64/kernel/signal32.c
+++ b/arch/arm64/kernel/signal32.c
@@ -487,6 +487,7 @@ static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
 static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_perf_data)	== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_perf_type)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_perf_flags)	== 0x18);
 static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_call_addr)	== 0x0c);
diff --git a/arch/m68k/kernel/signal.c b/arch/m68k/kernel/signal.c
index 49533f65958a..b9f6908a31bc 100644
--- a/arch/m68k/kernel/signal.c
+++ b/arch/m68k/kernel/signal.c
@@ -625,6 +625,7 @@ static inline void siginfo_build_tests(void)
 	/* _sigfault._perf */
 	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x10);
 	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x14);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_flags) != 0x18);
 
 	/* _sigpoll */
 	BUILD_BUG_ON(offsetof(siginfo_t, si_band)   != 0x0c);
diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
index f9fe502b81c6..dad38960d1a8 100644
--- a/arch/sparc/kernel/signal32.c
+++ b/arch/sparc/kernel/signal32.c
@@ -779,5 +779,6 @@ static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
 static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_perf_data)	== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_perf_type)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_perf_flags)	== 0x18);
 static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index 8b9fc76cd3e0..570e43e6fda5 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -590,5 +590,6 @@ static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
 static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
 static_assert(offsetof(siginfo_t, si_perf_data)	== 0x18);
 static_assert(offsetof(siginfo_t, si_perf_type)	== 0x20);
+static_assert(offsetof(siginfo_t, si_perf_flags) == 0x24);
 static_assert(offsetof(siginfo_t, si_band)	== 0x10);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x14);
diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
index b52407c56000..879ef8c72f5c 100644
--- a/arch/x86/kernel/signal_compat.c
+++ b/arch/x86/kernel/signal_compat.c
@@ -149,8 +149,10 @@ static inline void signal_compat_build_tests(void)
 
 	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x18);
 	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x20);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_flags) != 0x24);
 	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_data) != 0x10);
 	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_type) != 0x14);
+	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_flags) != 0x18);
 
 	CHECK_CSI_OFFSET(_sigpoll);
 	CHECK_CSI_SIZE  (_sigpoll, 2*sizeof(int));
diff --git a/include/linux/compat.h b/include/linux/compat.h
index 1c758b0e0359..01fddf72a81f 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -235,6 +235,7 @@ typedef struct compat_siginfo {
 				struct {
 					compat_ulong_t _data;
 					u32 _type;
+					u32 _flags;
 				} _perf;
 			};
 		} _sigfault;
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 3c8b34876744..bab7cc56b13a 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -320,7 +320,7 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
 
 int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
 int force_sig_pkuerr(void __user *addr, u32 pkey);
-int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
+int send_sig_perf(void __user *addr, u32 type, u64 sig_data);
 
 int force_sig_ptrace_errno_trap(int errno, void __user *addr);
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 3ba180f550d7..ffbe4cec9f32 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -99,6 +99,7 @@ union __sifields {
 			struct {
 				unsigned long _data;
 				__u32 _type;
+				__u32 _flags;
 			} _perf;
 		};
 	} _sigfault;
@@ -164,6 +165,7 @@ typedef struct siginfo {
 #define si_pkey		_sifields._sigfault._addr_pkey._pkey
 #define si_perf_data	_sifields._sigfault._perf._data
 #define si_perf_type	_sifields._sigfault._perf._type
+#define si_perf_flags	_sifields._sigfault._perf._flags
 #define si_band		_sifields._sigpoll._band
 #define si_fd		_sifields._sigpoll._fd
 #define si_call_addr	_sifields._sigsys._call_addr
@@ -270,6 +272,11 @@ typedef struct siginfo {
  * that are of the form: ((PTRACE_EVENT_XXX << 8) | SIGTRAP)
  */
 
+/*
+ * Flags for si_perf_flags if SIGTRAP si_code is TRAP_PERF.
+ */
+#define TRAP_PERF_FLAG_ASYNC (1u << 0)
+
 /*
  * SIGCHLD si_codes
  */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index cfde994ce61c..6eafb1b0ad4a 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6533,8 +6533,8 @@ static void perf_sigtrap(struct perf_event *event)
 	if (current->flags & PF_EXITING)
 		return;
 
-	force_sig_perf((void __user *)event->pending_addr,
-		       event->attr.type, event->attr.sig_data);
+	send_sig_perf((void __user *)event->pending_addr,
+		      event->attr.type, event->attr.sig_data);
 }
 
 static void perf_pending_event_disable(struct perf_event *event)
diff --git a/kernel/signal.c b/kernel/signal.c
index 30cd1ca43bcd..e43bc2a692f5 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1805,7 +1805,7 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
 }
 #endif
 
-int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
+int send_sig_perf(void __user *addr, u32 type, u64 sig_data)
 {
 	struct kernel_siginfo info;
 
@@ -1817,7 +1817,18 @@ int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
 	info.si_perf_data = sig_data;
 	info.si_perf_type = type;
 
-	return force_sig_info(&info);
+	/*
+	 * Signals generated by perf events should not terminate the whole
+	 * process if SIGTRAP is blocked, however, delivering the signal
+	 * asynchronously is better than not delivering at all. But tell user
+	 * space if the signal was asynchronous, so it can clearly be
+	 * distinguished from normal synchronous ones.
+	 */
+	info.si_perf_flags = sigismember(&current->blocked, info.si_signo) ?
+				     TRAP_PERF_FLAG_ASYNC :
+				     0;
+
+	return send_sig_info(info.si_signo, &info, current);
 }
 
 /**
@@ -3432,6 +3443,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_perf_data = from->si_perf_data;
 		to->si_perf_type = from->si_perf_type;
+		to->si_perf_flags = from->si_perf_flags;
 		break;
 	case SIL_CHLD:
 		to->si_pid = from->si_pid;
@@ -3509,6 +3521,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_perf_data = from->si_perf_data;
 		to->si_perf_type = from->si_perf_type;
+		to->si_perf_flags = from->si_perf_flags;
 		break;
 	case SIL_CHLD:
 		to->si_pid    = from->si_pid;
@@ -4722,6 +4735,7 @@ static inline void siginfo_buildtime_checks(void)
 	CHECK_OFFSET(si_pkey);
 	CHECK_OFFSET(si_perf_data);
 	CHECK_OFFSET(si_perf_type);
+	CHECK_OFFSET(si_perf_flags);
 
 	/* sigpoll */
 	CHECK_OFFSET(si_band);
-- 
2.35.1.1094.g7c7d902a7c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220404111204.935357-1-elver%40google.com.
