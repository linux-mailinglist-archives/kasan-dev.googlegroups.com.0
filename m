Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHLWKMAMGQETYQIYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A91C5A4C38
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:09 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id f38-20020a0565123b2600b0049469e0cab0sf1194486lfv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777288; cv=pass;
        d=google.com; s=arc-20160816;
        b=l1w67L1aT19f5Gc2S3ROw0kU8inwFJB3qoMRiI00+AUYB6z8ANXX2Z4EPByw/iy72M
         ErSUy3+5MaYCaP2DqqqDSDEas0zHvgYTABKpF08TsiGqKN39wgB0P0PoqfCBsOe5XF+p
         mUGnV7DLcOosHUjIkDpFPtH4gBnQyofCT/TG56dU9DZLXpiXnKXKQ/BHAXxDsryZAhu0
         9x8IAwTvr1iEeJHD3hcd8TMr8wE3fAJK6+dQDEpX9qMVR+43h4buK8zQzPCILeqXrQgN
         fAaU14j+AY15l9BKqHfx/yL4+2z4JaWmNHo0ESYTosoP5TYrscPXrgJpeAlD23SGXc4V
         4YQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=opw0uFwROxNPvqxhW8U7xX7Naqwer81Gkhk8T+9KQHg=;
        b=qica/WxAeuAWrVmRmmbibLKv7fjPHMcGtWgIgq0oN+zY5ciZZit2P9hLWvYpqMNqft
         ARVfERWHRclua6Si/Yk9hPMFBRiIlDwHPtc45hWemGMo56OS+EfJ6fOxpH64T5LE1zlK
         K4g3r8Kj/0oxJy462YcV2sy8wWsX5VFHG7Xhsch4L/LAwxr8IqoH+uTO1/uD6NTUkifh
         z+EKY7sKWaWKQ0P6ocfGfNYeJNiloHeq1jGDyhVLt63bqHK1CfrXHzIv88CXO3f4L+jM
         TcVgVE4aVmNWrwc5ow/pDHvD9qEEppEPQz7HYKBHSTNJF945KTzUvCK53kBLdQ2q1z1A
         rAdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aoWdQSkd;
       spf=pass (google.com: domain of 3hrumywukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hrUMYwUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=opw0uFwROxNPvqxhW8U7xX7Naqwer81Gkhk8T+9KQHg=;
        b=ITn/JPnNV8eyqiU+BJV7NK6iCCbeAIVruVdAduQ6hH/YTQ4g/lfWfM53fVFAT8l+1E
         WByR8/7WcdFu1d2SIFwt5PS1xbtlfOh2ra9RYTk5rp+ttFJz2xcTObRM0hJQ2qAjIxTo
         MkHW0Jx7+m1zwhjs1i0Y62qQ1o/TblcoegPMaSKWO7S1ZLQ8MF2p2nPIvcS4kIrJwTuS
         LVra1A3rpMSz3aFBo0Wl90rDXeYZlve3oTgg6HA4rdjFyCARR7RPupmNHS2jpfuSmLvU
         5l6s980Yufh4v53hniu6LAumKHKjx8LzKV7gRAIc0umuGCaVUYA9Ittvawdamut2MtWI
         QT4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=opw0uFwROxNPvqxhW8U7xX7Naqwer81Gkhk8T+9KQHg=;
        b=rHzniMKXy799oijqExQzc/Fe5WgtrIwQewUN043kniiw1AuUhrmO+qiclmldpPgFXD
         9elWXA6dM+EqcIBrsi6C4zmwWj32bQ7DatN1jr7cl3a7V222ag77Tuj6QL1nG+caUOay
         hZ+LW5ck1P0DCd6go5EnAC6AbNIM1oTtUvkeViEEwSo8bgIeyvcOP+PGTzfeMgiq05jK
         i3lYif89/lrEitI0DAFLRkwT4vMNtntsW4AWEZ6A1vEdTv5Q2skp4JXgwkIJHItzaK13
         VDO3nb4QIBvMlNbW4lPUvXdJwbonk6KC0IOkURSeehQNlx8IhLBvTDnDO+ds8wX6pXbO
         /49g==
X-Gm-Message-State: ACgBeo0d5wBe2Djc+nJV7bOWfDgPHclO2sBJZ32zIqCf817rDEUcKVWt
	tBR8ZdsVI6Dfrtx8NdFVA5I=
X-Google-Smtp-Source: AA6agR7q3ME95vLSKZ+rvyX2WZmuWxyPNHBiSJUNBQbOs1mADrTLZ3uQqqfumWNU83ZBvcHZM/TFSQ==
X-Received: by 2002:a2e:80c3:0:b0:266:61f8:919e with SMTP id r3-20020a2e80c3000000b0026661f8919emr619244ljg.88.1661777288607;
        Mon, 29 Aug 2022 05:48:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:20c4:b0:494:6c7d:cf65 with SMTP id
 u4-20020a05651220c400b004946c7dcf65ls1400220lfr.2.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:07 -0700 (PDT)
X-Received: by 2002:a05:6512:5c8:b0:494:6fd1:a935 with SMTP id o8-20020a05651205c800b004946fd1a935mr856248lfo.145.1661777287307;
        Mon, 29 Aug 2022 05:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777287; cv=none;
        d=google.com; s=arc-20160816;
        b=WsT6udgNE6OU1DxvXBGD+QmK5/vuAyoIqqqOotp27vQv5lOKLFsPuwzuKVJM7I7jQQ
         n8tIAYDZOkXE6NfbJsdl1o0pQzZ8Px1x9qczBO8Pt6YnMQi1mGSYYWFK1frvDPjmPGBq
         Qe1Sk4eafJf74GTQytl5hnYXref7OoQXDNrsfJRZ2dhxzSTOnzkhmJA2NbSn9cjGuUyN
         b+cRyvjxmx7MdUNpA2Jam39RLQdoPw3mRThM9zWwzuVaZ7DrwCsw3ZNZhIo/S+xzwKQR
         6v9PtWX+oyeHhkL7Xz9mosv8zFz5P6IueGzz/elhFv79rYyYlFudfe0VjKY7sfFHw5yT
         C2Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Xnrbr4NWXpH3ILMfaL+Hqy6Mh/173nAe6Rh4Ql+SwwA=;
        b=QSqgJ+Yipx0Vr/pK15ajMczZeH897EM1GD6pMwYMAwEc3g4PQtFV3isagqMkX+lhcl
         FyzJfxWqR7LumJI5abhiEtMv5e/Vmfsuc9Wb0xEaHSwo4r9752++RahkSVHEwGM+fHaf
         Uo8dqLeYLgT8HnOes0HizgiUqXWDJEw/6ZZJNuemb/p83aA6kNIAvS/0Zs2yQsRKSYs1
         lnPi0nKeSupqwm3JifE/5aPo+ro45KyD7s4EkTeCgs++zWknRJS/McnN1hvH8/47g45S
         dn+cIVFry5vsZK6hhzHeW2mmoJJldMN99ffRZsF62gImbDkM8JIrltbD9RP+PqsEXCQk
         95Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aoWdQSkd;
       spf=pass (google.com: domain of 3hrumywukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hrUMYwUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 22-20020ac25f56000000b0049465aa3228si232105lfz.11.2022.08.29.05.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hrumywukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id dz16-20020a0564021d5000b004489f04cc2cso694006edb.10
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:07 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:aa7:c946:0:b0:43d:3038:1381 with SMTP id
 h6-20020aa7c946000000b0043d30381381mr16380942edt.354.1661777286713; Mon, 29
 Aug 2022 05:48:06 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:08 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-4-elver@google.com>
Subject: [PATCH v4 03/14] perf/hw_breakpoint: Clean up headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aoWdQSkd;       spf=pass
 (google.com: domain of 3hrumywukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hrUMYwUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Clean up headers:

 - Remove unused <linux/kallsyms.h>

 - Remove unused <linux/kprobes.h>

 - Remove unused <linux/module.h>

 - Remove unused <linux/smp.h>

 - Add <linux/export.h> for EXPORT_SYMBOL_GPL().

 - Add <linux/mutex.h> for mutex.

 - Sort alphabetically.

 - Move <linux/hw_breakpoint.h> to top to test it compiles on its own.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v2:
* Move to start of series.
---
 kernel/events/hw_breakpoint.c | 19 +++++++++----------
 1 file changed, 9 insertions(+), 10 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index fd5cd1f9e7fc..6076c6346291 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -17,23 +17,22 @@
  * This file contains the arch-independent routines.
  */
 
+#include <linux/hw_breakpoint.h>
+
+#include <linux/bug.h>
+#include <linux/cpu.h>
+#include <linux/export.h>
+#include <linux/init.h>
 #include <linux/irqflags.h>
-#include <linux/kallsyms.h>
-#include <linux/notifier.h>
-#include <linux/kprobes.h>
 #include <linux/kdebug.h>
 #include <linux/kernel.h>
-#include <linux/module.h>
+#include <linux/list.h>
+#include <linux/mutex.h>
+#include <linux/notifier.h>
 #include <linux/percpu.h>
 #include <linux/sched.h>
-#include <linux/init.h>
 #include <linux/slab.h>
-#include <linux/list.h>
-#include <linux/cpu.h>
-#include <linux/smp.h>
-#include <linux/bug.h>
 
-#include <linux/hw_breakpoint.h>
 /*
  * Constraints data
  */
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-4-elver%40google.com.
