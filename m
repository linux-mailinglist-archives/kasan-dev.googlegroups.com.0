Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUDRSLAMGQEULYUHEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CBD99565937
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:06 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id h18-20020a056512055200b004810d1b257asf3149319lfl.13
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947166; cv=pass;
        d=google.com; s=arc-20160816;
        b=gQHD2AhNGxyVTFj+bdf6TcL55nZWVeUUPqBapz1E2yYlpPWOxm6OdUPWRQ5i91xpEr
         5lN9GJdl4y4DKMpNzf6i3q4EzMRMyCYk71q9dTk0YYvVVbSRhwQ9llmFDtIsKvOvT6By
         P+Q8lD9VPLQiSIEntYMXnCeHnDj+p3ZqOoyoTdf+SNk4bHvsGgrJ/w6gRk7giYoCHHht
         ZTMrmXg50Yzy757HQNGUPIL79qNjLwRWRilFMgO1P5+NgavyuW85uuSvINMa/W9XL50w
         +5B9pvFbg1YvZdTTSWZ3rkuL+gK2hoUV61FTZtXyfnsEJotKfyx0AyVE+tOTSF6cjbzT
         9Giw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5kayc3keBKJvYbeMEi5qc9aHPgSV9yQQeLbR+jhWhVA=;
        b=ojlnXDAo9VT1431zzWdfA3gUjc9FHMKPoxXWoXRNrX8puQcFeHB199jSgSOcqjxLhK
         RgKNjFn+tdCPVOuRNOypgUVX8vIh/NLayx7F+7Zk+oNTUKesY+pxwRzCmb53/9c33j0x
         6kO0UPAiNCLAIo9DlCaBSR4Ogwo5L259z3u9tH5v5QlfugdpmA+Uq73ds8a+VLUYb/ps
         65U1h3P4vr2iO0z02dmpmp50Jzsge8qFH4Ij2IUgZvUGWQsNTG31BnOKzG2/gZv9O1J/
         mPMf8pw4/X47Q+OGc+phKJ0r2Gx3Ccj/mAb5uWcoAWZ5FsFxZYIlvVUMlRpBwwL2O4Zj
         MElA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="rSsD/r2q";
       spf=pass (google.com: domain of 33ahdygukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=33AHDYgUKCQknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kayc3keBKJvYbeMEi5qc9aHPgSV9yQQeLbR+jhWhVA=;
        b=EhS3cxLm1/PWDaH/ACQtHK+4Jmbt+ALMCczJkb5RijQ35AUNVOD7jYfCiG69R8k+EG
         o/VGhOvQOzO6wae5GtXLZ9t+SBvJtMRFG+VWL05Sj+J0ajx0b1mJlFuS0ebRW+dhxSEB
         68gPlLuIcHO4FCc6RII5QZE78XCOTikK6i2cww2XhjxxXR/7NlqGXV2R54Ucush8epfV
         HBbHenKotHzAgMpSFTbSs2uAc7zuUWgBgrzskwAFI2CwXM5vXczDSwleSqWusRge0SuF
         Kq37bqrym4xdNCb8USqxaLAVS/F58Chbh9GOahboHF+HZ1Veonv+r2w39LJ8RVKmfCia
         fxPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kayc3keBKJvYbeMEi5qc9aHPgSV9yQQeLbR+jhWhVA=;
        b=f2dFBEUX8W1uA1wwHrwdNQt/dzVoJgmyqbjmMSCBwYOQxifii39+NXdvlFBNC0GW9M
         d1L8+HYsk1Y3OkGhl+VNXkiY0m0+61qmr1vvQWPFuH4t7XWf0lqRFWvhazv7JDqag2wi
         k2KXsNLrcweTieFlaz79n2G9eF9Z6C6puaB9RlonVphS7FvnXz6kNxZB8mQxs99rhJzK
         dRPVe8wM+gD9YB25E9HEMPhwJb/9kTkQ4D17xd6PS3OLaOzp4KK4aSYRvkrmrTL4XJUf
         36tiGrqvB1adL9W0/C6B6o/AfpqZRPlU2+BaBX/W9UvbRKZEk+g8X8vrGln/ssP3IMHM
         ZLFA==
X-Gm-Message-State: AJIora9nQPI7eXWy2a/YyA0PgDJXGDPuQEZyCC0yl657Dsw8PO0LrRJe
	hfFBL6DyRzv7L3l0FNBTueI=
X-Google-Smtp-Source: AGRyM1vlbk4uTvMGVssw5PLxPQzwxRFnvfjrLX5JoTAixaAre/3xyTor3gBfIOc/yTnYxEWmBxfIZQ==
X-Received: by 2002:a05:6512:2241:b0:479:6426:15af with SMTP id i1-20020a056512224100b00479642615afmr19126356lfu.631.1656947166198;
        Mon, 04 Jul 2022 08:06:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d1:0:b0:25b:c342:b0dd with SMTP id s17-20020a2e81d1000000b0025bc342b0ddls3855330ljg.5.gmail;
 Mon, 04 Jul 2022 08:06:04 -0700 (PDT)
X-Received: by 2002:a2e:a166:0:b0:25a:a3fb:44fa with SMTP id u6-20020a2ea166000000b0025aa3fb44famr15763346ljl.261.1656947164733;
        Mon, 04 Jul 2022 08:06:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947164; cv=none;
        d=google.com; s=arc-20160816;
        b=pcR5zSzzdEunu7uMYZmzp7ATmLF0QD1iUN4x430fRHj51qNbo5jlQ/XRlczio9QG3t
         p8VfFKM24CHgG2YjSM+8sOubFV2vq+96ozYd6yk/P+N7H383/GeLgym5SoXIcRlMA6hi
         P5E9xgqZWmU9Yffg25Pw89ETUlWzcVrg7udYHocsFPaZuAGQZqMOuDmPyv9aJ5/moI53
         cIJy9Jxi2rrhY8DHlfZUUgHTsCZv71TkOlgnU6Ny21Yu5z2q6b94qyYQvEMyjudpsoLj
         B3Yb7WOeK0LEJZx33sYbKaBetDSP3JCwOU4mUc6F5uc53+6A0vOLLBVLLioS8r7fci7B
         5U6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=CJh9nArzdKDvJ+iA1QR7bBHoipxrgc/zo0qPPTGYcZY=;
        b=D5HnbcdBtcE8k7klKbmJJKUFyS91ukx+DU85YhTxu1XqW/ig4R6nQugtboik8Wktfq
         u1NFwmIiTL9EJwB8CsZu1QaoOJiEePmFaVXCpNjN+ixKCrRg+U2GuZufvJ0bwAzKKhdJ
         mMmNCgY5Vl9wRtok2Yg4qWNUtIbiJJmtys0g2CJ+a0ttPdV8itmcGAXQsRZaKlhJPNgM
         CA9bNQMACKcGrpa6KzEQGVd6OG0R1Hlv7AL3if2JhGxYlCJj7WRyxuwfFu9t1V18Q9KP
         7k7wxb+KAPp6TnzOTppx9klb4DFW9NZyIDr0AG8ALRQsNbJK+AvHFU0ILAksTcwxlHTX
         SN0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="rSsD/r2q";
       spf=pass (google.com: domain of 33ahdygukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=33AHDYgUKCQknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id z14-20020a05651c11ce00b0025a7388680bsi875051ljo.6.2022.07.04.08.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33ahdygukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id s1-20020a056402520100b00439658fad14so7491620edd.20
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a17:906:11d:b0:712:abf:3210 with SMTP id
 29-20020a170906011d00b007120abf3210mr28767207eje.292.1656947164230; Mon, 04
 Jul 2022 08:06:04 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:03 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-4-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 03/14] perf/hw_breakpoint: Clean up headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="rSsD/r2q";       spf=pass
 (google.com: domain of 33ahdygukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=33AHDYgUKCQknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-4-elver%40google.com.
