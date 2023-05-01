Return-Path: <kasan-dev+bncBC7OD3FKWUERBLG6X6RAMGQEUGQW5HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 70C4C6F33EC
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:13 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-545db8dc9a4sf189969eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960173; cv=pass;
        d=google.com; s=arc-20160816;
        b=bWk7XERhtvhq9IC01mlL0FTneSb6ITHDXhZSdRFJLo586pGgCloWnNrFbpI1ANBRH+
         47FCy2nd104uhiS+DY+gBO+tdgTG1dg2hld9ZpsXYrTUAsbDw1E13W3bDIWCkyH0l/r2
         Kw4SUsplmPrgbdCQPbOTMniFZb5jhHIoMJd3961aEoDEHmM7P+UdV+jjgBT4F/7qBrlJ
         dLMBCcA+KW+QVVtW/2zINLCK3JURnAhG0UXcDzlsesjrJby5wALytqAfrrXIZUvb0/Ri
         6Dg8Ciy0PeEKtnnMXkJGDNmDy/5MG8iuye1XHnM2PKWsm07iuNu2MOly3FitTX5VGKyq
         scKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=S2IUVjE4VYwTv0fF8yAAVcUG4dSTePvASTPe5OnH7aM=;
        b=re/AUABy02yztgVdM8RY5LWqv/aoCdi291bibqI2lNm+LR4zmnn4RBkKLQ0VEGuwSZ
         KbD6V+EHVw+HOdJ4eYsF4RGEJXnrq4FeX7oK/GaDj0UO2/mHHaR3VGayskRnQD7CFDTf
         qbg4amlIsagrvm7ve7P54Ill1mGvuizbOFAmAjQvQQuIfg/7SvNWxgv5ohs2V7hd+QmS
         7gDVs0RNN1kWs0TJ6oSNrLdbKKgZbMxQCgB/TIc8m/NuNv+LcENkeo9D5osSX1busPsC
         1qOKYK28zU3YLFEVfqCSyKinWWCHQf/NWQrEswvjj46bcKfjlUVCA21WntiHe79uGbRt
         AmIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Glr4JSHs;
       spf=pass (google.com: domain of 3k-9pzaykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3K-9PZAYKCXIikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960173; x=1685552173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=S2IUVjE4VYwTv0fF8yAAVcUG4dSTePvASTPe5OnH7aM=;
        b=HSaZnCS48ivAZmgiRqIvnGt17fTu1nfzZlhE6lkqf2vlhXODB5SR6ob6m9O24pan2p
         1EwfSSssj1nI1bmILcaRqmP4gmcLXtj3kGM47PKnxQMtMFcDbZlSYY+69oCGJEAZBQ7L
         /HogRjFeoYKoc5RwzW3V4dHHfRL4x3zl8EcPevJKrlosChQMTDzKJ+D81r1FPXaOfd0l
         0T0DqNVNOMUvW0fzUNd7Pb8Y26fW/trntEd6i2UxTYE7jDan9bdHSH28pAU669Ix4d0f
         cvNQghHaE7+/uRwtsOA0leKQUTgdT2d+DUnzzLwuhp74LrfgqNKJZXzYLt1nJXyQx8yA
         NtwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960173; x=1685552173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S2IUVjE4VYwTv0fF8yAAVcUG4dSTePvASTPe5OnH7aM=;
        b=AAJ+1bUZ/0Y2VnW4SEfktG2hdkQVQzSt+Xcv7TOMUU4XbbE0AHNEGAINEycr2E5yAS
         ky3ykXBES78kCeuV3sh1T+ilgmTNrAh29n4kEV6eQhzS6N9idI+uxuaD4YPh6tKsmHZN
         dlyOlMgSwf/Oeo2MzAtV97Qyp8lHqQ82dY+Sh/iCZwKceunVC7pmnaYhlvei+nbf7fXe
         layGsUGG4MbR7NoZ3yU1KUf4OA78vLOrYgdKjhMXhhDGMPJ+LwqwWtSC3zDeTGMGVvJd
         epVON9q3cAZ9fDHWdCnvGlWDWBSgc5jZafMjMNKVXAqGXIAa0RjRAlBsceYjZvGfDgMK
         Ym8Q==
X-Gm-Message-State: AC+VfDwcxn7Jl88NVUnWCqCEr473ailfVeyEKBaQFToRSAGFauAwIcIF
	KgrQumHPZUTmQKqZwcYHsW0=
X-Google-Smtp-Source: ACHHUZ6HrpNBALH6joPtRcDv4Rd5nXh5ZIr6MAsK3nEnxxE300B26YPv07BsYX0xpU39Z93Pnm1TVw==
X-Received: by 2002:a4a:6245:0:b0:547:689b:73c2 with SMTP id y5-20020a4a6245000000b00547689b73c2mr3932451oog.0.1682960173044;
        Mon, 01 May 2023 09:56:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6607:b0:69f:b065:771a with SMTP id
 cp7-20020a056830660700b0069fb065771als1797869otb.11.-pod-prod-gmail; Mon, 01
 May 2023 09:56:12 -0700 (PDT)
X-Received: by 2002:a05:6830:181:b0:6a7:cb81:701a with SMTP id q1-20020a056830018100b006a7cb81701amr7904152ota.16.1682960172584;
        Mon, 01 May 2023 09:56:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960172; cv=none;
        d=google.com; s=arc-20160816;
        b=FH+LDmdZz6mU85pXEvbTXq2qzp51mkeXUI/bpT/TfntHKBt4EdmqHLxl5nB18KMDo1
         JLIf1lZSY45TFRyuDFN9qAyRd0GER2YgSytMbNbXz66MSr/Pr8WhQh6dIs3HkgCaWc7x
         9Lz3vUsqKzAZENC55ynruA/Z7Ew1KUS2YIUGGz96xp6+OuPm5AOniW6EpC3Ayj0p6rnF
         R3fxIMcwacAlUKRuq+od0EFk2Pvdirm+TzhNihCfDu/rvRzr0o8TZcKEbidpp6DC90R9
         VzbTsJcgVEDs6JnTO0jJ6vFNtMUahu2WRgKxhPjDll/0KQgIinGMbfNSvWUKZvgB/rd/
         aSSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jz3+CZtZwJ9/tSYfHBM/2MHA9DEGGjB4zlxzO096/9Q=;
        b=YYWPZflkFqwuNRhnITItykvbT6rWuv5FruaMPATLMbl1BQjNmJdkEkHBRs21iLNv/B
         Eq5voX9gvNj6Xc3VaspRn3Hag4Eokx2JyRfoFt647qmXasLGsF/tjg1tr721KAWQkwoI
         5Oxjjs5Ih/1G7TZRj0lFnSQAP5etmbogyyEJ/G5rwSXEhToWJxdhD5WKp24fIMI+W6IE
         7MR2kN+bVaiE/u6wrBKBtMuhSNL46XryQsrWY9i/+sVH36FzEVj1G5Gv7XZ/4wgDCrGq
         Ah25U1q0wqNYsWgRF58Nc73MV3/eLIOi1TbhvoNezi3+buQfYoWeJHMAzbwu4ilsqPUq
         UvRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Glr4JSHs;
       spf=pass (google.com: domain of 3k-9pzaykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3K-9PZAYKCXIikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id db12-20020a0568306b0c00b006a15693a266si2073372otb.3.2023.05.01.09.56.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3k-9pzaykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b99ef860a40so4734433276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:12 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:1388:0:b0:b95:ecc5:5796 with SMTP id
 130-20020a251388000000b00b95ecc55796mr5071137ybt.12.1682960171977; Mon, 01
 May 2023 09:56:11 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:38 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-29-surenb@google.com>
Subject: [PATCH 28/40] timekeeping: Fix a circular include dependency
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Glr4JSHs;       spf=pass
 (google.com: domain of 3k-9pzaykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3K-9PZAYKCXIikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This avoids a circular header dependency in an upcoming patch by only
making hrtimer.h depend on percpu-defs.h

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
---
 include/linux/hrtimer.h        | 2 +-
 include/linux/time_namespace.h | 2 ++
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/include/linux/hrtimer.h b/include/linux/hrtimer.h
index 0ee140176f10..e67349e84364 100644
--- a/include/linux/hrtimer.h
+++ b/include/linux/hrtimer.h
@@ -16,7 +16,7 @@
 #include <linux/rbtree.h>
 #include <linux/init.h>
 #include <linux/list.h>
-#include <linux/percpu.h>
+#include <linux/percpu-defs.h>
 #include <linux/seqlock.h>
 #include <linux/timer.h>
 #include <linux/timerqueue.h>
diff --git a/include/linux/time_namespace.h b/include/linux/time_namespace.h
index bb9d3f5542f8..d8e0cacfcae5 100644
--- a/include/linux/time_namespace.h
+++ b/include/linux/time_namespace.h
@@ -11,6 +11,8 @@
 struct user_namespace;
 extern struct user_namespace init_user_ns;
 
+struct vm_area_struct;
+
 struct timens_offsets {
 	struct timespec64 monotonic;
 	struct timespec64 boottime;
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-29-surenb%40google.com.
