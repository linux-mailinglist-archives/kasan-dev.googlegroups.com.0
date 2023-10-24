Return-Path: <kasan-dev+bncBC7OD3FKWUERBS4V36UQMGQE6H4NZDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E5E3B7D521F
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:46:52 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1e9a82ec471sf6342402fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:46:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155211; cv=pass;
        d=google.com; s=arc-20160816;
        b=QNutZgNQUTvY0FE8KcLeNe1yByphcMvxPzHekhhmzMQ3pqSYdjXbrm1xWmxBynNyRj
         fq6Gi+xfOGaQoYU6WmvDIQza/SLtXYrI++gpz+cDvJtE83QrzXwx4uREp+VYa5dU7Azo
         69kU0LTkCDqt92MjPZYx+okAVAcu/aF+RBrWSLfWmB4A4/rF9ggbUG08cVLglVrK/q21
         t2Mh4rdPKxunHvpo7VyGK6p+K0uvb//Z/ueV2SFP9G8QU2KJkHifH4oF7HDj86Ub9X7z
         ieUBcW2ZOTKBmvQTmquE6FMQMjFF6aw4oyrRIbLZUfo3KH/7+w8pG8qkSrGChwyTcoSS
         NlLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ob5nbcQUy2jsYNk2NZWLnVKr2VT/LSobzZ8XdEFZiUQ=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=RFjwhfT3K4Y07eZ1e/yzXAF6IS7Nq7uiwunrGi7/YqP5wK3D7+P/I4NHyowu/saLCY
         0NgKLZ/dKzzskDU6PDhGBeks2pLEoUinU/zC6d8uhQ+v6+dISeOBws3FwMfdgWlPgh/3
         w4MHKRrJfkNUvzA/5HCKi/S+D3q3fEVSemE6XkwheVT4edZ9HESwDn8FPIiRoCroqeFc
         WC/HggImXC7LIlSUXQab7uZcsIOWlMiRnnYtbR8RRSyrlCC4SO/QIhq+bPV5CzcKUJ7l
         zGhw45Dm7STu18feHbYz81ghZ4yurbEqTf6KcR9GSQh6J7Ks7oTb+LdqKcIWb+pFYeiq
         6NkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S03hdruC;
       spf=pass (google.com: domain of 3yso3zqykcw8fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yso3ZQYKCW8fheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155211; x=1698760011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ob5nbcQUy2jsYNk2NZWLnVKr2VT/LSobzZ8XdEFZiUQ=;
        b=GNIc2qcE4RcBLjdIxI/H2NjodLVXo1TyZFJ+eC1LaSXj5PCvbYdV4zbzvPtVozmPkp
         /QclndYbqosfdIQIHi5tTpdJ8ttMkdD8kfBwY9thL5CA1fAGP84NVvHllqnM6ZrLxZnS
         O4+/058nwwBuvC+xy3+NOUhW0+0APXndbrj/zOH74WQhLG/+QY/1rHdnX1AJzLfTzbqR
         pBPC4E4nuOjjeGlCeZ1UlfQeMksKrqqS8DxGkElpqVNirriPzINd0SRLtQ5r5yxPYiOg
         KZ9ez3Qf76sW7HJ/nI2orDmi7D1gLHFNteY4G24WdcTWAnXLcYHm8YSOX0P4OPS45txC
         aApw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155211; x=1698760011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ob5nbcQUy2jsYNk2NZWLnVKr2VT/LSobzZ8XdEFZiUQ=;
        b=O/jiqzMhtW0FSOaOzxnPstPRDiToAyYUI/jhi3cD5I1ucSbxC8fb0ZupKSGl2mbzmN
         4A3TqfO3R74bjirom1VedwKqUNH00GayBcs3bhQLPaIyTF2wSJVsLyALMF77wqV8b82u
         1hTskLxKqdc8NGl+2M5BRE3dZnqliiQgJ0pwYJuvfTn4l6WFsXHzWNtrGtyrCL/AiomE
         3OiNlc69jgiJoFgcFUrc3+PBef3CaRcklWI4pN8NHl+2/cLfZ+9pN+gPmXEZk6K29r6m
         AsRYddZl2dBt9INNQGWfJiRdk0faCDV+CEfbxMYp9ZYxD2rsGXrLrmP2vneid6wVH6Uh
         dtrA==
X-Gm-Message-State: AOJu0YzQDb0wFPXR0DO/tqQ5T1sqfGLYrJ3zQL/r9/qAWyUa8DiXaIY+
	P+LNpcWghN8Dc8hxUU+FRNg=
X-Google-Smtp-Source: AGHT+IE7gsLol/gtQk5/RR/Is12trERxyghhpro+oQCmqwTfZS0qBNML+GNbZeVk74CKTQCaFAY9EA==
X-Received: by 2002:a05:6871:4c15:b0:1bf:e2a6:b287 with SMTP id ue21-20020a0568714c1500b001bfe2a6b287mr10086390oab.0.1698155211595;
        Tue, 24 Oct 2023 06:46:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:971f:b0:1ea:d76a:4f02 with SMTP id
 n31-20020a056870971f00b001ead76a4f02ls2179040oaq.1.-pod-prod-03-us; Tue, 24
 Oct 2023 06:46:51 -0700 (PDT)
X-Received: by 2002:a05:6870:b90a:b0:1ea:4dc8:a17 with SMTP id gx10-20020a056870b90a00b001ea4dc80a17mr12704884oab.28.1698155210983;
        Tue, 24 Oct 2023 06:46:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155210; cv=none;
        d=google.com; s=arc-20160816;
        b=HHYwiOxORS6DiPTABYye+ATEnQ9JETvvbc3kjXgDPFHlSpuUZpQVpdtk7t5H/ua0Fy
         qCpbOo8L2prU+R1aCjPw6cUcQa/JtBoVoEPuCvPAydH+sTJ73I/nwKqSzx3RDbuQT5gC
         87HVL206DixFP+it4xIXLOeEkNUUFbsJVxFg1476mH97fWp+rxRGo6yWrSE9ZE2igQkR
         zJClGEHmfwfju38gpfOSzDES7vZD6vOzpvmNmSFqG+eHli24sIxCth/sWH4uGyTf3m1a
         5hF6CMEZN8d71XQLruH8IVbUk8FmSFOzIsK+0Zoz0bmTVvUg3cDXZ9QJiZloHpVnvd/Y
         hzWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=griUcA7GUXZ/C94ijw+khTWkXdhOo9/SkZ3zjzjerBg=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=qDEJzv3Fsj2cj6VI4VUg1KPmhWncl2TkS0gOsTR0gGMxnbfAniEFJcOrIbh9gdiDLK
         PV4M2lFDLn/G86Y6fYSiLhO74EK6AapGlysaT154gge05nEd26xdUaPIyftFqE0A4U6Z
         h7K8btBTiCik7O8zCnBvTYEWl1h2GbGyETF8Dkcet+oQh9Yyii0Bx0qbosDI2BldwWzz
         Dfmr9jkgSzO92cSnt+WpMHqRcu/7IW3OTskv1v2FSL+WHKeNyoYsdzDNn8mo6/eGpwyX
         w4i13aLGLgi85lCowbKTEiItS20PTLp/gAZOkgvAxfCzeTYt9kO68Kp3/ih6bEQDBx5k
         /0Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S03hdruC;
       spf=pass (google.com: domain of 3yso3zqykcw8fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yso3ZQYKCW8fheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id nf28-20020a056871331c00b001dcf3f50667si1259386oac.0.2023.10.24.06.46.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:46:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yso3zqykcw8fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a8d9dcdd2bso84668077b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:46:50 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:7485:0:b0:d9a:cbf9:1c8d with SMTP id
 p127-20020a257485000000b00d9acbf91c8dmr216225ybc.12.1698155210387; Tue, 24
 Oct 2023 06:46:50 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:01 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-5-surenb@google.com>
Subject: [PATCH v2 04/39] nodemask: Split out include/linux/nodemask_types.h
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
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=S03hdruC;       spf=pass
 (google.com: domain of 3yso3zqykcw8fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yso3ZQYKCW8fheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
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

sched.h, which defines task_struct, needs nodemask_t - but sched.h is a
frequently used header and ideally shouldn't be pulling in any more code
that it needs to.

This splits out nodemask_types.h which has the definition sched.h needs,
which will avoid a circular header dependency in the alloc tagging patch
series, and as a bonus should speed up kernel build times.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
---
 include/linux/nodemask.h       | 2 +-
 include/linux/nodemask_types.h | 9 +++++++++
 include/linux/sched.h          | 2 +-
 3 files changed, 11 insertions(+), 2 deletions(-)
 create mode 100644 include/linux/nodemask_types.h

diff --git a/include/linux/nodemask.h b/include/linux/nodemask.h
index 8d07116caaf1..b61438313a73 100644
--- a/include/linux/nodemask.h
+++ b/include/linux/nodemask.h
@@ -93,10 +93,10 @@
 #include <linux/threads.h>
 #include <linux/bitmap.h>
 #include <linux/minmax.h>
+#include <linux/nodemask_types.h>
 #include <linux/numa.h>
 #include <linux/random.h>
 
-typedef struct { DECLARE_BITMAP(bits, MAX_NUMNODES); } nodemask_t;
 extern nodemask_t _unused_nodemask_arg_;
 
 /**
diff --git a/include/linux/nodemask_types.h b/include/linux/nodemask_types.h
new file mode 100644
index 000000000000..84c2f47c4237
--- /dev/null
+++ b/include/linux/nodemask_types.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __LINUX_NODEMASK_TYPES_H
+#define __LINUX_NODEMASK_TYPES_H
+
+#include <linux/numa.h>
+
+typedef struct { DECLARE_BITMAP(bits, MAX_NUMNODES); } nodemask_t;
+
+#endif /* __LINUX_NODEMASK_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 77f01ac385f7..12a2554a3164 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -20,7 +20,7 @@
 #include <linux/hrtimer.h>
 #include <linux/irqflags.h>
 #include <linux/seccomp.h>
-#include <linux/nodemask.h>
+#include <linux/nodemask_types.h>
 #include <linux/rcupdate.h>
 #include <linux/refcount.h>
 #include <linux/resource.h>
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-5-surenb%40google.com.
