Return-Path: <kasan-dev+bncBC7OD3FKWUERBAMW36UQMGQE6S6KO4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id BA4BA7D526A
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:47 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1caace1905csf914345ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155266; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bn1ecS3w/qBdZ3W7B9p13zBVi6lwTcthAyrmlb96UWy0+tEC7sIOi8ES+k3ir7s3MQ
         kyKRa4L7pvaBMBoehFE4qeDfoB6QQNTz8sOcbDICnR/FOn91xj6Ci/tJi1J6WFreLiCD
         juv8elMmdILVSh9UEAaRi3QWrhQSKkkIyTfhfpP401utaBSezk5HOTQGkF4MCdQpHQvb
         ipws28Z9hq0aXAy1+Df5jSTPU3/NB0my3VNFBcLA+vtAP1J2lpmdEGxFh2ghknCXUmzQ
         t9Yw0n7OA3T/7RuxJh/xRrBSQpG7eJkqSAjE2DL4v5GjGydHWWwZZxzmmZw1cFoaUwbL
         TVSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0UB032bGfpR4BvNIbr7XlHUagJoG7+20XWv1ZIwxPRA=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=lBAFqj0Ha7VNOJwTw4QdKKqzZPHcX8iXDjAThzvsx0Cyg0r3VYbNO3VFS+n3/Ojvvq
         Tl7YcZbYa9XLNk/WQukkxLvJb6YQ0GAQys4v15MViFTOc7jt9mr1X542LPiNrkjnrChY
         xh4Sy/l4MdO4CBUy2nXzdKdKphkjW14Sw7qFYZ2tCQ78VA4YvRmGFDSqborZ7hEeXy1G
         9tGcVvL25SDBznACLdv7YizHU2yeBrIXwjViMgIQ2ovJ0azWJ3qAE44Q/87wdaJ//pAm
         y3OlX8rWMGhoaQTmBSipoeEs8AOlglzOtjGKlzs9tshOxyk1xHTiZKgxugXzCWS/BmBK
         PG6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VsLru6jc;
       spf=pass (google.com: domain of 3ams3zqykcauxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AMs3ZQYKCaUXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155266; x=1698760066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0UB032bGfpR4BvNIbr7XlHUagJoG7+20XWv1ZIwxPRA=;
        b=H9QJYTEbzCMHfx49vPRQ20HvrilH1hzKeIOkp/IJtmC7JY8CQ6lbQ0UQSAa7s641I4
         rw4wo2Ju4nsm1wM0ANMIgmrnDgkpp2ptXx5Hz7tn3+C/YgikRklLVC9biZ8BCTrs6T+d
         fFrrglngwozzXw2LDjwO5AxxxERZZ5C8V+XXXDmGw5G9qb/PPjQGCHZcHs2xK41qMF+l
         2XdgR9+0hgZ8Jz0eZj9L6x29xrjjL1ZKL+QYI+JYu4NXONWzYtWMrrL3+8zgfi7ZKCNs
         nTkk2IQwDFzWQ84Spb0G+XZCdrtTd35/gFF9M+NLdOgEpyq6tT5rPjX9gfB8T9v5ENPC
         pf1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155266; x=1698760066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0UB032bGfpR4BvNIbr7XlHUagJoG7+20XWv1ZIwxPRA=;
        b=eOEVf5a8EJqovtP4Shu/s2z+0EUC9y05TRJeLLyxZTAVYSRVTjWUkICL9NlxmlPFbU
         zTbkb/p8ndYSMUfBIToTYKcYJ1Fh5j3estDZgAYCeYnHx0EE89uzRMSaHmX1QSU9VE+U
         P+u35D0InVm1+JHLaSu61AKF7gSMD/QW2czlplsPwjmxnBIVJ38fKWAliJnjcvK5QuuX
         MGDiu+9KBepgbmdH/VvaEYRaOa6x2Wxo0Lt5eD83AA5Lb1XAopN0YUXAp7fvQz1dCnLE
         WHH7fJKNxEhldda6eRZiPQ8kGjPqG5CXQlc7AXAdb9N5ZbmjKG3gpg85RPi4AoIugbmh
         F19A==
X-Gm-Message-State: AOJu0YzYqTY3MRpHtjSExvkW+++K0+rlu1pl2HoyFlsVGUnxmLOmSfud
	M0a0Evij1+qZAzkt6BOaz8c=
X-Google-Smtp-Source: AGHT+IEZkyaTrW5NIvdYABtXScsluwOXu/FUNF8NcptJLQoOGoc2LkN7d+ZWQMVJxGOucvKIo9Gz3Q==
X-Received: by 2002:a17:902:82c2:b0:1c7:25e4:a9d5 with SMTP id u2-20020a17090282c200b001c725e4a9d5mr172066plz.17.1698155266097;
        Tue, 24 Oct 2023 06:47:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b90:b0:274:60b6:c873 with SMTP id
 pc16-20020a17090b3b9000b0027460b6c873ls931519pjb.1.-pod-prod-03-us; Tue, 24
 Oct 2023 06:47:45 -0700 (PDT)
X-Received: by 2002:a17:90a:f0c6:b0:27d:75e2:488a with SMTP id fa6-20020a17090af0c600b0027d75e2488amr11122545pjb.35.1698155265145;
        Tue, 24 Oct 2023 06:47:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155265; cv=none;
        d=google.com; s=arc-20160816;
        b=JwD0GLt5QpkE53WVvxWM4lUmi/naDo1TBDJNzaKaEUbggqBYCIipeKz3wNbvNNpIvW
         iynYAdyVFNCSyLgn0PlFL8c05UdgLalurXal0DNOj4dmvqCaMM47diFGcmPGY3NnEUgP
         bmvCTGXFc/b9gnEWSVPOUjUO1oQnmjIBur/9Ptlc0+lFguXlToy8vDKk9IBSA25T/dF6
         559b1VLNwdidEws7jy+STJz+TYh7o/iY9NBA4qyDjHoG1ZNow7ISPWaR7K1niOKcnE8c
         WzDaB3SSZOkYh7TgaAm7bs1uuynQHEmeKiChZsrpV813Nljj92IslJKtoXVTAPXpLBGd
         jfPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=7C50BM7p5C+vJ0clcF+/KvirWmdIP5XWEnNLFYgTdS0=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=UmO55ypWBsrrfHWwkx1ST6GHXhz76HNOvt65GylbDqIvQJPpovb/jXes7gBxwI8rbR
         +idchl26RNwhBJh9X/z5cunylbJko64a4yJ0YP6B1Ec3EXh/eFbq52dKVoGihXIzaKx/
         BrbBgtoTVfyQ3UWLOdKYzLm1x+CVp7uaAXOV322eYVkfcNRTm9iuEt2Cybm68Eaug7LU
         JPSiPPOSC3va5VQyiLpKf+yx1jWpT1PElaUY5DWiBS91MAWHqO+GxYNWyKt5Ebyvc2zu
         Wx4P+n8yMu+9df+cBVeFmSt0F7xQwWwVrgY7Nm1j4SKJDratqqUIj4GMVgQJ7g3Nvu0p
         whzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VsLru6jc;
       spf=pass (google.com: domain of 3ams3zqykcauxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AMs3ZQYKCaUXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id g21-20020a170902e39500b001c3fdd40f56si561437ple.3.2023.10.24.06.47.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ams3zqykcauxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9cfec5e73dso4391995276.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:45 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:d34e:0:b0:d9a:e3d9:99bd with SMTP id
 e75-20020a25d34e000000b00d9ae3d999bdmr212803ybf.5.1698155264079; Tue, 24 Oct
 2023 06:47:44 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:25 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-29-surenb@google.com>
Subject: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
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
 header.i=@google.com header.s=20230601 header.b=VsLru6jc;       spf=pass
 (google.com: domain of 3ams3zqykcauxzwjsglttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AMs3ZQYKCaUXZWJSGLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--surenb.bounces.google.com;
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
index 03d9c5ac01d1..a9e61120d4e3 100644
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-29-surenb%40google.com.
