Return-Path: <kasan-dev+bncBC7OD3FKWUERB6G5X6RAMGQEF5FG2CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A64776F33BE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:21 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-19259b178dfsf835002fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960120; cv=pass;
        d=google.com; s=arc-20160816;
        b=eqxesvIeher9qn9sJldMnlW2CgqjTCy1/CspI4CUW/Y3znQjqkigub4tYYUNWI53lK
         U0cLv+q0CT0EewoNSmA81C2ZK/w7KLlXx+4iDtSKUWrQPWwiHIfCHK8ftgebULYCtpdr
         1i0xRwlo5SXsbA/9Q2abvL2Y0xijpUzDzDAGp1ETHIXQ/NX3257UvzMmhxQ3VCLsAYUo
         78/sZfOd7zpaMp1GeSBBJORvN8oZ4X4OZRuBc08JPUh4Pz1PSw64YC/cMV2x1rBkqBa1
         ksJzwVfdJNhAhaBA6op0qavnLT+d7+w5xC1nzbto4IJpkO9bjjKaA5Yi1XvR2oSc8XSr
         Vv0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Z8K+cjMJ0IlcKnNT1IW9c4ouOlefA/bc/IKnWwB3jqg=;
        b=HEuKNTW8vv8wNPZd5HUi5BhRgxBjn78zj53UfHzzBhiTNOLu878s4pyQS3vYc+Ee8b
         GrDtJV3VXnG40ZRHMBbcphRjysn1237TsHb40n3ylg21VSGEhaqfA4CV6gPTfWnevm0b
         5yhyWMu6tXoAvMte2D80MuUPLjP7ex+1b0d/R+r1i13CgGzejqHVaKCibOTgK5qWd1qX
         mNWLmXzRdp9Mgw6fSCQzg4KhA2mRfsy/luDmREpafDDEtzpEVayfV9i9mORuKD4mm/1D
         QOQegc56V/+WhiV5TnkF9MUCRw6mDHs/aUV06b4VI75pXetUVGjCCNKCGwfN6KyGbIm3
         lqAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WPj8rory;
       spf=pass (google.com: domain of 39-5pzaykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=39-5PZAYKCT4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960120; x=1685552120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Z8K+cjMJ0IlcKnNT1IW9c4ouOlefA/bc/IKnWwB3jqg=;
        b=Jh11GKssxNYmwOaUb8TS8ff+kY9k5ye0OtsZtCglkROQx3bBzx+DF/4sXuJYHr4Cup
         xntFZ8CTHJB+gn5Tw4PqgiIPEVZcia0D/62FcCmba48KAvOZpdjLXjny2dNkC+SiyAYl
         fDPeQ9mDaNJxB33fb6XM9NqyT6nyI5d4gjrXFxKyrfkmiKnYdPgG+JJRyaZLelx4O+t8
         QNJprSJj8Bnq03HNbfxIkK2sFe/6tKyDBvfJ4FU7Tkvta3038qDIhrMPH3W0RVAZTSse
         FVHXivWY8vRhE42QLNHH7CSf48tTDkp6D3Lk2llmq9hEJ7di1AdlpX4LhAdtCtEb0a6d
         vbOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960120; x=1685552120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z8K+cjMJ0IlcKnNT1IW9c4ouOlefA/bc/IKnWwB3jqg=;
        b=biyLZjofTITCrqdYoo+wNu7mKpmvaMjntS+OEQTmFtISzb7Smo8JqVfGXULOsD2YaI
         iv3tp3s1aYW7Y4m4c3CMNxDzQ5o+Xa3sDfo+whRcK5Sy3/Xzq22Qro7BTeVWGLlBstg+
         5V3u9SApk2qP6xLZr0OWTELNFlJBjX0gDJw2pYOv0cvxiOlJy88QpKtGukQ5LwRrJuwv
         CZjwPJEfXioXXlW4sp1PAhFnZOSoAmbocnBBnrgSVE7ue4ePEoDysfXDOudYjvooMefw
         3XE3+CVexdYDYQGMLnX0H19wEZrJqIBwYy/+PVOYJo9qDsOW9ZWuwa3PxhChIdhenH5j
         R4hw==
X-Gm-Message-State: AC+VfDwE6vGsjLb7nWT8G7fjhK4rjxtU5/ir2APUH4Gqt9ZvWv+Kc9zG
	J80QgBVjSbnLEnNMyXWxgwI=
X-Google-Smtp-Source: ACHHUZ5pRVEO+7xP2D2Se06ludSnG6GeQmMzAQFivxmF749BzBRHcXez9KSogXvkM0CYHcRt7Mc7kQ==
X-Received: by 2002:a05:6870:1399:b0:184:95f:c74e with SMTP id 25-20020a056870139900b00184095fc74emr4977060oas.3.1682960120473;
        Mon, 01 May 2023 09:55:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1a03:b0:547:e5e:2fe5 with SMTP id
 bq3-20020a0568201a0300b005470e5e2fe5ls476996oob.5.-pod-prod-gmail; Mon, 01
 May 2023 09:55:20 -0700 (PDT)
X-Received: by 2002:a05:6820:414:b0:547:7816:303a with SMTP id o20-20020a056820041400b005477816303amr6243836oou.4.1682960120018;
        Mon, 01 May 2023 09:55:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960120; cv=none;
        d=google.com; s=arc-20160816;
        b=IThpAuMJLUrU9n1CinZnMVKe4NT/Y1PMFU+ftY1N+6Xwq+2gIm4dR9YYa5MivoccEX
         4ufQNkiPwb1ZXPle6EVrrWUrwYDPBJh2N48PzjK6iKDf0o1VvtYy0omxhfAYaMXHI4wu
         HOI/3oM+rWaKSbB3GPUEt6C1mcYWy2h2BHjrrEFOuzvDVB1g7uAsY4ubOECHWzsJHIFR
         M62uOJScr8TzlnKt3lEYcp6k6ShgyE3ALAYTuT748A717YIG5ZNkcc3NazMisHYV7z/u
         UNnk8MseqWGgzjLEfB+QbAtGi1h/+xgetz0yMgjzAKOL3JMBvJIoOHmVqvrMUpG6vxPc
         G41w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Am8x4T/C3ER6nwTMzq8wqC7nUn5OpA8nmjjdL2Y+IyA=;
        b=yP89UVXlYKw3N4pZfkMrNjSAUOqW4HlVJwDMGRUFloZGtcT3rBp8rOTK3DuomsHSfx
         SQUh/N1Pkq0j86kz//IXpmv+vL49C+d/kCbtS069F5+ujINF4xurSFHBlDvk/hmrY/X5
         V4/98Hvy5lW0Q+0/ixV2n7f01tRIBV9n9HDgV4waAj+ls3oupueSqUTghh1Kp6pKWGOB
         FRLPzyQ2j3I+BI3obmZJdIRfJlgFHqDZubyA9I70zLNZdYRl7tjiykIh28L8kj92E5Gl
         NVDHn7jY4KNWpTJyeFh0iwJrX0QVufYaTcXEbahaUmJn6kRMxxIoY0WYf+KY4U1Y7iYI
         MvGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WPj8rory;
       spf=pass (google.com: domain of 39-5pzaykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=39-5PZAYKCT4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1049.google.com (mail-pj1-x1049.google.com. [2607:f8b0:4864:20::1049])
        by gmr-mx.google.com with ESMTPS id v14-20020a056870b50e00b00187820f810dsi2170191oap.5.2023.05.01.09.55.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39-5pzaykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) client-ip=2607:f8b0:4864:20::1049;
Received: by mail-pj1-x1049.google.com with SMTP id 98e67ed59e1d1-24de504c5fcso2043233a91.2
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:19 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:90a:24a:b0:24d:e504:69ed with SMTP id
 t10-20020a17090a024a00b0024de50469edmr1685228pje.3.1682960119293; Mon, 01 May
 2023 09:55:19 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:15 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-6-surenb@google.com>
Subject: [PATCH 05/40] prandom: Remove unused include
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
 header.i=@google.com header.s=20221208 header.b=WPj8rory;       spf=pass
 (google.com: domain of 39-5pzaykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=39-5PZAYKCT4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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

prandom.h doesn't use percpu.h - this fixes some circular header issues.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/prandom.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/include/linux/prandom.h b/include/linux/prandom.h
index f2ed5b72b3d6..f7f1e5251c67 100644
--- a/include/linux/prandom.h
+++ b/include/linux/prandom.h
@@ -10,7 +10,6 @@
 
 #include <linux/types.h>
 #include <linux/once.h>
-#include <linux/percpu.h>
 #include <linux/random.h>
 
 struct rnd_state {
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-6-surenb%40google.com.
