Return-Path: <kasan-dev+bncBC7OD3FKWUERBA4MXKMAMGQEVJHDW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 11C145A6F8E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:57 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-11f203a113dsf2110634fac.20
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896196; cv=pass;
        d=google.com; s=arc-20160816;
        b=IB8/V+E9a9n2fZk3guKGwkmlGJHLDD1dunrBdf3RDrzH012TGcAVv2Tn2+DvhT6qZ1
         DRQPcU83vlmv+ZgLZVHKrTAO4u4hvd/SVh1yyrjkQ/IQSX3puFE8l9ARjDOoZ4rBggNL
         aGvPCGUxr6i0m1CtWLv2cUG9UNkqe/uId1VaqF0G+/IoFEimA680GwWr4CDVRDrMJ0DY
         rCHGZcD3vwkvmpprpj50fBJ2JgEr0b86QJQrV8q0FlVTx3IyGCAfdIVztE20JQpmTWaE
         OxPRevjUH8xa/fWV17ejqM703FTJcYq4RdoJo89PT+FwHBfBexNAfvmlK8eSL2y6SF/w
         KDJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1vBOG3GHTLEzOJ5Teu7EXWs1Rabj3tb9vWafJYI9lpI=;
        b=ezcO35OhTl5fcLMl+xfFC69Idha4wNe9SUrsqFxvGz73Z3qS5IqVsGNLUC2IXl8FdU
         jj1RNFW6gQa/n9urDK+WxT5e85BzEdOwfa9UafGJ/WDlqH9Sm+8j97Dj12rIzIgQm8oC
         gYzeeAp2uBp1wJx62tqhUiOVLPVimn+jrzowS3RaqNzTi8LfA7CCxfMgHIrclKPmWwd7
         6ASdwE/4JLQy9KV6Eb/t5DMUBvUIvgD3RIMdS7GhSCIUSCVrfWL3neJTjSEhW08xGj0D
         qMDGr9d8MtWBwtBg1DDZmuMGXNZ/cFCW5kwa1krfwXSzH+qrHrSkk7n5uHhrWkiLMeN3
         DqtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AFaSMy8j;
       spf=pass (google.com: domain of 3a4yoywykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3A4YOYwYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=1vBOG3GHTLEzOJ5Teu7EXWs1Rabj3tb9vWafJYI9lpI=;
        b=AVaHu4IAhtXkIC9b4HS8wubI8X7UQKLr8WOYNiBZDVS6e9QTmRWzRaFpPzlq2SC0hR
         25ny6lSzfO660+3x7ql64+tYvDpdxt9easDWTz7Ql5NLtw3nuUt+AZ82i+mVATNyTeGG
         Ga5KN62RqOczZrHJZWjyvPE9L2kqvVmgzc4IuToTzkoyNIT7pv4U9Uy/f3lkwy4Y50So
         5Crxg7xxyM4o5RmvMz0LmH8eTE/q7DLZo5U3D+I63wKmBVLMQc0YRU64NsU9iDx5smPD
         uTpg5Kc7Jau0ulTMJRyQng9COrNE3ZBSnUMQ90CemNglzIC0faZNvt1g97vaRKA5Djm1
         Fxdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=1vBOG3GHTLEzOJ5Teu7EXWs1Rabj3tb9vWafJYI9lpI=;
        b=hrjrtB1eIuHzu/tlV5NaCufcQFC7cIA18oTpFsHc6C5xlTYm1w8hGIBnsq8CII9Pdw
         vGJFS9Dq1CgZcs76rqPIvr5lpMmce2zvv6jhr2mdZ9yrH8yYNgssBHRlntx7sj5MvHpm
         ATdOdU/wTvkB+mfRGPYuNftIIJnXNuiMYobiSKe1W1ppiLWDHzxdv7bdCCuIMqCu+fP/
         Zpxh1tzT6tkvbnTs/zmfmPGhYka6vw4qDU3KvcnmsLfIpwPsCwZmewUH3JircS56fXxq
         ERu9edmGsVGZcd4iAEUML9Eq5ERTBkQdr70EbaMlhtfe2pD9+WwXTA51jJcM/aDIMWZR
         0Syw==
X-Gm-Message-State: ACgBeo3zR1/NKw24LsfgWsKR6S8e+xewCToVfyCpvMFdeonjEwkE3A+Y
	P0GlOFMjsZfGzYb6Scbq1i0=
X-Google-Smtp-Source: AA6agR4Q4JQMVS2oi7kNt8xRa53X3h0m+z9JCwvahwsM4ihVgKDH5IE1N6vi0/l0h00QGWwaC1P+EQ==
X-Received: by 2002:a05:6870:f626:b0:10d:a798:f3aa with SMTP id ek38-20020a056870f62600b0010da798f3aamr33750oab.194.1661896195928;
        Tue, 30 Aug 2022 14:49:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:770d:b0:11e:47d1:a33a with SMTP id
 dw13-20020a056870770d00b0011e47d1a33als4195904oab.11.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:55 -0700 (PDT)
X-Received: by 2002:a05:6870:b00f:b0:11f:b1e:6142 with SMTP id y15-20020a056870b00f00b0011f0b1e6142mr26025oae.234.1661896195614;
        Tue, 30 Aug 2022 14:49:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896195; cv=none;
        d=google.com; s=arc-20160816;
        b=gmUMW/8vbnQFu0yYQaG244aRJbwZJJaUyybb7zDxMRcqa7JX1lw9rCSTL7oFwIF0p5
         s82FV1nobWQkxqpGvIrhP9Rcu1gg7aHEMwBlrSDTsV3igCgOA4y4jx59riGe+99/d8fh
         UK4rKt5g/zIEnvLDoxvY73ZuVq2O93CglLpOfwSpST/Srx3l+lqQjQmDIHhMpg0l78rY
         yZSGS8MbVbdW+qV5quNjPxk/wz0Qryf8FVW+PEY2avUQ/bMA1My+Tt7Fo/eRreACIJjK
         +vW75KJ1a94SoRK6EGyrQQY4pOcJr8ilNqrDKczkZDmkiBJF+NtJmCU5UYKbpqzJ8HcG
         kiEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+dBCH/ZYeXKPl1XZC0y8jtwH0hgKGXE3JjJWq8gRM44=;
        b=z9PwZPgWen2Z06iOcOZgmT0ieKwgUM8/qdNYObQWRAZUhlOmfd/c/SALbDjMN2BLQU
         REfUbkqhYv23maZLl0FRYW74hCcYsvBKEz+xGOExgKNFcOCDnned/+V8Oq+HUa2Sk7up
         6lMy7pAFOgnu1hZa987JdOAuA2bSSL87GZ333QglfpiFnqRis3xw7DZV7Tv9Kdt5cZ3F
         we5QoNur5Mvd6n3m0vvwzISVP0LlsHnufCEUefEvXGyVWLWBajGVrY4lwBOU/Uzgdo1F
         gdyjXhRxm0tMGstBwi1wTFDOJQCMpmFNHAqXofNuSi8UXtbtAzk6Etet9VowsotZl/wR
         L5Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AFaSMy8j;
       spf=pass (google.com: domain of 3a4yoywykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3A4YOYwYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id l21-20020a056830055500b006371b439b4esi537910otb.5.2022.08.30.14.49.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a4yoywykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id j11-20020a05690212cb00b006454988d225so723091ybu.10
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:55 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:94b:0:b0:68f:4e05:e8f0 with SMTP id
 u11-20020a25094b000000b0068f4e05e8f0mr13319593ybm.115.1661896195289; Tue, 30
 Aug 2022 14:49:55 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:01 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-13-surenb@google.com>
Subject: [RFC PATCH 12/30] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AFaSMy8j;       spf=pass
 (google.com: domain of 3a4yoywykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3A4YOYwYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
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

Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
when allocating slabobj_ext on a slab.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp_types.h | 12 ++++++++++--
 1 file changed, 10 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index d88c46ca82e1..a2cba1d20b86 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -55,8 +55,13 @@ typedef unsigned int __bitwise gfp_t;
 #define ___GFP_SKIP_KASAN_UNPOISON	0
 #define ___GFP_SKIP_KASAN_POISON	0
 #endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define ___GFP_NO_OBJ_EXT       0x8000000u
+#else
+#define ___GFP_NO_OBJ_EXT       0
+#endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x8000000u
+#define ___GFP_NOLOCKDEP	0x10000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -101,12 +106,15 @@ typedef unsigned int __bitwise gfp_t;
  * node with no fallbacks or placement policy enforcements.
  *
  * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
+ *
+ * %__GFP_NO_OBJ_EXT causes slab allocation to have no object extension.
  */
 #define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
 #define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
 #define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
 #define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
 #define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)
+#define __GFP_NO_OBJ_EXT   ((__force gfp_t)___GFP_NO_OBJ_EXT)
 
 /**
  * DOC: Watermark modifiers
@@ -256,7 +264,7 @@ typedef unsigned int __bitwise gfp_t;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (28 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-13-surenb%40google.com.
