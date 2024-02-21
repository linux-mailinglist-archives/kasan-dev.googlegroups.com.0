Return-Path: <kasan-dev+bncBC7OD3FKWUERBW5D3GXAMGQEYKPVUSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B981785E774
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:16 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3653c94ed71sf19575ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544475; cv=pass;
        d=google.com; s=arc-20160816;
        b=0wHl1eu2hRuiobjfj5C/gU111BRkkCf7lIuqf6BF4g2bz7QIBq4CpOQrekeOmloNgc
         ufa3fP4XbiVVtfwgY2vHAeKCkXql2iUSB1XzFuQ5wAY2H67DVUhZbzDuSq8zKHiWG3Jo
         L3LRLiXnP9sk+o3bCngMpMzIAJbpbt5ragBLiB+YJwk5nSwVbfLbU5PJjo/5y/F2nmDc
         9zwq+qsJeJMgABdHwrhGH387lZr8QpQc2bzy3S67Hp0zfjc/e/F01LryQtIGhSLoiONn
         VSg8+x6PsaIR1SFoNjEoako9b0acPE3U3F6W6i3dkbdWvV6DEGOFns1noIOuLnS0qAHb
         /SRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=FElDtLgyZ62n1wnujF2sLX7s3wAbwK06z5zt2Fh6+UE=;
        fh=wX29FyXbamn0+2ibeH70b3f/kfnRHz1FoX3E3JT/bJg=;
        b=vaSJakktuBewWy129zGh/TqxopkxYlsKBqrihK20VttDZclfIY7til4Vzk1qKlCBEY
         7MU95Z/65yZERAh5ffL0fN5aziV25E4xUwjth4rQESi1gI3RleXIQnvvBKZdO4f3/cQc
         CXKXgKazHZKX++hQiCaDhc/PBjv9Tf6aHNUvWdsJSxIDLZU0msFhkMskAvcCHybFkUX5
         IghqWvEq++T/23mKF9LJjCbrvwXnGHAmpvHe69RsPVvYQ0hLNY1e15suEOqGD295UIwO
         uXuF3fhz/C5I115RAkqLsnD1o8pPmISOLVuG7u0KSylE89f17J4608PjCAVz6Y6Iq+Ap
         w9KA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qAteBTFf;
       spf=pass (google.com: domain of 32lhwzqykcq0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32lHWZQYKCQ0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544475; x=1709149275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FElDtLgyZ62n1wnujF2sLX7s3wAbwK06z5zt2Fh6+UE=;
        b=EXGVEiZc401JaA2Hw4LGLVUCzcayOmh7U7bbrLiSIcxL/ZShdDnE1DBBKmLL8LESca
         tzrxhfyKcExqJmvav75viQlRn1oM02KblpWYTOgITM2cFmuhkVqo+lDqJ8z54J6BI7wi
         mz900YHcIgonxiuN9y/Vz/xBn0CtozN8Qs+Uoi37zBeMzSOrCIayxX+vbEAOx5K8rohs
         9FEr7/s0OMOgURnfxWIYwNg+Ox7EGoNvo3tKDAXwIjrCCJNoMBU86ny7/B5zCXL/yGpg
         +3Ktf/VY2kX2bX2BcwJflRinXmPwOKwTVRFeXl8ENsDFFO7+dA6g25wU+UC7BgySZyVt
         hQSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544475; x=1709149275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FElDtLgyZ62n1wnujF2sLX7s3wAbwK06z5zt2Fh6+UE=;
        b=BASS86lgfj+TtmvkZCddsyiweG5Wj2ShT4rLlFb5tz2VHhhutnYZ7SFipty1kli+n+
         UKiR7DgrMbmyj5JqDa2Up9cTnhPqFlO3vF4lodNz7QGG7kpXRA6jUAtFv8yhXxuD71VQ
         ZPFf9Cy6nz4EXRsCLMiEkleMvpBHZp8aA8KS7Tm3TrGPhJUK6szQD/tf3fac3aXyFRuv
         PoFa2AagyDM9+HJfQMVRQ4Er+NcZ3r31YwokmbdAa0Db6pBjiyqI/s+b0X+5varscyid
         0OxZW9Wsi/Tkz1SV3tAWZ7bRknUuRmrAxJBHVdP/Vd1/w9MbIodQ4GrDZVvxY3Sz8y+y
         bBEA==
X-Forwarded-Encrypted: i=2; AJvYcCVCXztzNUdZbzNsr/xzvsIzhti7zGuX8uAJmStcs636x3H38sae9xRVUDIBOUL/BY559unpFfdmdFZ0EdcScVRFcZeysecv4g==
X-Gm-Message-State: AOJu0YyWjhgQ8uD7ggsPB02f0wiIBKN8nQ5T9MaqOCo5ywaJ9bPJRE71
	ZoFZGoclDPmzq5FPaWXZW6L+u9/aVnU4LU78VKhFgpJkfZlTIUtr
X-Google-Smtp-Source: AGHT+IHdX2ge/IPEQ8Z0X6tdjPDWLdLFbyUJ+wolBFtyC3AA+DYZ/6rXhW5H04+Ps6gt1U3ADAAsrg==
X-Received: by 2002:a05:6e02:1f0e:b0:363:db1c:22ef with SMTP id dh14-20020a056e021f0e00b00363db1c22efmr310419ilb.24.1708544475569;
        Wed, 21 Feb 2024 11:41:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cec3:0:b0:361:9298:e7d9 with SMTP id z3-20020a92cec3000000b003619298e7d9ls2426248ilq.2.-pod-prod-08-us;
 Wed, 21 Feb 2024 11:41:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5LiEpq4uLanYrSkhW19qptvMhW8odxUBosJG7FeaBg2TONy6/30mxPKyeIHsCxMqR3eQUtVeHKCcrQvNxKmnA5+NYsc1VkntCqg==
X-Received: by 2002:a6b:7949:0:b0:7c4:9cb9:dac with SMTP id j9-20020a6b7949000000b007c49cb90dacmr20980695iop.19.1708544474897;
        Wed, 21 Feb 2024 11:41:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544474; cv=none;
        d=google.com; s=arc-20160816;
        b=wCaUL7KTIcKuDG/i9wIt3+QbPibefOrADOAVgFTCkyX61/UkNKRzq0U3VdCVhaMuwk
         qwz3ae0ViHMYB8c0sqhM4Fze1xdJ+VVtZNz9c0sG4Syozqh9A/jhRCxyDgGzVKmqZrnK
         tt/2wKN+vBjVqwdks+9dsKrAuqhXs8oRvIrgCpvRyoxSZw1Es4XGuAS+/FIJ/Efik22T
         mFb2H/BsMPZXLzjJM0ra1rrJMVgedyGTcBDnV/H/glhTBR8o38/b+OSBdPl7baBs4vG9
         +AZxVkCFaaD4VA4z+vwc10vUxuevEcKllVGvCo76Itv5WyPhrAmJxGg0tzZwxo5De6uK
         QV/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DcVDeB20sah+c6m+q7qbj/Bohzcv0RbxXXpsl4x4Og4=;
        fh=8eT9GceoP68a2DxuxlttrjwiRs2RlfB81NlC8+DX2zA=;
        b=gQLjxTtHrQEobVhSiA+xYO+Uy8M601AVIq9q/DGafPKJnpKjydJK6ETxpqwgwaNDfM
         WSq1JoHi4t+hcqFLnC9L2RiDOFPO4QnF7Wr0P8NeJBp9aMQYcDr0kwOlMRORV5gMJVN7
         CGDEauNgGyg226mn4jREwT37aDi6m5t3PMH5Zdy0sJrlisM3whOcq0+gbO6EV8uwwbtW
         y8XHiuzKwXy5K29kK3N09tG8R98jZUgerY1x9sYwUTn0DOJihFrjAaG+W/EuDmoMsnsW
         U4A/xdXwAZL6/f57atuxATCF4rMAjFeYL2BqL07NMhN6fWJfsbqHbUCfBIMU4bC92uGr
         80mA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qAteBTFf;
       spf=pass (google.com: domain of 32lhwzqykcq0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32lHWZQYKCQ0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w17-20020a0566022c1100b007c769ed87a8si135632iov.1.2024.02.21.11.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 32lhwzqykcq0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-603c0e020a6so58045637b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWNRs14AHDZZad1+UoS9FiAxrgAyjavKX2zxk4hTH1cJrSCe+/3eO+oKIQlQl3qlEZFvul4+1htVR9ymv+wPJQlbYQrCQc9Rkg61A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:4ecd:0:b0:608:9561:fdbe with SMTP id
 c196-20020a814ecd000000b006089561fdbemr96126ywb.2.1708544474186; Wed, 21 Feb
 2024 11:41:14 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:21 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-9-surenb@google.com>
Subject: [PATCH v4 08/36] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
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
 header.i=@google.com header.s=20230601 header.b=qAteBTFf;       spf=pass
 (google.com: domain of 32lhwzqykcq0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32lHWZQYKCQ0574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/gfp_types.h | 11 +++++++++++
 mm/slub.c                 |  2 ++
 2 files changed, 13 insertions(+)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 868c8fb1bbc1..e36e168d8cfd 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -52,6 +52,9 @@ enum {
 #endif
 #ifdef CONFIG_LOCKDEP
 	___GFP_NOLOCKDEP_BIT,
+#endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+	___GFP_NO_OBJ_EXT_BIT,
 #endif
 	___GFP_LAST_BIT
 };
@@ -93,6 +96,11 @@ enum {
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define ___GFP_NO_OBJ_EXT       BIT(___GFP_NO_OBJ_EXT_BIT)
+#else
+#define ___GFP_NO_OBJ_EXT       0
+#endif
 
 /*
  * Physical address zone modifiers (see linux/mmzone.h - low four bits)
@@ -133,12 +141,15 @@ enum {
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
diff --git a/mm/slub.c b/mm/slub.c
index 76fb600fbc80..ca803b2949fc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1899,6 +1899,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-9-surenb%40google.com.
