Return-Path: <kasan-dev+bncBC7OD3FKWUERBTFAVKXAMGQEC7AGLHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D54F851FE8
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:30 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-297040eb356sf2742162a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774028; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJv4cKg8XZ2lkoaWSfb7sajlQ3bTfuZR77e1/ZN1ECuGoofasWp+/O0nknlsWJhDug
         79YU6xLRZmljP8ICONjvnTHxsUBbmnxgpFuT1KvdemPKkuSFIKHshxWMSqHSENdY2aE+
         7jXSDj16u9UiYPDuQTfpZSTYtD1WQ8/cyKikb/aaRsFgd6oHNgokug/VPbGlZ5PqTtsV
         NDw3f1dFmuEYgToW/HK6VwBsi5u82R/Lch6UqfvioEPi8LnqrELWoI6xkAx7c13lJc9Z
         Hz2Z4fxM4WbtpB1Kqc340zkbNLOECr91W51MX9f6Y64RSb1ahyTBZex5aKtQyfIaRME7
         Z8HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UtrULaQyvOTP0B4HNo1XDgNCDglM8jB9EFpQYb38+Ig=;
        fh=tAtgESmmQz37cp+ZTEt3o8Tk5FayIaZT9gEkeWUNS2o=;
        b=rjoVHkMJh1AL7lTJ2abpuaKVAMSpO/Hp2WkQUvqC0/g6Wqn56xB3M76IbQcM4aiWEB
         CMACiCyALmLiuvDwC73m3ptKmCxcKhbmrPLN2jWdIrvJ5/B2x5Cn8bvi/WqlDCUY9fAQ
         aHaWHZEuqtspJLHuRuXPX6ne297WjuHRJYCgofvwZ5QTYTxzky74JB2TH1q6UfAWBl0N
         uzAsyWa4h+XSB98CeW2Sgyr9L5a2aEY0URj47I5W1yTI79N3FLGIhkqRTrJptkPt/7Gt
         BVrA1RpzZXb2eiNIN0k6/ZxdfM0OLJxJ1HsA74u1ZjtGhEEl0cdIAFvxbPr92y9U3/o1
         24KA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TIYHuojV;
       spf=pass (google.com: domain of 3spdkzqykcck796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SpDKZQYKCck796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774028; x=1708378828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UtrULaQyvOTP0B4HNo1XDgNCDglM8jB9EFpQYb38+Ig=;
        b=sWvQhOvKIMIW2PdpH9z6Ve1PJRFyoUwN7Gc2Hx8M5n7Dp7okUT4VpgRPU/Tn+W5nZV
         KE2UzWcs50RkM0LqM4s3ph8CxhtgAGYtw1jiFjZ1X6bxcyyWK9GdE0I9jBaBeM+c2wLg
         LFIlXroLlsgWbw+hrCeY17XMsIYOdOfsvORm32O0cdPxvWpLkZxk5s8W2+MbN2LPlhK0
         4imbI46mkuuRVI6JLRBYL3NAoi0+bSKuBLxjsJbgX9G+RisxLeE8pUzMeHsX3kf86y0G
         uQf0iRrI7lZvlholvXwBOBYE6n8w7h16X3KY+SFhMRIMY4t38tOBKZZnAvkwY4lJBtxH
         GsgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774028; x=1708378828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UtrULaQyvOTP0B4HNo1XDgNCDglM8jB9EFpQYb38+Ig=;
        b=jh8ZIDN/UYsNVVsf1ODKgHqokWx6nrDhgxRumD0HsQhBL35ASo6BXAPi/CdfyjpXUP
         TjfHBSCNjOV82zjqsqmGPlNYpzXv8LsndbUZbj3Pn69AFYPd+suMUktdys7zX2eRR//p
         t0eOS93CAGYQqrZDUVfx8aQQ7PROmPCqxYL3b3A+uY6K5QF1JvuD1HXRd2DiqH32WAln
         +xum4mTz+6UFPy7YFee6QymuEpEcIZIcPfTDIuJTRFoehPOeSS0bZtdkE+fwYKGmE3zH
         uTeuXif0gqecYVU6um19tbxfEjok11Ah19pLMSLb3TrADo5XreOsRwonCWVCLzlM03R4
         jeQQ==
X-Forwarded-Encrypted: i=2; AJvYcCX1cHGOXvFlimGJkt16z31hvAXX4MhMBbN/3rZ1s471tBv4him18sNX7/8QOOXyVMmlkx3ZW8unrI9/z8IDrmp+7AXCEGVtBw==
X-Gm-Message-State: AOJu0YzFXd5SKlEvTLZEkh7sivJBae2b8iBTNUy3yyvIEdE6Cc+Gh0t1
	lLmeVdWhD7tpqDDwIoAz5QzqBJOZiLCoCsfIeQBFYIb6h3S2UA4F
X-Google-Smtp-Source: AGHT+IGvUzKUKPR1Nxhfep9SFDR4xxCNqazYLYPFUEd4GJW4teE+5bCvo8gq91MMyfE2LjxgHbiyTg==
X-Received: by 2002:a17:90a:e394:b0:296:286c:4dd6 with SMTP id b20-20020a17090ae39400b00296286c4dd6mr4331723pjz.46.1707774028606;
        Mon, 12 Feb 2024 13:40:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2b44:b0:296:f3ee:5700 with SMTP id
 rr4-20020a17090b2b4400b00296f3ee5700ls2177218pjb.1.-pod-prod-05-us; Mon, 12
 Feb 2024 13:40:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVkfnzVzFVT6CI4w0JFjyeIXa2OmIA6MVPXrRZsTy1ZIbOwvRL0olA7eU/gpjZfVuI9V6ITPTzIyD/xqqjwn9KpUs/IuOBjMQ5l4w==
X-Received: by 2002:a17:90b:2d8a:b0:28f:f2c9:3908 with SMTP id sj10-20020a17090b2d8a00b0028ff2c93908mr4167864pjb.25.1707774027626;
        Mon, 12 Feb 2024 13:40:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774027; cv=none;
        d=google.com; s=arc-20160816;
        b=EC61oe3dC5P6l8kjCmDvIZKNSSZWzIKaGm65VrYXhJuHIQd8HJzWZQXvT3tmKYqltV
         28yBc2rCS7Xhys5e7Uc7b7vNtyAdwa1DgWzvhfkXVSZ5/0GIO7BI2OHS7i/e9p+zHShy
         VcfRcfpJ4Q2CbZ43WscGRK5sH+WjECTBdmEsuPGDKRTan4qwV3uq7wYzB4WrGaAZzRlT
         JK9nY/YuLbnYcqVgxsL1uvuK1Hhe1YN3c2pIp9AWiJIsT6pviHUE2oXzeioPznnlKptb
         TAfq9/W1RWEJFtJ+39MTgYBJmhwHR5wGBFY6vuLPSNh6nAeS8b0ZGsykM/o3HMBXh5Yh
         2AJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Uyzb7E9FIhn/mbh3tSg2FbzBy8bNHcnwrWfMf2QZXg0=;
        fh=bi2ziQtAQmp33O6JiXpwVePoKwPUI85uopck/YJt0Xk=;
        b=NMQAwosKxnjGNWc2iYrZ+3puAVyQ/UroEzJZyCA6hgVcuLgvilNYAxm2/5I2Uc2Bcn
         ndPbhz/tuuAu8udJrh2zkK+PyE+33mCoHMMXnVJnYzmgoC4Sz07fdqV5WnSmBEG43Bip
         l+iLBvJ/96aBVlSvov0woWbzdis14llHwz0q7esa/Px6Nr1aSiHdV5HC+B0eosljE3IT
         xws6v2bx1j5FGnCO5TroRpGcWHqeszxGS9MQgzs1uPtH0eykj3USTXPUy3zzEwZGrC/L
         WBLdmzwQn21g9oGIH/IbWaTRb1oiMSbAhxDGFJ7e7PDboiwQ9gKyE3gapUpFEF0nCRut
         eR8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TIYHuojV;
       spf=pass (google.com: domain of 3spdkzqykcck796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SpDKZQYKCck796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCU/Yi61VnRpfd3AC+l1iBAM3ygXRC3DgtPU79H7TPuUKWjhEtnzX7JjZcWZzyVGCr0EpWubUJYvn7oooO0f1ebLmpz0WvqG3+DeVA==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id a5-20020a17090ad80500b00296cc9f0923si142665pjv.2.2024.02.12.13.40.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3spdkzqykcck796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b2682870so6221873276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVvkGj+qgOZvJ4nIFJdihi7iSSsiqmD1/vrGs801pFW3dyx57d5FuyvBjXnSnEuY4O9cQ7vL+lD6oc+n0qdaVUK57uv0zflGcj1Kw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:1505:b0:dc7:48ce:d17f with SMTP id
 q5-20020a056902150500b00dc748ced17fmr2107200ybu.10.1707774026593; Mon, 12 Feb
 2024 13:40:26 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:11 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-26-surenb@google.com>
Subject: [PATCH v3 25/35] xfs: Memory allocation profiling fixups
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=TIYHuojV;       spf=pass
 (google.com: domain of 3spdkzqykcck796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SpDKZQYKCck796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
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

This adds an alloc_hooks() wrapper around kmem_alloc(), so that we can
have allocations accounted to the proper callsite.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 fs/xfs/kmem.c |  4 ++--
 fs/xfs/kmem.h | 10 ++++------
 2 files changed, 6 insertions(+), 8 deletions(-)

diff --git a/fs/xfs/kmem.c b/fs/xfs/kmem.c
index c557a030acfe..9aa57a4e2478 100644
--- a/fs/xfs/kmem.c
+++ b/fs/xfs/kmem.c
@@ -8,7 +8,7 @@
 #include "xfs_trace.h"
 
 void *
-kmem_alloc(size_t size, xfs_km_flags_t flags)
+kmem_alloc_noprof(size_t size, xfs_km_flags_t flags)
 {
 	int	retries = 0;
 	gfp_t	lflags = kmem_flags_convert(flags);
@@ -17,7 +17,7 @@ kmem_alloc(size_t size, xfs_km_flags_t flags)
 	trace_kmem_alloc(size, flags, _RET_IP_);
 
 	do {
-		ptr = kmalloc(size, lflags);
+		ptr = kmalloc_noprof(size, lflags);
 		if (ptr || (flags & KM_MAYFAIL))
 			return ptr;
 		if (!(++retries % 100))
diff --git a/fs/xfs/kmem.h b/fs/xfs/kmem.h
index b987dc2c6851..c4cf1dc2a7af 100644
--- a/fs/xfs/kmem.h
+++ b/fs/xfs/kmem.h
@@ -6,6 +6,7 @@
 #ifndef __XFS_SUPPORT_KMEM_H__
 #define __XFS_SUPPORT_KMEM_H__
 
+#include <linux/alloc_tag.h>
 #include <linux/slab.h>
 #include <linux/sched.h>
 #include <linux/mm.h>
@@ -56,18 +57,15 @@ kmem_flags_convert(xfs_km_flags_t flags)
 	return lflags;
 }
 
-extern void *kmem_alloc(size_t, xfs_km_flags_t);
 static inline void  kmem_free(const void *ptr)
 {
 	kvfree(ptr);
 }
 
+extern void *kmem_alloc_noprof(size_t, xfs_km_flags_t);
+#define kmem_alloc(...)			alloc_hooks(kmem_alloc_noprof(__VA_ARGS__))
 
-static inline void *
-kmem_zalloc(size_t size, xfs_km_flags_t flags)
-{
-	return kmem_alloc(size, flags | KM_ZERO);
-}
+#define kmem_zalloc(_size, _flags)	kmem_alloc((_size), (_flags) | KM_ZERO)
 
 /*
  * Zone interfaces
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-26-surenb%40google.com.
