Return-Path: <kasan-dev+bncBC7OD3FKWUERBRW6X6RAMGQEYZTTYYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A5446F3403
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:40 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1a513f84690sf16352095ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960199; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eeh6ywaYEFz8uaI7iXbL2zGBxDdVqwDz1tDuSPJvzmtRgH3WDNTtrxCVHldyiSYjgP
         Jr6gOiJ+l5us0u2LnCWdvGNhMj4RODu3JHy4bVSEJpis6ya/PwQ8jyz1mlbjbFTj8qGl
         j+kDYIwHB8SOO9OAPYEUnGO1DvWSMZ37nVetecFJTw4nuW/q6J1kefehphkMeF4Vl8i1
         /0AMKHqM9xh+jsQh23DH6kUe2xbTxEt3IpRhxg0kj1jBnU/jFO60O5Tfqiz6RftgbHEq
         CvaTbraxzgCANDavXVnyz39c1zRbN6B7ROioCjzRsS3ZrVpLe598sjanF67rA5ix4Khd
         ZDRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ovd4rGzkkK0UQNkQyxQUVNCNO9KUt4/dFcDhhh4HopY=;
        b=XVmxPk91ikdLLJvazS0X8vaPYvQRoiM3+2XLiXiLT6cZ2R9yVwoO4e11majLRJosXL
         PvRZdFyvSzkmEpVfZziRxpNNXBvLnxrBt3Ko04YMADmivyMlEVtvuLTmjLgGdZCeHFfH
         VyC+/b7A6yMYA0LxxwykHxsIESdkhnlC/zNwHAe+JYho13XbUMOiWz3Pa20sk0Uu/yGP
         GVDv7YKQZKWexsa9XptgRlDWzBZA+gFXfSEQhaD9kY9biDtEEqyRPi2LU4F/B2HO1u4u
         5JIiI2xHl2Da/tZlNlhXxjx1Gn9zYlmw5zk8vuGi4Tn4izaLxjZq6BX2VjqzZO+W3NDM
         L4+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=48U8jHG6;
       spf=pass (google.com: domain of 3re9pzaykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Re9PZAYKCYw8A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960199; x=1685552199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ovd4rGzkkK0UQNkQyxQUVNCNO9KUt4/dFcDhhh4HopY=;
        b=NKSacRSpIaqyb/apsUkpKDCVdzPBSK1i2jFBXlFq+KwhHpmi7FXRT6uEoSbdrjQphB
         r5ulgDmY2S/TMXtRrVdw/rHtUegc50UuIQ4A0kobg3Ci4ZCjTsCkjJ1SwzE1qp8OSKm/
         hJ/Fub5Ts4YEhjCTz4duw9UNsPA/fmSS0+Jnp12h/0Or0sq9Kk3x4pGQnRUOIWGKh2aJ
         FxIbl0AzSh92QMxIj5NE2lyKdNZ+JJiM3+BpIvON3D80lZx3ZZ5X+POo9wwFjgRn+sip
         mJunJJpvHED0bqaJ36Nlf5vsdvwe5rCSwOu193bt98vUJBvgucNrcFRZ7T/7SUs3n8mO
         HiBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960199; x=1685552199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ovd4rGzkkK0UQNkQyxQUVNCNO9KUt4/dFcDhhh4HopY=;
        b=VdcSPgttP/VG/xcWIilAyuzSvgUUzgCO8CXSW/TKYRWK1owMyEgULsOinBnbBfTfBl
         C7bCrIcnEoJ0WVljSQXuqQTNNeSAKawbwucF2Uy53DPeoV7y++Ylp5jx6Wvbmwt0Dfcb
         Fb2Yu2ol5e4eTgffxkAZe64syrXtp4O78fQgy0jFuGwVWkC694wQkoOr9brGB4TJlJYG
         2IYh/38CjdU28N13fOfFmtR/SGuSHZpc8gaS6dCBVg/I/G+aL+SHrX6HwAmFVnXBiGLp
         01PfFZdTP3Pw6sv98BsvjnimE/Z6M3FldyFZM6kkdXbghRHZU5X1x/P+mLpQ66tuyF8m
         EXdQ==
X-Gm-Message-State: AC+VfDyvrnHhnguloQwUvebaremjSm1AeyEj0KjSts5NHJtTjG0rKwBQ
	jEGHonJcqnytRyA0fvsKwAA=
X-Google-Smtp-Source: ACHHUZ5Iz4A+EFtZzUlycajP6tvroiM5ege9b/6gjlM5cPolUXvV1mMsw4p5l87adhfSyVHyIjfixQ==
X-Received: by 2002:a17:902:b287:b0:1aa:f53c:df13 with SMTP id u7-20020a170902b28700b001aaf53cdf13mr1193462plr.7.1682960198849;
        Mon, 01 May 2023 09:56:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9f92:b0:23c:1f9b:df20 with SMTP id
 o18-20020a17090a9f9200b0023c1f9bdf20ls11629730pjp.1.-pod-control-gmail; Mon,
 01 May 2023 09:56:38 -0700 (PDT)
X-Received: by 2002:a17:902:c44c:b0:1a6:a7ac:2ab5 with SMTP id m12-20020a170902c44c00b001a6a7ac2ab5mr12082458plm.45.1682960198168;
        Mon, 01 May 2023 09:56:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960198; cv=none;
        d=google.com; s=arc-20160816;
        b=NeERDSM9nBJJWDXVdNx49Lo6KTyNO28ZPYpxLjKuCvENjfIXqnt51uG85YDU+f8YB5
         0SEeVIcF0UDoL1Y5Y0hypiG0qG0kf3YdccaxE19e5ABTjGk6TnMNBzFotGSaU5UB92Il
         A0T41iGrCGqdQuQIvK1EwRIW7g8c2n47VJcAlOnXnFnfOiSZqaQSGxjC3OfwA+dlocSh
         2am1J/yg1sRJxkBo93Rbne3SKVQoBo0fFr1xSep21AFFTGUPaM0ZV6MAeda88f+Ui8/0
         aSZbisMM4gfNtaHz/tZQ9TVcNlJlkEHZpS6OMNgOwFNlhbNxw0NP07dw6Worf6lLM1wW
         9WOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=6mzPQystPbLbDwPdw2fPo41K7qknlkieEKK3sweddW8=;
        b=ZXMjUuh0MFtpFhiUi9AP+Wb4iawVRoTG88iWNBTxsadpD1rE4ZYQNqaAsd3ggSnTjS
         HPqBDPiNbhFFk/bHNBHQuqn5mCEScHDM+ahOXRDu5sutVFtjf+NMRRmkXAIr4HX6Q60w
         LgMMBIOePr8CnMfgCAGg0vykIOGYzZg5oXlyNsDzz3ARgbZuRr9wLJZSbS3tlgRBTATy
         0M3shB4blikni7azuYzQGxke87tAXeSyk23Boo8TDyvlEepAJwZ2ASiPyrkA3eCAy+Bz
         xkz874FfSXFPtVRCEGDy7wmNZ2ZM5ql51k1g9r0fipwu6tHk6fsC+QNGfWgIXwnSMWg5
         ddJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=48U8jHG6;
       spf=pass (google.com: domain of 3re9pzaykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Re9PZAYKCYw8A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id b17-20020a170903229100b001a4fe95baf3si1376082plh.3.2023.05.01.09.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3re9pzaykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-559c416b024so28961267b3.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:38 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:e902:0:b0:541:61aa:9e60 with SMTP id
 d2-20020a81e902000000b0054161aa9e60mr9069879ywm.6.1682960197340; Mon, 01 May
 2023 09:56:37 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:49 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-40-surenb@google.com>
Subject: [PATCH 39/40] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark
 failed slab_ext allocations
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
 header.i=@google.com header.s=20221208 header.b=48U8jHG6;       spf=pass
 (google.com: domain of 3re9pzaykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Re9PZAYKCYw8A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
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

If slabobj_ext vector allocation for a slab object fails and later on it
succeeds for another object in the same slab, the slabobj_ext for the
original object will be NULL and will be flagged in case when
CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
Mark failed slabobj_ext vector allocations using a new objext_flags flag
stored in the lower bits of slab->obj_exts. When new allocation succeeds
it marks all tag references in the same slabobj_ext vector as empty to
avoid warnings implemented by CONFIG_MEM_ALLOC_PROFILING_DEBUG checks.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/memcontrol.h |  4 +++-
 mm/slab_common.c           | 27 +++++++++++++++++++++++++--
 2 files changed, 28 insertions(+), 3 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index c7f21b15b540..3eb8975c1462 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -356,8 +356,10 @@ enum page_memcg_data_flags {
 #endif /* CONFIG_MEMCG */
 
 enum objext_flags {
+	/* slabobj_ext vector failed to allocate */
+	OBJEXTS_ALLOC_FAIL = __FIRST_OBJEXT_FLAG,
 	/* the next bit after the last actual flag */
-	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+	__NR_OBJEXTS_FLAGS  = (__FIRST_OBJEXT_FLAG << 1),
 };
 
 #define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 89265f825c43..5b7e096b70a5 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -217,21 +217,44 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 {
 	unsigned int objects = objs_per_slab(s, slab);
 	unsigned long obj_exts;
-	void *vec;
+	struct slabobj_ext *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
 	/* Prevent recursive extension vector allocation */
 	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
-	if (!vec)
+	if (!vec) {
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+		if (new_slab) {
+			/* Mark vectors which failed to allocate */
+			slab->obj_exts = OBJEXTS_ALLOC_FAIL;
+#ifdef CONFIG_MEMCG
+			slab->obj_exts |= MEMCG_DATA_OBJEXTS;
+#endif
+		}
+#endif
 		return -ENOMEM;
+	}
 
 	obj_exts = (unsigned long)vec;
 #ifdef CONFIG_MEMCG
 	obj_exts |= MEMCG_DATA_OBJEXTS;
 #endif
 	if (new_slab) {
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+		/*
+		 * If vector previously failed to allocate then we have live
+		 * objects with no tag reference. Mark all references in this
+		 * vector as empty to avoid warnings later on.
+		 */
+		if (slab->obj_exts & OBJEXTS_ALLOC_FAIL) {
+			unsigned int i;
+
+			for (i = 0; i < objects; i++)
+				set_codetag_empty(&vec[i].ref);
+		}
+#endif
 		/*
 		 * If the slab is brand new and nobody can yet access its
 		 * obj_exts, no synchronization is required and obj_exts can
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-40-surenb%40google.com.
