Return-Path: <kasan-dev+bncBC7OD3FKWUERB7PJUKXQMGQEEQ2U46I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 52892873E78
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:02 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-42ee24bf0d9sf26421cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749501; cv=pass;
        d=google.com; s=arc-20160816;
        b=VxFilpFHe4BXMTntWQABd1vcmWQzNyRfsbYxdrnmc8QniIHuEB3Jl2iNhQUk2JbNVl
         SQiNK6m/eT7Hb1nFYHx1OcfNCnKND4X5ptLaAt7NWG9ormM0TlNDXRRexDQdEyLxwaTe
         7wjvTIKB/TY5JvLpXPBb4EPUCOC95ZEXNTNQ5ACyTLxFMdp4MwPqFmVFqaXhW44bfJ6E
         HVkvRnj9bUwd76CyPXp72S8cT5uvUTAMqf83590XhUcyJvluk59/ZQ3LPvVnwiFDlioL
         aG+FXF7us+yRZRYML84mCHdlNFx9WV/ayN+7oywms0o1daLZ27tu4SBIIe/BM4PenecB
         cZ/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SrCmLJfa106SWuHpw8OFLs0Eyus2/Cnd8iqmBD1PlFY=;
        fh=mCbiySilywzYVZAU/dTMGW6/73rcrLiOjc3ISlxYOU4=;
        b=orMZZjPlZjOhyHSqXwMBT+0WNQUT47ufRFZrzwGv42SE8C3ussogYBEyTFyM0hw2rg
         xxfJeZAjgwUAKc5sVwvnrmz1MGaUOhrKAvhJ75VOO7kPRqUKWcR2B8dPNA8/4/eeiFZD
         rF4DJcbpzRDIa4BXVNYnJ+OTgrNNmqjC8bngGMk3UHl6dMfOD6/6d1r6MZot9TVxmN4F
         NtrSCcYQmFtS/oliXjKXtCkH9MSRAOs+G2oTeGiaiMPAwVNoict70+A62B25NhboC1pW
         OKwKNa68rVT7bt6nlAnVjqmwMBnuSzMlnWcSOEq6rN2SnIvvFzv4UMj7gYnHk8Hbqbh1
         SB7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X8lRqwzD;
       spf=pass (google.com: domain of 3-7tozqykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-7ToZQYKCT4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749501; x=1710354301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SrCmLJfa106SWuHpw8OFLs0Eyus2/Cnd8iqmBD1PlFY=;
        b=v8qL+c5LpL7TWWgPLip9NIafvIxwdJOgUUFxIboXsS6/OdUv9zO5+bUuDL5rpqCVN3
         59DC2Cw1VQlMArRLiGzJrKW0D+BQuhwALeCKqvo061p1u+Co9xi7/ZtxNPDOeFibZij6
         XpNjxPOCXkVbeoSXB/+Nnn5p3PlMwtCHsC5tI/jzLozEVBJ7PQWAzLsc2mDWcLlGW0uk
         lkHth4OFao+7H6Oi+DS02GC7hhz1PAIhLyZMtn5CCNZhT8KGTnKX16ly4EtzKSCMmq8K
         ifs3ksX8EfGiTbRMG/QYl4HbARj1OQJNHluT/ZtV3Mf95Tej/6KL1Og8+xR/0AlH6gCq
         N4xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749501; x=1710354301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SrCmLJfa106SWuHpw8OFLs0Eyus2/Cnd8iqmBD1PlFY=;
        b=j1PHG1oe24rWJ2S+um2zGel2L8xo91xMZJAbzBxroZ+X2aOV8CcJMI8IMGl3nwA6Gp
         qHy0oQ5cdqRDiqimf9NA9vkTrbyXLKxBb6dd58oaXXEruxwgCG+KioJ7mOVXXq2YB0XP
         tciE2ib0LqwblEBrNIrWQ3qLjOUPnQVLJSkHCKL7LuGqZ3QYZmA2B4vCWWt0Iae86XHr
         3sOJychmvSW9BxWevInbXB5WRqcN5ZIdX5dj3Zfh3QchQLA0qklgL1F/GSqAOTVNUE+R
         3e2hiNeYEAsfJrjl6E2ujRkugjwFOq7mCFzmhLUjeODWzy3SEDeDdjBXG6gIJPFXgY4+
         3K/w==
X-Forwarded-Encrypted: i=2; AJvYcCVUv0l7pNwRpg0CTF99TZa30hc6YJsdHNx3m751L8jPCUiNgntgi1gITuB/zfElQMYo/B2+maZ0ch39FwKqINn0T60XptW6mg==
X-Gm-Message-State: AOJu0YzvOYqthMkzswd0MQ1eSuQ2iNF1GLqdrzsERwStC99Vbvg6h8Ms
	Z2tVUFpyd+ycUhOiy/NoToo7jXuoLn7fBtWQy7wf51/qLrbRc4Df
X-Google-Smtp-Source: AGHT+IHogTOMTicqaygHZCJ5aoS3C/TnfH1pV/VNPBzMIK1dRGQ7Hh2KNFdRa4m0rLyC6aAQ/umoiA==
X-Received: by 2002:ac8:5f4c:0:b0:42e:f958:ea67 with SMTP id y12-20020ac85f4c000000b0042ef958ea67mr55136qta.7.1709749501217;
        Wed, 06 Mar 2024 10:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:c5:b0:42e:f856:c144 with SMTP id
 p5-20020a05622a00c500b0042ef856c144ls123400qtw.0.-pod-prod-01-us; Wed, 06 Mar
 2024 10:25:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWla+k1Z3cmvcGgIje/Ix2hEGsrOTv+OJHZUYZsXLUV6RFkZH4oCnhhuQcJc7OYrgcJkmNdZ7YUTc1dmVAnddG7Rj8PBx+jB18anw==
X-Received: by 2002:ac5:c924:0:b0:4c0:1918:27de with SMTP id u4-20020ac5c924000000b004c0191827demr4893791vkl.16.1709749500431;
        Wed, 06 Mar 2024 10:25:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749500; cv=none;
        d=google.com; s=arc-20160816;
        b=z+Av5YcXAH4XSuQ9ObHHs2TvzzQn95vfNUBPyzY1XbXexgZPtTaE7QigtI7z9Fq3cn
         nI2rnQmbyI8g2RvzIX2tRfNrnHeOOoBYPNlji0mTW8IBrQqj+UNjbwIYlPWfWizILxyv
         wmlrq59RbjTvsuQ7PX/PhGg4p72m+xLDWBQFZJSAdz5MmRZNfvamf2w03pipzC8SkgC/
         xM6pLBo4b3wqYHL15nYXFO8dtEeoZKblFyzBnE6hMS7f5npeCNM0AvnNZ1I1MZ/FJY66
         76Y0A3gFY0upEFHD4JtLus762aA50ttMb4HUQeichUOAvKPWu1OI6J9XmGPQ3n8H93q+
         BnFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=6rH9mI3mTJcaBoi8NvQC9FpkTZd7d5upxL04jrJdHuE=;
        fh=6whhfxG6FFpwZSkSFkqeD7qE7/2cEwtyg/LD5ri7UJo=;
        b=z44Zp+xRjW/6FDqfBgREcdZSZyjJ4iGyYaj/YQHBy1sf1fcxNGwEFZsvaYbtGjhKGj
         WWed8GpdEk+roDqH1GHqxR2YXi5qg/nHpHanYwJe+Qtmvszp/uYrmO45jOzKUuD/IHN2
         AMlImJ4+EslasEocwXS54tlvB/+NcM4TI+7HE7fP5p6VYFA+zp86C01Yd8xDuOpV1eaX
         spC2AKftNbJeyCgNDsZ9plFYCZqYHP2hh4Sx/PURawp15Ofg1o7L8NRDIaq/LDoxl7kA
         /1QIu1guyPJo0tahz9wfqza+mJiGMOB1bwRazgmG3Iom74n8ZiOINkkrIxALxI+8d/Uk
         buxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X8lRqwzD;
       spf=pass (google.com: domain of 3-7tozqykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-7ToZQYKCT4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id bq16-20020a05622a1c1000b0042c35cd8321si1504731qtb.1.2024.03.06.10.25.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-7tozqykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60998466af4so105607b3.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXSzjNl2mrapQMvl5kDbiCZpgO3GC8pfPcKgHzg8RcL+UPuXnt499e4a0HKfDMrSrdGT64P7EuV/dOUgYUigykznDEeio9Yvt4bMw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1885:b0:dc6:207e:e8b1 with SMTP id
 cj5-20020a056902188500b00dc6207ee8b1mr3919663ybb.2.1709749499865; Wed, 06 Mar
 2024 10:24:59 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:05 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-8-surenb@google.com>
Subject: [PATCH v5 07/37] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
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
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=X8lRqwzD;       spf=pass
 (google.com: domain of 3-7tozqykct4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-7ToZQYKCT4xzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
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
index 6ab9f8f38ac5..2ba5d7b2711d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1899,6 +1899,8 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-8-surenb%40google.com.
