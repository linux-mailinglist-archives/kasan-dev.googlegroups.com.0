Return-Path: <kasan-dev+bncBC7OD3FKWUERB465X6RAMGQEW7X76PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D54F6F33BA
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:17 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-32f240747cdsf169145625ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960115; cv=pass;
        d=google.com; s=arc-20160816;
        b=RMYADRolW6RG9XiAikNWZLUH8W0M0dwJHu8JOPESjPNgZ9wtuJLA15mxI4O5dwtpbI
         2ML+6I1T20Gs7vTLonGxw2KD3tIO6nVH4jAsYjjIm1mAYjm5jwZ99s+n9ifL3tuNegN8
         vORrudKtmajtlnRnfC2epJqnkkm0KBYOaFfu9+GHVGss3q49zn6nukpJFZlPcOvFY6fR
         tr3maB7nW6WsjyyzKpdidQsfuxYWe4ZdsAiX6PIn5uiuatiCCjIoCWk2c7rrZ0UsehJ3
         +R8rBeTcE4Qf4PoRsSHiMO4dHTEWghMQ3zfrXn5ySC9G7B00f5Xk462yT1v6FJ/Vl8oj
         Mgfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=KSFcU2n1ICp1EUodZD4j3+2A5D90OBIXAqnxfpqNLEw=;
        b=bYPvbxJEO6z3C/ejRfXNU5yz/Z1HMQ93Vo24U3o47QqrfNekFhO6aY8GgP6pGKGi29
         MIxaOStnIEtmTX7IViL4W3r9tpkkQwCje8b1k9SPzr7YSNQ+NdFaSFxiv3GQOdo0jUUm
         vMucgLqcdlOTgDyJf1IkTznVP4GND9Mrl+Qi/z8vb6+/OBtfGXkaIpC6YfNtOHgX1FN9
         RvURZtHMKeXg5f+pdVDkJilx54d+A9vatKnf1rDt4E6LJ5UPNshZF4jkwkNrmJmDWWkl
         oHPU12Ge8lthYyeQ7xgxhV+ySAR8XYscCoJJeHSpDr3712DSAk3M+7mFUgUIgrEM6DP0
         81Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=kNURb9oR;
       spf=pass (google.com: domain of 38u5pzaykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38u5PZAYKCTknpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960115; x=1685552115;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KSFcU2n1ICp1EUodZD4j3+2A5D90OBIXAqnxfpqNLEw=;
        b=fAXwabbj8K1aW28+6QpK2ktC38wIAw9XewQOAlv0AsBcwSrlqwN86Jf/SBv2y7E+Qk
         VfPow/a5HynD4DVIiReN2S3ThvrjMQ7LqO3JlBvGEdAlsVmQVRPtX1d1n1OlAburSGzi
         QarzoQcaroyLcLZFzKasYG+wBrm+6FyXUzYsAiXMk/wz8CcpwO0dtCI1Rzn8vDjcWcV9
         ZBA2F3xsVQHQJbFYV4DlWiA47eXRBY9XBZRTiVT9Tj9ZKB+3x7/6Ghtodm9+tkLYIeqk
         7ImaYvzrLIr2FSTeveae2DQM1yYXDakw5BY/u/cGXFVHuxFA97exSlGFthG4Z/IROAn6
         nF8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960115; x=1685552115;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KSFcU2n1ICp1EUodZD4j3+2A5D90OBIXAqnxfpqNLEw=;
        b=k9JFiGCGiYRyYZGzw6skU4QFfmxNxGNUsgjeYOKvp37GKrtxDoCBo4QX8Um6rToAVf
         RAA0hFEydwHJRjoA5gNtlKLzkasoHUGHUhtTCKJt2eOHDsQpCS91vJH78vjZO0pMj+97
         pIALl6MlrHZj9/Htj3z+O6gZdBLZ6WjSyrpP2UGw9Hb8YNideyW+23WJ8O0Vlb1iusTD
         CuEgvBam2czNAuVcwrKANC5+SmIDNS6CDUykib5RP3gKMmGQUq7Tr0UWFKdH389k4yFW
         Gqxj9MrCfSCnBLHEsA5y+CYqEdFSxLJeAsopYrBiQjEx1Fdvm2AZB8rTnZ1ZJSiErnnc
         cFSg==
X-Gm-Message-State: AC+VfDz86n+cGF2R0GfyReNXTAFRuS/fX0M6TObe/37v1KHiNrn36qg/
	zZZwD0WdrySb7m18LpwzEqc=
X-Google-Smtp-Source: ACHHUZ6TvpWbNOPc5+P/p4likW9ZT7Ext+8YLHlb+wJH7pBQ084/dM/WtGg0oO8mu6w5oZ38UNCODQ==
X-Received: by 2002:a5d:8703:0:b0:763:4ebc:36 with SMTP id u3-20020a5d8703000000b007634ebc0036mr6740192iom.2.1682960115533;
        Mon, 01 May 2023 09:55:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7b04:0:b0:326:a5a:b7f3 with SMTP id w4-20020a927b04000000b003260a5ab7f3ls3414359ilc.2.-pod-prod-gmail;
 Mon, 01 May 2023 09:55:15 -0700 (PDT)
X-Received: by 2002:a05:6e02:6c6:b0:325:b002:89b4 with SMTP id p6-20020a056e0206c600b00325b00289b4mr10591016ils.25.1682960115005;
        Mon, 01 May 2023 09:55:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960114; cv=none;
        d=google.com; s=arc-20160816;
        b=GPqYAvSsr5u3h11De/WuiZUKqmbcnKstGMzZN8td8S0et/XgJc69kkPxGOY8IEa1S/
         UV6PrywPySQkgklqxQEMNvqCalZ2nALkHk0R5Wf37BtA7QZAD7ONv40JQ4WoKZzCPLtH
         ObA3NkpX6LFO7SJbUVnbzuv0cO0vgoP7lQxWYQSvAUAAK5Q+Wxw7MqGVvJ/BVipgVSE/
         XmwZRlXEUHBPKyi3R2CMiEZO+E0+8sKjCSXQr2Y4EXBoFGq0k8uKWtpzGxuCTY0MWiy5
         8jHIPu7I8oD5mT9otyWvjRftc4wSd4uxbiyoLB7E1sLxXyQSGdTLAETjPtdMrUJkHcBS
         Cj/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bGdFaZ9yLSvpkzL04e/VHNU0a1vWusSmGZaxEHf2wm8=;
        b=CBY3WbU/nfntps4e49mEiNQOfuHWw7td01D5naEBV2LTQfecn48Nm2M3OWHMcTDvkD
         2xFKPluh5hDmhVX+Y+2JRdyaKLx5h0qRHPfqFYgXLCNy+2ZwAIO5Qv8G/UvS+Q1doAOy
         +R2HTo0qmVdZwdKP/dDMFaGLU6ll9GpUI7/WRdQWwxOSr6imHUsMFP6zhgQ3q8asGJ74
         Xz/JS1vadyy2hVetFd5DN2oVTO8DKYNSKle7saaTi7hz+tsjYU0Ti3puymfWS0uMs+X3
         m4+Flq1NPg1FgLHJBi0TJRpu96B3QCm9JgVf5CJmlju+k+uuy2EmidgFjYNyWNTi5Cwj
         c16g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=kNURb9oR;
       spf=pass (google.com: domain of 38u5pzaykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38u5PZAYKCTknpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id cx18-20020a056638491200b003e7efb1d848si2471524jab.3.2023.05.01.09.55.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38u5pzaykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-559ffd15df9so31972937b3.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:14 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:690c:723:b0:54f:68a1:b406 with SMTP id
 bt3-20020a05690c072300b0054f68a1b406mr8285886ywb.2.1682960114403; Mon, 01 May
 2023 09:55:14 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:13 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-4-surenb@google.com>
Subject: [PATCH 03/40] fs: Convert alloc_inode_sb() to a macro
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
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=kNURb9oR;       spf=pass
 (google.com: domain of 38u5pzaykctknpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38u5PZAYKCTknpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
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

We're introducing alloc tagging, which tracks memory allocations by
callsite. Converting alloc_inode_sb() to a macro means allocations will
be tracked by its caller, which is a bit more useful.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>
---
 include/linux/fs.h | 6 +-----
 1 file changed, 1 insertion(+), 5 deletions(-)

diff --git a/include/linux/fs.h b/include/linux/fs.h
index 21a981680856..4905ce14db0b 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -2699,11 +2699,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
  * This must be used for allocating filesystems specific inodes to set
  * up the inode reclaim context correctly.
  */
-static inline void *
-alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
-{
-	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
-}
+#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)
 
 extern void __insert_inode_hash(struct inode *, unsigned long hashval);
 static inline void insert_inode_hash(struct inode *inode)
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-4-surenb%40google.com.
