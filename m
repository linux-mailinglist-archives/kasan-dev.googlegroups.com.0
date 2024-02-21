Return-Path: <kasan-dev+bncBC7OD3FKWUERBX5D3GXAMGQER3RUVHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 44DCD85E778
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:21 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-6087e575573sf22027607b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544480; cv=pass;
        d=google.com; s=arc-20160816;
        b=BwngxoZFWW4TXRb4JbfT7kuuYKgWOcfm/K0LMrV5WsmpIV2+Xv/fKdphJ8hclGNTro
         7peSgsUPiIhVwy4lrNAppgaDRBfy0L1W9903VkIGrczWrs4kPDfkT3Z2QGz1MxXCol3E
         d3eY7TDiVB3c3IGnG7guYxnS8irupLathsOCTJMqpctnUFpv2k5SZzXL2jt7yt4AvpQR
         5kNiiwd78RRbq99SlWD+32Rtz5UN9oWEPf9NeYgjz10rdqThbEWLdXfef3e8hF9ozqVf
         QQ6RWPJy6QteJIVhh2+nwP7sci6KoSVk/cRbdIaBy4Faiy4P2s3VqjBBsFIh34eHcqR4
         HrQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9JrNNmtfkMak8rwMkpOhPL90GfTlSstLcRz80iItm+g=;
        fh=eJkSNJCyyWyR9q3FPM4LadlhtXMR4XZKNLn6esgZReU=;
        b=Y4UkWcAvsdbxnuS5c3TErMI3eFwIvqnMXA3ACFHEnCjGV/mnx+B8fYVKfiWGyOcvQr
         Fr041hByr9hVcifXPy5wFOndZ18jq9eG+uJRM7b8TIDI/OzBc2tKsfsIp75LbwIZAJPu
         fjXDsN1JUoEf6NHENqD5k+jeoj1XVXkuxIzb9fajRYZYoNTE9SdwwpWhrFfn+2dEZMx9
         uFbjsiCcTUedg2X13IJksXFWY1k1mlbDrzjyeLbcbeP1ZpkMCoJ9GDkW+QPQBNiHRZ9S
         e7Eee3y2Aifc32+hSyjfX6vOsbTu/OU2hmUmBDWdD6WYJpjZ7Ga8LDShSgUqCUHPg9r6
         k4Vw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=l9sJopv1;
       spf=pass (google.com: domain of 33lhwzqykcre9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33lHWZQYKCRE9B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544480; x=1709149280; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9JrNNmtfkMak8rwMkpOhPL90GfTlSstLcRz80iItm+g=;
        b=bnmsN5DfT39Vb3WNm4C/lC+x1CSTwg3ARDowMc8AKuGzbMg/S/2Ekptfz7PAGcCk0A
         oIG7WAK8Bdt8CGOzq+LqTXlkC05ynag4LYKW9k+VWvG4K4teDsZtwAY0ZI5Uowt1BLuI
         YrwdZ8V4aVD0Hbbq3ThtteGH8Q1j55bKgKthWVSZIg1HHNikIN+y5YuJ1vkIutl+v+iy
         8kiEVYv+bDLWv0LbUZ60qaY9j04olAx253SPk8QXdofkt5+lnP4yqwERCV2VG7HkZlkd
         zu1vKxbgcaNDebcw+j8dxjVZjZSJ1bHWp/aCbWhF7Qv+EXZzMRMSZ49P9W3kO6zJDuuo
         fbDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544480; x=1709149280;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9JrNNmtfkMak8rwMkpOhPL90GfTlSstLcRz80iItm+g=;
        b=l8MRsKaEPkps5Nf0Hp3/J7g4/wcA7LJOWrCRyLfizdzrZERzdmN8wm+Q//zBQ8MAuO
         klOxmFYWai1+q0lSlaWzAYSLjV12s0I1if66BBUou936h0nBbqtj0K0lAX6ed5pzuIg0
         Aenue5gINTok85b1rGbGzywnlpMEbmZv6JMoGptsz2njUNYWikuWswusLTFg7GVePtY+
         M4JzhNidq9ghREWbZBNefz29rV53ueB6qnEqCz4P/YkqX/K96tGrMep3Fiur+9UBr8Zm
         8dJxilGnaoWKcBEo8Jbv80MyEmk2pN39fTZ/ZF9KFf2Olv3GArochEjN1uHP80EGs6ML
         eTYw==
X-Forwarded-Encrypted: i=2; AJvYcCWaWDrpohjZAAb01rO7PP8i+i+t8TPkehfE1CIokzDHUtApKB21bdzJaD9y1cRjVWDDSYlAcDsFe36IWvF68004YiPxoLaA8Q==
X-Gm-Message-State: AOJu0YxfYhavrhOV1b95hTDKTEk+8t3UoQYBIZSpFxgsQ6ZKDW1iAs18
	K7Ca8gci2hOZh6uHPejuvqoikVvTp17rp6xV8Bko0M/VUXknYLUr
X-Google-Smtp-Source: AGHT+IHtZIXPK98fRB0d4uwpiGybBYRmyY59/ipZfWnLrBqeBQSArpCUDBizUcvNT/AdO2lvu3d47Q==
X-Received: by 2002:a25:46c3:0:b0:dcc:b69c:12e1 with SMTP id t186-20020a2546c3000000b00dccb69c12e1mr279644yba.59.1708544479789;
        Wed, 21 Feb 2024 11:41:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bdc9:0:b0:dcb:bfe0:81b8 with SMTP id g9-20020a25bdc9000000b00dcbbfe081b8ls1773333ybk.0.-pod-prod-09-us;
 Wed, 21 Feb 2024 11:41:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3BJvFYayiiwlzVCt0/AIwwehgMkBwqKDbC/ItkxzJpDhrWroWyPLlW5moQ6Bg/EiyP8vvUsBaqNGCO6i/gK5C8lYoDN+5Epo9fQ==
X-Received: by 2002:a05:690c:3609:b0:608:2513:64ab with SMTP id ft9-20020a05690c360900b00608251364abmr13122011ywb.8.1708544478950;
        Wed, 21 Feb 2024 11:41:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544478; cv=none;
        d=google.com; s=arc-20160816;
        b=Puqn3xk330XCmIdFpbCpZKtYxYKgcE5eMWaUkf3rJxGiaB+6prVtID3O/l4uLRWg03
         OCU0aR8DtmCB1RtazVvpiQ3INqm5tU/2VfzkJAeCiuWOXZzREXuUptE4XfyST8o9ajVS
         j8xH+Li7nxcPPD+v2ParzHh9wjJqgyLT6pROzREaLA8zSTGWsWH1+9C14wXyiKCGnsUC
         xmJAacW70DSXUeMxvfbjcuy4AC0fd7BWU/sgZcl3DwQZP+UySN2wBF8jDiEjcR7xFQbU
         QWXqSbcmJ2H+qqtlXzIQ6FENgtHKeCmB3YlaByRNhtqqjS5kkRZL4jJ9Zj1qGc5Jg+a6
         DvZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RtUIa2LF9EHhDqysRu/yxXfpC6tMV2p9GldnGdUYEsQ=;
        fh=uXW8CM3ciR79QtjJsOf3yVcr7HlAvRu59c3zEjOgRXA=;
        b=bzyHezp3BXIRZUiIO+x8xckQPWGAH2osO7czMMRjG6GDuXe6eIVRbH+LqP2fdvg0pt
         RbMsRkv6IxTgtw+wUUOOPjIffDOTqntvrGxZj0lGCzHNV7Bgkigz8Xd9mPrWQ7pG7LAo
         IqyBHruKZDlZUcBnV2GMhR7C0kNTXPTWiFGMFVVmgy3mmdkZYyTTl6pCPILH0J6pmbqd
         xEnBilx7fWEv7Ap12HmmufUwP4OjiUcP9w8nfJetDi97B4/pMDYekp93zR7qHL+DcdUf
         UyYjtCX9JJCcYpwt1Iq/WBIb3mEFUk6i6l9xT0sIGkoHnZ35KJhI5VnQU+Hrxt7SOO2K
         h6sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=l9sJopv1;
       spf=pass (google.com: domain of 33lhwzqykcre9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33lHWZQYKCRE9B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id o145-20020a0dcc97000000b0060894eb7d22si75876ywd.0.2024.02.21.11.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 33lhwzqykcre9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcdc3db67f0so148531276.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUPFqG3ffS1ktU/DOSfIGV8Ddn8kLb18RpivkpuKoy2J1XYmq1uZxmCPR7/ElnmjK7PL1XI77XQeI6W70CCCr/phXCUb+J0kJH9pA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:3f06:0:b0:dcc:2267:796e with SMTP id
 m6-20020a253f06000000b00dcc2267796emr31950yba.2.1708544478455; Wed, 21 Feb
 2024 11:41:18 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:23 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-11-surenb@google.com>
Subject: [PATCH v4 10/36] slab: objext: introduce objext_flags as extension to page_memcg_data_flags
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
 header.i=@google.com header.s=20230601 header.b=l9sJopv1;       spf=pass
 (google.com: domain of 33lhwzqykcre9b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33lHWZQYKCRE9B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
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

Introduce objext_flags to store additional objext flags unrelated to memcg.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/memcontrol.h | 29 ++++++++++++++++++++++-------
 mm/slab.h                  |  4 +---
 2 files changed, 23 insertions(+), 10 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index eb1dc181e412..f3584e98b640 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -356,7 +356,22 @@ enum page_memcg_data_flags {
 	__NR_MEMCG_DATA_FLAGS  = (1UL << 2),
 };
 
-#define MEMCG_DATA_FLAGS_MASK (__NR_MEMCG_DATA_FLAGS - 1)
+#define __FIRST_OBJEXT_FLAG	__NR_MEMCG_DATA_FLAGS
+
+#else /* CONFIG_MEMCG */
+
+#define __FIRST_OBJEXT_FLAG	(1UL << 0)
+
+#endif /* CONFIG_MEMCG */
+
+enum objext_flags {
+	/* the next bit after the last actual flag */
+	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+};
+
+#define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
+
+#ifdef CONFIG_MEMCG
 
 static inline bool folio_memcg_kmem(struct folio *folio);
 
@@ -390,7 +405,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -411,7 +426,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
-	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct obj_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -468,11 +483,11 @@ static inline struct mem_cgroup *folio_memcg_rcu(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -511,11 +526,11 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 static inline struct mem_cgroup *page_memcg_check(struct page *page)
diff --git a/mm/slab.h b/mm/slab.h
index 7f19b0a2acd8..13b6ba2abd74 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -560,10 +560,8 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 							slab_page(slab));
 	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
 
-	return (struct slabobj_ext *)(obj_exts & ~MEMCG_DATA_FLAGS_MASK);
-#else
-	return (struct slabobj_ext *)obj_exts;
 #endif
+	return (struct slabobj_ext *)(obj_exts & ~OBJEXTS_FLAGS_MASK);
 }
 
 int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-11-surenb%40google.com.
