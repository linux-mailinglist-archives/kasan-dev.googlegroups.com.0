Return-Path: <kasan-dev+bncBC7OD3FKWUERBKNAVKXAMGQE5CIG4VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80C1E851FCB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:55 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1d7465d60b7sf2089215ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773994; cv=pass;
        d=google.com; s=arc-20160816;
        b=awwvRxaCZ8QQDHTMQZqbyoJccxnOK4r2yGFCMcxonu5JpVAtyt57TtP0rQ0AINGUdy
         Zmwx6pNtJQoLUR18Ec3SYNSfdGRB5eliKKUqYoGjSQH4USihJST/Nord/HwG0tk9V3as
         xE+1MAP+U9oODW0ETaQQC/t0yA8T/fouZM1b/Dy8lGo09GoSPyD8GrG6N50P79FWXUr0
         YqE0EZkbn4q+YZbcFZmnxBnuA1N4LGeupA1/bTdxnlnFxePlVfUH2VJ1jaAeVMTbcf6h
         uDl2voCw8C0nsVdjimIGSLoT+ieUmkEFkNkw8tlwM3sZTVvUCJCQMoCk7vQ/q0BvvbEi
         NyoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vZr5rJb7o1Yjx8eVvGgdB7Mh9GoFo01hmnsgJOotrzI=;
        fh=2MC7Bl6boVcBVPTCteu4J3EDORzBrVe0jZc0DcAGWWY=;
        b=VuYmdu8LWWFK4owDKBckHrd1d1WAhNaouYqMKjPhNvUiLi0w7vsP5F3rUv30qMp8Aa
         lTvBzogZ64qCTyjbDDJjnbwV4uZ1HnF5BiKUvVF5Kwx6udn3r4NMmD8BXweHMKhdOhtN
         kDPGhQ5GqOwgdjEVkEWqZ0bOyou9OezsIy09jLQhe+x7TGYucVMFDfMVxcbPZrLcxUkH
         U441TsotslgWYqofhCKS4zTLxh5IkF+rVoVFVPSi5/nxL3OSZilONmEUd3zt0mBs9Cfr
         1L4bo1cX/pkiumqU9mzn9F71tORbECRb33tiK/t2KorvGnEmpEc8i9q6cWXEebOqT8iY
         V0ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Dvy48RnQ;
       spf=pass (google.com: domain of 3kjdkzqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KJDKZQYKCacZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773994; x=1708378794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vZr5rJb7o1Yjx8eVvGgdB7Mh9GoFo01hmnsgJOotrzI=;
        b=Sz5uC1XDu3gdUrwsel7FmlOrYMLF7Vtgp0+N7PfyqRuIKT7R8Oier/AQaBl+cl5x4A
         OU7A63Jwvfk6zR0IJWMtdIn9VC9h5rtoW6wTSvLiZpT2ZyxGcQKnVlvHNfCcmVr9FiIc
         9RtC9dkSa7LMzHiZ9x/UwExKoBls39VMotmetsTNjA4IS4NBxVCWlGB5js9tc1rI79GF
         M0mk6Sqd2YEQCB/kcL3XNio6u7eFf1TKkW5pXi2Ogwvj9vmrV1KCUxfl0TN5sRiG3GvV
         bZeJ1XUJdD7DXCmKCYe32VvkZmG7KO4z8tv/7Pc3VMY0gKf3C2MrwdwT5fHrc0YE0EF1
         fSjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773994; x=1708378794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vZr5rJb7o1Yjx8eVvGgdB7Mh9GoFo01hmnsgJOotrzI=;
        b=TtwJbStpd+8R02tniNbcAyz+G+e4YkZ9cv4bZKD6zg3K9ISs3NrQWOO9N9qM1V4lDk
         MGUfojmiVneBD0F4k29PSKF9X1VgiCMbqBzKMogx4SR6FR4GizH2VSWw1DVGMuIX+LRc
         Myw1115VKUnVeu6a1zeZefWepqMFvuqwWppKw8UFgm1lX7qUEgc7/jHZpNg32keevRtx
         f9IVYFFxlSEuD0EAVChwadbQEX+ktbkDGAheKvRD2/bwuAja/pmIEHJ768eIp8UCDqtn
         cTWqhYTtYI9UVBcuL6cDRLGr4CD++mM10fyUdqCM3NmswlhLamrd8XG9uqsNjMHwvofB
         EmXA==
X-Gm-Message-State: AOJu0YwUWnFJ0ujjy2P1vjrsxpX0aUtxZ3zd+D3tTNMVuK67BGUP/vGN
	InExACjCa6AusjlwFsgFxDWNYnrU7RwU/GuzTQtBROLKGuw1BoQp
X-Google-Smtp-Source: AGHT+IEq/VylWBxXCmWsqrzxZS9/kEzfjvakbjIMCEfcH3AGoP9CFeSniG88GPw/FaVEyvalwFDAuA==
X-Received: by 2002:a17:902:e5c8:b0:1d9:2369:d0f8 with SMTP id u8-20020a170902e5c800b001d92369d0f8mr9837649plf.9.1707773993951;
        Mon, 12 Feb 2024 13:39:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c24c:b0:1d9:8f0c:d2fe with SMTP id
 12-20020a170902c24c00b001d98f0cd2fels1838485plg.1.-pod-prod-02-us; Mon, 12
 Feb 2024 13:39:53 -0800 (PST)
X-Received: by 2002:a17:902:a3c5:b0:1d9:f83e:3a54 with SMTP id q5-20020a170902a3c500b001d9f83e3a54mr7310004plb.64.1707773992897;
        Mon, 12 Feb 2024 13:39:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773992; cv=none;
        d=google.com; s=arc-20160816;
        b=dGz2wKeNOetcNOTkpjVDqX0hZwTMZQ9vqCO2iqkUfHsqHgzCNdglkdkiNhQT8R09z4
         Rvo8lzVV9Sxk1xYgKuoX8Kv2dLC8te0StEI/IKMSYnzWwD88iPK+c063RwmkQ8WU0sn3
         oXHK12M7kxUEqv8sTAQI2iVLt2EDHsdbvL5ymjicPY9uLQEbTAWeVHMKHlmuyfwMPSEp
         8hRl2kH91pmPJyBIZqsZv1LXHQ8GeRNapeS/Z7A8LxQfSNhFiOJ9B1zDVJLNSJLCV1V/
         +AhS5cyx6POZVoMHuy70D8dbHLC1NNkJIaRucAPUxyHhcCFQ0obowVGFi9Q/obkyt5Em
         jn5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Wy0D/wmUn3AGzRHJaKJZBS4cvr5irQ3tEAXEefF/wd0=;
        fh=2MC7Bl6boVcBVPTCteu4J3EDORzBrVe0jZc0DcAGWWY=;
        b=yWvZivrpDNLugAPpnA6Eiqxtze1K3EEApaEb5JtaeAW9X2i2kFB90JCY+C6OcYxH9d
         g7WMmff7iEm2tiCTuW4+BYEZSpN2ySoY+abKT1jYdf5dBStRXCOjiOz7mDI4AqNlRDRr
         EBDbKzsFyOYCj/o7/ugPfP/dYaD4Q4d6vQXOLv5sEQHpc2Bd7pVQVRj8fun0dUWv/ZBn
         gMSaXWBrTkHxSybdkOElFT9f93yWh7j6vnfwrrbiLuUbVIDBd1jnAQJ8eGankfSs+9rz
         0gV9usYQqtFkv4dshqrkedJPwlUtxamfTTOAdbz5ZMRFmQKLPdby8OrTPwW684BKx9ti
         Fb9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Dvy48RnQ;
       spf=pass (google.com: domain of 3kjdkzqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KJDKZQYKCacZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUgmsPHWWVkLQFeIhljsKVq5qcXC3mQaUq0qUbywX9VTMezKOhOBYb/XegGt02G20IsrEvfsmXdyRE3AUe2JCMGz/+zyB1GU/aeEA==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id lg6-20020a170902fb8600b001d8e76e7179si87408plb.3.2024.02.12.13.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kjdkzqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6047a047f58so66770687b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:52 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a0d:cc91:0:b0:607:7bca:e8d5 with SMTP id
 o139-20020a0dcc91000000b006077bcae8d5mr286452ywd.0.1707773992000; Mon, 12 Feb
 2024 13:39:52 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:55 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-10-surenb@google.com>
Subject: [PATCH v3 09/35] slab: objext: introduce objext_flags as extension to page_memcg_data_flags
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
 header.i=@google.com header.s=20230601 header.b=Dvy48RnQ;       spf=pass
 (google.com: domain of 3kjdkzqykcaczbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KJDKZQYKCacZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
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
index f4ff635091e4..77cf7474fe46 100644
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-10-surenb%40google.com.
