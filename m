Return-Path: <kasan-dev+bncBC7OD3FKWUERBSWE6GXQMGQEDXI47SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 41EC1885DA6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:32 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id 71dfb90a1353d-4d8616cd3b7sf292554e0c.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039051; cv=pass;
        d=google.com; s=arc-20160816;
        b=PP/OZPpyJo+eYzJYcGN8KBXmvVJTqfGBEqMbEvYteMQCzujQ87+x9UGzjdSX/X5P6q
         Ahm/x4jPxdYG3qgtzE1ohDgF6MTFAt2W07Jmbgvn2AHga+Ik8LWKLEBGezwosN3nKMR+
         BtrNfCMD8Ap6fcenVklKUPLZiKdxe6S7dQXZSthc4RSNKTkTAD4kByW8bXw4UzthBH9a
         IHz+z8V8cqz5VczyLGRyqVCqxixRMj5YgJe8ZvYL/Hk9jeejp+hkek5tfcNKqduO5ssp
         7wMNQugxnlurcO5Y+7+qK0nSGBr+q1S6p+wynxXkKBXJmJUqhTKPmvI6X1Ls85LtzTuK
         wdcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=r370FLSNy59YDry+wX6SvfJRgELBzg+0whOHDEWkovI=;
        fh=Arw2hRS7FQsfwgTkEgk0gmCTS9OEX7TCof8tz76DSLY=;
        b=emFiAId26nCXKpi+iAbl86h4X6yk00tccCcNfcGBBGssDkgb9jsIyWlUs9kbefpfLT
         mCNNxFfLnJNQjw9uCechEw9o/ifOuQd/1WN8CVT/u/tB2fljMI7Cqw3NkCg/WImoS56R
         K56WGRlsXnYRVd+3jlTC2SB4HYuTgJMLvEYqMx6anjJ29lryLKFLScAsjl7Bdk7kwy5C
         G61PmWjmvWB/zx5yYlBh2oLo5mM9oti/bOv3Q+pE59QYz6JM/PvlVsa/Wwk3qJNxc67x
         4K2weDvlj55KwUMiWVwSs3ASn4wTnbiWb3Fg1OyKJXsz0k7Oul74R+rucdwB1KudAhuf
         3EUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C9Pl+RdR;
       spf=pass (google.com: domain of 3swl8zqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SWL8ZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039051; x=1711643851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=r370FLSNy59YDry+wX6SvfJRgELBzg+0whOHDEWkovI=;
        b=Xm92gsVNxmbK5oMHzjQZvMifvhg48/D9K4OyGMMBKjJxKvgYql12MHv7XyjTqQ94tT
         YfTiEevIElSnYFoUuJxQl76TnHOehFXIX4EmRs5MBuOdn84++d+/ZwFR6J2zV0Al6GZx
         HEmbYCeovo/KZ4mGfjPzO9WNJZkWUkiFHSKPBhsFhsTX6T/QTQnNPlvL8WJARPScrz/R
         3Ilb9QP+lej4RmtP7NBVL2XSQ+j+tBGR3A0+BO0Th5y1hTvoiV6IEd97cuHf/anfVucD
         FjfvcF9JLnfQCyi9utcJeRocsUCvFUwleAiYJE/K2YBa0YBinQxhONHzuaJm0rgTcv0T
         z4bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039051; x=1711643851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r370FLSNy59YDry+wX6SvfJRgELBzg+0whOHDEWkovI=;
        b=JW3dYQOJbBOTUeJ1rfmNlMTyNeQfLZZ06up/7fpip9dW6Kw6iKb2J8E/AoelH+1USZ
         sQAUBXk7cgoPyYB0HbLgTG9lORwGRbyAHT+Z/Ma0bGC6HsI3XPY8UZlF1Av3f1Y/9JL1
         rne0SLMIgfUEDspNP/W7Rr9hfqTTVSixHPbrX891wZv4hv0sjYsV0HPoP9PglEgnZxda
         0TQhGNJiWYLp46n89SH9pVY61OaHP117HcbUf/d83Nv5bTe6UqlZVtp7ZBkpFYqquZfV
         njsIeRZY3SagqRtRMjrGoTRCYlV4LN4N2nuA+sX4Swmz0bYR69r2p5HOPttWGM4hA0JG
         lL7Q==
X-Forwarded-Encrypted: i=2; AJvYcCUHL97f4zOzkghdq4itYE46ox/y7NO14CQnBydmCi3QNOHBuQnkci7PiAlRqrkPZ41aT3dLBNY7uVp6IDAQ9TXpVJpBzLL/SA==
X-Gm-Message-State: AOJu0Ywl/L7PzRsw3t/5K/WoPngfhS9WCZzKANIevmzy+6JM6UEG787T
	nMWXd/BxXb4WchGOPgjpCHLGQsSZuaijGX3k6vuvUtEno4mnntZI
X-Google-Smtp-Source: AGHT+IEOGBg8G0XDI0Z/KBeMMt1+1mhnZ8TlC2M5/nLiz/ZjDOu1wnhjsTK22vLwJVaU9K2Pu7Ni4w==
X-Received: by 2002:a1f:eec6:0:b0:4d3:1ef2:c97d with SMTP id m189-20020a1feec6000000b004d31ef2c97dmr5127452vkh.2.1711039050935;
        Thu, 21 Mar 2024 09:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5006:b0:68f:db5f:7faf with SMTP id
 jo6-20020a056214500600b0068fdb5f7fafls1973601qvb.2.-pod-prod-07-us; Thu, 21
 Mar 2024 09:37:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUR4iozIGH6EkbPfVqkj05a/zZL8LBvVwqwOMt+p4WRCaXRW7HeOHGgB0amDPqQOz9sFXt6GEpWSHT/HY+02o7Kxr/8iNGN0TrFXw==
X-Received: by 2002:ac5:cdf0:0:b0:4d3:3a8c:13ad with SMTP id v16-20020ac5cdf0000000b004d33a8c13admr4838952vkn.8.1711039050114;
        Thu, 21 Mar 2024 09:37:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039050; cv=none;
        d=google.com; s=arc-20160816;
        b=aMjudxdPeC2ADEb4QBrHFzW0PN+zAc6eq6VMsIcz6NQBCH2f8r2a1q+V1457grWm4b
         by1/Gvu0yYFBFUf9raBayU2T5obCVW4rVIJ7J9VxLsxflBFcloAUQf/0zWy97QbFLqyN
         CIMUyahhXBbLGwrOc6O3Jrh/2pDq1j5rGGQj39G236pqpU+NKtx5rdUrc/SbX27YLXwK
         Lz1snTeJ68Xh+I1piqaPyMxVTiteQhYmdxHt8wGRzfFzB8Twg1tlRvZStrD20IIKkQwh
         0IGdUCDHaEwZw4FXCkOHHLrq+jVWyKYcOpILx9bqVm2EppVfwuINI28m/sq1QgQ28fzK
         FaJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=dkdT2DGL8QlDQh+VA6yRS9pNWPbAmDPXuEOr3/wpZDQ=;
        fh=IhmwvdReb/UIFTqlfVrriUth7NFYpdzFN6YC1+HzMv4=;
        b=ZFdmfgyGuaZUwZjL6JyTnY+A+ifqVfye9XIslQAalFYAE/M5Txgmszf3AUrYOCnu4m
         9VLjwqXNjfb/clJr9G4tUi1SWTu9hS4+LUX02YB4TrBSLKhZ5pPA28Da4dyEvSnDEYG+
         EIoSPvExJWlswPSSZ6uOJpP3FD2rnOz+A5bPTy+8JrIKefq2LcdG10MndCG4ACUW10Dr
         XqvVnV4g7Tx9LQsozlwHwgpdPAHk/AFObOW9ohCDEQu+3Ip4l0I5GVO/eCiZgVSXsPGJ
         Pl7vRYbGl3Ral1B2HRGqKZHdnjBUJtoTTL4tt78tpyrfOJHl1kzD9NYgHfceBv1zgyWq
         8YvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C9Pl+RdR;
       spf=pass (google.com: domain of 3swl8zqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SWL8ZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n190-20020a1fd6c7000000b004d3c4a37c63si25469vkg.2.2024.03.21.09.37.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3swl8zqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dccc49ef73eso1588800276.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQKQh8ty3+yCki7KugsKv8G42Rl2snW8pklSzBNGisHiZRPpYXnT+GSG7x4oAW6e33QwwaMUbHB0A12bFuKrEXitWHoDSGr5GEWQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:188f:b0:dcf:f526:4cc6 with SMTP id
 cj15-20020a056902188f00b00dcff5264cc6mr1142116ybb.11.1711039049407; Thu, 21
 Mar 2024 09:37:29 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:31 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-10-surenb@google.com>
Subject: [PATCH v6 09/37] slab: objext: introduce objext_flags as extension to page_memcg_data_flags
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=C9Pl+RdR;       spf=pass
 (google.com: domain of 3swl8zqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SWL8ZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
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
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/memcontrol.h | 29 ++++++++++++++++++++++-------
 mm/slab.h                  |  5 +----
 2 files changed, 23 insertions(+), 11 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 99f423742324..12afc2647cf0 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -357,7 +357,22 @@ enum page_memcg_data_flags {
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
 
@@ -391,7 +406,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -412,7 +427,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
-	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct obj_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -469,11 +484,11 @@ static inline struct mem_cgroup *folio_memcg_rcu(struct folio *folio)
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
@@ -512,11 +527,11 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
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
index 1c16dc8344fa..65db525e93af 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -554,11 +554,8 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 	VM_BUG_ON_PAGE(obj_exts && !(obj_exts & MEMCG_DATA_OBJEXTS),
 							slab_page(slab));
 	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
-
-	return (struct slabobj_ext *)(obj_exts & ~MEMCG_DATA_FLAGS_MASK);
-#else
-	return (struct slabobj_ext *)obj_exts;
 #endif
+	return (struct slabobj_ext *)(obj_exts & ~OBJEXTS_FLAGS_MASK);
 }
 
 #else /* CONFIG_SLAB_OBJ_EXT */
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-10-surenb%40google.com.
