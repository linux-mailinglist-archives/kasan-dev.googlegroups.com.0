Return-Path: <kasan-dev+bncBC7OD3FKWUERBDVE3GXAMGQEWZ3R7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id ED01085E79B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:07 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-205c90a36a3sf7799769fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544526; cv=pass;
        d=google.com; s=arc-20160816;
        b=dxpgfYzQNOwO/o6iWf83cWZfexu/G7FkRVzZgbcF9AND+LwBtxIM/Ne+rIw7StP8Ha
         16aQFDJyGB7sYaXIfnbJjP114jA+3gSHPGYDor2tbRoIGZoyPakPSksu08mys+0eBBaT
         Y2Ymc/Yrkv8P7Xr+UvFrfniZgxcXoFWFLpqg8yFU6vsvYve0l3naXcCauI7KFdAfh33i
         mHhIFm3L3XWj6/a5Fx5iVtWSf/bXrNzLikbA8tsowyjlW8q5j1hR4jjDO4im2Wbq5SdL
         hz5SEOGlP9wMtVufZe42Kj7FTCDfRV2uM3SDpMkmEMDj5NPOkcyitp0uR4Q9lqbCHHOU
         XwLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zVJd5kiKLZjs+RMne78BTvDCgnpqcrqLZGscYBAkF5Y=;
        fh=vh5LBDPel7sKa3+l4LXefKIzLh+QZJXDBZFOdYKCoYw=;
        b=FMOISrY0oyjHC7j7vlW9O282ENDgy7g+42iljARQ8F5tdXy99Nqbc4eSQzGYwnDjQe
         m8uBaSjETmUFlKn2HbckqWNWMmQoLV4eSIhRF0zeyJ9S0qKSzuJIdS1/ILv6f89reck1
         s02ev0lFWw7/NhiA6Vp9zr0zCAE+J4fIo8p62w0DYPthgTs+ON+ae5CQqJL2edclofB5
         sG81CWZApF3yLAaVphnolVyozuv0MUaLiG8Lfmbesne6dV8Mo637FmkJG3AJbuA6meuc
         78Q6uHRCYYuAfv1xYd4FFnzIM/ped3aqjfk+5K7uQu8Uf86ykmzjKt3bVej+es6SO25e
         XHzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u1jq0yJe;
       spf=pass (google.com: domain of 3dvlwzqykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3DVLWZQYKCUAuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544526; x=1709149326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zVJd5kiKLZjs+RMne78BTvDCgnpqcrqLZGscYBAkF5Y=;
        b=sAhv0JUSH4H/v9rovqIdQniaW99w0SPb+6eHGP6GuQhzZXgAoFrzmgKCkIChqkCZ8q
         FAPxvj2M4LgiGt3X7ZSPOnVR5FFA6yk4nfSwtNs/NZZjg5Jjl/JNfcIT1mmzFKeq8ARh
         Itqm/blMSTQMw+ZJXsd23BUa8TQR5LRVYfGLsIX01DxWVXJAe5dn6URFjjSbQJYPZbzj
         JPRHa73LH/CPZ3iZbiGQs3OqH8d4D8rkQkHPj1aZs7RhbmmFUBGmyra3Y4THNfF6QD+j
         FSF/e0SJKLD4YT/3oYxrnRjC0kFZGOsOysCBKWGteSJqv5Ih2jH0aOdeYhLtseGKKREI
         tOqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544526; x=1709149326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zVJd5kiKLZjs+RMne78BTvDCgnpqcrqLZGscYBAkF5Y=;
        b=rr5kZgR/YLsHaf+IFjevbQE5Ew+h/foQOZEYCuIKrw7wWwBhfgzZGFZs4toWaJvuaz
         07mSO58J+fL+LCxypW/fSmA9ZjkPZvKNxqAzYUpP8FFLk7UfEMrXlQu27u/eaoTqXDUl
         rMlxKv0mgZRLVO70v72cd7UJ8/yQwoFTMGKIxUNz0itX6lM63A6oETc3jGYuvTt/EICZ
         aGiKuSmZQnu+o1EKnBqlVUhKkRYPRGxulAzOnQK5uDfi7ZkKH69YD6xzIyepNAEH+IRW
         x9c+Ewd32Lq/I3uKvFJ9pEeNcOsW3UV0kqV2J3b7M0hSVDCgVAbZ4f+WLYPKgASyu4LC
         U2pA==
X-Forwarded-Encrypted: i=2; AJvYcCU9G+CJibvFJBxf5uwqxvePSyvBgCv1X9X8wW50/pO8WgMkXV+VrGs4cPuU2Vk7REPspxqRC2cKFGRXBGIhZi95CHeizYTbmA==
X-Gm-Message-State: AOJu0Yw5FGbW+4puMQVgqmdCdV/tgy7d/Y4fefHrGKsUBSdoLZ1BJoQq
	Fty4YxKs1gCtTsC/cUNvv2z1Fy+7PYv5xSgSFoMk6qATtelXsRri
X-Google-Smtp-Source: AGHT+IHJayo+l7pQxaZ5XViQVBEQyg2dviHWKjY+fUbxfa6r3YPzxd8AOUWY/ZeemQoMkleJBNCuYA==
X-Received: by 2002:a05:6870:23a8:b0:21e:9e8e:66e7 with SMTP id e40-20020a05687023a800b0021e9e8e66e7mr11488950oap.0.1708544526749;
        Wed, 21 Feb 2024 11:42:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ec8f:b0:21e:3b64:cda4 with SMTP id
 eo15-20020a056870ec8f00b0021e3b64cda4ls5789412oab.0.-pod-prod-03-us; Wed, 21
 Feb 2024 11:42:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUTn9twPL3a4jSXVb/zApOVSvDW167RkAeT2bk0f5FI1T/T59laJ6AB7uayXsjKK0ABfJkPi6inTdRAghkXx5GNDuprxM6Z6L8b6A==
X-Received: by 2002:a05:6871:7509:b0:21e:93d0:7b18 with SMTP id ny9-20020a056871750900b0021e93d07b18mr13355638oac.50.1708544525914;
        Wed, 21 Feb 2024 11:42:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544525; cv=none;
        d=google.com; s=arc-20160816;
        b=B0QASbVq5/TIR4pXtxBZC0AAv/Qrkiu88/kPJl3w+upAxm4RFF4XXwZgMRhsHvGH4e
         vA//tv/glFo+6BAYMoWIZP2XwIdmzrF6Bo6QsIf+G/pUr1jtYMiCGH7LlY5Vy0TT7SHI
         VjBuoaCH/DX4V/J0zZkWTSnC+PNC5gYQ7Mdrdqw7amAzJxwS8Zs81sraORaErXJyupEg
         shEFxNqZagZdRentP9HT73lkeCkA/+C2szIQDlrZmxJZX1X6Oc1Lm2q5g62fEQf7CgyW
         VkqqvvLjZqOWwufSi0SmmzvZMYW3eJTDP7efmiwsEAGbnmTFi0ZKFpYD2mlCufjhaWbc
         kFuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=LC7kagHHnwmHwKr3BMy6MtJI28X2XJIX7s9nejqSpcw=;
        fh=2PETA+dMMjTNZvtNLp+ZHISDX6b5HqOTlfcEugB6qrg=;
        b=GbJYHYsIP393UxiWFpUzEw+WFd7rN3KEPo8d/zGESGFeFC8uPOSF9CysJL8kUUBKUb
         praXTZSVB6JWWzvnM9gsH+j1z9eelw2rQVTv5o9nmMjUCwKxKiwQmTizbfrZLqqnaO3R
         QGO+YWJoByGspc9kWNd2cbHxNQK5WxtekHLO9PgY52+SReM+MIjSyloCz4cgiQP6W/Oc
         Q0AX5IPLQPhJiFZ1wfFWfmerYipRCzn2qNAHjSQQohrVRwGDgGSAJ8nhW/PxnjManLF5
         k0sMajC0vBKyRGM0F6VUfYx+PgJqooq3WCArJNxHw/fGV79zxP0py0iTlZNVYlABsb+7
         TqZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u1jq0yJe;
       spf=pass (google.com: domain of 3dvlwzqykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3DVLWZQYKCUAuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id pf8-20020a0568717b0800b0021f2da568b3si340275oac.5.2024.02.21.11.42.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dvlwzqykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-607a628209eso127410677b3.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVNa7BUR1b5tD3LP5NFf0V6rG1oZS1kXiEw4v/pgZnbG2uV6CV8J5rp/R7ONHiOo0MPq1NNMYrSbyTvaX17mefU586FsiF1BaEb7g==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a0d:e611:0:b0:607:9268:6665 with SMTP id
 p17-20020a0de611000000b0060792686665mr4677189ywe.10.1708544525062; Wed, 21
 Feb 2024 11:42:05 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:44 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-32-surenb@google.com>
Subject: [PATCH v4 31/36] lib: add memory allocations report in show_mem()
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
 header.i=@google.com header.s=20230601 header.b=u1jq0yJe;       spf=pass
 (google.com: domain of 3dvlwzqykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3DVLWZQYKCUAuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
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

Include allocations in show_mem reports.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/alloc_tag.h |  7 +++++++
 include/linux/codetag.h   |  1 +
 lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
 lib/codetag.c             |  5 +++++
 mm/show_mem.c             | 26 ++++++++++++++++++++++++++
 5 files changed, 77 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 29636719b276..85a24a027403 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -30,6 +30,13 @@ struct alloc_tag {
 
 #ifdef CONFIG_MEM_ALLOC_PROFILING
 
+struct codetag_bytes {
+	struct codetag *ct;
+	s64 bytes;
+};
+
+size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep);
+
 static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
 {
 	return container_of(ct, struct alloc_tag, ct);
diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index bfd0ba5c4185..c2a579ccd455 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -61,6 +61,7 @@ struct codetag_iterator {
 }
 
 void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
+bool codetag_trylock_module_list(struct codetag_type *cttype);
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
 struct codetag *codetag_next_ct(struct codetag_iterator *iter);
 
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index cb5adec4b2e2..ec54f29482dc 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -86,6 +86,44 @@ static const struct seq_operations allocinfo_seq_op = {
 	.show	= allocinfo_show,
 };
 
+size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep)
+{
+	struct codetag_iterator iter;
+	struct codetag *ct;
+	struct codetag_bytes n;
+	unsigned int i, nr = 0;
+
+	if (can_sleep)
+		codetag_lock_module_list(alloc_tag_cttype, true);
+	else if (!codetag_trylock_module_list(alloc_tag_cttype))
+		return 0;
+
+	iter = codetag_get_ct_iter(alloc_tag_cttype);
+	while ((ct = codetag_next_ct(&iter))) {
+		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
+
+		n.ct	= ct;
+		n.bytes = counter.bytes;
+
+		for (i = 0; i < nr; i++)
+			if (n.bytes > tags[i].bytes)
+				break;
+
+		if (i < count) {
+			nr -= nr == count;
+			memmove(&tags[i + 1],
+				&tags[i],
+				sizeof(tags[0]) * (nr - i));
+			nr++;
+			tags[i] = n;
+		}
+	}
+
+	codetag_lock_module_list(alloc_tag_cttype, false);
+
+	return nr;
+}
+
 static void __init procfs_init(void)
 {
 	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
diff --git a/lib/codetag.c b/lib/codetag.c
index b13412ca57cc..7b39cec9648a 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -36,6 +36,11 @@ void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
 		up_read(&cttype->mod_lock);
 }
 
+bool codetag_trylock_module_list(struct codetag_type *cttype)
+{
+	return down_read_trylock(&cttype->mod_lock) != 0;
+}
+
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
 {
 	struct codetag_iterator iter = {
diff --git a/mm/show_mem.c b/mm/show_mem.c
index 8dcfafbd283c..1e41f8d6e297 100644
--- a/mm/show_mem.c
+++ b/mm/show_mem.c
@@ -423,4 +423,30 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
 #ifdef CONFIG_MEMORY_FAILURE
 	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	{
+		struct codetag_bytes tags[10];
+		size_t i, nr;
+
+		nr = alloc_tag_top_users(tags, ARRAY_SIZE(tags), false);
+		if (nr) {
+			printk(KERN_NOTICE "Memory allocations:\n");
+			for (i = 0; i < nr; i++) {
+				struct codetag *ct = tags[i].ct;
+				struct alloc_tag *tag = ct_to_alloc_tag(ct);
+				struct alloc_tag_counters counter = alloc_tag_read(tag);
+
+				/* Same as alloc_tag_to_text() but w/o intermediate buffer */
+				if (ct->modname)
+					printk(KERN_NOTICE "%12lli %8llu %s:%u [%s] func:%s\n",
+					       counter.bytes, counter.calls, ct->filename,
+					       ct->lineno, ct->modname, ct->function);
+				else
+					printk(KERN_NOTICE "%12lli %8llu %s:%u func:%s\n",
+					       counter.bytes, counter.calls, ct->filename,
+					       ct->lineno, ct->function);
+			}
+		}
+	}
+#endif
 }
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-32-surenb%40google.com.
