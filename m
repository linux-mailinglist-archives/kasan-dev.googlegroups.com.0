Return-Path: <kasan-dev+bncBC7OD3FKWUERBGHKUKXQMGQEJTC2IOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 26C39873E8F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:30 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dcbee93a3e1sf12145426276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749529; cv=pass;
        d=google.com; s=arc-20160816;
        b=hFB+Np74+qaZx/YSmBpLFoVEG6W0gvi9wmouf8ZoRixFxhonwxNVSxhoL5I9T4u3Lw
         4oXyuL7EfIzyKQ+MhUsqDq6RgF3zZrRHovyxHGvAV7AYTJYpaKh9WTBLmqXlySUyva+z
         VkdrQ/rRJdTT8GyGkQtGpKv9Hp+FqY/CY0EkzAt+z/uGQPPQiquAeHvr8UCmT5qU4YfM
         JWLeiI2TpvsolxJ3hUibZIJrC+fJfiF4pD179gbIvPlGwihmR3Rw1cq7sBnXJeUsIjUE
         P+PYaRoLg6+7kP7ES+6zOelh9GFACZgfVvo+mdYhI0iQO5A3AAZCCNCsxuPeRbNP+vLn
         OeNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RPpkCQSMMI/qR42WMlpHCsILcx9zsJ1VdqVqiCQyZz4=;
        fh=7YKCBG9FeZpp2GvYtlBXcdTr1HphUhT7UV5KvTGQyPk=;
        b=MYb6T45yyKau3zJ6TtJecne5VK6Re/790VSdY94aGdh71qW8uyifwDKa2j1TkEC70F
         pdAGafTPbGc0pXt8y9LCubjU1u8djLmODEvyq/bejOcW/mNRvQGfeO9u2Yg66GNF4YkW
         7whHb/PWAgUsI9sUUR1Dwvr6Adx5y9UDw0RzpOdQgOPm4x3sodIdligojzYCzKmHUiMU
         hOQjuj0bKgky91wP8VgQePa9BSU/N6lmWTbZ5+PeJsz4PM8te9yEHV084T+HU6gcc8wI
         TRMF7pY44y/mwsH/vCBOyTbqTOo+BfA4TPAaCIzgLQv/5xjWeE+Nxu+mWnxXwMvv5Saf
         aJiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Rdit8aHo;
       spf=pass (google.com: domain of 3f7xozqykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3F7XoZQYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749529; x=1710354329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RPpkCQSMMI/qR42WMlpHCsILcx9zsJ1VdqVqiCQyZz4=;
        b=k6UExQmKHhj7b4ldnXqV6BZhWpHskgnGu897Uf+qbpIZ+lAO88tUuNyNkZCSpqJ8en
         Evvws137l9QPLR/y3dLpwh12fxhOobAr1Kn3/cZxkPk2Z6ji5C6QuYLoYoz28MyrzItk
         KgrHj/42RknBKjjV+M+IVcsuFRl58dYNpJWtPoIIuwck/31jxHTICOeP/ows55cpIxlC
         bIM3fvC5FmeFye42HNr3UU9ylnbaqgcV1Z544y+1tnhxsVW6+gajKh2icXtYkSKkqw4V
         7w3Vv2n2hdmx+rbwHlwGSv2kLxQoQ78CMyA5Z7b7+DThx5rDSU3QSRemeUx5m8DEyYQd
         f7Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749529; x=1710354329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RPpkCQSMMI/qR42WMlpHCsILcx9zsJ1VdqVqiCQyZz4=;
        b=U0hfEJ5IY4pJX1zgIPHY9j581UlZ8x+bL+1t96hjONkPRug25khMveoRBgXw+XfNkZ
         SLFOenYh7TyqZI3c0u5+j+J+o3MaL7bEcctnkAtADMtZw9vyxjY296Fk9jSCGkvJ7X4x
         IbUV4QEvy1iStwIggTD+tu9h+63lmsob9Twwh1imwrkQ/7V+2b+D83+RsoWwT2vkupU8
         2hVw25JrqEIbtJc1K8/MtCrrSarlbIdCjg9GfelQXmZkKXGYy8tSvBmJ6G1wImRt7BD/
         r/Co/NNaT7UaehDN+XEdvuk8vAFAVOnH9BKEQVJRfMYe1/ZFnYeo8mLlxAvSpXSy1tqL
         oCFw==
X-Forwarded-Encrypted: i=2; AJvYcCWkc2nVqSYDi7R9FSnJGyzdJ7CCWxR//5mHOBxzLEzTe3M3s1cchTUEGAezyq2/McJzTVJo4Qq+Oh4QBNdfi2n4S/SQJUBNhQ==
X-Gm-Message-State: AOJu0YxLytmKCvOclYNRSyEr0cnLEAe/BVNkhxmFsg2adoBCt5GLTW8y
	JQEOuSFlD/ZPDRrmkK7TJSWb+miiVNzOnlp2poZjd+Ki3j4j3B4O
X-Google-Smtp-Source: AGHT+IHqSX+ShM5avIGMxfWnOgFdK5Xe0esXmwSGOa4gKjepXrO1bmWyMr0QPJNrxPkw5neQhIchBw==
X-Received: by 2002:a25:9287:0:b0:dc7:4c21:fbd5 with SMTP id y7-20020a259287000000b00dc74c21fbd5mr11696432ybl.0.1709749529043;
        Wed, 06 Mar 2024 10:25:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6943:0:b0:dc7:4417:ec4e with SMTP id e64-20020a256943000000b00dc74417ec4els70126ybc.1.-pod-prod-04-us;
 Wed, 06 Mar 2024 10:25:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZP+DPMvEMLyc+nRXvaCxN9MFfvYC+iyCh82hzglRxbkbSHvDzONWSzyYVEA3N7v0SzXKnagY+N/a8MeDslIxD61Pnq1h7WyCkFQ==
X-Received: by 2002:a25:81c6:0:b0:dc2:65da:d3af with SMTP id n6-20020a2581c6000000b00dc265dad3afmr11368720ybm.65.1709749528314;
        Wed, 06 Mar 2024 10:25:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749528; cv=none;
        d=google.com; s=arc-20160816;
        b=KQ+4sSPDscWTPozbkPr5B0dkQx2B9+19C8VMhlnMR75ovAhDIFLDUPOQit/YLfuEM5
         5gkKVfneqqAWW/cnV7jWfDocl67S0nXZNnqfNHlvMEpPCQEe++CGBVdGjXeTZ6288rKs
         FPNvB9suhORyO5JyplNXgsx7p7jpxHDLb3LwF7kGO2sQRIMWh4r9J+jeA/X7Gr1jg2Li
         AkZ/+G1dpgHYpPhGLYLJsbm599LS2l6hO0lWFUCJHkxSzVCFk15BdDb2jM08MbwkvxJm
         mYMetqWqbt0s9vGLgwilmXjP6krf4x8G1u+Oyps9CYwyEuft4hjn2I+tPgDr4npz1F81
         2RaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=EvAS1Tk9rG7Nm0pd+ehjWtNqiQusCGfZiqvBjL56bfE=;
        fh=lpDI8PvRqvUiLDE59n+PfliwQvqfJFjq4J9xs6FskxE=;
        b=Ud7IpOmu/Fq82gqoI6TqP8ROFxC5NEqtVaEfnsuhVUEN8jDqP4Fn8QnGGblmGsa17N
         OA0Lvvc+UCGVEclCkyqNB/5KIl0E21tj2YcD7Ud12hgFd9v/FFvYmtViTT4o5NP3Me/S
         Bt/NLbO1S0POiMQrCxLLtGy0rbRAWR0GN1wKPBp4NSAkywvoLMoSXNQ6W/OJoC2rl5ne
         +Cv+olfCRo88t/Bfu3TzKfB+pVbH5Hyk44suHDWatphXG2WgHUNkmm0LY2cB8/IwukVm
         Iwt1Kc4hQjU7JNu+daC4qaP4xBaF8Pz2DOmZn/BT3In8fJZhG9duCYXq6w9bWV2JEIuD
         cDcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Rdit8aHo;
       spf=pass (google.com: domain of 3f7xozqykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3F7XoZQYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id v68-20020a252f47000000b00dcc3d9efcb7si1108647ybv.3.2024.03.06.10.25.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3f7xozqykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-607c9677a91so172447b3.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUh2wz8Oh7PVTKu1ExZwzGeaiUL2e0potoqvd2WkHQiyKobwD1GXmQPFIRYUDfpkTP/Us+lb/Ruc2JhYXmOHEmpuAXglcQmiFecLg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:fcd:b0:609:33af:cca8 with SMTP id
 dg13-20020a05690c0fcd00b0060933afcca8mr4422200ywb.2.1709749527811; Wed, 06
 Mar 2024 10:25:27 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:18 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-21-surenb@google.com>
Subject: [PATCH v5 20/37] mm: fix non-compound multi-order memory accounting
 in __free_pages
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
 header.i=@google.com header.s=20230601 header.b=Rdit8aHo;       spf=pass
 (google.com: domain of 3f7xozqykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3F7XoZQYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
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

When a non-compound multi-order page is freed, it is possible that a
speculative reference keeps the page pinned. In this case we free all
pages except for the first page, which will be freed later by the last
put_page(). However put_page() ignores the order of the page being freed,
treating it as a 0-order page. This creates a memory accounting imbalance
because the pages freed in __free_pages() do not have their own alloc_tag
and their memory was accounted to the first page. To fix this the first
page should adjust its allocation size counter when "tail" pages are freed.

Reported-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/pgalloc_tag.h | 24 ++++++++++++++++++++++++
 mm/page_alloc.c             | 11 ++++++++++-
 2 files changed, 34 insertions(+), 1 deletion(-)

diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 9e6ad8e0e4aa..59de43172cc2 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -96,12 +96,36 @@ static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
 	page_ext_put(page_ext);
 }
 
+static inline struct alloc_tag *pgalloc_tag_get(struct page *page)
+{
+	struct alloc_tag *tag = NULL;
+
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		alloc_tag_sub_check(ref);
+		if (ref && ref->ct)
+			tag = ct_to_alloc_tag(ref->ct);
+		put_page_tag_ref(ref);
+	}
+
+	return tag;
+}
+
+static inline void pgalloc_tag_sub_bytes(struct alloc_tag *tag, unsigned int order)
+{
+	if (mem_alloc_profiling_enabled() && tag)
+		this_cpu_sub(tag->counters->bytes, PAGE_SIZE << order);
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
 static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
+static inline struct alloc_tag *pgalloc_tag_get(struct page *page) { return NULL; }
+static inline void pgalloc_tag_sub_bytes(struct alloc_tag *tag, unsigned int order) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 39dc4dcf14f5..b402149a795f 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -4697,12 +4697,21 @@ void __free_pages(struct page *page, unsigned int order)
 {
 	/* get PageHead before we drop reference */
 	int head = PageHead(page);
+	struct alloc_tag *tag = pgalloc_tag_get(page);
 
 	if (put_page_testzero(page))
 		free_the_page(page, order);
 	else if (!head)
-		while (order-- > 0)
+		while (order-- > 0) {
 			free_the_page(page + (1 << order), order);
+			/*
+			 * non-compound multi-order page accounts all allocations
+			 * to the first page (just like compound one), therefore
+			 * we need to adjust the allocation size of the first
+			 * page as its order is ignored when put_page() frees it.
+			 */
+			pgalloc_tag_sub_bytes(tag, order);
+		}
 }
 EXPORT_SYMBOL(__free_pages);
 
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-21-surenb%40google.com.
