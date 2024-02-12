Return-Path: <kasan-dev+bncBC7OD3FKWUERBWFAVKXAMGQE6NL63LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 28871851FF0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:42 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3c036e04a9dsf1891381b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774041; cv=pass;
        d=google.com; s=arc-20160816;
        b=lAJY7oMoxpUDbTVlreKrwxsFd1WJnQVYc80c9pTnOhxJsrxU5VmS4nUzd1U+4N0+At
         NGBemeYQ/aPb6YnepEn4IyURVOW1pqtRuUhwo3q3TGqjnKO37ZLV6q6eHIhh16a3hC5C
         /wsvq1t55QpxMcQlpuj7EJUcQBJfNMH+jNj6zMcmMK2n7c9tnDiIUsebh43aSw6RhP71
         uUYxlrjO/K6TRtMyZvvaLNQTzsrP9NYB3CSc3MjYkZR46MOW/iPYTR2/ygqQsA4c+2bO
         Gqa0KYfUaTb5oD7KZMEXsrnM5Hpj7b80b0O+cC2I4i1Zxsp/Uz5pDWlxUwL0/LKj8X9+
         Nchw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=P1qcAE0YxCWDxQ5RREtkOW6oDOcyWU650n/fsFpT2Kk=;
        fh=KNGA36HOmHOUui7rmsFvKRhbP2Lh3JN6a2GbHY6eJwA=;
        b=b0tXw7B3llSkCt9U6W8/fpn+vAAtQ+g48EvrdKeFwXCnlYnestY+ECed5Tl4od5vye
         CQIk2vZmhiCp5kCL0P2dNUXRCruSkBfISQePswNtZQYSk59UmUHa7hLp4viztMOVAfTf
         bhrxz/UsM1t+OEQA/a/mD0KJgogBgv6AiEajF3Xy1UCYIPhLJOe8Q8uLvQFAdsRkPxgF
         dSYNmTsD1z5JkQ9WVojX+ZQucs0QcyRVU0KGX9l7nyP4Ms6HbZpKX9wBx6qEGMLOZzwC
         4ZggKMEjUUKrKT9/NcHvUNg+FxrGRqXEqr7PoaifuwHJd9eFrD+IiU+VxEQMHANfPM7i
         zWzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aB+Arjdq;
       spf=pass (google.com: domain of 3v5dkzqykcdykmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3V5DKZQYKCdYKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774041; x=1708378841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=P1qcAE0YxCWDxQ5RREtkOW6oDOcyWU650n/fsFpT2Kk=;
        b=S7lKn1ZTPNOcF+a1nVu5oXpkGVX930K1RvL3z41/7GFvIrn9afD6pwqKd1FUpgicsM
         0BuA5EvgfLNyUsCPMyrXlCRgGPbtok6JUQTu4kuCJCsvUw7qQ7NGTqwhxMrjG7Wb3jWn
         wxMZzB+VlEJEzEYUXLvvyCRUohcqG7d+jOtXeT1Kgvq36Rolq2VJDTY04wR0nrkYUx5P
         mQBZwAisziiq5I05mukEHPL1X1tmkxW8qL57Kv+CIxCoHhp/war/s7AVpjrfjK2ZNvsp
         3Kc5piZ37cryONvK/eAKkvB6cdMJ71+Fk3LQPpwyD43mop/vn6Yytdzc/2nsEfxs+pua
         t3og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774041; x=1708378841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P1qcAE0YxCWDxQ5RREtkOW6oDOcyWU650n/fsFpT2Kk=;
        b=G8/HZiYU3XJkWmn7uXGE0CI32G3a6bXE6AI8TCpYQEbNJwfKymhtitgA4lhKfJX/Pf
         nafQqLmT0PRa5mb1BQduyZ8CcKwJVBDdmdhCXd5Oc1vi5K0KsPnF56EtGZnejkcnYV3p
         d2CnnwjI4RCGAIN2ffFXIbvvvNqRxlovCP5guZrYMQW6R2UqeZmcnhINy+ArjA5gDp+Q
         qiKsTKs+OnQsCm+fNRNy52XnmEF/QExiQrYIXRCtT1g79E/+CZLYSzpKg7lhcwUsimWQ
         JPPMSYoyDrvYtRPPVIyGRg84AVNvzeKf/DNBcHGQMPu8iI3qZN15s4ytvYaxRb37WyFZ
         mE9Q==
X-Forwarded-Encrypted: i=2; AJvYcCW1OhzUz4MKJnZ9vFz7oH0QnzjKKtoJIA87fyn4sWR2UMZcLPtH5oGJJOZCtiSo92XUT1OWo6lyeX9RunIoOYQYh9LcMkTnpA==
X-Gm-Message-State: AOJu0YynvwltznmmvmIS5yS6Df4w5p7irPILmK4INDKrzEMB9BI83i+d
	cdCJBMo98+8KOVeQihMyfncVE5Qw+PtPzgMkqf0BtIcLfetMGcoy
X-Google-Smtp-Source: AGHT+IHfl5ZQMcs0I9zw0cLoumg0W+UFITyclTXCj/ZqxDbzgRejPjQGfK281KxlZqZ1jXjjATx+1A==
X-Received: by 2002:a05:6808:ecb:b0:3be:a312:675c with SMTP id q11-20020a0568080ecb00b003bea312675cmr11374885oiv.17.1707774040905;
        Mon, 12 Feb 2024 13:40:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:3d4:b0:42d:aa3f:7c25 with SMTP id
 k20-20020a05622a03d400b0042daa3f7c25ls379107qtx.1.-pod-prod-09-us; Mon, 12
 Feb 2024 13:40:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUyFO1jcGBMcWMsTxd0CFYNA8rYzAxTDw8HhrmnEtHmzH0EGaGRUUanEg5d8QaT1zuWtqIXSQP5Oxgy5RYwGmbu7X+GH1UNczOieQ==
X-Received: by 2002:ac8:7dc3:0:b0:42c:1e22:9bac with SMTP id c3-20020ac87dc3000000b0042c1e229bacmr13012892qte.32.1707774040175;
        Mon, 12 Feb 2024 13:40:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774040; cv=none;
        d=google.com; s=arc-20160816;
        b=gC0JDwU3mLVZgBQOW/HUxggu3iPecu3Ej22JtTmtqEOErqo+PHp+aX2hoFnfssox7I
         spI8IREsS8sZtB9ME8J3YcOnVYLAOCFpTl6P0gnrDN+s6eY9C7oy0WwX/4t593m6/N8Y
         Mgw/U0KHu5nte16JvzDNKTrwJ4KlA4+/pGxBda6vsZksR0KxnpGYv1AKLdkJDFbqp6Ao
         73nWBu1ECVQk3ODKz3bk/K0ouQYbsblDXK/Uf2dwBCR2zPTy++8IM81EsQip7JhBg110
         PxV0SsklSsWw7VVulNES9LiiYYX6/C3rTVW/tQfWa1h+gfM37WA4zaYwuaCEMTH6MRxy
         rY5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hFi0jScQsczt4c2Plav2pAvubIeyjPFOX5wIUH8AZHM=;
        fh=hJZuFkdlgpIBW5LcOj6RFp+9yGk5Svap2kB0iFk896o=;
        b=vd7f7QMMN3mMxYbwx8kpAsdWKWyQ/xxogM1aicysYDh5WH20K8smwdu6zn0ia+ERoh
         MbdTowCmTLnf3F2+3ujG42x+Zy3PMuJCjL3pbKgEbwfFKBZ4ca2vX33pjVgm1Mf2BDPS
         qSXZGRMUvv3O0lWp+oCaQ39Zb2NVLxheCUl+1whbeFIAIg8p3ybGAtezbFX/prBwzgGJ
         bASy+n5Olj0jnHUD6JNtmYdDMxsxy3QdCtPFo2jlovhV5I/WpDB/kRa0NSZ7+rV8yC6N
         zjktm97/dVFvnMoi1sqwHo6UUxst/eb4TPsysPp1GlYN8W+ZdinynamhFUqA5SU/ICEm
         uO8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aB+Arjdq;
       spf=pass (google.com: domain of 3v5dkzqykcdykmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3V5DKZQYKCdYKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXaDIxV3ez6MI1hvXPiBLozJBbrAps60o9Yb0gYMQZMeAtfuUMdu0tD3KEM2EMJBb6X3Oev2iSydh9DrEAZRL1JutNxXhno3BgBrw==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id o3-20020ac87c43000000b0042da8da3d03si121683qtv.4.2024.02.12.13.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3v5dkzqykcdykmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6047a047f4cso97757677b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU//yhhE4VqMaB5gsFLjPaalTNIen6FjHjFFd4gt97pqlEDs63laGQ43fDNB6rk2XdWnkyX3TXmZwcYUfq9MUyAzv3hKKnTJDaG5w==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:690c:b8b:b0:5ff:96b6:8ee1 with SMTP id
 ck11-20020a05690c0b8b00b005ff96b68ee1mr2134418ywb.7.1707774039644; Mon, 12
 Feb 2024 13:40:39 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:17 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-32-surenb@google.com>
Subject: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
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
 header.i=@google.com header.s=20230601 header.b=aB+Arjdq;       spf=pass
 (google.com: domain of 3v5dkzqykcdykmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3V5DKZQYKCdYKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
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
 include/linux/alloc_tag.h |  2 ++
 lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
 mm/show_mem.c             | 15 +++++++++++++++
 3 files changed, 55 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 3fe51e67e231..0a5973c4ad77 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -30,6 +30,8 @@ struct alloc_tag {
 
 #ifdef CONFIG_MEM_ALLOC_PROFILING
 
+void alloc_tags_show_mem_report(struct seq_buf *s);
+
 static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
 {
 	return container_of(ct, struct alloc_tag, ct);
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 2d5226d9262d..54312c213860 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -96,6 +96,44 @@ static const struct seq_operations allocinfo_seq_op = {
 	.show	= allocinfo_show,
 };
 
+void alloc_tags_show_mem_report(struct seq_buf *s)
+{
+	struct codetag_iterator iter;
+	struct codetag *ct;
+	struct {
+		struct codetag		*tag;
+		size_t			bytes;
+	} tags[10], n;
+	unsigned int i, nr = 0;
+
+	codetag_lock_module_list(alloc_tag_cttype, true);
+	iter = codetag_get_ct_iter(alloc_tag_cttype);
+	while ((ct = codetag_next_ct(&iter))) {
+		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
+
+		n.tag	= ct;
+		n.bytes = counter.bytes;
+
+		for (i = 0; i < nr; i++)
+			if (n.bytes > tags[i].bytes)
+				break;
+
+		if (i < ARRAY_SIZE(tags)) {
+			nr -= nr == ARRAY_SIZE(tags);
+			memmove(&tags[i + 1],
+				&tags[i],
+				sizeof(tags[0]) * (nr - i));
+			nr++;
+			tags[i] = n;
+		}
+	}
+
+	for (i = 0; i < nr; i++)
+		alloc_tag_to_text(s, tags[i].tag);
+
+	codetag_lock_module_list(alloc_tag_cttype, false);
+}
+
 static void __init procfs_init(void)
 {
 	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
diff --git a/mm/show_mem.c b/mm/show_mem.c
index 8dcfafbd283c..d514c15ca076 100644
--- a/mm/show_mem.c
+++ b/mm/show_mem.c
@@ -12,6 +12,7 @@
 #include <linux/hugetlb.h>
 #include <linux/mm.h>
 #include <linux/mmzone.h>
+#include <linux/seq_buf.h>
 #include <linux/swap.h>
 #include <linux/vmstat.h>
 
@@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
 #ifdef CONFIG_MEMORY_FAILURE
 	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	{
+		struct seq_buf s;
+		char *buf = kmalloc(4096, GFP_ATOMIC);
+
+		if (buf) {
+			printk("Memory allocations:\n");
+			seq_buf_init(&s, buf, 4096);
+			alloc_tags_show_mem_report(&s);
+			printk("%s", buf);
+			kfree(buf);
+		}
+	}
+#endif
 }
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-32-surenb%40google.com.
