Return-Path: <kasan-dev+bncBC7OD3FKWUERBEEW36UQMGQEJARBLMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CB54B7D527D
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:48:01 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-35776684d48sf1038455ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:48:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155280; cv=pass;
        d=google.com; s=arc-20160816;
        b=pZfVWuwOJPwP5FbQPDaNnkMsfaEvsKRwWdc1t93ssO+2d2OYpvpiUd5B3x1wC2Me03
         Q7ezvGlQ3kQKv6+hP7eKdNdgj/Aa0uQLFuDrN1JV2zAIpedXttMDSheiItHvmgpVaq5q
         FQ2UuzDEQMAqIs6VNaRnHviEuR0S5DmWXE2TThocDQXWrtrhm0BJkkOH6i+Jb1p6NWHX
         yP3apjw4wM4e2lM84Bj3ivdzwjNkJfRV/PScB/TghmND01sqbVV5HDNVZW8CogTrMWzY
         69njNScNqjO2T2VRLNQIyvHrOV4l1Y5oTH2jyZB1/m982jQT1ZyMQUnhQTmWksJn+rcp
         rojw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mcipUTiPoohdV818Qag/flBhfXk9jjO9F+VkfQVQ9qo=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=HHMQ5zx1lyzhWt7F9oKqy8dEb3uwSZm9yV9aZW+/1Y2/AgGg9sLc7jjNHcuTSkgYLq
         qJ0WUtELkhlHm1V2RleHMhmHRLbYwILMq/VSnX1KN8UURUWaExb5nakKfZXDm7InytF9
         vHCNP8LkvHaiUaEIj+MbqSoJPGUQfddFF8lHAVectDAXxsPygf4MUiWuzFUTb+UyJj1Y
         DTS3h06Ynl2roLmY+MyXHAOpIWrq3Rk8yLvM8hnAZqL8BhlBxVzT8BKjHlJDrn/1zlYX
         wDAAf1JVn06S/smr1fYY2DsqwdtHLaiGjsdQkhbenKjjL4sG7i0V7GfqMWFZU8TyNTbQ
         7k0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZQ9xSZDq;
       spf=pass (google.com: domain of 3d8s3zqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3D8s3ZQYKCbQmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155280; x=1698760080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mcipUTiPoohdV818Qag/flBhfXk9jjO9F+VkfQVQ9qo=;
        b=KPF5viobkQxXerO4BP8lzBPjYLlkzUjewhwXvBf8Rxz550r6I/XfJfzmDgCkYCAQWQ
         5qd2uEyeQY6UXwD0/pOLjxHXgV3BOL0e9DnmEoUWBvt6fREaRKFQxzmUxP7uV7MzSMO1
         5v25eUPJVn2nlhoxt+gjNwiAyOdfBTx887JYRYTH+wUzFFLxHhDbt8wXT8e8K5MPYoKa
         ICwunVwH8ZsqMj1/PkZWVdiqy77TEY3HlOY+LsLI5IVG2+WtdDyBCL/cVQ/PvmZEa8tw
         oiS68Kn65FOFKv7Y/r5maL6X3vymCn3tTOT364KDBKr209FUtZRXMZfm3PAVaVRlPklE
         raDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155280; x=1698760080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mcipUTiPoohdV818Qag/flBhfXk9jjO9F+VkfQVQ9qo=;
        b=DVAyjlNvzmal9hcypDWWNWRSNv3/7pGPt1M4gQFr/1N+p5eYILgDnwSvHLUFUFkT7T
         8kT3CvwhKZ6npnGPDRJuZ7a85XNKZgjYMZ6QZIDPpB13bLDxXuS1InkKL4XvzIu5o2zm
         Vys6QZx1nZtrqdrmGwWAuUL/HkSesOxAxUQPOkL8kpUqKxFOu5eWcohM/MB5H74Jxyf8
         UPCFfa0Q9nnksSQ+MZ25+YNLUlGuigYpvh5xUN7g6Fv/58jBFDZ7w+8mdO5D2JVaAJUA
         bfQhzhCoXAN33RD0ujb+wGK6CHz/DWOmxBnKBaAYbpNZTTO7m1NJ1PYxsb8cv8+PVv3W
         wrnQ==
X-Gm-Message-State: AOJu0YxMSmyrJHHMBmw8h6vpgBsZD+U7Ur9frjD6WuXy6R4tqm63a2i1
	54PgtQ3yESPnoIbN1bS8Dd4=
X-Google-Smtp-Source: AGHT+IEMdFwslUu2wLjc9suOQy6bxU27cRhi+a04A2weUurMZw0JeANf/+wwdIGfbbT7aiZ88tgwPw==
X-Received: by 2002:a05:6e02:348d:b0:352:a277:9a00 with SMTP id bp13-20020a056e02348d00b00352a2779a00mr253780ilb.29.1698155280603;
        Tue, 24 Oct 2023 06:48:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:da0d:0:b0:349:17ee:89a6 with SMTP id z13-20020a92da0d000000b0034917ee89a6ls1293382ilm.1.-pod-prod-05-us;
 Tue, 24 Oct 2023 06:48:00 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a21:b0:357:f487:32b6 with SMTP id g1-20020a056e021a2100b00357f48732b6mr273291ile.22.1698155279999;
        Tue, 24 Oct 2023 06:47:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155279; cv=none;
        d=google.com; s=arc-20160816;
        b=K/4IkS7O0NGvx+IsPeo6rtKS/WKcrr0q6XJGTXRezN1H0wvkQWyaPK/mpSqCjvBd5U
         5ZKt0eYHu+QCE1jj3Zm9yHWAgnqTyNc2GobqFsoijpL82PvZxpvjWM58Ho3FT5IF5r98
         z1bn1ypJs62hP6bAZDjHFztPLuSeva/zwXVqYi9BUNMByu/aqPl7doekLgMNBNa1uWJv
         38wAEChr26a2ySrhr9rCFS3hzRQm2H6OoqIt9MJI4JtTlBGPjrcwSG5arh1lA6ZU+skf
         NME0UPgl/gikjwWZzOzF8cUn2odKKbXLpnHy7qMFQkn78bp1sFdSDdO54nDTRj0vO7d6
         3QRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Od9SIx6nrlV00gepzGuthWnU/KWY+8bGDr+wczV24Vo=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=jwpJqAA/9Ud0eZLvjzujGWQ9C73SLMmUmsJWmZSXhmleCpdDYeMn5b7iD+J9UVyFtR
         TqIt3FxNFVUcb7+qkV8CdOha1nWt3J7h8idPBZ4q0BC//T100yiiWSjV+v+qRvDgUxBl
         X1rKnRjzJ9VgjDh+ruUaFqiIWexEyb1d+hwz2Jf9lJCwsDrUZo+sXWC9aJqX+rAoGTqH
         1aMjigzgS151Jd4Wk5DpiYmacLd2vpLH5RYmehJCLW0YpL8d+bh4IVptLLBnF00DQEKV
         0rZO5ILZVjyUB7nWneWQOvutCsHiJzNu5r4Imp8mGhtzJ0HxPemfvKavXPO62FFDuhRB
         hbiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZQ9xSZDq;
       spf=pass (google.com: domain of 3d8s3zqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3D8s3ZQYKCbQmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id o5-20020a92d385000000b00350fd9a47f9si84591ilo.5.2023.10.24.06.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d8s3zqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a7af53bde4so60190537b3.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:59 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:76cc:0:b0:d9a:68de:16a1 with SMTP id
 r195-20020a2576cc000000b00d9a68de16a1mr246429ybc.0.1698155279398; Tue, 24 Oct
 2023 06:47:59 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:32 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-36-surenb@google.com>
Subject: [PATCH v2 35/39] lib: add memory allocations report in show_mem()
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
 header.i=@google.com header.s=20230601 header.b=ZQ9xSZDq;       spf=pass
 (google.com: domain of 3d8s3zqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3D8s3ZQYKCbQmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
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
 lib/alloc_tag.c           | 37 +++++++++++++++++++++++++++++++++++++
 mm/show_mem.c             | 15 +++++++++++++++
 3 files changed, 54 insertions(+)

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
index 2d5226d9262d..2f7a2e3ddf55 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -96,6 +96,43 @@ static const struct seq_operations allocinfo_seq_op = {
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
index 4b888b18bdde..660e9a78a34d 100644
--- a/mm/show_mem.c
+++ b/mm/show_mem.c
@@ -12,6 +12,7 @@
 #include <linux/hugetlb.h>
 #include <linux/mm.h>
 #include <linux/mmzone.h>
+#include <linux/seq_buf.h>
 #include <linux/swap.h>
 #include <linux/vmstat.h>
 
@@ -426,4 +427,18 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-36-surenb%40google.com.
