Return-Path: <kasan-dev+bncBC7OD3FKWUERBP66X6RAMGQEFJCDHDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2750E6F33FA
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:32 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id ada2fe7eead31-42e38a1b344sf304620137.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960191; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mbc4h5xwedj1bq1NUqZqurHLc1nezHD/bR6Q0sbOBrngFVOjzMzs5SfsR94hHetYLj
         gSo4ibFBYTxtyS8KIkrBGE+9oAAmguWf+T9a1yrEoM3ptOhbljphimBwc3Cmdxp9QxOv
         CuPG9a9Xr8Uhtz3D/oPadR4gB7PJqwM2NZ2NL7myvoqyU+JCtd2mmU1JfyF8DKRWQiU8
         zs+cUZsFJkWucxEoZ9iqPvoIUZbXKGDY1Ah+67faV2huUtkoGHBjFayMphj3iwWX0RdO
         GONM+/SVZ20VfDqPYJAqX7SDtp/63zrnIsASvWGJ7gyTmUuhM5GBq5XDFLCCVX6MUkbG
         0SKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=cIOMRKRh+i71eLb2v+r2ZFoNv95vwGGoZ6zBq5lUImU=;
        b=YWTx9ykuv+wNibc0+dWbhn2GhNkPK79yxGpySFfAxf/m87UKKX2dHVaYY8UztWVDe6
         pSrcpWcGmnWs1JnKhSvLnACBn+YkqsjgS/fUtfg5gP1aoFTz2UGQVcrBs+IjRl+NWfJS
         LvDrJo7jE/X92EJaS+fGV0EGIQmUEVOg2u5DckhXDGLhc+uRflzbwFe3GP0fW5l1WJA1
         pDx+k1gTGj0SibpuR6WWo7bcXsIU+liVAWZm+7iNGHus8jR8AWHQTuy/CIvJsPGEQswE
         W7FpxI3b7SeIbn5EvOU0UJToDLNlYpuwSBTnI610uLRgf90djvk3xPMnduj9Ch3N6nDm
         OjfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=y9PADbKN;
       spf=pass (google.com: domain of 3pu9pzaykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Pu9PZAYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960191; x=1685552191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cIOMRKRh+i71eLb2v+r2ZFoNv95vwGGoZ6zBq5lUImU=;
        b=EpWPNEcm+hp8IxaUON0NS8bo2iRdj2jpBDXqpGVTn7WuT5XP2u7QqQyhlaFuEpVbf6
         jb9XJm3XJmZsXqYC/WUICWBcvcC3ROu7IZe1ANwq4hH6pzoaJySPNEZJ+O6+Atj5UUcN
         EUdLDo9FwusNmwfhZqOVKh0y4FHn8zG3qGK0ncPQgiusldm9F8+A7gYYIGTWq9BRRvhF
         MYyjrOqS80fEcvI5tNMdgF/tYlx5YE/M1/O0YnCnAyXsnbeYCtjErqxjFbxFr7Fre7zl
         kVdqUM/ievM/wx+b6WsLWaXKs0nzGhIztYafityVXt1dhj9wh1qm5O7dBkSBa6ITCFUo
         6Ktg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960191; x=1685552191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cIOMRKRh+i71eLb2v+r2ZFoNv95vwGGoZ6zBq5lUImU=;
        b=TXGpqN5//mqYu/y81cuYtUiaeoO5DW/91For7l5WG7b4041QbK6YYlCobktIVtpGWi
         1MbaQU52oOb6SlAEgI9WueCQi+7o+wduT2tjf4kjhbPG11bndytg4YJGmbUQOoJJQepL
         J9EecbG/wAr1bJ0hKMxM6M2SHjTrKgw+by8THsn/J0xPExUXIfRhwQaPJUuEDsA5/9zE
         Bi/NXjsY2G3GtcEfVLIrn0kxUV9Lq0z/T1u2soa1r1au/wpA1HbvGs5acGhNCbc2NMYQ
         y0+0vVyYDQr6E8TYLinvldM8tjidZ0GR1oZuyk/Bq5KyAnOkrFn1BWJ0i87in8s7zEFm
         DGOg==
X-Gm-Message-State: AC+VfDwJsUuJjg9Z2zxt73i/fAu9c3hQu3zC34VA6pkuc3dc/259yNHK
	EwKcDcHk4RUoLBUMXJw++8Y=
X-Google-Smtp-Source: ACHHUZ4aATbN4m5DqjfhQgTxmKHhabaytYFKNqJ5R9NNoVfVIw1cREuIk0jWyGLglbzTE8KrIAx2Jw==
X-Received: by 2002:a67:c309:0:b0:430:165b:6737 with SMTP id r9-20020a67c309000000b00430165b6737mr7336938vsj.5.1682960191214;
        Mon, 01 May 2023 09:56:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:370e:b0:42e:5faa:fb58 with SMTP id
 s14-20020a056102370e00b0042e5faafb58ls2741412vst.11.-pod-prod-gmail; Mon, 01
 May 2023 09:56:30 -0700 (PDT)
X-Received: by 2002:a67:f116:0:b0:425:bbce:67e1 with SMTP id n22-20020a67f116000000b00425bbce67e1mr5938195vsk.3.1682960190565;
        Mon, 01 May 2023 09:56:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960190; cv=none;
        d=google.com; s=arc-20160816;
        b=sN68oo9LB7yD4tKFzugH+KklBwqZS3+eoVPghS/1tm6aSwVgB+ijAz1GHBW49y/s9u
         jU0ACgVCknx+N+lzzkL1Lqbp5Lr14kNf/r06eksF1NYK9bIf766+LnQUHG0KZ+gLO8PB
         vyDJ+NnLHN3fIJPyRJcvUmBeVhXJsoL4+NnbONs8sa8JbtcCO/tNCgjRalNwG1ihxSa5
         Eggx7lkk2Yw5emKdh8SSB+ciXkUqcVZPwN795gwRTMIYFF7EZwSPNoSTXFW7+lwWr3vV
         kW40R+u8B+fSOW5Z8hMUXk1uZTwDY9HNF1niL+YM/LZiBxM/vekOPx8SN1F8RSNKr2av
         6qhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5F2YZ+zSEbu/k1s4F5etygangPIkg0EznnOkCCfoew4=;
        b=yvlqgJR+kUHtqd9xc5lKK/LFVLHZfZy4alt1sOQGmIjs+6+cTb5Zk7B+6o2FumFupU
         S21FgoK4cvYAuOR+FLoGLHXyvqUA2xcvTKg+yP/xQLPyCcrv5KRmELflzLVSM/JwwZpA
         q0B9tARsdQgQOdPWEvkIshHapOIZf/zchEYjTnPfEsF8Kk0mvmxL3Waf2Jpdrbek/rKA
         KTtP76dDeafA3cXU8GZv9qgLaI7Tmjiy5lJ+4MWYGQEycmAhN9QJ/RFskb1iOhE6yAl4
         x6bav2K3bPA4ZmqMtgdn3+hQ+6UWg6X6YSM/vxP7ExKhECk/bOZ9/HhKADasCwO5CvWh
         Vdxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=y9PADbKN;
       spf=pass (google.com: domain of 3pu9pzaykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Pu9PZAYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id bc35-20020a0561220da300b004409ac628a3si23784vkb.5.2023.05.01.09.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pu9pzaykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-559deafac49so47807037b3.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:30 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:a8c4:0:b0:54d:3afc:d503 with SMTP id
 f187-20020a81a8c4000000b0054d3afcd503mr8631819ywh.8.1682960190091; Mon, 01
 May 2023 09:56:30 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:46 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-37-surenb@google.com>
Subject: [PATCH 36/40] lib: add memory allocations report in show_mem()
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
 header.i=@google.com header.s=20221208 header.b=y9PADbKN;       spf=pass
 (google.com: domain of 3pu9pzaykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Pu9PZAYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
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
 lib/alloc_tag.c           | 48 +++++++++++++++++++++++++++++++++++----
 lib/show_mem.c            | 15 ++++++++++++
 3 files changed, 60 insertions(+), 5 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 2a3d248aae10..190ab793f7e5 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -23,6 +23,8 @@ struct alloc_tag {
 
 #ifdef CONFIG_MEM_ALLOC_PROFILING
 
+void alloc_tags_show_mem_report(struct seq_buf *s);
+
 static inline struct alloc_tag *ctc_to_alloc_tag(struct codetag_with_ctx *ctc)
 {
 	return container_of(ctc, struct alloc_tag, ctc);
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 675c7a08e38b..e2ebab8999a9 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -13,6 +13,8 @@
 
 #define STACK_BUF_SIZE 1024
 
+static struct codetag_type *alloc_tag_cttype;
+
 DEFINE_STATIC_KEY_TRUE(mem_alloc_profiling_key);
 
 /*
@@ -133,6 +135,43 @@ static ssize_t allocations_file_read(struct file *file, char __user *ubuf,
 	return err ? : buf.ret;
 }
 
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
+	codetag_init_iter(&iter, alloc_tag_cttype);
+
+	codetag_lock_module_list(alloc_tag_cttype, true);
+	while ((ct = codetag_next_ct(&iter))) {
+		n.tag	= ct;
+		n.bytes = lazy_percpu_counter_read(&ct_to_alloc_tag(ct)->bytes_allocated);
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
 static const struct file_operations allocations_file_ops = {
 	.owner	= THIS_MODULE,
 	.open	= allocations_file_open,
@@ -409,7 +448,6 @@ EXPORT_SYMBOL(page_alloc_tagging_ops);
 
 static int __init alloc_tag_init(void)
 {
-	struct codetag_type *cttype;
 	const struct codetag_type_desc desc = {
 		.section	= "alloc_tags",
 		.tag_size	= sizeof(struct alloc_tag),
@@ -417,10 +455,10 @@ static int __init alloc_tag_init(void)
 		.free_ctx	= alloc_tag_ops_free_ctx,
 	};
 
-	cttype = codetag_register_type(&desc);
-	if (IS_ERR_OR_NULL(cttype))
-		return PTR_ERR(cttype);
+	alloc_tag_cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(alloc_tag_cttype))
+		return PTR_ERR(alloc_tag_cttype);
 
-	return dbgfs_init(cttype);
+	return dbgfs_init(alloc_tag_cttype);
 }
 module_init(alloc_tag_init);
diff --git a/lib/show_mem.c b/lib/show_mem.c
index 1485c87be935..5c82f29168e3 100644
--- a/lib/show_mem.c
+++ b/lib/show_mem.c
@@ -7,6 +7,7 @@
 
 #include <linux/mm.h>
 #include <linux/cma.h>
+#include <linux/seq_buf.h>
 
 void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
 {
@@ -34,4 +35,18 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
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
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-37-surenb%40google.com.
