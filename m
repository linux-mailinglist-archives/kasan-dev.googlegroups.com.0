Return-Path: <kasan-dev+bncBAABBV4VTSVQMGQEKUEBUAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F1137FD359
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:41 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-6c4cf33cf73sf823275b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251799; cv=pass;
        d=google.com; s=arc-20160816;
        b=iffjrNDVy4NlliIiBDNybFSgQ/feUW3kAknqc69L29ZuXm0HleW3FuLQL6SOo1QUiA
         jAiqUFWoQ3sJdkup/Wq5fzIveVj9lmTdz0anvhUBkBzZmFOkIvx3VWroE/FKelk2EHTa
         /6/JxW3zLerVXY6mfnkg1OdesbaSBzJY9mj7KO6ngKlui01C9J/AyIAIaHF2ne8eQW4A
         fu5lSzmpXBSuJU8JiAIsNXeyj0zqJOGRrl6W1PAhydzDS1x5DDz/7VmZuuqAZJ93FEP+
         /V7Z442ZMbTLtMkLs1sL0i9Ms8rTf95i7GkqZA9EsHTNe0nbxUQh+5oPM7/pGpnA/Tu6
         9KdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=qL2z94V+E8af6/aUC/IMX3Qx3aqd9v3lSM0M5JSIKt0=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=JFda+Uqql/nMkcEDLxlByXk94Te8+YQPMlCIb6x77ewDxpcZw9VS7CJfrOQJ35uIM8
         n8zu0TIL9KHbrU/+OJUwF/0gk+nJceqQtpWWzziIyzp+xE/cknX+VIs/CwnzrXM/KJGq
         HbR1NSf1XSQQM6Dwm7rYyPFG4I32OEAdyDvHTxCOqbZQZ36EQZUZn1KuzQQQpY3R28bd
         iyVsiPWsMTJrjqGWoYUHMv9X+/0OHy2Vekjs8OnIjzjayc96a064RNwBchqG8losjxZx
         aRgqnEJGJjqQim4z3nDgWsxoelGTGOIliHGRnEvDJR+oUYC6aiqlw/nLzlztZ4SeXx0B
         AuCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251799; x=1701856599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qL2z94V+E8af6/aUC/IMX3Qx3aqd9v3lSM0M5JSIKt0=;
        b=E2qr07pit54rSYmSV7wWkAXArrJ5XUD+BXEr4zEAIHqn5dkL44rxQh1ZAWInIdUfHm
         Lx/Gncv0s5gt9YrEP1alk9phlRm3SQUBUi6hLOglOjJ6o6zSmZkrwfc5SZBTwvRPsPyB
         1sDYrarNNtblnMrnI42uv1F5Q5Ilu3lC36lwrEuQUog+AT1LdtQ0uPFG3vYNtJ64JqJ+
         7x1ElO0QaZyAmnstpZIlDv3TPdG/UwCply254qPJwQ1oEaJ0tILdlo6KDtzZffhF360w
         qDpphcZca7zYsYv3KZQEO+378l+0/CReoIvQrBQbyg9qyAhWt7bABI+c9VcQR2KS95Q8
         1lgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251799; x=1701856599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qL2z94V+E8af6/aUC/IMX3Qx3aqd9v3lSM0M5JSIKt0=;
        b=T+gz7t31s62M7GPQDheWHYE0rYJtkrrhsmhj/lnZX4GNeCTZjvUTYRYynnwQHJGRsY
         rnQRMRfjiPiPqdRaB3/GYeJyvJTKkxbx6IVsCx/3ujvWvZJp1ZqeJ/Bp0KCynlQM6e1i
         Gv09RJwq+jpPh/i7CvvPWzTAZ7O6tvRd5XNegFij2vzK/wLYUU7i44Q/itbsVZKiOOPs
         1XTNU+DLcXTfQ5B3pV/Y/obDWAS45mHRqJmpWlAu42SvwQDyNoKL0jWNf6/FSA/TE0Lm
         JQm/VVlvnYTxLaHKRPzwaeooif2lzL+hBngpv6SGn3Gu7ZF0muAV0LtwZRQ/NZpyax8c
         Y7BA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx0RKR2BdS1pmh+twsP5xgM0SPP8AZ/GWTUi+97O5IhUlNJEcFE
	+J4mmaN6lekLEd2t0kisO+4=
X-Google-Smtp-Source: AGHT+IGn0dhIBfXLuONHj/IvT8vqNOxvlkg66QylnWuif2qkTQ+fLrVIBqxgpaaQ7lBXLyNYP174/w==
X-Received: by 2002:a05:6a20:7da0:b0:159:c07d:66f0 with SMTP id v32-20020a056a207da000b00159c07d66f0mr25415039pzj.6.1701251799187;
        Wed, 29 Nov 2023 01:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8c11:b0:690:ffcd:3bfd with SMTP id
 ih17-20020a056a008c1100b00690ffcd3bfdls4730226pfb.2.-pod-prod-00-us; Wed, 29
 Nov 2023 01:56:38 -0800 (PST)
X-Received: by 2002:a05:6a00:2d8a:b0:690:bc3f:4fe2 with SMTP id fb10-20020a056a002d8a00b00690bc3f4fe2mr5128560pfb.1.1701251798602;
        Wed, 29 Nov 2023 01:56:38 -0800 (PST)
Received: by 2002:a05:620a:191d:b0:77b:cc25:607f with SMTP id af79cd13be357-77d63f5307cms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a05:600c:3b86:b0:408:37d4:b5ba with SMTP id n6-20020a05600c3b8600b0040837d4b5bamr15104518wms.12.1701251618439;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=nyJuXyUO9lONGCWrZ1cz1FgbU2VjfeTmL5yzArzMN6xgfEPhb+slJBNUwagtmY8FE8
         Z0w+ubB3Lrj+p4hX6jPpOGG+JtVdzVQPlv9XU+TK6fEcgsOzyH8oxNtJbFvLUtUamngU
         llHAAD7PlxZgGKYbUgUoT5YbE56v6871OXPNwBpCAYFa5GhFj/iol8KOmBAFl4io5TyO
         S3qsNm7JylfiZxsmHxJ2H/9h4Z6LN2k0gV0q1ZOHfZd1hnIphJ8B50IHSWqvIjsQ7VLN
         7oLfzVXpvgkiWEHmyGVc17OXY+rz+A+FUrzfrQuzeJ7pDKU//DLoBJGMY+2l4Eh+R0Jx
         2o0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=PX3MvAB9bT05yeaZSR4WJfiyLfcVNVB/Ayxh6IAIMM0=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=uMsV2aUO8P9EFzbjoto6PSBGMCykyb+QAe0sVtraETyLC7/arLD2G+qtFVOtJWbGCp
         Z5Y8j6kCRO4giQ5xJgiXZ/a4hD2VrvAApEG1erCSutCjRy+LV03heYK2kc0rUkYlme3q
         ScURvdQmO+T04MYfVynYeT5Rnbwd3bkKUn2AGOAqdwtxL/jVJrNhfOEe7ZojlN7nNIMk
         YA9Z1P9y23pPIhIbQl2fKzsRxQWA+/8dxtS5Jol1bvxL/7R/t3yoP4KQBb1maYb65Drz
         plr7wnJkwsGQd+5fITTed0hlQCn76Bi56Cf3CWBKSC+j6h6wm49yilKhoIaVOGxS57Yf
         k4Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id p35-20020a05600c1da300b0040b4055397csi82158wms.1.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E628721995;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 59C0B13A9D;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yN2eFSEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:31 +0100
Subject: [PATCH RFC v3 6/9] tools: Add SLUB percpu array functions for
 testing
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-6-6bcf536772bc@suse.cz>
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Matthew Wilcox <willy@infradead.org>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: E628721995
X-Spam-Score: -4.00
X-Spam-Flag: NO
X-Spamd-Result: default: False [-4.00 / 50.00];
	 TAGGED_RCPT(0.00)[];
	 REPLY(-4.00)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: "Liam R. Howlett" <Liam.Howlett@oracle.com>

Support new percpu array functions to the test code so they can be used
in the maple tree testing.

Signed-off-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 tools/include/linux/slab.h              |  4 ++++
 tools/testing/radix-tree/linux.c        | 14 ++++++++++++++
 tools/testing/radix-tree/linux/kernel.h |  1 +
 3 files changed, 19 insertions(+)

diff --git a/tools/include/linux/slab.h b/tools/include/linux/slab.h
index 311759ea25e9..1043f9c5ef4e 100644
--- a/tools/include/linux/slab.h
+++ b/tools/include/linux/slab.h
@@ -7,6 +7,7 @@
 
 #define SLAB_PANIC 2
 #define SLAB_RECLAIM_ACCOUNT    0x00020000UL            /* Objects are reclaimable */
+#define SLAB_NO_MERGE		0x01000000UL		/* Prevent merging with compatible kmem caches */
 
 #define kzalloc_node(size, flags, node) kmalloc(size, flags)
 
@@ -45,4 +46,7 @@ void kmem_cache_free_bulk(struct kmem_cache *cachep, size_t size, void **list);
 int kmem_cache_alloc_bulk(struct kmem_cache *cachep, gfp_t gfp, size_t size,
 			  void **list);
 
+int kmem_cache_setup_percpu_array(struct kmem_cache *s, unsigned int count);
+int kmem_cache_prefill_percpu_array(struct kmem_cache *s, unsigned int count,
+		gfp_t gfp);
 #endif		/* _TOOLS_SLAB_H */
diff --git a/tools/testing/radix-tree/linux.c b/tools/testing/radix-tree/linux.c
index 61fe2601cb3a..3c9372afe9bc 100644
--- a/tools/testing/radix-tree/linux.c
+++ b/tools/testing/radix-tree/linux.c
@@ -187,6 +187,20 @@ int kmem_cache_alloc_bulk(struct kmem_cache *cachep, gfp_t gfp, size_t size,
 	return size;
 }
 
+int kmem_cache_setup_percpu_array(struct kmem_cache *s, unsigned int count)
+{
+	return 0;
+}
+
+int kmem_cache_prefill_percpu_array(struct kmem_cache *s, unsigned int count,
+		gfp_t gfp)
+{
+	if (count > s->non_kernel)
+		return s->non_kernel;
+
+	return count;
+}
+
 struct kmem_cache *
 kmem_cache_create(const char *name, unsigned int size, unsigned int align,
 		unsigned int flags, void (*ctor)(void *))
diff --git a/tools/testing/radix-tree/linux/kernel.h b/tools/testing/radix-tree/linux/kernel.h
index c5c9d05f29da..fc75018974de 100644
--- a/tools/testing/radix-tree/linux/kernel.h
+++ b/tools/testing/radix-tree/linux/kernel.h
@@ -15,6 +15,7 @@
 
 #define printk printf
 #define pr_err printk
+#define pr_warn printk
 #define pr_info printk
 #define pr_debug printk
 #define pr_cont printk

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-6-6bcf536772bc%40suse.cz.
