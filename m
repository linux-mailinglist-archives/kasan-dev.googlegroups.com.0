Return-Path: <kasan-dev+bncBC7OD3FKWUERBJFAVKXAMGQEO2LNSSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 03F62851FC6
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:50 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6800714a149sf83102686d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773989; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0fKbQP68lvN6l52ohndVLIz/j3H5o0x5H6r+oSlLNnKX7niOlG069OAbRkGW7hfHj
         qbSvGuIwEuy8u2unE76zMW7ES/ivEzhqqWfTUi9XBXq+E2EgXxICKf41YbY3HOMQBsGv
         zJQAEqPU4FvHdbYilnqKm6NfTRcTWxDHznKa7Tdiac+Rg4yy+0LqkGqq7otI2snq0IfQ
         LDMp0TGpZKpaH2RxA6G6OTNa1IcoZ+Mzmrt/5EzbKnpjjLmFKqOP57zRXgrK9YCZQteE
         ZQRg9WOSrEoFaz/wTi80rILO60E0mqSb/pu+3Ruv4FT5UwzG4tDPd8LLGGPTiRGn4gjw
         bGbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=inieDJWjcd+LNvFxCKGG87enw71YWpMPdHRHSebLLMA=;
        fh=VX/0A9lcZET9ORQqPvmtFsOhdFgNvJS7SuvXCYBe+LU=;
        b=i2NIdYVVsk2YHLDQSF/FHFzSsFmMpBz+4dRkFLzQ+FR8s7stIaX10s6U2zRKiZievT
         wuXrSgUEHSJveDtltV/wqmmh4U3EnvJhAnoTzcU661wzab0ZLoB+v4wAcjIDLkqEKaIh
         BHe9iB/JPVEGMYkx6gBbmxB/mMSPKUbGcj/USGlhG+9nPqt3lE4hdDC2OBSZTtHlKOn/
         dsshMuQus2GYp47PpzN+H8Jj5+GnDoIbuEZ9uL3YxB+KEmQq0CfXaDoBBsCQ9d/SEDrv
         TTWiT3tdHWZzmSKerRAV39FrVlUezEw10ogmczuakyv2jvMPGbVaIZJb1+pfObh6HLgl
         jtpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vG0/nEYS";
       spf=pass (google.com: domain of 3i5dkzqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3I5DKZQYKCaIUWTGPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773989; x=1708378789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=inieDJWjcd+LNvFxCKGG87enw71YWpMPdHRHSebLLMA=;
        b=LUb7Q1Njw2QjsUmpQcENj4EKeqo3b9xn7wn8NnGsBqMYuDv9xnr05AcBPmdhIaru+/
         fHDXnF9Sj3n1R/WHp8WRcXW26j5+iPAHO36AGevDxplaGwjTNOBCeUdgNOE8sA9zuCOu
         YEelydClGv4aIzvH38GRJmASa7JcdFDsQocAEdHSvLTEqkQHb1HPTK1KU9/Tm7qltqQl
         X/7Ljf6/3m1zzCE+/RXH+arFp1QmEQ58+Q8YarCEQTi+s6ZV6UEd35ZgimCoqhomGTQ1
         DVQaoGlrZbQnFbPNHlzCnBH7t+FPFMoRCLcA6p9sDcki8EMOP24+xIcFYORUiOTJxuQ9
         7Olw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773989; x=1708378789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=inieDJWjcd+LNvFxCKGG87enw71YWpMPdHRHSebLLMA=;
        b=EIW1LAfIqpKI6WlRsG38ub71O+bUhTPu1SXnH6xrdZCuhIeD06SDU3te1I389sFxIs
         3U6LNciqE6RZcPSk5527fIDVPyXCwciIgkXjBry02nKABMos0sQpF/FYt9pnIq2ofdIU
         2sB9tX2XOYcP2xxHZ5EvWbw5sxAmrgWhrpdQa36jCeXHt/EVOQrPfFza27IEW+VH87dN
         +BCfB3zVx/799YIFziEizvEmqtlqBzuV6hvEj8XEeyyU4F11jAd9xZgLkusqL+PHgo5V
         AOV7mWugQ3bo9h/VwWwUQdgPLGjAR1OrzNHF9wPYo3u7qKN8eKRR1Yku2HuGcTgWSRNB
         HcLg==
X-Forwarded-Encrypted: i=2; AJvYcCXgL7T9I7as7ADjHldCDfYgLiMoKlP1mD6oHhW7HKdlVqis3GtOqxXmg6gSpvnx/wzJgIlDoUiVyJn8rLcnRXGnZNB7fG1kKg==
X-Gm-Message-State: AOJu0YyjFYzayIjHcf2YAJU5IbShXwXkVPmXOIkRUsRe+Y9QgXwrdpgs
	POtMCeQiI+c7JHU7XUJle7SDbgptPpW0zlzXJUDTo/Yvpv54mq2l
X-Google-Smtp-Source: AGHT+IGBzNYXaw2WFI6Y4aFsO8gBq0BjWVrIoOg7PXYzAJaoAaNud0ZEXbew3Y5d/z9pUTy2Uxumag==
X-Received: by 2002:ad4:5c42:0:b0:68c:75e8:b8cb with SMTP id a2-20020ad45c42000000b0068c75e8b8cbmr15588392qva.29.1707773988876;
        Mon, 12 Feb 2024 13:39:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2a48:b0:68c:cca7:f6d5 with SMTP id
 jf8-20020a0562142a4800b0068ccca7f6d5ls2296622qvb.0.-pod-prod-09-us; Mon, 12
 Feb 2024 13:39:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVegYhfceoUC37a9PW1K+ccVIwgUC0vnF3LXu9bIwXY0aI+Vgpv23MxmMIz1KelfTzHmUp0C2isM3WrJOmaZmLCZCmUJHIN7gAaEw==
X-Received: by 2002:a1f:de82:0:b0:4c0:2ba1:830a with SMTP id v124-20020a1fde82000000b004c02ba1830amr4928633vkg.3.1707773988234;
        Mon, 12 Feb 2024 13:39:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773988; cv=none;
        d=google.com; s=arc-20160816;
        b=bfSfh9NnbgTzfE4YzDK4Tsoe0Zstba2+GsYy0lE1xy2XPYR2u4eMC+ro4T1cgJUDDX
         zSJYGqKA4ITKuSqco9zIZugNrq6SndemxCFJRxY4l0tjGixmhx82YMGz/M/Q2kSBJNMG
         /3t61NoUhM2e+ZAXSrNPdpK2XBT3ef1ZLEr/VaGCJ3K3WC5HloVvo2YA+4qKPxjH1/ia
         7jJo9vQlPSSX75cBZrnH8chygR6rLJa4j6a0TUdlJapy836hAk9fr+jlp9dtQXWrQLj9
         M0ROgoS8n7MD8Tj1LCmITHUARnnPFS4slHHpzileQXhAuqL6jpUh+53VmiwfwC+j4LYO
         u8yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QPRNF15NS/yHs+nflQ9JCJcKpeGLPrq2C4Bm4JvXiOY=;
        fh=HdUdUqIcb94/3/MRVwrKK31GXsPhk00cqIsKQsk+oFo=;
        b=gMmu+o/uaUrsIbUkTHgLcQY3XtzVf+pDuvplcuvcaHGqCA4zGktr57ANgq7GA9IuLi
         xtErY+SwacWTFVFAE9feuRnV826SYKOZYIiyGqyhxDfXb6/OAjZ28BCvDqya0Aw8aJw+
         4wGkrAXWn/sStMo27PUNw9xMqyVA31wjZSQfLnazaG4awW9xPt+q7c8364l0WnmgythN
         CgIAUaUMNCd+Azt8KfO4stHdUVc+hUj1rKi7fX8aFIVljpvXVmap2XqvIX+jGgndjD7O
         WJ1igLvu7ZRnB0Hh/RlihDbFJUAY2RliyYtW22DQ/aszLUV560QoU0FGp68+T4lZyUSb
         HOkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vG0/nEYS";
       spf=pass (google.com: domain of 3i5dkzqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3I5DKZQYKCaIUWTGPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUH91rXXu0CTJewnFMiz8osUS5VXILJ6x8udA89KzVWKN3v2JafqsEVu2KE5+xNoZO3+9Pl0arH8Ba1oYS31TegJiXWDPDrgStPNA==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id z24-20020a056122149800b004c0373aa700si755691vkp.3.2024.02.12.13.39.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3i5dkzqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-604a351d3acso65840687b3.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCURT8o8uDaPcGAmmyg2Tt5lew6ASknf1zRFqayiDdHKvJwxoA1G/fJaEJM3PxZcm3Q/mBBF2MMyFHl2hyLuTmrd0ogWm3lLwlFYvA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a25:53c3:0:b0:dcb:c4d3:6e07 with SMTP id
 h186-20020a2553c3000000b00dcbc4d36e07mr382686ybb.5.1707773987608; Mon, 12 Feb
 2024 13:39:47 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:53 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-8-surenb@google.com>
Subject: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
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
 header.i=@google.com header.s=20230601 header.b="vG0/nEYS";       spf=pass
 (google.com: domain of 3i5dkzqykcaiuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3I5DKZQYKCaIUWTGPDIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--surenb.bounces.google.com;
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

Slab extension objects can't be allocated before slab infrastructure is
initialized. Some caches, like kmem_cache and kmem_cache_node, are created
before slab infrastructure is initialized. Objects from these caches can't
have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
caches and avoid creating extensions for objects allocated from these
slabs.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/slab.h | 7 +++++++
 mm/slub.c            | 5 +++--
 2 files changed, 10 insertions(+), 2 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index b5f5ee8308d0..3ac2fc830f0f 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -164,6 +164,13 @@
 #endif
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
+#ifdef CONFIG_SLAB_OBJ_EXT
+/* Slab created using create_boot_cache */
+#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000U)
+#else
+#define SLAB_NO_OBJ_EXT         0
+#endif
+
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
  *
diff --git a/mm/slub.c b/mm/slub.c
index 1eb1050814aa..9fd96238ed39 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5650,7 +5650,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
 
@@ -5660,7 +5661,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-8-surenb%40google.com.
