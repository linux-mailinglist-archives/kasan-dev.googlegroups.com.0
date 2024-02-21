Return-Path: <kasan-dev+bncBC7OD3FKWUERBXVD3GXAMGQEMWHYGMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 22E3785E776
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:20 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-218e3197761sf9974875fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544478; cv=pass;
        d=google.com; s=arc-20160816;
        b=zPwtPaifnwWbK6nxf9fsdOHyhlVgHEghVVhQldwX3GoXlwNu+d7gfWwzi+Jgers79M
         ZGGgZ+07cBAIDoqIYm9rh47EYiOz6Dm+74iW4Tf9tGEJDpy/WzkpEu9Kqc6jvtxpBfKz
         oFwMmUbGip/QJMiSzxxGOw/XQWCNM4WBDNWE4sSA/zpxRWqm+gx+ha0rS3OP1H8Z0Wl4
         +fNE9UVGFIDARzge4xVqIQC7hiO2WJSK3merINqC8rsCssl2xITbSNLZmT/38kDKbjFZ
         beWrXZHIbkKM/nPSwL7HEOoPnVWSDL0q/Ss5S3Fzbh9BCyCPlLrqxT3X3g9aGniJzDLi
         vuOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7MbVEEpLwylXioUgsl5PdTFozZgBeDhW68uD4NsUCVE=;
        fh=QDhVhzYDbWhwrZmNRPFeHTpmoywBiVgFUe64+l98X1s=;
        b=YYQc9MuDRZBanjxldydNBGPjqAXPCLGH8UI16JwriALph943BrPtcftdEZU4eR4pFm
         dvhvmOaqLXLTrgEUDSQs4IV9E57RirI3QU2eZVXuHs7XjmOw2xkPmg3s8lvofbOTBp/v
         9mXfMxXCeABoqjJ+eFLQiBTgVChjMIA5F2bMFUjHcVCZtwGcnvBdgPXU1sniuH2J9j59
         P2yi5ueFep6HxIq7UV7r+QHpEZzV+PHTsS+HrsPRAW50JZTgZMJuGzJ4qyTEPzilkd1i
         e2/otVdqd05U/LtMb06QmadK+I0ifa0h+VXLMENN/+e4WtflXAiX6NsrBCZMGZkCmg6J
         +ggQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DyRjSknk;
       spf=pass (google.com: domain of 33fhwzqykcq8796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33FHWZQYKCQ8796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544478; x=1709149278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7MbVEEpLwylXioUgsl5PdTFozZgBeDhW68uD4NsUCVE=;
        b=Jzs+bppcOHgTENmOCEZacZ9oMZltjvqXmRu64T+gN7vTL4nCZbvk63iddN1W7FxjQm
         lSu7sWNopMRwYNXi8OgwXukrTE5VDopoFjvCjRPwXiKMOWhXVaY15Ti2/3xy3d98YWAJ
         WAbloNxh7dNygFa1fen7roGutaCdB2uZU2Lu38K2cu4JcKqvNHnCpCHia/MuMhd2jfBB
         DnF6/6baLK+tPgdRyZoOb8788ss81W0ef9SaymY+ZQahMOlyQbTKfefv8Nw+WPnJoQ7m
         TQSplmJUMKztxg3BYWsUIDDsFbMl4RCHI1GHboVz8SNc1lihZcZF9LbH1ypiVzCeYNTN
         P69A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544478; x=1709149278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7MbVEEpLwylXioUgsl5PdTFozZgBeDhW68uD4NsUCVE=;
        b=vuy2oqRLlSpLoU010tPSqjjiHkfxoDblahggBG9GvM9cIZwLjcjvDr+sc4TNHlOUJD
         gs07SdYuda8mi07AsQiydyy3qJuzpp96J1ciJSyQDYi0JSQrQVf8D0/9ZtFxzzbSKftr
         X64+PvQHpL2vRIsAi9frpwYJC06b8nryiUAH4Eyd1ipKBmVngWFZYUCl+lwk6rO8S4pz
         KywKPkCNW0AYmwzpIKtf94xPqbsbEREIx2NlsIG0SqHdCPxROgrks6EMolwuFq8ULtET
         zZRp72JadEjMl+XYwUyn4NsZqmzQdXwz99DpmAt1oO/zZqBYxVw1o/W5j/luCXLpLE/t
         O+GQ==
X-Forwarded-Encrypted: i=2; AJvYcCUIgx4Y8Lrlktpxo50AMV1Bh5+dhPfoKG3FduGEHImAOt9qkllLpRHOH4pWreeM3bAKhBBvs6DInsexIRu0TtSpj6NOB2o8Sg==
X-Gm-Message-State: AOJu0Yx5lMTq4CEXnDJVQjInJBc0oN1yM+B0aR8FxmouiJaVmscUGHkY
	NgWx+HMto24KW5a+JmaOuTxwbvL6QwPUrXeTxYSN45LbLv/TBB9n
X-Google-Smtp-Source: AGHT+IFcE/NyIi72QJpwrUrqfhl+gXxNFWHAmsf7+t20KvkDOmvMDXGl0368jqBmbE8r4MlTwlQyJw==
X-Received: by 2002:a05:6870:2c97:b0:21e:854d:e846 with SMTP id oh23-20020a0568702c9700b0021e854de846mr13683745oab.30.1708544478126;
        Wed, 21 Feb 2024 11:41:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:fba3:b0:21e:3c20:945b with SMTP id
 kv35-20020a056870fba300b0021e3c20945bls1925659oab.2.-pod-prod-02-us; Wed, 21
 Feb 2024 11:41:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWjC66OSmzjM2Q76EXgQ3ei9Qubs1YQ3ncoEYBsglcuFQTU0pjhgULlKB6J3tVHPe7T2jCPQYlsoUpIZhrPtSX3UDstCBCdt2xVeg==
X-Received: by 2002:a05:6358:d393:b0:17b:6171:ada8 with SMTP id mp19-20020a056358d39300b0017b6171ada8mr2603568rwb.15.1708544477344;
        Wed, 21 Feb 2024 11:41:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544477; cv=none;
        d=google.com; s=arc-20160816;
        b=PQ3pPXUFZG+bJnlzKpWYtXsimmtDr6d64wwPnsHPT+mF2IT4L2BAgghOuPAByd3UUr
         IChhxVzOELp7nNjqkCpLO9hDAAgITAOLzL4Aa5kt3hYR4uVU1AGY4EF2HKN6KYbfVb9T
         gWgWNzrxWzzIUeGybZ/zoWDuehgLz0k4iigOV1SMNc5US2qCZrxR/9LhYQzC4zWQT2sl
         Zephii57AaJYJp42fWVO83MTamVFdJa8ZgFB3FE+38Jnf2loufcJolUxX0kkQ6vS1bPG
         fc137NiUJ50k0Vm1bdemJbaF877O8ZNCNKSnk1fvAP63MXsxaHVTxoAueZR1eYKIBdyk
         wnKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=zEkUZGmdT8FEHHQk8lZ544d0po9Jm+ENmRP2MkpUgMM=;
        fh=uLdWgk8jtRKsJib9OM4BBJb3rxcT6Qjl9xm7mY+WxTk=;
        b=PslZmfihSlqpyx6qUlzTjNjt9dX9UmMLrwVgHFIoGlaeXxY7QK0ytOsOXvV5vkoIBP
         EQ38qMwCrIt6+wl78IhtVI12vOFzk7F25xCVCPPJERcxLkFHBgNUybFqeZlLi7hyyJsd
         Ja89JSxZyGxFKeA3u+0vQqSnwqddsksTtvKZaxmjpPCjGo91Fbw2Gs1ln0ewNlIX2vlZ
         WaPJUmzaHNzOWwEFJrav+t6GM2wQMTeSyfb+ezyvJnr1lXB37WUs5trswYT8EWOb4nNA
         +rNOT7e3MnLa4h8/FwVBhZa+xuxrkC4p6+NgjlUhVJkiQmnp3PfFm0FoJI+oSCDVl+hE
         w/Tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DyRjSknk;
       spf=pass (google.com: domain of 33fhwzqykcq8796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33FHWZQYKCQ8796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 9-20020a630009000000b005dc1683daa5si697230pga.4.2024.02.21.11.41.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 33fhwzqykcq8796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dbf618042daso11731890276.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWNsthC7nB40QJY2ZRfO7z7xt87Xgthp64b/nbIY7hVifB571wwgnft67EM1N0d/fPsDWQKGSZQN0Zj85Y/LlQ+rBZOEKzom4w0LA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:26cf:0:b0:dcc:41ad:fb3b with SMTP id
 m198-20020a2526cf000000b00dcc41adfb3bmr6923ybm.10.1708544476345; Wed, 21 Feb
 2024 11:41:16 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:22 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-10-surenb@google.com>
Subject: [PATCH v4 09/36] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
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
 header.i=@google.com header.s=20230601 header.b=DyRjSknk;       spf=pass
 (google.com: domain of 33fhwzqykcq8796t2qv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33FHWZQYKCQ8796t2qv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/slab.h | 6 ++++++
 mm/slub.c            | 5 +++--
 2 files changed, 9 insertions(+), 2 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index b5f5ee8308d0..58794043ab5b 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -28,6 +28,12 @@
  */
 /* DEBUG: Perform (expensive) checks on alloc/free */
 #define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
+/* Slab created using create_boot_cache */
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define SLAB_NO_OBJ_EXT		((slab_flags_t __force)0x00000200U)
+#else
+#define SLAB_NO_OBJ_EXT		0
+#endif
 /* DEBUG: Red zone objs in a cache */
 #define SLAB_RED_ZONE		((slab_flags_t __force)0x00000400U)
 /* DEBUG: Poison objects */
diff --git a/mm/slub.c b/mm/slub.c
index ca803b2949fc..5dc7beda6c0d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5697,7 +5697,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
 
@@ -5707,7 +5708,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-10-surenb%40google.com.
