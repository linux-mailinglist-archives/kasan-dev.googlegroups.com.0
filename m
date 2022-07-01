Return-Path: <kasan-dev+bncBCCMH5WKTMGRBK4H7SKQMGQEYLQGWXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 29745563533
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:44 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id be8-20020a05600c1e8800b003a069fe18ffsf3105718wmb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685484; cv=pass;
        d=google.com; s=arc-20160816;
        b=M4V/LdsU7L0ekI+oMfLpl4sTdNpAJkbcNBQx6Zy39jDiNk1RI8QnsaDbzkoIAKhkmA
         fze4IVLv6Zv5hXdx8HoCWVserQI7jGXqL9UtBTvbBxie9nNNZkm5CC/a9pnyJ5CfHi+k
         GKATnN77YUng5EqJVGneuwY6njFUgSIQZ7Epu1VB+rQJUoJ2aTafbYvsHFoc/26lthsS
         qdS+ZeOzRwPhXtYlna4P/EAaYIh8U/cPhozYPecLfpCyJIp8Ocad3pD9H4hd5v+dRhJo
         KceLZVxozExgGZ1sgahM0XA7yndkMWtHHNc4i9dZQD4/Jorqe1ddsYUDEfiVgQ9C+Su3
         KMUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=0v2xqDM/9sw40epbjO60WAOhRIiYrOamPb8XOP1aeYg=;
        b=eo10r9fKr2kKtlVLRQG8Zd1SbUll7aMnbIHIzYNuOKJgt9UZNTk/xOtJLnBa4CXt05
         gLFYVOJu1MSorNoGr9YxhX2l0tNX5bhsp4A81xiIsc10cTXv9BxX0A3uVVyvlE6AP0Go
         3dKl7xDrjiLlyHmrLweW6n5w8zVWHjRoWixE4R/0MTugFQUOZgeCbyAA8Bjr+/HYx/JX
         Bw46CL+VX8IVC9iuGJ0q46bkLsP3AVi32h8KVGqlDg1OyNQnh52JryNaV94Ksv0Yopsa
         1t+W+bm/7WFRzsOL5AGCaGRMx7V3mwoh+LPtkIi1gA0zvPGhuF0iVOUkUGR94n3nVoFV
         BPCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=A0D6vxcE;
       spf=pass (google.com: domain of 3qgo_ygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3qgO_YgYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0v2xqDM/9sw40epbjO60WAOhRIiYrOamPb8XOP1aeYg=;
        b=Qw24I7axMd6snj9H2/NDx74Y6vPGPfgVupKnffY2tkr9XqgpgMQ61ttm9J50m4+kdb
         FfG24d4K/qam2xUoMNrs+exz5PdJ65VdmODAhd/tav7F7+kNISeCyfL3y5BFyGMf14aa
         KX3ptfXJWl791Yhb++/UgJLYBkMyKrbnlYChR/9gQukK5saNYKC7kgj2kMO6h4/0Yhh9
         NyVgBzK80re8RKhpPHO0KZhq+yNLIMjsJEL4OtGfwhQZH7piVVAHwVuv5OXXRqT5+dBT
         fU2+6+Lqpvr/yXbJmLG6NqYnZBmCwf9D6QA0O2ZBaLQVmKzW7H/PTasi5JoguQcKKLZk
         Sbbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0v2xqDM/9sw40epbjO60WAOhRIiYrOamPb8XOP1aeYg=;
        b=cu/yAgS/RPkMllSYqavYLUlejuGGzwCXdYp/BoEiQa92aWGlmibCJI0LmD6IHcKeZr
         o9Yj0qa6xLUEowTRQ7SfbCkw929JYIV9bkgDeTh2h4zaMp1ZgfoXt8CrTf7zY4DOEcI4
         mXcA5qcPp+03eq2kOUlBsBH+FEbQIcB7ZinkuQJbAVfA248L99+RiwPJEuORWaXTBJl5
         G/czNglz6/6zFbTTZ/rvC7fPkPWwgJoBq0ml9IrTOaxiCekUmjLzz8XaBHX8j9Ub8354
         ua1luOWVS4SjXO4AaVMiUF/VR5hu+PhgHH8wkY75nUDDsjgJ2fn4Ppdg3VeSkTspcBGS
         FnZg==
X-Gm-Message-State: AJIora+N0mUgCYgMRhOROWqSkz9tliAdCc6AuHqFYqcoggFskaGtKJMZ
	BIRmq6rbubDHwzxxh1WDWfY=
X-Google-Smtp-Source: AGRyM1tjGlPfLbVMSOmJ48SwgROFCr7lu0pTgXhy+amMoRu49a0xR1pJZaJIH9RVMgW7eHZY7qydrg==
X-Received: by 2002:adf:e752:0:b0:21b:80ae:9d7a with SMTP id c18-20020adfe752000000b0021b80ae9d7amr13837820wrn.362.1656685483898;
        Fri, 01 Jul 2022 07:24:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c23:b0:3a0:48aa:51f2 with SMTP id
 j35-20020a05600c1c2300b003a048aa51f2ls3476731wms.0.gmail; Fri, 01 Jul 2022
 07:24:42 -0700 (PDT)
X-Received: by 2002:a05:600c:348d:b0:39c:652b:5153 with SMTP id a13-20020a05600c348d00b0039c652b5153mr18569658wmq.24.1656685482920;
        Fri, 01 Jul 2022 07:24:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685482; cv=none;
        d=google.com; s=arc-20160816;
        b=sUnaHjIvT7W9H3IOW24k4Tq6ZFcQohsiHemQl03yR/jIbvI7b1auU+dZNs7Mom1OVi
         vqzHQ6P2YknfC4wqzXAloiejC+Pfg4Q6XOxYa3QDIK84nkcUgLDFqI12OBPEogX02OsM
         4P4SmYAnsvxl4RQ4w2Pwqk0Au4Olfq9Q9F4PVUv7KwRo21gPAOrjJ45AAyNU5CybspDg
         wg0lzF+smMcYIukgyrrxD3v8dTEJ3eIr0toFl5DgVEn1TCiqcxu3WzrtZPRf5vGe9AzU
         Sz/exyFpFh7vw1TOWwvuAThqyMAZ+Ic5PMZ0L0Xd0Ns1BI4EzXnFDLmlUkJqyDbfAbsL
         uxrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=j/MMQ3wL35Ri2ZE1mUjRi1/flHRltTweDkn7/EP9qns=;
        b=kN0eiaaedkvWuKcKRpD4MQV9IWCk0MXzhLeWBpLOYHWbmIkTkRfyTOv+7109RRXqUB
         zhhWxar2Nx72UvOavF7CDNff6Ln9mvarz0j6h6+DTGcSEYNgbvGPd3Mlf0qjLKiBI1P3
         EFUio+2unHB5SJnzInCdrKrq6rB0grm7pvx09CdqwNEQgyNao3droCeCJgFOeM33mxgf
         j7xU0Xlu++xkXwuP94EkiMatVjT1PYyzSEAgp5QsyU/AXf7yaIhwlB/gdNBdElQSBV6s
         pwJkPMlYc225NZGa/zYNG7d5aWTYODkwz0zpAbGZS0CuzvSVlyKTy6UAdZE+uEPmc+gw
         t1jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=A0D6vxcE;
       spf=pass (google.com: domain of 3qgo_ygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3qgO_YgYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id a10-20020a05600c348a00b0039c6559434bsi247670wmq.1.2022.07.01.07.24.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qgo_ygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y5-20020a056402358500b0043592ac3961so1867423edc.6
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:42 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:906:9b86:b0:6fe:d37f:b29d with SMTP id
 dd6-20020a1709069b8600b006fed37fb29dmr14586176ejc.327.1656685482242; Fri, 01
 Jul 2022 07:24:42 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:56 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-32-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 31/45] security: kmsan: fix interoperability with auto-initialization
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=A0D6vxcE;       spf=pass
 (google.com: domain of 3qgo_ygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3qgO_YgYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Heap and stack initialization is great, but not when we are trying
uses of uninitialized memory. When the kernel is built with KMSAN,
having kernel memory initialization enabled may introduce false
negatives.

We disable CONFIG_INIT_STACK_ALL_PATTERN and CONFIG_INIT_STACK_ALL_ZERO
under CONFIG_KMSAN, making it impossible to auto-initialize stack
variables in KMSAN builds. We also disable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
and CONFIG_INIT_ON_FREE_DEFAULT_ON to prevent accidental use of heap
auto-initialization.

We however still let the users enable heap auto-initialization at
boot-time (by setting init_on_alloc=1 or init_on_free=1), in which case
a warning is printed.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I86608dd867018683a14ae1870f1928ad925f42e9
---
 mm/page_alloc.c            | 4 ++++
 security/Kconfig.hardening | 4 ++++
 2 files changed, 8 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e8d5a0b2a3264..3a0a5e204df7a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -854,6 +854,10 @@ void init_mem_debugging_and_hardening(void)
 	else
 		static_branch_disable(&init_on_free);
 
+	if (IS_ENABLED(CONFIG_KMSAN) &&
+	    (_init_on_alloc_enabled_early || _init_on_free_enabled_early))
+		pr_info("mem auto-init: please make sure init_on_alloc and init_on_free are disabled when running KMSAN\n");
+
 #ifdef CONFIG_DEBUG_PAGEALLOC
 	if (!debug_pagealloc_enabled())
 		return;
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index bd2aabb2c60f9..2739a6776454e 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -106,6 +106,7 @@ choice
 	config INIT_STACK_ALL_PATTERN
 		bool "pattern-init everything (strongest)"
 		depends on CC_HAS_AUTO_VAR_INIT_PATTERN
+		depends on !KMSAN
 		help
 		  Initializes everything on the stack (including padding)
 		  with a specific debug value. This is intended to eliminate
@@ -124,6 +125,7 @@ choice
 	config INIT_STACK_ALL_ZERO
 		bool "zero-init everything (strongest and safest)"
 		depends on CC_HAS_AUTO_VAR_INIT_ZERO
+		depends on !KMSAN
 		help
 		  Initializes everything on the stack (including padding)
 		  with a zero value. This is intended to eliminate all
@@ -218,6 +220,7 @@ config STACKLEAK_RUNTIME_DISABLE
 
 config INIT_ON_ALLOC_DEFAULT_ON
 	bool "Enable heap memory zeroing on allocation by default"
+	depends on !KMSAN
 	help
 	  This has the effect of setting "init_on_alloc=1" on the kernel
 	  command line. This can be disabled with "init_on_alloc=0".
@@ -230,6 +233,7 @@ config INIT_ON_ALLOC_DEFAULT_ON
 
 config INIT_ON_FREE_DEFAULT_ON
 	bool "Enable heap memory zeroing on free by default"
+	depends on !KMSAN
 	help
 	  This has the effect of setting "init_on_free=1" on the kernel
 	  command line. This can be disabled with "init_on_free=0".
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-32-glider%40google.com.
