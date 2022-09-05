Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4GV26MAMGQE7RJXXTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C0055AD26C
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:25 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id r23-20020adfb1d7000000b002286358a916sf420697wra.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380785; cv=pass;
        d=google.com; s=arc-20160816;
        b=iSLf4NKkEIjXgG3zDQIzWig8qVOlPn5EPbJYQvqltakEvM+2y2L2/LRL3vCL8hh6iW
         k2rrOHW4huXMrcwO72zMslKNhPINP3hv7TJa8CUDx5H2qQg/Y9POuoFP0nMmLxHZXQ2q
         56+AsQKdJ47uK32FOKDuYaQv4a+Vn9D0Ny2a8jEJelhr64+ZLcai+WUFulk2bNHVMtqS
         Pzs0dC2kUWTrImOO4kRi7v5YU9vLOLMPD6Kxw61NOJlznAkfa4Nd2DRwGUXReYVkdf0o
         qxmb3pVsH5a9nOJxOtY07ZHXK/ELUNtVg2WpaeFjPA7mGQynt2kdWk+WQXev0XneQ/IO
         x5mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jB+UsrVRI0Za8jW78s2+cQeyaWQhp2DEJJfy7LAcP4c=;
        b=uJEfY/52L1GSYX31GMuRDzIevIRNMYXlEv6dhIrA0+hvuIlPx9by7+6R5Uodv0uk8j
         1K05honqeVMMns506nxsPRvmAwOd90bu7ubxmt1+jAVBfYlgOMFFE6c62jA18nobqcAX
         /EJRVOXPAQ58ztRs9DlQ094CabAt6yG6k929Fyx7vsz1EZdBJVoNqkZv8fEwgUG4stNc
         eHjxaVs4YyCDvHw7JO6Cv2dkaQuBAdwsg61Ver7928hzmuwjbNBkHR8xoMmRBIatDS7c
         3o03Ou9pPLo2AItj+ae48G3BZFEGlUDJ+Er+VWflUWKN02eofi2xZ1fcRLY8AY2/Rryc
         pygw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Mky7siHZ;
       spf=pass (google.com: domain of 37uovywykctsdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=37uoVYwYKCTsdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=jB+UsrVRI0Za8jW78s2+cQeyaWQhp2DEJJfy7LAcP4c=;
        b=ewLerH3U0MSsRCcPwCRHiLgLpx+Ka5n+r9kadmit5tUXXe7F04OzydGFWoP8jODT2I
         WyaTdF5ZopHaiQOL3srIyrqn65OoJgD6ijBUdbp5SyVZ4o3s3ODd2OYNSakLqGy+IbSH
         IfRvwWgFZAJLB8vibTDfHiCrDLJgGXIoYwSCdv7AQDGCHQ2cj6fKqbnjGnlCjgPfk/3E
         6YU5sdfzodW/B1wrpOwdX0cn+oO9RHJnHQNfYTFrM0jxl16hXdF3USg7Y4TOJSLRzLBu
         Cp+i8Pa6gQhb2igPWbuIeSjjSMTjxx5D0tyyOF0+JWsSnBP4J7rRdV3BdT2XFMkmHyKs
         kECA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=jB+UsrVRI0Za8jW78s2+cQeyaWQhp2DEJJfy7LAcP4c=;
        b=lT99Psbko1ZUKjt23i6Uit864MDDgtJvhgmkuBhZCTlaxb8+x+3mEXdno1AKgQjVPB
         ziT4ueZssvSc0Zl/8GbkcNgg9Pb8ko1ZOzIjHGW8G/gh/FZEBnPuwHyJs7ZQHQbEarrJ
         uv+MPxZkelxYYNg3ajr/m24120ja1S/2fGdkCkcutvtVxbrpV4hNJNx0ZwBxF+EcfUmm
         zVwDJQzl4D7RYAuvwV7G8YbugRhfJIl5aT3ArDPtQMXQoYlrJHF5Ks0KfIOBuKWsRDLh
         qHYHU67w/PL88dw547K2kQe0gXRWBS0RAHLWTgjP29uISpLIgTq73MeNaAa9N2lkznBy
         vduQ==
X-Gm-Message-State: ACgBeo3L5bV3458Qm+FwLva97eHU48R79saBfKcg75Zlm+ZH1Yy6Acuy
	Fo7ZA65pYzPLYpiZmZaio2Q=
X-Google-Smtp-Source: AA6agR7nsIoSp9s7GrdMkrUC5PSJ8hPvJYeHSnmfvVJfUDb3t7bFiB6QGER4cqnu1NCwfgClLJIDFw==
X-Received: by 2002:a1c:a107:0:b0:3a6:8b06:cf19 with SMTP id k7-20020a1ca107000000b003a68b06cf19mr10466008wme.195.1662380784878;
        Mon, 05 Sep 2022 05:26:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c5:0:b0:3a5:24fe:28ff with SMTP id g5-20020a7bc4c5000000b003a524fe28ffls3828138wmk.0.-pod-control-gmail;
 Mon, 05 Sep 2022 05:26:23 -0700 (PDT)
X-Received: by 2002:a7b:c38e:0:b0:3a5:c383:c68 with SMTP id s14-20020a7bc38e000000b003a5c3830c68mr10456819wmj.163.1662380783284;
        Mon, 05 Sep 2022 05:26:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380783; cv=none;
        d=google.com; s=arc-20160816;
        b=UekQUkiJkHunGAeYyaa9kxStg7Sj2IpWclllZ3wqzK0+DbcrVJWhdQ0QJYjSUsC1Sq
         fzAHP6vlQ7kmBmoOIn6CxsXYhGKm3qU0uXOW2yjjLFbuuN+l2aWzMFhQp4xo+6nReK6y
         PcYxsW1xRmaLb4An4MP/WHwJsdTt+i/sFmWKWlRK0UbIOIdggIIV6xHJl0u52fd/Z08y
         IN/bXt9BcWPj7Rg/bsgSwWd0Wq6AFAIs8XFQ4brvB/nJWMfc8mLNCdDOMfAEAF3mxCt1
         QiGfmUTCrN/fgBvCxH8DPGg2nzjZzDMX5lZT+mGFbBp/ZO5aWICzxtOvs/SUJgVfenHb
         /Reg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gorYk6QZYQqsbqX3c5FquLgSIgOkVhkBb0FBAlBlnNE=;
        b=0lrbRVdymo1C/LnPh7AUdVdXQiOnofkF9bhm6/Y+Tw1nwK4DxbrbUcYAji6J8kNxml
         hsStoLu8+bZ7BFa7W8aEPb8FiVqR+mpa9Fou6+4CPHjWJrBuJcuS4X3f+2Rv4Bt959Aj
         BT+Q6Je27AkeoWx1uApVrS6hzupSqTWTY2U5hlexFWG5ALt+eEM2mc5fjgwa80KrLVyL
         S1vpb/KCoyg+S1vCR0LWksfrsLYrMSK9/noLA0b233RuuExBFoHBeQlEtj3UEJacgoRZ
         hRHDQKmCYbv2ur23sEHKDan7GkjyWUz2jm5hDcqtU5Mya6Of2LG6xu+vix3/YutW2Rbo
         MOqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Mky7siHZ;
       spf=pass (google.com: domain of 37uovywykctsdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=37uoVYwYKCTsdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bp1-20020a5d5a81000000b0021f15aa1a8esi301320wrb.8.2022.09.05.05.26.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37uovywykctsdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gs35-20020a1709072d2300b00730e14fd76eso2277073ejc.15
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:23 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:17d7:b0:44e:95b0:3741 with SMTP id
 s23-20020a05640217d700b0044e95b03741mr2597122edy.281.1662380782901; Mon, 05
 Sep 2022 05:26:22 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:39 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-32-glider@google.com>
Subject: [PATCH v6 31/44] security: kmsan: fix interoperability with auto-initialization
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
 header.i=@google.com header.s=20210112 header.b=Mky7siHZ;       spf=pass
 (google.com: domain of 37uovywykctsdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=37uoVYwYKCTsdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
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
index b28093e3bb42a..e5eed276ee41d 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -936,6 +936,10 @@ void init_mem_debugging_and_hardening(void)
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-32-glider%40google.com.
