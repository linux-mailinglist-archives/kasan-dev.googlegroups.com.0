Return-Path: <kasan-dev+bncBDQ27FVWWUFRBP5A5KAAMGQE455GP3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 324D230D95B
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:00:01 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id e11sf3315292pjj.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:00:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612353600; cv=pass;
        d=google.com; s=arc-20160816;
        b=kyNFqNTGwZ7gJd0PFuvftjv1nEH59C7al1nLdBOY9RMNtOwClDtvlOy9qV81NunQuA
         0VG47b4IBD7n14QGJPvNVkZNvCZO8tHJbzD+KICBmTBCU1liN3V0bLQoiL2HUpiQPnSz
         EZnHLJgg3JMM59WbjXldplu50WHvB1xp6Wi47rDSadrWAjZhLKEgROZJ03sjMDLgrhtO
         Zro7LpXK+WpZHO14eK84a44WIlUgiYMUSOEXMcOERGj69c+6wR3AA8BnuJHEzvI7/Ali
         3CIH/7YJ3Y/UfoP6cl0P+5A10apFYLF5/iNfzEV9O5cBzUkGs68CM+j/Yskh4jr970cH
         U3rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pPsYXqxtaAZ1KIFApcBqMamIighzP5CFnD0kGy6ZLLw=;
        b=cuRRkr7/q3NsylOMjLxtuKR9GcTG4ZN9bpkp4v5CFcXFYeoDIwdvecq8jzOdPqmEdN
         JTkQ8JeZFPdv0JgOd58ecxi4urPIDXG8LdAClDeH8fmg8uWOQcPF3z73EDWWfR7EkLbk
         GzEMzo+xEZY4SBRgnyxbgRKbHknOMW3/4zo/Yeeib9oY+rR/m2uNRYsbR4AEmChdHwnP
         nkaVHCkChEzXKmh2TAoSog+pVUhEwC9r/qUU3O5pEcgLhdfuJaHWPTa8S95yZ0J8RCJo
         6xDh4B5Oq9AOWleMysPpVBNI6Q8ED50Wt1rXTf5xlbonUTZLEzdwtLTlkBDT22vylb7q
         GIww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="VmzeA/6j";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pPsYXqxtaAZ1KIFApcBqMamIighzP5CFnD0kGy6ZLLw=;
        b=mokAe4oxsIWPVr1c7gpeR1Ad6itdRx42oVVYcC01iRa9v9phFjmeStMEG6JHUnPHlP
         qUK2wyU06zNgawtHAk9CSV7bpL9DiXjmsJu0hcLAcbq4mN87dy+xrY0+YF8ECJKfa7zp
         fB4TAfkzPtlQX9IskieHIFzvDcP8bQ9xaDV10QODAT6T18RaQrY5SrnIkovJpGueNIFV
         uspJXbswCsejKJ6wq5hKzHJFPEllkiCo/81zJgo20E5tgCySqMfDpFHzr9UubeCnR6wA
         3H6jkiphJR5h7fjzCw9s4Eo2q4foUbk9Bbe1QzdLyrK5kIayCtsHdOEOOocoAFpq6xHW
         893g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pPsYXqxtaAZ1KIFApcBqMamIighzP5CFnD0kGy6ZLLw=;
        b=g0j5mXqouMRchMEfXhc1+YkmeGjFBVT6O05jQeonOziMBvY/Jx98OlKx5antyZ5GT4
         T3deSAFgNi73G6tOo/7+QeEg8qSkD2QYJ/ihc9NQv5ZxEVecU2gRQNaGK8LZtcUX65/0
         V+7JboiLh+DxVTL9tL9I8xu9EFC7v3WrV0IolJ7Kn8YTRPmRG9DGSzze8bkYKqnZZJS4
         WdSf874awSzNN8z+8KNEjWvVtCDOn0uThhWMdApcLd7+Ff4t+RluLC2eo4hBWU/wGkus
         UYxcDT4JWE2eCrwXHx5NqkcG1QBh+yko3a8FOvMKxo9XhMLiQZSXGaZ4c7eXFwPOxQzX
         YV0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bmIWQyxX1gqu3HaMbnzNP8eWQcbxylQLwbLsiUylBtHe+Mn6G
	/j8iB5TwkLayFe+g0oIKi88=
X-Google-Smtp-Source: ABdhPJzWsDBX3ZAZ94JK9j3w65ZjPnGLKnfwRkRQul9uYfESC2HCKp0qtGSjau3SOPKhcWnobrGqXg==
X-Received: by 2002:a63:4f09:: with SMTP id d9mr3408914pgb.70.1612353599920;
        Wed, 03 Feb 2021 03:59:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9309:: with SMTP id 9ls858263pfj.0.gmail; Wed, 03 Feb
 2021 03:59:59 -0800 (PST)
X-Received: by 2002:a05:6a00:a88:b029:19e:4ba8:bbe4 with SMTP id b8-20020a056a000a88b029019e4ba8bbe4mr2786202pfl.41.1612353599326;
        Wed, 03 Feb 2021 03:59:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612353599; cv=none;
        d=google.com; s=arc-20160816;
        b=TBF9lyoMmI7Ha1KAY13aeqjEL62Gsejmro+EMCdpoLe/jncLRgO4kOfRHKid8bpyqS
         SK7leDiRjMFoNHpMj/uyiLcmBuX1bkNgMUM7v9U16GXwH+FLLu2xu+nyns6dcNYmUVA+
         8qZlQ3VdqO+DNqHMan4kxqExrpp/QZn8/jB7QsS4BNMOBnXVra8FAUplXqDZ3j2aYyIv
         rfZG1OOGEaz+4el+5HGry1kyKeddN283ulXy6yqZ1PNzRMKSE7r7wWk8/NQCew9rIbfI
         XTC5DAXmkE1B8h6Jr4z8TwTRoBDbhUNSSY1l2UzcBiec3kn/GxDncTLRLZDG2o7Zg/BY
         zmqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FaxU8G6b68GEdEbXS6bZDEyMoHhbuYhFSTBo6L7+8wc=;
        b=CnwmKsQo8Gp62QAwdo9Z7zeux017ydh8hF1TSaEBIHkPiHW0ONzN7I64Piz0xqHBYR
         v3WNJqemNfgCZlH2uYZXQ48pjDQoMpQTi5gjvx1NFkPseI60wPUjdp7ZugFTFgRVf3ir
         g0MGysAoLMfzX6kWAVi3XhNFRHnscV1ULxIkGWXc9rJes3Tvh0Ty2ly5+SCWncUL8+US
         Iv6Eu5ZuFWIB+92+4MLx/Q5ykkx9BOta5WNONxPO8KeAjaryuxM5mi1oL3Zzjl2kFznJ
         tYjmYk/6DHYuHC/MabOjtFdsMYhTb1mrTMRPAVF62CVxRqr64XhQXy6SUjrOavlQrtYD
         bFwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="VmzeA/6j";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id d2si71128pfr.4.2021.02.03.03.59.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 03:59:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id c132so17232697pga.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 03:59:59 -0800 (PST)
X-Received: by 2002:a62:a204:0:b029:1c3:fb27:16f3 with SMTP id m4-20020a62a2040000b02901c3fb2716f3mr2777075pff.61.1612353599093;
        Wed, 03 Feb 2021 03:59:59 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id p2sm2491813pgl.19.2021.02.03.03.59.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 03:59:58 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 1/6] kasan: allow an architecture to disable inline instrumentation
Date: Wed,  3 Feb 2021 22:59:41 +1100
Message-Id: <20210203115946.663273-2-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210203115946.663273-1-dja@axtens.net>
References: <20210203115946.663273-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="VmzeA/6j";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

For annoying architectural reasons, it's very difficult to support inline
instrumentation on powerpc64.

Add a Kconfig flag to allow an arch to disable inline. (It's a bit
annoying to be 'backwards', but I'm not aware of any way to have
an arch force a symbol to be 'n', rather than 'y'.)

We also disable stack instrumentation in this case as it does things that
are functionally equivalent to inline instrumentation, namely adding
code that touches the shadow directly without going through a C helper.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/Kconfig.kasan | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..4f4d3fb8733d 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -12,6 +12,9 @@ config HAVE_ARCH_KASAN_HW_TAGS
 config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config ARCH_DISABLE_KASAN_INLINE
+	def_bool n
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -130,6 +133,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
@@ -141,6 +145,7 @@ endchoice
 config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	default y if CC_IS_GCC
 	help
 	  The LLVM stack address sanitizer has a know problem that
@@ -154,6 +159,9 @@ config KASAN_STACK
 	  but clang users can still enable it for builds without
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
+	  If the architecture disables inline instrumentation, this is
+	  also disabled as it adds inline-style instrumentation that
+	  is run unconditionally.
 
 config KASAN_SW_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203115946.663273-2-dja%40axtens.net.
