Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQ5MVSDAMGQE2NFY3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id D0BBE3AAFB7
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:30:44 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id jw3-20020a17090b4643b029016606f04954sf3611168pjb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:30:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623922243; cv=pass;
        d=google.com; s=arc-20160816;
        b=RxWa4wb6WJbMG0FGuQPG5jVs5ER7wTHO5nsjmVOeoHUMFqmlCQ5C6fn1iEt0hXGO2M
         M+N/m6CrtYyJ4bL6Ieryx+lyw17bw9/BuSQrkcx5wUpxOCucMDoWbsheaZzta1xL4BaM
         WtmqrN1UmgUfnwl+6Av1AeEb/nwLxDsuHnOMziIjMZNkH7u2WFH1AHLFyY32F5Glfo8o
         ZXVzS4zT18q5zEaj9SKiF8Tx1n6Kj7D0QKYNiH4DDYvn/3OC2jLBXKPgwOtlIXNtGC/7
         1eLM0rVidP9PiidTTzZh8aqMhxV4Mn718/JStX16GqiywHzm97CNwBBQMAn0yM0EHD94
         P2rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qCWeq7KKOwQDvGgflVoz2rYK1aJVpGWNFt9TsXaQbp8=;
        b=Qm/2f217t6X2L5bwDjEK02PAPN4R+4q/KhSnjlK5ifM+qDf62OHUS73Rsr9HzBlPQE
         098OY30nZAjc1PHp7Qxf5acS1IDkuadxpMfxJVQ8uRDRCRX/R/nklezR1B5yuwY51ITu
         5PEJyKYhsTiEQvrvkbaneRLkZnJYJ3GncsMQ0yg76EtQLKqRLqtdDOKDhA0cSKCqwgFy
         Fx5hto8roid8fcfsW7B3mtrJf8vsysq5iENIF6gngizgp6gJ2Xen2ocMKw0n7ymZfH1a
         gXhnWXg2R2gOchq3U1IwmiD+m4nRc2UswfRXg7rErd7DFMBI9srjrYE9zTGSbWxk3Jxc
         Pigw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=VxBhETKa;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qCWeq7KKOwQDvGgflVoz2rYK1aJVpGWNFt9TsXaQbp8=;
        b=D+jRfKEmYhsf4vEAGQzpUuckKLCgkf9hRiTMfxWFFobp5acggi9iKwtoLjJoMGcK6Y
         wBGByl5AVcSEy7FOT+727QxB8XeWOF1kA9M1eRL9DKHtvOXUG8jB3mgC5xuxzdM00tvs
         AOMWo9dNnGyflj5yFvp/i2yo1UhWA9FJOg/satw3HtyNuVLqxaSz1zpCRoRghnVVj0Tg
         YctSHXhWGtjC/2XxuZSUdlzDcEn1SWXul7flTGXcNrXOI+9eTwnfEPu3yIjQulMOy2Np
         mNQ5CM9BHQQZuw5sTxIPFv8BrMc5aPnH8bF+ISwlOfSU/gbFrQNgKgU18A8DMA2uL4Ev
         BEsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qCWeq7KKOwQDvGgflVoz2rYK1aJVpGWNFt9TsXaQbp8=;
        b=uLi+kHPf9KuaB7qRrs+Z2z3Wzsg250UetNc5HDLu9i4IsZBgUwK2ATf6ym65mUCB8j
         eYuEhQ5U1LMrGmqzzPfAdVxm3X4Z+87hs7R6jHECW/MWd712wLMLnffXUKgdef1jVxkp
         hCbUsij1K9SEobcLPsU0j/DyUXSRIbJVVhWRBym/iOW2buovI4oNMC2raukcPNMRB81Q
         p1A6xe0MJYLETLcN6wwhz0o81GcWPb98AYdIGOP4nfrja4x0S0Rdl2ZSDLx2qh537tvh
         32iJpwCebSKj93P7bo+nf1lmFcXGLBJ9xEmavhh76ToLwCrejby4Km/XCqqPLFMYcnA/
         Fujw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Fku425ofncl+DNcXzfRtqY+byveUHbSXku4Xh36ZBzV3UAUR7
	Sj5u2HfszNEZbcgB5wmjDXE=
X-Google-Smtp-Source: ABdhPJwIal0R21KcGUcFGjMDfUz5ZlvARdgJJkHuDf1hX37AOV0/csH/UIV+tntxhV1mYhAtriB1Xw==
X-Received: by 2002:a63:d511:: with SMTP id c17mr4135172pgg.219.1623922243196;
        Thu, 17 Jun 2021 02:30:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6701:: with SMTP id u1ls2592760pgf.10.gmail; Thu, 17 Jun
 2021 02:30:42 -0700 (PDT)
X-Received: by 2002:aa7:9ed2:0:b029:2fc:b328:ad67 with SMTP id r18-20020aa79ed20000b02902fcb328ad67mr4355478pfq.63.1623922242635;
        Thu, 17 Jun 2021 02:30:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623922242; cv=none;
        d=google.com; s=arc-20160816;
        b=WmSxFXHw3EnVFS/liGRMuxCgHTaH6btwtqK66fms5iy1aq56RsQerH/bMSXGPvWNO1
         zU1y3byyBxhY6pQKCLD93iwuagEmOd6aE38+A75y74LD3hmG3d/d1NZuHyxnb3NfPK93
         M7xhWKIz2SaIXJOmrjQ3U+xuoIezPrXdEd+8V+W3HZUVkN0YFRmRWPIi8IPs+v7zcUj8
         wDAHeBpN9LMR3rbMRn0AO+MFGvlQN1Z6Q93YjyBUiD6CjKy53wXQ4DeMOIHJN8tXeRgL
         A1GvcBsqp4jXV/e0WCkK7EknTgdtoQphM3rJF+m4HwalW/mY1DpyAqirn6iJ/SKR7B2l
         odrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1nSYxJY0N3aZr/pdi8HOrkpkeyyKzwB00+Ef/RsvCEU=;
        b=0q8nH4ey9DhPAOdiNby6mLsf5uCsuwPuKj3W/59TBd9fQm149WESqiM5w6LL9rFueJ
         5xoLD24d5mSfTsZCdanKQTOTDXwOe9zMufoGrjqBLVwwYf8VmbGzT3bNwB24ljZ1lar6
         QfaMsIkRmIP9+IzTsSLB0FuL22oB0AFzKIi8dKMaHI1lmgXS4NqYPvOyN7lkqfI3zKQs
         TIpGj2XLE6B51v37h+LPiVMCDl/tzYd4UU1QOS/LoOGZ8Cgc78C7JPTn2texoxkiTE81
         owbYH+sCHzKjq6pKZ+w75tuZMkXA8XEAZ9QXMORmDItsU3ghsgHIkE2y+QjO66xEXCTk
         davA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=VxBhETKa;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id d15si18198pll.3.2021.06.17.02.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:30:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id z26so4533367pfj.5
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 02:30:42 -0700 (PDT)
X-Received: by 2002:a62:380c:0:b029:2f7:4057:c3ed with SMTP id f12-20020a62380c0000b02902f74057c3edmr4363473pfa.21.1623922242435;
        Thu, 17 Jun 2021 02:30:42 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id a23sm4404876pff.43.2021.06.17.02.30.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 02:30:42 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v15 1/4] kasan: allow an architecture to disable inline instrumentation
Date: Thu, 17 Jun 2021 19:30:29 +1000
Message-Id: <20210617093032.103097-2-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617093032.103097-1-dja@axtens.net>
References: <20210617093032.103097-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=VxBhETKa;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::429 as
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
instrumentation on powerpc64.*

Add a Kconfig flag to allow an arch to disable inline. (It's a bit
annoying to be 'backwards', but I'm not aware of any way to have
an arch force a symbol to be 'n', rather than 'y'.)

We also disable stack instrumentation in this case as it does things that
are functionally equivalent to inline instrumentation, namely adding
code that touches the shadow directly without going through a C helper.

* on ppc64 atm, the shadow lives in virtual memory and isn't accessible in
real mode. However, before we turn on virtual memory, we parse the device
tree to determine which platform and MMU we're running under. That calls
generic DT code, which is instrumented. Inline instrumentation in DT would
unconditionally attempt to touch the shadow region, which we won't have
set up yet, and would crash. We can make outline mode wait for the arch to
be ready, but we can't change what the compiler inserts for inline mode.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/Kconfig.kasan | 14 ++++++++++++++
 1 file changed, 14 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..cb5e02d09e11 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
 config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config ARCH_DISABLE_KASAN_INLINE
+	bool
+	help
+	  Sometimes an architecture might not be able to support inline
+	  instrumentation but might be able to support outline instrumentation.
+	  This option allows an architecture to prevent inline and stack
+	  instrumentation from being enabled.
+
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -130,6 +139,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
@@ -141,6 +151,7 @@ endchoice
 config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	default y if CC_IS_GCC
 	help
 	  The LLVM stack address sanitizer has a know problem that
@@ -154,6 +165,9 @@ config KASAN_STACK
 	  but clang users can still enable it for builds without
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
+	  If the architecture disables inline instrumentation, this is
+	  also disabled as it adds inline-style instrumentation that
+	  is run unconditionally.
 
 config KASAN_SW_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617093032.103097-2-dja%40axtens.net.
