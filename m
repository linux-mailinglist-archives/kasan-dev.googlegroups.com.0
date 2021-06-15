Return-Path: <kasan-dev+bncBDQ27FVWWUFRBJENUCDAMGQET7J3W5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 976533A7372
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:17 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id i24-20020ac876580000b02902458afcb6fasf8564303qtr.23
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721636; cv=pass;
        d=google.com; s=arc-20160816;
        b=YjgP3EqOOdHsGqHPfKu9MNYzyyTtFlA5ZOJyF+YjSt+NxqvSiekP6ikYtN7tl64a5b
         LW6zP7cpfp/wdOhD4EZhdL7evQcr0D/zC2oIFkOmZeaVPUgE7zwX7k788PXtNN1Eu5PR
         VOzCpJl62KToJZCiGu1YQFWYSIR0Qez96G0ES5MohBQJkjI7MLPlBarsKcn+jovE4RNc
         wbfTvkoi7XeQVOhuYsyg3Q3k1Toc4nWUSN6keGYJdNML9nYpzKHTx5jPETcgcwz+QXgH
         ROvRKPlsSzNEkdf+B6teg8mzXNm4EhLSo5LvTM4ss4PbFj3vSZrJeiEp7NzFmP9PYIwO
         2Stg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=plQDst7cKMdCbJDpjaWU7nTJWRFX5z+NC/xYEw71Pr8=;
        b=EvVsuHT8d9ruf0+j+sfoWJvp3uvm4GTkjGhlhEXfgFh8X2KXifCgsew1pVgnGmIh9D
         8RevFQ0wPOugl2JuI4n6Wlb9+KSaENT4ldIbI7rxGhKBLAoMXeaKtH5ltciZUEfHuGaL
         isU2gCX7xcmvFQUSVcMTtCRHEo3CtWAwQ344jgawNIJtcLnuv18skJLBtVX4g+fvp1jm
         MTUkh8Qzbbykszc0mruNGauyoXMa8ctjeQa/CttLXsnf+ULA8DIORxCGOTVb3QiBkUgH
         XzIfp7G2FGWq3qse77Ql4zsQl9xUBhNUmhx3QBjSfMlcf+Q+Tb69HSz7dpkx9SgEhVK6
         8TTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Pn6LBDzC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=plQDst7cKMdCbJDpjaWU7nTJWRFX5z+NC/xYEw71Pr8=;
        b=aRegTj1bZtbQdTAAgM8sci5AgDvk53xHUs01txHIYKgUXNG0t8v9H/uOQq6GhjuEkV
         OrPmnOkbaWbrDbXXjjrrK3ARPAsoeutpG/e5JC1JPRLnq3BTXrmFV1DC1Vv2dcjNx82t
         q8C2DYLBmmph1NrLwiOyqU6o6tD+Iks7X7r9qHHMnNajU6S6ndWRn4L60ddglcc65hUD
         u26M2eDrm8iWTdVpq5WE1YrDw7YV52A64RLpyLTdZ5bePm20rmvRgzHe+8OdL0Dc5q6p
         J66HLSX+p1FR3QSlhLvqphGAWz9EbxSxewJ5R8l2cYbixsMPyQbyI8jJ35KTBeU6vVhJ
         fjjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=plQDst7cKMdCbJDpjaWU7nTJWRFX5z+NC/xYEw71Pr8=;
        b=ThO6j7G2r97jYPDS8pcC3Wzj7LbbFoUrsigV3unxko8G+HnUzL7AvcWUtKWFqWuBu5
         V1oU7jneX8DilKPMQ9Z6PHPhfOOiu0J3Jflh0KfxSBQJQkbz4X2STqFo3Er7mz7C8OZ+
         1g7n8BwEFhpRyPyH7xBMXG4UOovSpIhyeaXl2cIUlAU5dhapYZQD27saYGQU2c4bAltJ
         ni1cX5GosyU50jQjDXE3ODFkuFHoPLAy3PGIdj0p3tbzw9CQ4YCUi5T3DOZv2ZRPrLSZ
         +6swz/T3Zr+1bFeyKhkIptxTrBVNiGJ9lYQstFs7tPuT//lUp8pLAMS+S1aV85GRr8Kn
         7dhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IZAadY1KRVPMZziWvw6rFY3nVD1vCV3ci6VikxSGU5JPDTww1
	2W7gbXNMECpbSYsvO0IZGJw=
X-Google-Smtp-Source: ABdhPJyXYyHJMWyQ1yi2qIh3Jdd6G2uAWHdxNUWZg547sOCBrGIcw6AUaI+tgrIxlllI7KctYj/z3Q==
X-Received: by 2002:a05:620a:109a:: with SMTP id g26mr10585787qkk.450.1623721636432;
        Mon, 14 Jun 2021 18:47:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:bd85:: with SMTP id n127ls4272402qkf.8.gmail; Mon, 14
 Jun 2021 18:47:16 -0700 (PDT)
X-Received: by 2002:a05:620a:ecf:: with SMTP id x15mr16130582qkm.275.1623721636011;
        Mon, 14 Jun 2021 18:47:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721636; cv=none;
        d=google.com; s=arc-20160816;
        b=xkzWdJcdWBj/xoYDLqMR9+7Jkvwfei1byjSjI1l2NOwwcIBUItjjwK3LsSiqyUZb0S
         1pAF4GgM/YEqzpOATG/N3QTWlrT2t3v9VIuZRNBMPIq2DOK3NhT2iLAfZ3nP9fXKoWoV
         G7fGtx7DQ43vslhoUe0rVTJF9EZbQ6B2MIKcUUDcMquRoryK1Y82phTwdevMDcfavvCr
         6qLhecRyN0oQKVI2LDnSZDOULnjqvLHa2yFIrfIzoJd9xyN4/WrpeaNdh4dxc2OIpq4N
         aZ7dmfFythoFDe9BevvfW5l/IHUBM+oC1F5JbbqMvc6dPG13Q99xsuO6huApjJwTLNWl
         ft3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HOnQVo+SWV1H037ZQ/Ye/PGWwO/+/ZmfPhIlu9wOFzQ=;
        b=fpYey/gNESUfJwvVEsp8A3H+f54RT642Si5asODn9XqBbldpSVAu1laxYqVRIffT3C
         pKlahz/gowYBKj1v8bdvm87jWqJ8x8i/bjX1ZCZfSGGrQ+8oxJAbjbYGvnv4V8Cba/Lk
         3WZWHUTQSWCheglD170LdNxQ7uUlGw1Uomn90DQtx0En4K+SlDm3z/3+0EfrIwf9ERMs
         Y3vBc6z3dJStfdbOuatLYvD3KKbhTj0BDhBIQs1ldtg5oz6MU2MugcJSvlpNIjLqfFF2
         ZubfAy4uUfJlIyKEP6GwkAN1qtQT4k2TnUjrMvnx+9nnEhv8eSdfFkRE5Sifm9opvHg+
         yTIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Pn6LBDzC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 85si120282qkm.5.2021.06.14.18.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id t13so2787967pgu.11
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:15 -0700 (PDT)
X-Received: by 2002:a65:66cf:: with SMTP id c15mr14734452pgw.121.1623721635179;
        Mon, 14 Jun 2021 18:47:15 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id gk21sm13168157pjb.22.2021.06.14.18.47.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:14 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v12 1/6] kasan: allow an architecture to disable inline instrumentation
Date: Tue, 15 Jun 2021 11:47:00 +1000
Message-Id: <20210615014705.2234866-2-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
References: <20210615014705.2234866-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Pn6LBDzC;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as
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
 lib/Kconfig.kasan | 14 ++++++++++++++
 1 file changed, 14 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..935814f332a7 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
 config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+# Sometimes an architecture might not be able to support inline instrumentation
+# but might be able to support outline instrumentation. This option allows an 
+# arch to prevent inline and stack instrumentation from being enabled.
+# ppc64 turns on virtual memory late in boot, after calling into generic code
+# like the device-tree parser, so it uses this in conjuntion with a hook in
+# outline mode to avoid invalid access early in boot.
+config ARCH_DISABLE_KASAN_INLINE
+	bool
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-2-dja%40axtens.net.
