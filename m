Return-Path: <kasan-dev+bncBDB3VRFH7QKRBQ4YTTCQMGQEVJ7445I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F85FB2F78A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:08:38 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-88432e1f068sf86497039f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 05:08:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755778116; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xb+GhVBUlA+GfZohf3msGFtTAUtzWT4dp/k/k3CVW8OQjjlqysOBBSAS4VuUD0AdVV
         YUapqN6sdtC3qM5yBaH/kHUYPN1sKjNgBRi5Xl6UaNcSEN9xUZoutR1fAolXeoM5ekKc
         9b/AMNhMdv+yChAwpBv97MNVf88DoP6krp9vgrFT0siMzJxbm9KnyDxAv11FUpJpY7x+
         J8zisi6v6x6dw0VqhoCHoqowHY3LusBYUj+vG3JfcfZ7PkNIHc/8ziNMPDTjdu/FWGCz
         MlmDQ9rAxL5fF0kQQ6PrV2WpYzNN8OkwhZmXQgpFUCVWcJQuj09xLliRcdyBmwxMzjt8
         nIfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=D2fhENlX0r24IplMd3575d1wbQR63mF/vcj4PeEBKOM=;
        fh=bHq+d+ETvKyq/+xV3j19jURZmXnrMZCnaFBJm9TNhzg=;
        b=GzYWCsGVWNJPg0J43jdj5kVmvK5hQY+mBb4BrHYgq+4iXYbMeJGg4du6rFwdfKcRAQ
         y/BYdLO6pSwyHuek1HjKlXA/b0tiWoku50/IEu8aVLg+4mqvNFTeXYlC33dJA/YPWXHZ
         ZgY7Yt7FC982ojbf9/YJr6iMKQhXrBcnK+m49vRAp9qOWgpCu0Al9zSGtMKixA/zaWr1
         rXbAHYuVHuXSoB2F3p8ls3sXszNFtQPgNJCAPn6xA3FpEjCZ63qK3hgHNcrfsnfVha4i
         FiHUbt4DqVbH242PUB3SyftJZh0JS5br82ZGN0Q0/9rjLaGd8+yLcu8DO4dZAjAtgk9c
         4KNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755778116; x=1756382916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=D2fhENlX0r24IplMd3575d1wbQR63mF/vcj4PeEBKOM=;
        b=QUzYja6uTmVpQvBLA+2Y2de3kxqsJgrIbetQtxq8PN6r/cP8VGwSoJayDLHgazSxRg
         Qc94W5Rkzgecm6w0co6bt9lBWn/rllewb1j1dA0NKWlGb8Tf/5Wy5oRJiMjDlKVN/kZn
         gGqRKR0VLXA0mbMIuo44hCzMEIsOgDXZfgstvruTOYMWYKkv9XQHGWwgUdcjTfx2sMD8
         kBuBPWdC4jJldleeJ4FR5CNX5SYnkk1LuLD13SMn3GyHoxBZ9yZrRWWeNJ16i/iZN6Gq
         v281obXFNXoAw0Rhau2fr1VZoQKdPCyA8zYkwx+4DLGqcCTBSs+VxP/XYOYTuZyQnLRR
         njVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755778116; x=1756382916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=D2fhENlX0r24IplMd3575d1wbQR63mF/vcj4PeEBKOM=;
        b=bvMK2CHcPTwB9eWI/yy/BcQ+tuizV2kZiXj+kZpvtONJVlGYeYgfOpMWRifaJYSGMc
         xfxLQ4MD4Z2CuF2fH+KKmEw8r42VijahcB6mRMYlNnAwntgaL3D6sUU7fX5JekyjWHA4
         yk8ohyU7Ifiiew1g7BOPIDcFsLCUs2s+Vgbaj4w1Bf7jjWi7ykxY03dFUYfZn4OfZtZ0
         WTLUzY8aH2UcB9wh47VbJr63goun95IBM+zf0LJVqFhwn0+B+gHpdCLdJlvjSVofeZsM
         VUXeSI2GHtHUVhojM1rysV2TIwfgvDRK6aCcw9Od0/FJbJ1PrLDmUodmAupPk98yXPwg
         3YoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLcHSSpvDE/RX4QBZxJtQnf69DgmKSe7fXlsYsYrYCk3pX3jyyMMmjlqEy/rzWziHGfVpeXw==@lfdr.de
X-Gm-Message-State: AOJu0YwUfCEb7n1g5gSrUSv3X0HO/UkitXIYqwSyECnw6hGZMwA771HM
	A5feaZIYQ2kAGoL07NXXZh/fRRpD4AZvaDBIiKKSl2/1WyMFq+qdbi9k
X-Google-Smtp-Source: AGHT+IGaQBv5bltA3f5znGPI50YYHuS+yBJkmD/KTdasveBIAs6Sa2iVLk86npcYl7U8pKa0K7Og2w==
X-Received: by 2002:a05:6e02:3e01:b0:3e7:223c:a5f5 with SMTP id e9e14a558f8ab-3e7223caa53mr25482345ab.12.1755778116249;
        Thu, 21 Aug 2025 05:08:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1gyTBvx1ViXMl7ErluHagbwyRpX+rv7c2iOy+5ChiAQ==
Received: by 2002:a05:6e02:4601:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-3e68361e7e9ls7131015ab.2.-pod-prod-04-us; Thu, 21 Aug 2025
 05:08:34 -0700 (PDT)
X-Received: by 2002:a05:6e02:686:b0:3e6:8334:8a33 with SMTP id e9e14a558f8ab-3e6d66f7c81mr25740215ab.14.1755778114081;
        Thu, 21 Aug 2025 05:08:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755778114; cv=none;
        d=google.com; s=arc-20240605;
        b=F+zB7HxH04VB+a19CzvFHXP7H2JPFzqody69tLxK1548CtV+ROJzrBXshAxA7FsTUr
         I+Dmyfqdb4hYumssup/4FEwWeBA4Xm7jWuHxQsi5tMRwx0TynD5cz7jW9fIijURI6Gyq
         QwC9y1XZWWFbD9lTMqfMZ0U8MOtMFrE8+itlMVCVFGsHPLjZHn6LbluMh5UAt08eOlFn
         hpXlh7vJU/XaPzwjP4soJiH9Bsxe+FxinI36gWhrbhNNpjg0VR/iO6oxmcQi6BF1iYwN
         ipEKlqn1spGtT8GXfxQp6o0JIJsGO+JvMfiRRRNYw2lzPnqKvBHXaUvYcBAVKVZCZXBU
         zJZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=laMsasaucYt76+hlosAvgSlSNqkbB+EJ5q4cNVyb5d4=;
        fh=8PxB6oDDe6z0uc7uTj3sDMBfzq8XuYPHOlgUpbThYdA=;
        b=Ykz18Sf6e2G+FQp//Gj6RSUhsVn8z1QqtJCZtewr5/CbHk7bxwf32Qhr5Qgz9MfaYA
         PNUoA3bSwy7g5DdKLHmNLoB+2ijAyIP6W/8kkW2y3A8K8Zmy+tUjjUAibk9e4kLjFtyX
         tiQRYAbmr4jOkx4FnoSe9k8NHjkdUO9DvJKbune4pQP0TEwZgo9AZEL4hT/6FweU3q12
         PI6Ir2tvTRo6I+QQyv8I1qFYSbcfSd3OCZu3u5R5+rVoiBd2JsozPJPeU1mKVI4hjSwR
         O+vFdbx1nPjtr1PBTSLZgXPHn4Vfgx/i0giHUPIFjAKq9j5xF+7yrF9raYwhhWgE8vuB
         N/Pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-3e66ba5ef4asi5999965ab.5.2025.08.21.05.08.34
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Aug 2025 05:08:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 27EE7152B;
	Thu, 21 Aug 2025 05:08:25 -0700 (PDT)
Received: from e137867.arm.com (unknown [10.57.1.220])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 23BC33F63F;
	Thu, 21 Aug 2025 05:08:30 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: kasan-dev@googlegroups.com
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Mark Rutland <mark.rutland@arm.com>,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [PATCH] kasan: fix GCC mem-intrinsic prefix with sw tags
Date: Thu, 21 Aug 2025 13:07:35 +0100
Message-ID: <20250821120735.156244-1-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

GCC doesn't support "hwasan-kernel-mem-intrinsic-prefix", only
"asan-kernel-mem-intrinsic-prefix"[0], while LLVM supports both.
This is already taken into account when checking
"CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX", but not in the KASAN Makefile
adding those parameters when "CONFIG_KASAN_SW_TAGS" is enabled.

Replace the version check with "CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX",
which already validates that mem-intrinsic prefix parameter can be used,
and choose the correct name depending on compiler.

GCC 13 and above trigger "CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX" which
prevents `mem{cpy,move,set}()` being redefined in "mm/kasan/shadow.c"
since commit 36be5cba99f6 ("kasan: treat meminstrinsic as builtins
in uninstrumented files"), as we expect the compiler to prefix
those calls with `__(hw)asan_` instead.
But as the option passed to GCC has been incorrect, the compiler has
not been emitting those prefixes, effectively never calling
the instrumented versions of `mem{cpy,move,set}()`
with "CONFIG_KASAN_SW_TAGS" enabled.

If "CONFIG_FORTIFY_SOURCES" is enabled, this issue would be mitigated
as it redefines `mem{cpy,move,set}()` and properly aliases the
`__underlying_mem*()` that will be called to the instrumented versions.

[0]: https://gcc.gnu.org/onlinedocs/gcc-13.4.0/gcc/Optimize-Options.html

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Fixes: 36be5cba99f6 ("kasan: treat meminstrinsic as builtins in uninstrumented files")
---
 scripts/Makefile.kasan | 12 ++++++++----
 1 file changed, 8 insertions(+), 4 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 693dbbebebba..0ba2aac3b8dc 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -86,10 +86,14 @@ kasan_params += hwasan-instrument-stack=$(stack_enable) \
 		hwasan-use-short-granules=0 \
 		hwasan-inline-all-checks=0
 
-# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
-ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
-	kasan_params += hwasan-kernel-mem-intrinsic-prefix=1
-endif
+# Instrument memcpy/memset/memmove calls by using instrumented __(hw)asan_mem*().
+ifdef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
+	ifdef CONFIG_CC_IS_GCC
+		kasan_params += asan-kernel-mem-intrinsic-prefix=1
+	else
+		kasan_params += hwasan-kernel-mem-intrinsic-prefix=1
+	endif
+endif # CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
 
 endif # CONFIG_KASAN_SW_TAGS
 

base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821120735.156244-1-ada.coupriediaz%40arm.com.
