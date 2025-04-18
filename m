Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDMNRPAAMGQE4X3B5LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 48543A93F84
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Apr 2025 23:39:28 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-85e6b977ef2sf349337339f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Apr 2025 14:39:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745012366; cv=pass;
        d=google.com; s=arc-20240605;
        b=LClLsh9FbbLC71CVcUN+34kzrWjNOE1CVWnh+ZYAb9he7KfpXZfwK3c8t9upihE1RF
         JG8D/+pL2AgwatJ7sk8fp3fC3YeipeHSCPaHR0kdhP2zdeE5UIU+GTvq5zigajHuhchM
         lOBUL/4qcTM2NfW+yarYxw2Di1BiU4WsuMAqutWd6gG0EdnUd6DmPv5uzR+q+h17wqVB
         mkgGvWN5M6wl2KTDtsh+IsgaECLzOFv5osap+MPolLg6XHZGflGarlvpXBInQrJNlNEJ
         l/PlH7DGvB4SVhpb+Z1ExpfPs8EHNRTRZn8RxgMc2YCSMfAEZinK96uQTxGmq5HKAk2Q
         wBSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=SAhSkhiu3uqUuI9QTOsPUUXb1crNNnDXHQK/G5G98So=;
        fh=mp0RsfCxLTYJyP9YjkTSs1w4zRc6UOcfZkjPAt/kGdI=;
        b=J/p0oFz0NLb6qVXYnH+jiKPsTx9TBumrcM6mMb69abMU2Skk2FyE5V57ZIq0zVHkl7
         PPn+TYxZ7Yq4pguFjAMabk+hgOgHPfyMptvilpMV+OlJdr+XVdr71/988rerMUCTW3CF
         Vo9+ANeHd1lzrEtnAKvb/nazsz9CCRoTDtOFtAXATcXyTSIURhmg0KzwVHPjhJ6LOz49
         WexZqgfeDsJUHY+YtfDKW/iySKD98ZUsC0NVNbVtb8oCZDg/g2c9pWeDkupbnj9Bl9z2
         ZdIQ9kp+S1DE4IefuphEK/lHwxexYclAORwLwTatdkWrgq0LSJhBlb+ciWTDx6pbnuiI
         /48w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G2WCddnk;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745012366; x=1745617166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SAhSkhiu3uqUuI9QTOsPUUXb1crNNnDXHQK/G5G98So=;
        b=HkoUyrKgVpAajV47NbpI3yD48pZnOC3ByF2TsyG50fOmR594z4PlsxAdtFq+uSh4PB
         pLcusGJl3hNo4z4Mawni4ZTs1dWtbEHIDXUnlA2P5Qh5zmxlN8mMiWlwac3WAR6uJq/u
         +fkTKImWRdFiNO+GA2EPUNwia0vvQAkP1GnQg/MLMz4roOI/7s/NTq2QYXGhiFcZUAjY
         IFDOV5ruRwGTxYotsYo/uNzUrDWPp+kqb13yfiKPcajbLOG05cQjJzr+JQzuBnaZrlH1
         5M7tb0KQv3iTXHp5xT7FvdvwUObsaXxzC5KMbupA10bPOUf7+uU51LTLFvIQIFqxlQsI
         inow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745012366; x=1745617166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SAhSkhiu3uqUuI9QTOsPUUXb1crNNnDXHQK/G5G98So=;
        b=ZZnv4Scw3acacIdQ9aJhWwilSu5I1SaOmTKyOMLEzvlaAALoTwMrJ5KcIrDd54GVHd
         x1qA1O55uX5lv2+hDdDeAr0PCeJq67LGMpyBbjDRR40RqI/mvBDKcd7T8pbyJ7gCibPE
         fIfuQE17iLGZU8qyVnfxXhdJF/gRm/tHYiB/WLO1I4AZUOuz4jIxMRWsG2HccB8MgjPi
         7RwIzaNtH2l2Gf6tlLXkkwWjR3PNTer8Mvy4h6zgkp/wo41dh21e5Ek8ltarUem4tib3
         thuWVDpFV4INxbLjTIFK8J2I+5fiYRZsNm4FIyrSrJ2Ar1TkOWR1CyqMF4VIzC92T47I
         m38Q==
X-Forwarded-Encrypted: i=2; AJvYcCWWwLLZPxM9bX52kA0r7QT17QBuaCtTPJM1S8P9FqmYUJL/X6CKKKa5Nj3StjTk9BSY4Lr7Dg==@lfdr.de
X-Gm-Message-State: AOJu0Yw+F2xrymvdmW892KCjtcYcSUAY7jXtrbZzCAp5SMN64+xCWqP4
	/0JkEiz9bhw58G1jj/QU0ytLLcmuqn5rFVd4ZUonBeLc6U1bUPEj
X-Google-Smtp-Source: AGHT+IFljQ5CYY0ADZCVzqNEugJb62qXjWWloLjyNZ7Kd2dlW7Yt6ZGHpMjCYCcOTjgdNZXDc+ErNQ==
X-Received: by 2002:a05:6e02:3083:b0:3d3:f4fc:a291 with SMTP id e9e14a558f8ab-3d89428c213mr52835265ab.19.1745012365935;
        Fri, 18 Apr 2025 14:39:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI8EZg4MPt1vAw0fGnl1pgN5rXYMFszO3bNFka9/rPB4w==
Received: by 2002:a05:6e02:3710:b0:3d4:3543:15b7 with SMTP id
 e9e14a558f8ab-3d81a763fe5ls20428065ab.0.-pod-prod-05-us; Fri, 18 Apr 2025
 14:39:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTEJe07QklnnGN6zcLSuYHeqLoB426Fi0yNRzDgrtu6QWCn/hpSljaM24Vxh8W+CfhIHScSGZknJ4=@googlegroups.com
X-Received: by 2002:a05:6e02:16ca:b0:3d8:1ef0:4921 with SMTP id e9e14a558f8ab-3d894180afamr39594385ab.17.1745012365169;
        Fri, 18 Apr 2025 14:39:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745012365; cv=none;
        d=google.com; s=arc-20240605;
        b=KMsgPA0Rpm76AQxgbiNUfAgzO0WNgdgxWTbA7Fqi1Hbskg5irKOD/z/8G4Ii/xD4pS
         d8aVuefmG16shUAwoVSqZO/cn7VIeocLdjGgw+Y64cxzKGCmvcDZHVxI/eBMG8HLLHI4
         P9k7wbgyjLwCIZk86DhRam561oHpf1xUJ6NoJ7vUDJVu1hPTdKShd7KDiJcAYjvwKqGr
         TvegP0wJTEGyLiS1RtDdO315S/W54LUYZpkmXjw/1xXsv9AYTL6j8T3M4Z26lVop7+ML
         hpcr+DiykVi08GYvGxjqivDwqioMyn1szF19EoXAbGK5l7tuyHx03070MfNlC4Vu0Joj
         H/aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=rk68TsA3o31hTgJLBf2Gv0fYT2I1YziG/5HO6l5R5L8=;
        fh=e/QSydFulLmaZXr9TmdGaTU6R/Ye//vtsI6ypfd2Dp0=;
        b=MQGpsQjPHSaIyc+Klb1Gbn6P2XszYBw837tJsf6FRAQHEkiVCnBHpjMgj7ET1+bvpv
         MWXT3EFBz+gwnJdjddKhhnXQOlK8TzNxPlEnHX+uu3YJRXhaiG4DZAFV+8ZlchVqdi1N
         1kNTk3roLQlSp+GGWss06PSY7D5uAegGaS7dv+BpDHxoUb13TF0a4ydcEOheXka9cbBp
         H3N+he9mzgS49lbfEHutuzeuB/3XZeuS3E6La4utFnf/uKzC5XR2IQ3QKS6YzyIe6oQz
         irCXV/Mnbp00p7bSkY2ZuEnaLCcYOjYtL59nPpd55G1V7meAR0Co14iK95xt8GpAT0zQ
         Pauw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G2WCddnk;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f6a388428bsi47531173.7.2025.04.18.14.39.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Apr 2025 14:39:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 170C54A50A;
	Fri, 18 Apr 2025 21:39:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2B194C4CEE2;
	Fri, 18 Apr 2025 21:39:24 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
Cc: Kees Cook <kees@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kbuild: Switch from -Wvla to -Wvla-larger-than=0
Date: Fri, 18 Apr 2025 14:32:39 -0700
Message-Id: <20250418213235.work.532-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3972; i=kees@kernel.org; h=from:subject:message-id; bh=Dxddxm0RejabRVjCTL14ao3nM8RrH3k/YV8zdVVdCso=; b=owGbwMvMwCVmps19z/KJym7G02pJDBlMR75tUNcXehp4aNuTF9IufZcazwSYsVpMuhT1SYfV7 DZjXfTDjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIlU6zD8sxcrPZD7z3HyfV5/ l5P7Zidtu6JR9j1/s8OLWSp8sROaOxkZ7tvemrNQJZAjpFqnUJfJSVdjfeDhLfxyf09LOTKE/fv OCwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=G2WCddnk;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

Variable Length Arrays (VLAs) on the stack must not be used in the kernel.
Function parameter VLAs[1] should be usable, but -Wvla will warn for
those. For example, this will produce a warning but it is not using a
stack VLA:

    int something(size_t n, int array[n]) { ...

Clang has no way yet to distinguish between the VLA types[2], so
depend on GCC for now to keep stack VLAs out of the tree by using GCC's
-Wvla-larger-than=0 option (though GCC may split -Wvla[3] similarly to
how Clang is planning to).

Switch to -Wvla-larger-than=0 and adjust the two VLA-checking selftests
to disable the updated option name.

Link: https://en.cppreference.com/w/c/language/array [1]
Link: https://github.com/llvm/llvm-project/issues/57098 [2]
Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=98217 [3]
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Christoph Hellwig <hch@lst.de>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Nick Desaulniers <nick.desaulniers+lkml@gmail.com>
Cc: Bill Wendling <morbo@google.com>
Cc: Justin Stitt <justinstitt@google.com>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-mm@kvack.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <llvm@lists.linux.dev>
---
 lib/Makefile               | 2 +-
 mm/kasan/Makefile          | 2 +-
 scripts/Makefile.extrawarn | 9 +++++++--
 3 files changed, 9 insertions(+), 4 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index f07b24ce1b3f..37b6e5782ecb 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -71,7 +71,7 @@ CFLAGS_test_bitops.o += -Werror
 obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
-CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
+CFLAGS_test_ubsan.o += $(call cc-option, -Wno-vla-larger-than)
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, unused-but-set-variable)
 UBSAN_SANITIZE_test_ubsan.o := y
 obj-$(CONFIG_TEST_KSTRTOX) += test-kstrtox.o
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 1a958e7c8a46..0e326116a70b 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -35,7 +35,7 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) $(call cc-disable-warning, vla)
+CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) $(call cc-option, -Wno-vla-larger-than)
 ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
 # If compiler instruments memintrinsics by prefixing them with __asan/__hwasan,
 # we need to treat them normally (as builtins), otherwise the compiler won't
diff --git a/scripts/Makefile.extrawarn b/scripts/Makefile.extrawarn
index d75897559d18..0229b10c5d81 100644
--- a/scripts/Makefile.extrawarn
+++ b/scripts/Makefile.extrawarn
@@ -45,8 +45,13 @@ endif
 # These result in bogus false positives
 KBUILD_CFLAGS += $(call cc-disable-warning, dangling-pointer)
 
-# Variable Length Arrays (VLAs) should not be used anywhere in the kernel
-KBUILD_CFLAGS += -Wvla
+# Stack Variable Length Arrays (VLAs) must not be used in the kernel.
+# Function array parameters should, however, be usable, but -Wvla will
+# warn for those. Clang has no way yet to distinguish between the VLA
+# types, so depend on GCC for now to keep stack VLAs out of the tree.
+# https://github.com/llvm/llvm-project/issues/57098
+# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=98217
+KBUILD_CFLAGS += $(call cc-option,-Wvla-larger-than=0)
 
 # disable pointer signed / unsigned warnings in gcc 4.0
 KBUILD_CFLAGS += -Wno-pointer-sign
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250418213235.work.532-kees%40kernel.org.
