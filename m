Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH4AXOPQMGQE5QD5PCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id A669F69A297
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 00:45:37 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id kc3-20020a17090333c300b0019ac36d3fb2sf1815531plb.20
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 15:45:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676591136; cv=pass;
        d=google.com; s=arc-20160816;
        b=k4NWwMhwYPmR4ozEV3k6uusB3pSV0yAVgaLbqG79usWyYuNHK8z1KX6avK59+0zeY8
         fPNfgx0ABPW0FVDY0VzHwXxunKQeDaMAB1W86Jol5XvnYyALJzmqm8NyTx4c224AZXyh
         6nYuVY2+E24Y79yS6ss/DqV/0P8AH0s+YWo+41fGb7h4GPaHcdrrW75H9M4MkbFMN3oq
         YTlTR4fQJpZZSLmN7pxseIU5B8id+PA9yhWnWTDESyyqtVWDPHIZSBLNskRzz0TAYAzE
         K92TLc7klPFuEcH7SvJnfTm6oPZnt548gHYXylB1urAmikBx+2/O4iY718g24wA4jOtf
         zDKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=g9hsjXXz+bV65OVfHhcuisbDPn02Ytn/iKMVIqg8Ul0=;
        b=NvPCRhJQQbPtim6I1qjQHx38A4iN0gZ0hNq6W1WqCKYM9v9w78jzQ8uKagwCx2jscp
         YH7MzvrxcJfV/BwatZCjrbqSU0P6eabxJ4z9PvX63ZHOPd6vl0C0XX7X0o7FbL9DYLrU
         51mcZ1VVI71xuCOwOGQW0uBiC2sxclqsVWcX7ys5vojdApWkPvsl8uLHOC+NnPpqLlzX
         Y4WkzomkPwbnQaDdR+uGKNB5+cDlzFv8qIAhGLtVUJivat8aQ9M7ooT3XI4nO1LnrZAQ
         LF6ArGxA6JtkS8hb45dFAg4z07o5y0g0iBaGyEjPAo7eO5a9Zyap50iYX6INCNcpRtSf
         nmRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T1m8J9zu;
       spf=pass (google.com: domain of 3hsduywukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3HsDuYwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676591136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g9hsjXXz+bV65OVfHhcuisbDPn02Ytn/iKMVIqg8Ul0=;
        b=mgoeIPBy2F1n+BxPbJHKSEI2fzxOpKAoCOwewHRhmeUADQX10CJ9eFMVM0+7c5TLQf
         CamfA8hhZAtyBP5Uj9iT2BWmllS+8oiE0m2wjvQI2zpHxHprStD+S4Fdvi/T12aTe+G+
         hVJ3ptu1bBqG2M4G7TZiaUD8o1k6SKoh2XbOER1tiAzswK/BXUmnvPSwwTyzfGCpbrRn
         otPwY92YgHGCL0tRP12EUGgz7yqSw6o/w+bVnjxL4YUX/ZY6XmfaBVeas89nfBvhH6Nt
         v4H5yyQBvf9mX9x+GqfmWibwWJKtc83s2+uyhAhL1YbY0U6OOvOhPSvnCoCdBE1aGZiv
         2mDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676591136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g9hsjXXz+bV65OVfHhcuisbDPn02Ytn/iKMVIqg8Ul0=;
        b=QeFIVeo6jK9udh+eMQnkbY9X2VHDdjei9CZL8azD1wFKj7XR564vha8z0ixNSkPSD+
         s8Fnhs3wco4wLVsyMZZwLTOLJbGEgObXiNNxorR8YfPDnZjJb8oX/30VO4cASY5mKvO7
         bO1zDmbSXHM3uUKXJdD1plAoJhgWKKRCm+wkiUFPQjdyifaADKhpr+5MACjw62tpHZy4
         a7l/CTR2fcnk+EmtapYZp9+tCzycJ66vUlUiZUjB/qWh6RTa59EcFGGe+3d7D1ovCv0y
         pMeAj/ces5omjtUKP8yx06DNDCPS5G4CcQdoeW9lscjUh7qHj5Y4D/ujtctdSHuEcIPn
         NAXg==
X-Gm-Message-State: AO0yUKU2G3xIdmkK9dEfG4gHD21K7VmJ/m2aME7htv6oGXBuzsl/k8FY
	1PDOr8xoRYVBl3ovoJW46Wg=
X-Google-Smtp-Source: AK7set9Oi638MEcluyws37WX0jJdT1W0IT4NDzTh1Ml6K8Rusbvc6xXF8xIMItwu3/8HFs2DfLfH8w==
X-Received: by 2002:a62:79c2:0:b0:5a9:bd53:eff0 with SMTP id u185-20020a6279c2000000b005a9bd53eff0mr374002pfc.56.1676591135837;
        Thu, 16 Feb 2023 15:45:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f68c:b0:19a:9972:d4e with SMTP id
 l12-20020a170902f68c00b0019a99720d4els2121972plg.6.-pod-prod-gmail; Thu, 16
 Feb 2023 15:45:35 -0800 (PST)
X-Received: by 2002:a17:90b:3502:b0:233:457f:e71c with SMTP id ls2-20020a17090b350200b00233457fe71cmr8888407pjb.38.1676591134943;
        Thu, 16 Feb 2023 15:45:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676591134; cv=none;
        d=google.com; s=arc-20160816;
        b=x1h2BQW30K9nmoTWFLIp/YW2do/haXyzvdxulqnTjCFrf/KwgcahZBodTYsImnTEeI
         HD4+iHH9zBczw09rt5xeK8eVYTQpoT/6YYEDSrwaoPtSOJgAseBxGW/I4AyLvveJxgnZ
         YCuB0CbFkILx82Ubr6Cfdnid19IAw18+spllFyar/6Fcf7XY4W28FmzlkvIHG/34fGif
         5DqAxP90PCu5GsXZ18Yz0fVJVVi189/+3TYUpiCHBm3mhtETCKVtJ/hrWzYW3yK9avAv
         H/Mnffs8/JMVTS7+7gkIyN95i7Cgaj67IxKtA6+nzFdjugjV6ZaylfulVI2HIQ59Eat6
         GIdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=f9fSJ8LX1LV0NJhDIu0hFxwhZk7Rq4zVsb0PZTFK4Co=;
        b=KcsHdhXJlSWaYFb192EeGzFpcSsBZuyOImOutZWCdZ0IpG4+27qUXZiO77po6mHspk
         oSmslFixVOduftwEEN0Y1cKu4LcxsboEOLcahYRrmZxoD8IdI4bP2voRYp84WG0UfSia
         NcgOFUFFhKN+mEjNZX/2Xjb4HxyWfrNqHsKF1umwvMI3cwnoXqbQsA3c6C2dCCBsCzxk
         tj9p7DGaJYM7RudmV7eYZdvS1p1Y7eO5Ol9v0uD1ggAnFhIrtGovB4VbixqMASL+uqly
         +QuQgq9IDwHQF2Jt6znU4GQoeBaH5KSsdJnkbY/nnAr54A3bPVXdgLyVDj1e5uvVMVfl
         kGbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T1m8J9zu;
       spf=pass (google.com: domain of 3hsduywukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3HsDuYwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id s3-20020a632c03000000b004fb840b5440si177721pgs.5.2023.02.16.15.45.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 15:45:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hsduywukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-52ec7c792b1so38459657b3.5
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 15:45:34 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:34a3:b9c:4ef:ef85])
 (user=elver job=sendgmr) by 2002:a5b:6c7:0:b0:8dd:4f2c:ede4 with SMTP id
 r7-20020a5b06c7000000b008dd4f2cede4mr5888ybq.2.1676591134138; Thu, 16 Feb
 2023 15:45:34 -0800 (PST)
Date: Fri, 17 Feb 2023 00:45:20 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230216234522.3757369-1-elver@google.com>
Subject: [PATCH -tip v4 1/3] kasan: Emit different calls for instrumentable memintrinsics
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@kernel.org>, Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=T1m8J9zu;       spf=pass
 (google.com: domain of 3hsduywukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3HsDuYwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Clang 15 provides an option to prefix memcpy/memset/memmove calls with
__asan_/__hwasan_ in instrumented functions: https://reviews.llvm.org/D122724

GCC will add support in future:
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777

Use it to regain KASAN instrumentation of memcpy/memset/memmove on
architectures that require noinstr to be really free from instrumented
mem*() functions (all GENERIC_ENTRY architectures).

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
v4:
* Also enable it for KASAN_SW_TAGS (__hwasan_mem*).

v3:
* No change.

v2:
* Use asan-kernel-mem-intrinsic-prefix=1, so that once GCC supports the
  param, it also works there (it needs the =1).

The Fixes tag is just there to show the dependency, and that people
shouldn't apply this patch without 69d4c0d32186.
---
 mm/kasan/kasan.h       |  4 ++++
 mm/kasan/shadow.c      | 11 +++++++++++
 scripts/Makefile.kasan |  8 ++++++++
 3 files changed, 23 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 71c15438afcf..172713b87556 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -637,4 +637,8 @@ void __hwasan_storeN_noabort(unsigned long addr, size_t size);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
 
+void *__hwasan_memset(void *addr, int c, size_t len);
+void *__hwasan_memmove(void *dest, const void *src, size_t len);
+void *__hwasan_memcpy(void *dest, const void *src, size_t len);
+
 #endif /* __MM_KASAN_KASAN_H */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 98269936a5e4..f8a47cb299cb 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -107,6 +107,17 @@ void *__asan_memcpy(void *dest, const void *src, size_t len)
 }
 EXPORT_SYMBOL(__asan_memcpy);
 
+#ifdef CONFIG_KASAN_SW_TAGS
+void *__hwasan_memset(void *addr, int c, size_t len) __alias(__asan_memset);
+EXPORT_SYMBOL(__hwasan_memset);
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__hwasan_memmove(void *dest, const void *src, size_t len) __alias(__asan_memmove);
+EXPORT_SYMBOL(__hwasan_memmove);
+#endif
+void *__hwasan_memcpy(void *dest, const void *src, size_t len) __alias(__asan_memcpy);
+EXPORT_SYMBOL(__hwasan_memcpy);
+#endif
+
 void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index b9e94c5e7097..fa9f836f8039 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -38,6 +38,11 @@ endif
 
 CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
 
+# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
+# instead. With compilers that don't support this option, compiler-inserted
+# memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
+CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
@@ -54,6 +59,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 		$(call cc-param,hwasan-inline-all-checks=0) \
 		$(instrumentation_flags)
 
+# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
+CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+
 endif # CONFIG_KASAN_SW_TAGS
 
 export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230216234522.3757369-1-elver%40google.com.
