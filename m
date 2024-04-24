Return-Path: <kasan-dev+bncBCF5XGNWYQBRBYUUU2YQMGQEMDOX6SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C5048B1645
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 00:40:36 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1eab0209165sf218985ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 15:40:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713998435; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lbs1rL2wKa5h6cY2evZe2W+z5um0B3UDVB5OQCYrzrot0zJsFN81FZLijWQEHzxuqG
         kuyDRT70LH5TE7pMSt8mYB6w0SVk/n60S7eT9rbGs/wHIx/ZONcx4QcCVrm59cQJDlQe
         LS3emPKxcFKkg7b2ps3iE3X/p9Pa3mcZNsiVDus1yngbANfeugieGZ5vjo16Iv96XH5h
         aiuXFuWEcBmpbeQfOZeT6/g6mDshC3BUoADJ98waKxdztDEFiMUEey65GgtHWe3G4g/R
         T0YiSIv6hDootNR0UWobw5OnaSwcUMtXuZvnTPRGb2W1bS6PcCcMnhm1FCPtBJKEtEwY
         ZjkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dzHe3zIY3B0/K3kCgPjBgPN1ei9YpXpgoE/kt0W791Q=;
        fh=nOcz4LtuhrGtj6c+6MUSxHc3ZSvB08WCA9edxSvhTko=;
        b=Ic7/cNnFC9bDiWqDujom3Segjk0kdDJIKvRd3/I2HbOF/5gE/MFYEC9QN4L2v3ncNf
         sb8+qM82TajW/JPXsy8ICZJJFrjiGC6pjdv5c1ICc4jsK8dplguC22MWP7YYrE4L3GjY
         rv7/IligGZUEkkVv05kTkw3PJA61TiuIolkhfTlkQoNdx+YD2m0og37+LWq04P+ltzxV
         Dr0m6Vtc4N7nsrbkxa7XopJ2dUtqjGRUTKXbstZkh2Ne6l42eTf5cF4AMuf1AA5HTjEy
         YhFRn04AV4b81y3K/R0KenI2bfWVQr07GrZ3v19127BjpDT2ueTSASdxdw22qIR9hDaM
         CB6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=A1uThsLl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713998435; x=1714603235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dzHe3zIY3B0/K3kCgPjBgPN1ei9YpXpgoE/kt0W791Q=;
        b=IN+XNCLyxcX5BCsm61SqbqptMRHYjyjoh/QwrrciE6dt6eTcsuYq6jRCacTX9ugIOH
         4cSE21imVUs0KsEeLMG0sStzROFrKgHMAS2YeElTOIfT99Xsnr2vIO7Za1Nx3C91uP73
         pA0fCgAM/jRCdvKVTJwHO1PQw84GSoeytXRqWtltqKDkUEN4aWdL1fEJoTeXcsro1kVP
         vpKEGweEMQdZtA5yskGqiP68vTdAuA2/zY5akbNk/4/Lo6qQpQpqg8Agdy3m2Yaj4T/l
         csATKGC7mT3rbeaoJplAg72vA8+5rE9JedjdyttQnnFww1Dzmo3u+PI9A+A/37P1I8/6
         nKig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713998435; x=1714603235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dzHe3zIY3B0/K3kCgPjBgPN1ei9YpXpgoE/kt0W791Q=;
        b=HSBIrwBBauu4Lt6Ky/bVp1chYmMG0d/pmn0Zk2Kt+sgbfuLRKpNt1PFe42fqGbNsF1
         QUCQzg8wRRsx7XxNO6Q9nbrQS7WsHu5ETnVm9y/uIIA/7sqlf4n1iZ7qoqGqxzLsijpE
         XTZ20BrchhGyIvyVAw6fAcRsZujs8oT4BXBTlB4f+WxBK/l4/Jg0FyEh27uJT34VdzHj
         X/hmujgvqk1OoNrMjrPx6NmaBI7UUkXYFlfH0omfmij4rWUWjRP8h4gOxytP7SUDawVY
         qDqZadVWxy3onTPDchPJ8T8j+6vuuIXLtLy5kQelgveHg2PFiM5yzfXwIBwxSSuuo90+
         w6fA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDpYmyWLZjLTooZof0I4WPFpoZ511C52fIYbNYtGRZ+Drb42STI2ePzaBP/U/kkxiq8lyDZPQpZE1jqUUUKaKwHDTJlNNxxA==
X-Gm-Message-State: AOJu0Yxs3u/ERr4E1uuCR18ojNV3LW3NGAZijNB6HYduf1ERZUGuHhZZ
	6nU7aR6tRb0MaLCZjErllzfJRTrHEzazYcE5xo38ssQyGm4dyIpo
X-Google-Smtp-Source: AGHT+IF1mgK7eosJXZTzUL/2GIKbl7bf1iCPbv5mYRnBJqFUerRfO4fSeCLRvMVlbuzw//UQLEilCA==
X-Received: by 2002:a17:902:ea04:b0:1e2:573:eecd with SMTP id s4-20020a170902ea0400b001e20573eecdmr38320plg.3.1713998434649;
        Wed, 24 Apr 2024 15:40:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3d0c:b0:6ec:fe13:95c with SMTP id
 d2e1a72fcca58-6f3c8a919b6ls213246b3a.0.-pod-prod-01-us; Wed, 24 Apr 2024
 15:40:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWWJxAtDeXWofcOIXJikkgLTPpRlzHnw9kezQolGwFjiNPqB8gfHk/KDD4EMLAFq6jTeRCGJp67uSGuexXiH7wHY64KXSLRwiR2w==
X-Received: by 2002:a05:6a20:96c3:b0:1aa:59ff:5902 with SMTP id hq3-20020a056a2096c300b001aa59ff5902mr3894343pzc.9.1713998433412;
        Wed, 24 Apr 2024 15:40:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713998433; cv=none;
        d=google.com; s=arc-20160816;
        b=tNgbc8yqEnkWd0bZtsFtox5x55uBUFmmS5zANuk1w7K1FMK7KXSi8083E+Kgkk+jIe
         Fa/KHPgidnYPY/LKmXuyEZLXmfxKQSM0qdpJ67Dg6HUawXTbbPR32KvKxWutAeYC0PPb
         5h9sSK6tLX0Gjn2lDyiuKIx33arHEwOkwz3C+c5IkUVBHiBNYOAy+cFAaVkEAHVvGQck
         mSr9jF9BSs/KJSDv1mbf4xTAvQSvmgjwJI/sN4VHlOtzruswwOmM6VKhAFSqd8n7STOS
         LIykgG5KKpaEKmw8qL+fiRvPDaGB4Cwnjai422qJj4uIoG2hreQPL2g50BvelOhcMKqa
         6s3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=JTbZyDAE7D1exiHp1TgfWwHZGetvSM17QuiylPP4Ugo=;
        fh=m/xV2/5oP2D4dNLe/Gk11l/MhZEQHbN7mrqrh866buk=;
        b=E0kbz1dfzTF5qC8bwHxwn+K19HCblgcWEAoIKGD+Pa4bdGN9fx0VD7+15LbE+erZMQ
         v89ypYt1jLfwTCYG70veDyy6+9cVMaddB6871+XFCfSRdulKERNem+raE2MM7c3mfAYw
         NPiusGVywh4A4cUmsu8gXnAJP+bFwJJeRZU9OK1X1xyF0fFG5GgwT5lXv4o5FETgovs8
         D6iIKMrSkpPp9/ZP5Y5LMM2wLVBGRX9/kFM8xCo0qzlpJCcCOmux+A1KRb2ZTQqNRACp
         0PuWGkmu2nvVmImLU/03ybAGN5tPa29it5cg840Li+ny+svP7iypBalklcOu2Prz/np5
         9ZbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=A1uThsLl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id a4-20020a17090a8c0400b002ae70be297fsi69336pjo.1.2024.04.24.15.40.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 15:40:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id 5614622812f47-3c749aa444fso276493b6e.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 15:40:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVqTKKl7bSWMGgEZoJKdCj+1q9Lfri0C4F3HDXtjAdDnSrMvzT90pGURT7XyDKmyrfKTK6ThYfluvRucOPmagNqnq4HadSUsAjF9A==
X-Received: by 2002:a05:6808:6146:b0:3c5:e81a:b5b6 with SMTP id dl6-20020a056808614600b003c5e81ab5b6mr3457731oib.59.1713998432715;
        Wed, 24 Apr 2024 15:40:32 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id q24-20020a637518000000b005dc4b562f6csm11655715pgc.3.2024.04.24.15.40.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 15:40:32 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Erhard Furtner <erhard_f@mailbox.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2] ubsan: Avoid i386 UBSAN handler crashes with Clang
Date: Wed, 24 Apr 2024 15:40:29 -0700
Message-Id: <20240424224026.it.216-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3862; i=keescook@chromium.org;
 h=from:subject:message-id; bh=S6pSKGU1vZkqsA6JyZACfXvcQXgSDSwKOAh1iNHOK7k=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBmKYpdOvL4ycJZMfmelPH56Xu+0zUCHN/li7yDD
 JlCQAIXtpKJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZimKXQAKCRCJcvTf3G3A
 JsthD/4qvBqX1FE7+CepCN/bUSsdc70zA3IoR9J74pMA+cDoufvy18SuqrI0QlPCbAV5PeKztge
 gzibb8xd36rAisAJKA0utmRkVAydrRwbmjUFVD79yBBujbfyNlK8mqPsmCr12I9QlHdXgxxmzxE
 A5WfXC0Mbp3BegjRlKorI0bVF+zZWYjG97ThyMxlUrdcabHqXdWFd9SG1iQ97Ee0Za9QRRRyTbn
 YdM2Zslm2eF4PHkTiUJkeJphrHtXmEVaC14vmKIcjDJ2QneeeP+Pg84whwO6ACNLtMWA9Gd3/F4
 h2zrUXv0HRIS/0lxYFm9jJyRfUndtgLpAA5jHq8vVuwYFys9z0e/TRGt3HNdbXmZzqJLkd3lW7U
 A13vTr2W7Btz+q7N23001OYIcFSqsnNpu8njFOauxcB/Pc9iNywTi03uFpjYQUyy/mfTp1bgV7x
 Hk4rNT49RY+kiA3pt5TZ9+aT9n+raRjt80v/j8TD4x1zi6/p0nT/0EG6ObbiJv2GdzF9a/AcgDB
 3Um3HWzzyCD2aL/HebIwG30sZZ2gbPO8cGU7REXohAIk7OWKGavgZLd1ggwZoNGk5dhd0V03o0K
 zn98pxzl3fqDdXgn1zZXrpNUj7pk2e4a/s0FsZNdqV2jYJ1Khhu7Ncyqsjkelvd9ho56XocxX4e
 fljUYFZ Og7QZA1w==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=A1uThsLl;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::229
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

When generating Runtime Calls, Clang doesn't respect the -mregparm=3
option used on i386. Hopefully this will be fixed correctly in Clang 19:
https://github.com/llvm/llvm-project/pull/89707
but we need to fix this for earlier Clang versions today. Force the
calling convention to use non-register arguments.

Reported-by: Erhard Furtner <erhard_f@mailbox.org>
Closes: https://github.com/KSPP/linux/issues/350
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Bill Wendling <morbo@google.com>
Cc: Justin Stitt <justinstitt@google.com>
Cc: llvm@lists.linux.dev
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
 v2:
   - use email address in Reported-by
   - link to upstream llvm bug in ubsan.h comment
   - drop needless /**/
   - explicitly test Clang version
 v1: https://lore.kernel.org/lkml/20240424162942.work.341-kees@kernel.org/
---
 lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
 1 file changed, 27 insertions(+), 14 deletions(-)

diff --git a/lib/ubsan.h b/lib/ubsan.h
index 50ef50811b7c..07e37d4429b4 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -124,19 +124,32 @@ typedef s64 s_max;
 typedef u64 u_max;
 #endif
 
-void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_negate_overflow(void *_data, void *old_val);
-void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
-void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
-void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
-void __ubsan_handle_out_of_bounds(void *_data, void *index);
-void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
-void __ubsan_handle_builtin_unreachable(void *_data);
-void __ubsan_handle_load_invalid_value(void *_data, void *val);
-void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
-					 unsigned long align,
-					 unsigned long offset);
+/*
+ * When generating Runtime Calls, Clang doesn't respect the -mregparm=3
+ * option used on i386: https://github.com/llvm/llvm-project/issues/89670
+ * Fix this for earlier Clang versions by forcing the calling convention
+ * to use non-register arguments.
+ */
+#if defined(CONFIG_X86_32) && \
+    defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 190000
+# define ubsan_linkage asmlinkage
+#else
+# define ubsan_linkage
+#endif
+
+void ubsan_linkage __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
+void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
+void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
+void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
+void ubsan_linkage __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_builtin_unreachable(void *_data);
+void ubsan_linkage __ubsan_handle_load_invalid_value(void *_data, void *val);
+void ubsan_linkage __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
+						       unsigned long align,
+						       unsigned long offset);
 
 #endif
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240424224026.it.216-kees%40kernel.org.
