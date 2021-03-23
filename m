Return-Path: <kasan-dev+bncBAABB3WD46BAMGQEYX5I3FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F5EE345E59
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 13:41:19 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id o27sf1712902pgb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 05:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616503278; cv=pass;
        d=google.com; s=arc-20160816;
        b=T9Ae4CJb49i+2RFWRsr3C+FqxzGz6UjU58BNHXJv1rNwpF2Lmatrb42EmppwGAeDnL
         SB5nqPg8BQR03aqRqr6KfJ/K0QDUodnnwIbgRox8ccuIqPdipdGm8Z68dI+B7jNBWwiR
         h6VbSxTt+dmh+XBrlF90rvGGGX8ZXgaW8Wggxw0xMmsHDtrg1pvQQDhTz+5tJ7Cgrhw9
         bm+JvHBPf4wLb9OcMKrOEjjiuDzYclK5RgYlU/gsZmH21QpfXDRTCy48ru2oinDKRlk9
         lHMx80IjEpCiGoATRSkaiSCuF+NTEmxiMcUDhsCId6ZSOWlv739MTvfJLtVf7kFiebLR
         mqLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/YlWwdARLOc6eTWgZh5o/Tmz1FNyEv5v7OT0KAfR69k=;
        b=SnakXQbin5gLpNmuIMLzG5mtthqzxanxTbJVTG0s+SqK2qGMtSegFntRg1uwgra+SJ
         ycD49xnhI0Tvk3JmjAfrBwTCqaiG/+VLx9W3FCS9PFlh5QRBhHfDSfenM4h9PhNm7KSD
         n0t3BRA/TCi2yzAajCE6ceyZ7aU1SyAt7dY2IKUVcyQrs4RvecZegdYa9gTYB/Eu8bT+
         qBy8dIk9bUx70YinMfMIrfOtrWN/I4Oy3oDa0MtQqfh3H49c7Im2NqEHCOHiDM7Mt1DA
         ws8fizO9ZkzQm4aaHOTXNRaATdKVfuTnH/MLho+loULBSV/wHOx//h1/K6mmKT0llwJ4
         YBjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tz0RmbNA;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/YlWwdARLOc6eTWgZh5o/Tmz1FNyEv5v7OT0KAfR69k=;
        b=nuZdRDD3qhnOG8XMVB46sxFdIgBXr6CygkD9wYg2hqoQMol1CA0skg3NJ8sJ5aNPBV
         NMPVWPTlbEf8jngSNpJc+Vuby2uVAynpOa0mSr7E/6aB4RY+a6x2QPIPgRmtS8XQ6Ljf
         /ECqvw9jG/jOKLl3LyzXfu4jLxw7dRBj731iZ/SUJ6/9GNUVsDysFyhEUDzwkt684mgz
         DLGclsE63MSoFyxvi05RNE67hXyNuxVk8fLlZQAuu8tVHqi/4U8k2kfmbILErrHO2DxC
         MV/G/IyCEACCznpnSzPwEiW3Sp6uiayVuvLV/5v18daZZ65QNHcoOgQCnxpJWDta0WnW
         M7ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/YlWwdARLOc6eTWgZh5o/Tmz1FNyEv5v7OT0KAfR69k=;
        b=s30LqKLZZj2jW8Fa/CUSBo8TR2hx9REDB8+AddgDa2/cST9mQyAcsTDZmMOU9eUuEK
         q5QFvqGjqlpuKb1Zt5a0q/WGgtyNQ6crxpORMftcUtKV9OusyR63Iw1WwFcPpJDlg2ql
         nDSRkE2rD3JTl+MvvzQJTxwMQRxag9Uqw8j/pdXxWutMetpyKu/RF1CLk1JFDKsX7us1
         H6xc+vGb+AVjH/iq74o+NuCFFQcvnKHvmsA4NdmoOiVK5PyumUa8+vPJ1l+8v22mGZen
         ETQlnLG9RQvFCGxOzIdMeU/RUahkaKQFP8GZ3B9RWfO9wB8NGF8HTI2xfW6QWQpVZQpC
         n9QQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DqgL2ZaQJxmkk3jTzb/o+urYQoCpPu3kucIE5AR02GqfZz8H4
	JvnOOx2CauBouAR0FR6bQ6A=
X-Google-Smtp-Source: ABdhPJxkn/Ny81H1pRW9xfLJ23moyHAQgwNY7z/54mrm+FNrcxkWfPVpu845f1B2MvumbbutD/Y4MA==
X-Received: by 2002:a17:902:e54b:b029:e6:b39f:63ab with SMTP id n11-20020a170902e54bb02900e6b39f63abmr5610704plf.55.1616503278314;
        Tue, 23 Mar 2021 05:41:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5302:: with SMTP id m2ls5530507pgq.5.gmail; Tue, 23 Mar
 2021 05:41:17 -0700 (PDT)
X-Received: by 2002:aa7:8f30:0:b029:20a:20d8:901a with SMTP id y16-20020aa78f300000b029020a20d8901amr4324733pfr.7.1616503277888;
        Tue, 23 Mar 2021 05:41:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616503277; cv=none;
        d=google.com; s=arc-20160816;
        b=nZKi2Hq7iY30IiFCaDfjCffTX6nhQEpQDV1gDZu7ce/6S/jDVus8hXASarayZ3JOjF
         mjbudZTByCp1aLVsy3vtjkSCrDhP6QYIRX89ruds7QwfO/zavljqCBfzzujuym8elanq
         asjbJqAKA28sK91HMj9Cpb88esu1j3rMOn4NFMm30MarWlvBH6YP/OZlSNHXQuXLT2jJ
         cPhrERyI2n4GHt/V3NX6E6I8c+lYgT7FSY4C/E1oebgP9hTTe+tIPix/wmieE01ZUgBi
         Ha8OWAhPEUpLRbr2gv1lMUlMwGfS17XzSOrXFKn7Re+L5+Cr2FSJM13oAArmu7nXpPmn
         CXMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AigYVio8j3jcDJrytHMY3xAl7FXaX/MjBRD0+d6keVQ=;
        b=jI0QkM6z2Ih5266OY00rrinW+/eZSrRB6jODNo+j9Sh+V+TG7zAlYRBwgHPNgslPI3
         d8ElOPE0FMKoE4y9J4tIvBZj1D80JdjpCgRQO2Bqf6qdh/LVyNfzWFQhLeIPn/rVxsZH
         1l3l1tzg6zbzSHwR3A56yEMaqlnFHU/RwkPWCXN4LbvXFRW5cCiE8DxkGUiIMzcemDAV
         79I77qONY7A+DKqf3gcX+CIht2/fERJ8oqRd7wsCyax3Y2dFDFaGt6EHlj5M3QSLiMfU
         u1K8kGHa7rHDUtRYbiMA1DiVnVE2J53e2YMkatLXcykOM+74+Ae3NsK0IT5qYdIoz7FN
         JKag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tz0RmbNA;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j6si99402pjg.0.2021.03.23.05.41.17
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Mar 2021 05:41:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A7790600CC;
	Tue, 23 Mar 2021 12:41:14 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH] kasan: fix hwasan build for gcc
Date: Tue, 23 Mar 2021 13:41:04 +0100
Message-Id: <20210323124112.1229772-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Tz0RmbNA;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

gcc-11 adds support for -fsanitize=kernel-hwaddress, so it becomes
possible to enable CONFIG_KASAN_SW_TAGS.

Unfortunately this fails to build at the moment, because the
corresponding command line arguments use llvm specific syntax.

Change it to use the cc-param macro instead, which works on both
clang and gcc.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 scripts/Makefile.kasan | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 1e000cc2e7b4..0a2789783d1b 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -36,14 +36,14 @@ endif # CONFIG_KASAN_GENERIC
 ifdef CONFIG_KASAN_SW_TAGS
 
 ifdef CONFIG_KASAN_INLINE
-    instrumentation_flags := -mllvm -hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
 else
-    instrumentation_flags := -mllvm -hwasan-instrument-with-calls=1
+    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
-		-mllvm -hwasan-use-short-granules=0 \
+		$(call cc-param,hwasan-instrument-stack=$(CONFIG_KASAN_STACK)) \
+		$(call cc-param,hwasan-use-short-granules=0) \
 		$(instrumentation_flags)
 
 endif # CONFIG_KASAN_SW_TAGS
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210323124112.1229772-1-arnd%40kernel.org.
