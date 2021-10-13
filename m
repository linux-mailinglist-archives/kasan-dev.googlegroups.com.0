Return-Path: <kasan-dev+bncBCXO5E6EQQFBBEHJTOFQMGQEGLQB4JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AB0742C44B
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 17:00:33 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id s18-20020a5d9a12000000b005ddc91c47f4sf2052871iol.14
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 08:00:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634137232; cv=pass;
        d=google.com; s=arc-20160816;
        b=anXOAYMRsbj+n3nOG0bCWtuiKSiNClt2S5Ab7R36/7DMtzIa/ZXFcmZr6EvJKE2VX2
         vXMrclj+oYERrjep+ySlrBW7QvnaqtNJHE6Dec5knUZYL2A4zjKZK4/7+PzQDq0lyqnJ
         HiZofJlnYZa42iR4O3e4GfhSX7dtpHCbIVwZRdalRy5X+542MBwWvRkOnuaSM1Hrfw/H
         1HWop/OyCk7EE8rysdwK0FRXzQl09juIG36gGnPWL4+dZ3X1s57iEJS+cGI92h1V9J6K
         DtYbWZk+ho/m+8xj6+LNtIdkEvtXJA9Qjr/VFUeV97p3WaCDH2JqcZllO92rb8yO4ELE
         zMow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Rm5YsW8hkXRagXPFNwYHkZwSJdEHRpNtoyx6I3knehA=;
        b=IADqrFCWUbqRgfkCK+8FoluDuhOZwVuWgffO6y60dcdyGpmcmjkhkQuD7/BMwWNYce
         VaG5ElNSg7UxeRciwvqxP8GgPDM1av9DB9ywlAwmjLwmzP5fMjYHZkGZusAaAq680uBH
         8e/MgO00nSWg4mI3DZCAZ0b7Ti6JBrvycIKWo3ZQWzMsWp8g1v72/2dhU1PaTArx9qb7
         oTB8aDpkaXrb2EGS8MWW04lx2JOPT5QnoeBhapgCDxl0SErb7rPj70uB3xpGUSaVEvS3
         CYIHtczNpdX8X5VfzjGXHHy57eRuxs6OLL/v8wpowIoAVfiOp7r2asj1tgLjWJpUdqut
         RDOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D0mhcJwL;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rm5YsW8hkXRagXPFNwYHkZwSJdEHRpNtoyx6I3knehA=;
        b=hI5JKqlvp2eGxDrf1A6mZ6W12KFHjVS9ehhvp+ab8r176g8GTFcHmKEKjxy8+WmEnX
         dX4MpoAYPq1MhBpQrlHHbAVSlgpBdqVLbBatBAbmkLAgweoXcF3R+HexMaMb9DSWNHN3
         DLLTmD8pAvuLuyPIOMHTyvLcKUAK2tpbStolBfHqVYxn9uje8Do6s8M9uHHBn2X+1ySv
         hVygtXZw7AN8Lu9Xc+CgzfRKa4pmreqLk60fzU4fUGdjy/c6QifpdznrvwtFgzBd8XVv
         KRR7AihU08zg6twRIPNNYsnxS6p5NYLfmeVWVArb+GKCrzWdHkkqk3G+qF3wTy8qG79J
         +Pcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Rm5YsW8hkXRagXPFNwYHkZwSJdEHRpNtoyx6I3knehA=;
        b=jJv8eldewbMXm4ldvbLJWeX2KYMdJwddiS9xd58h1BjLmwwmIgWxXrZsGvdjdKdIW3
         /+L3eowutcaex+r59EvvArt4eXUEBnuQfSr3UhUfq9v30CW3p8yV+n5Au764rl90jiHF
         HiZjBXIGaSxksKQUn9V4MbEGQeKXpDGm+kQZCkh7zRHICMjSAPvkifUpWDtxuMT+DF6+
         3I6lR3mt9m13cGD82hYKucwajXU8Gl/7LrUVGTtKoC20oNo5+Y6ibNeG0RJa4r2c104s
         ipY5+uwGs3sR/zAdsFdyv2eNUnr9LklqzH6a6690MGprDmnEaKufVksa8FEp2bhZ4lck
         DcCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LoDMj1Ct6Aucfzq7mHyDJDEbJVjFfS0+GHJAgXRpJ3C/jfBAU
	6emaSpc+J+zGZ50873RBuXM=
X-Google-Smtp-Source: ABdhPJwntQbrgYEZRcFWxmVITg9plOqBLxB47luOmpUmlqHjXalzJKTdD/7UlDfHicI9zWlvZmhR4Q==
X-Received: by 2002:a6b:b589:: with SMTP id e131mr21132iof.100.1634137232109;
        Wed, 13 Oct 2021 08:00:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:2b97:: with SMTP id r145ls504665ior.4.gmail; Wed, 13 Oct
 2021 08:00:31 -0700 (PDT)
X-Received: by 2002:a05:6602:2a44:: with SMTP id k4mr27968iov.56.1634137231790;
        Wed, 13 Oct 2021 08:00:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634137231; cv=none;
        d=google.com; s=arc-20160816;
        b=gryBaearfyqSKJ9YV0TNImg5CVkpFpPMqAF6D1nQWMTM9ZNfCz4pjsWVGZ38WU4obp
         PnZ/+FKPPwCz7S+vuaMvi9nld6czLHcrjbDlLXXgA3osoRm5/YsBEGvk+b2ta098zBfX
         SmXoRJnhEDsvXKtn9/pp1MiR6fqFOcA0gHzqUpDRYivESp1GYaeYEyDZtMzmdXmzqY55
         OEcrYVF/li26dRb3mIfjErYXc67nRAXbUehI6Y1pBBwqOWNRSsEVvhzTaDFZ3RqHF3UG
         PFdHhqJcfijLGjTbDBaz54+as8UZ504AvHKbumQdyDvA0EZimZd+TAKtRYF7DR07+ZHy
         jW+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Z/4U1ZtgzbYAgnHL2K329RrZBH4lvI5Au3vtocKGV1E=;
        b=bLVkuONp6OtiWD92zXiT5rfn/m+2R/64dXZoOiRbBEfMF5e37QFrgqG3ICXV4nJpB3
         6GkauXzv4MXCyrcfYXT75TgiJmwwBdLge0tOT8JR6TT6RO+N7DmTxj0XrybyjBE2rd0r
         O+E9wpe2zL+k9Ve7iPag739quTx0MB+fmzLztGU1bwg57t3nlTC50FJwZEFM4DpJwEpX
         CRO62UCJEtwiVR/rRa4NUFBBXXLS84geZyPVw0HCm7zsKQKaY2fWmTXBq6tqk+KuYLgS
         GVHBt27ZK1gh/Kml8IZyj30vb0L9M+lE5cRbTrtI92olQaTli8aXX+/q8U9KXXkgqzmM
         LVug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D0mhcJwL;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j18si1045364ilc.4.2021.10.13.08.00.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Oct 2021 08:00:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 692F860720;
	Wed, 13 Oct 2021 15:00:28 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: linux-hardening@vger.kernel.org,
	Kees Cook <keescook@chomium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Cc: Arnd Bergmann <arnd@arndb.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Patricia Alfonso <trishalfonso@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/2] kasan: test: use underlying string helpers
Date: Wed, 13 Oct 2021 17:00:05 +0200
Message-Id: <20211013150025.2875883-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=D0mhcJwL;       spf=pass
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

Calling memcmp() and memchr() with an intentional buffer overflow
is now caught at compile time:

In function 'memcmp',
    inlined from 'kasan_memcmp' at lib/test_kasan.c:897:2:
include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
  263 |                         __read_overflow();
      |                         ^~~~~~~~~~~~~~~~~
In function 'memchr',
    inlined from 'kasan_memchr' at lib/test_kasan.c:872:2:
include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
  277 |                 __read_overflow();
      |                 ^~~~~~~~~~~~~~~~~

Change the kasan tests to wrap those inside of a noinline function
to prevent the compiler from noticing the bug and let kasan find
it at runtime.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/test_kasan.c | 19 +++++++++++++++++--
 1 file changed, 17 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 67ed689a0b1b..903215e944f1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -852,6 +852,21 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+/*
+ * noinline wrappers to prevent the compiler from noticing the overflow
+ * at compile time rather than having kasan catch it.
+ * */
+static noinline void *__kasan_memchr(const void *s, int c, size_t n)
+{
+	return memchr(s, c, n);
+}
+
+static noinline int __kasan_memcmp(const void *s1, const void *s2, size_t n)
+{
+	return memcmp(s1, s2, n);
+}
+
+
 static void kasan_memchr(struct kunit *test)
 {
 	char *ptr;
@@ -870,7 +885,7 @@ static void kasan_memchr(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_ptr_result = memchr(ptr, '1', size + 1));
+		kasan_ptr_result = __kasan_memchr(ptr, '1', size + 1));
 
 	kfree(ptr);
 }
@@ -895,7 +910,7 @@ static void kasan_memcmp(struct kunit *test)
 	memset(arr, 0, sizeof(arr));
 
 	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result = memcmp(ptr, arr, size+1));
+		kasan_int_result = __kasan_memcmp(ptr, arr, size+1));
 	kfree(ptr);
 }
 
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211013150025.2875883-1-arnd%40kernel.org.
