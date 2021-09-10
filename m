Return-Path: <kasan-dev+bncBC5JXFXXVEGRBSOJ5KEQMGQE2UBM4FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CEA34060D4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:27 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id v24-20020a056808005800b00268eee6bf2csf208124oic.11
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233226; cv=pass;
        d=google.com; s=arc-20160816;
        b=w7f/ytLrwD2lkGaLGAlCL15scf7WWvmvGBHGlJiOA43dHWmH/+qi5FkHN6BC3YMGB9
         ZiSDSZGA5MHNCZ1jRGv9dxK7MOEysXuwrk7cvpmwGQs7TspfHQUlU6qEW9f6llFK3yX1
         Q6ghZ4Op+MrghQl7k+LUzIe9vhgArXLEZTt4tLVIKhEM9vlaA+GiyCxemmT66timyBxv
         YkR4taG+0e9VLNmXW0tkrBXme2I95IYbNg0Fqo8c8hb3Bqp0Uw0ISDJ1k9/LWf85AEwB
         xudp8HDN6m/ZzsQjxBmNzQqvgkVtuw+6NT2RVmor3zsXfOvqFOMU/RE+vVAyIJLarfiT
         9Lfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T7F0eFHpT5vQlz0/rvqNmVMu0/bElD/2spyUhQ5mhy8=;
        b=ytRteNxSpAp5BoEJR1x76pYuIoK6AbPymSxuHmqkOv5HfpMjVuz6zijtaH1d17yrI3
         W5UX9+XcS5dBHY0rr3Boa0sY9RGgRyD6IOGftORjxCf/WAvVd+08BfuUDCcWS6uwN+eL
         j/AoFzm0POgeuIWAnJ4jzhtSY7HHv0c05e5Im0NURcGevAEl6LVViRKbE8ZnkCnF1soA
         QZTvoQ8ieMzZ9S97eIJ+WR6Ix6qJ6ZJTCTIyCoJSf489hqWfnIz9BjeF/FGNRWmTi+B7
         ZpZMesjYQU2c7ytnGTxHWDXJUlii20Z0bMcEzvdBOLvGwG5JtocJBbnIgyAItvZoLqQl
         FOJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h0Frb48J;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T7F0eFHpT5vQlz0/rvqNmVMu0/bElD/2spyUhQ5mhy8=;
        b=NAvd8lvN3BYlSEX3PX7Oc8ClY16tGzKRBbm2OsaAGA0HL3pAbbG4OrrN/9E3BPsWbq
         9fL7tF4abniaVse/YehsROTGAToHQLmYhRQmQwpE/JBUlHF+juOSNg7DhDwqEWIA2WS2
         jlNLGzAWFcvrwjEm4YsG7AwwxzrG4R9n8i0ZPekqAGjNZUA9sUddr2cV9bpEmgHZnME3
         JfpgBYPrlGnmO+Tdn7wPYwYSVubFrHQ+1d73+hoZaFaTSfoYPcegnAUzrYhoh1NbIK5g
         833KCQNCe0+EK5BtH7EHoMaAo6BoOn1abazSiXQ1GqmHKVWJZN9q2VpLkZJDkCl3Sztc
         l5Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T7F0eFHpT5vQlz0/rvqNmVMu0/bElD/2spyUhQ5mhy8=;
        b=Ch1OsKekTTbyJy4PNx33XVpCS4+/Ydk5rGbLOq3aTNqtnOSXs8e1SA2ojbi3GRudzN
         /8/EFgqnrEymiC/h5sICk1lubTHYTAURQ0PA43Q14IEthjkBPUCMkbATZhnyLT8BIo4B
         AmR5XyF18rBWPvi+VVytIUM/Qlch10UHi+xUMTc3mmCClI7YYf71bYIyo0aHHjmud8Lp
         KltS9Y4gunflzOykPq+ukI7LL0g6c8jhhxxcY6H0e+lWYqtLS3YsTlKtfCcsSvIjDOzD
         YCAtA7Vr5RDK7A66/XRkDzwn/n8OJ36ij3c5VHJxt1NA+2lKZ3PxJuV3ig/ypuhGMZTL
         q+Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G3ggeyq7o2ewDIMp/uqCTRHcr5/1UR+sHq6ldblDNZHAZx7Gt
	Scl6VpUDnlyS0rAFWthLbXA=
X-Google-Smtp-Source: ABdhPJwJ1DFJw4cTgfpx1rSYAC/uLYPFvDj6q/IBEguRw6c60Gdpr13v+jqWu+CTLhYuMWxz+t7N9g==
X-Received: by 2002:a4a:db86:: with SMTP id s6mr2127151oou.58.1631233226042;
        Thu, 09 Sep 2021 17:20:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:354:: with SMTP id 78ls1076884otv.8.gmail; Thu, 09 Sep
 2021 17:20:25 -0700 (PDT)
X-Received: by 2002:a9d:ea5:: with SMTP id 34mr2223736otj.258.1631233225664;
        Thu, 09 Sep 2021 17:20:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233225; cv=none;
        d=google.com; s=arc-20160816;
        b=WsrcbKwOgq91YwDYm6wUACApPLqa4wZSlELZ/4dQds8ZSWqVB4kxWHelVWv/mc01+3
         YtsPYham6BaUf955Ge5H8V0qUsxFspCCwxeAEpmExA/0tiT3XOZHRgoO2E9jTOjQNscY
         BsqnAlkVpMHoVn04aTAn11VPHYZi5PSnZhaT3oxGTzI8+4YVhsuXzwvdNRVsc3saCtgl
         OJnIkZHF9tNLfWMVC7Z5oYILpyrxOfRf1BjRA67Ht0vTzwOwFggWimiMAQvppL05vkjI
         y1k9HB+cSN7VjOraaEMeZ7BSHWibpOd0Hq6MjUXwzUoy3ERS70ycLsTpbagX7zERfVmc
         gxAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q+RweFKyKp8qtsTxLGSHLb0pdUmr0gK0TikvDyUcYVU=;
        b=hqeJtb5letpFjhaXuojLyqyiwkv9UJi1BjuujQQtws1BRojTyMr9hE5y8mDT7numkm
         paXvYrXEe7ABYmQ9p0S2LGUiwlE7K4v/OldWeZInjUWYLcN/dJbNom0p+glbItcYeLn7
         TuGJ9evXG1B41km+MR8nFQc+ss9kF+tIuaBSsJK/KzNbqI+ivQYmejMMUvAZiQ7laMSg
         Bi/w8QHfoDNhFDXhGCM2JyfX17qRiTRdoFg8uBuWa+bMzc3BBzJaohGvmYO6lPKYPpWy
         cgXNePMWPXTPnh7VaKICIppwy9gw0oQ8pia2/rEKJuCNXKcNxyYPeohuQTH5PwoJgvKL
         Wu3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h0Frb48J;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bg35si439058oib.3.2021.09.09.17.20.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CB54C61167;
	Fri, 10 Sep 2021 00:20:23 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.13 87/88] kasan: test: avoid corrupting memory in copy_user_test
Date: Thu,  9 Sep 2021 20:18:19 -0400
Message-Id: <20210910001820.174272-87-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=h0Frb48J;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit 756e5a47a5ddf0caa3708f922385a92af9d330b5 ]

copy_user_test() does writes past the allocated object.  As the result, it
corrupts kernel memory, which might lead to crashes with the HW_TAGS mode,
as it neither uses quarantine nor redzones.

(Technically, this test can't yet be enabled with the HW_TAGS mode, but
this will be implemented in the future.)

Adjust the test to only write memory within the aligned kmalloc object.

Link: https://lkml.kernel.org/r/19bf3a5112ee65b7db88dc731643b657b816c5e8.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan_module.c | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index f1017f345d6c..fa73b9df0be4 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -15,13 +15,11 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
-
 static noinline void __init copy_user_test(void)
 {
 	char *kmem;
 	char __user *usermem;
-	size_t size = 10;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 	int __maybe_unused unused;
 
 	kmem = kmalloc(size, GFP_KERNEL);
@@ -38,25 +36,25 @@ static noinline void __init copy_user_test(void)
 	}
 
 	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = copy_from_user(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = copy_to_user(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_from_user(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_to_user(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = strncpy_from_user(kmem, usermem, size + 1);
 
 	vm_munmap((unsigned long)usermem, PAGE_SIZE);
 	kfree(kmem);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-87-sashal%40kernel.org.
