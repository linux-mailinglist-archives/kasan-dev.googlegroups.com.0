Return-Path: <kasan-dev+bncBC5JXFXXVEGRBBM5SCYAMGQEYDBWRXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FD3C88DEB0
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 13:18:15 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1e0ac20246bsf35038265ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 05:18:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711541894; cv=pass;
        d=google.com; s=arc-20160816;
        b=HTxVKbw7CfV91TGQQvk3EUiLH8uYAWj0/TkYAjCXhx7kdVQpl9cnF9sG7J5wGaLc+w
         oTfVgV13Vku0KdDpY0CgstZ0LYAVKTeo9KpGV4GZSyOkBHk6gjps+LAJOKwMq6NBx+76
         YEZYlUlU9tA66tL4BXltMV15YyEr8+hO7h+15ZWcZIsVZxNWgGr1QoA9DUS4Aju94AFq
         FH6pFclOVLov68eomIIVPMy8NUDMwoxhUVPQ5hEArL3e3QychVp0nsijoMW5fE75/9v0
         OQrX7nu6aHlbCFCXD1RID3hZf83os9HR8dIy5ofESJNWTpwbWhrjXzxOIrEIm5zP7V0r
         pj0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=p3ksABOBy8bTpWzZkVfKRR/DgA0vF1szVsESE6ebbGg=;
        fh=1hYHYBgZaIE0PG9Nc84y65xDHRuJfDfF2qUNLCkdsFw=;
        b=LIAw4Yc2hitYvWqlAD5rIuAIYZBVuPsQPBiiHdDbl0Kj8NPmessVwFISEwNpqAEupO
         crg1CDAMJNm6tpwg5vXOqORuYWqyM1x77gjdXIlGLFt9urwc+xMZUR3+hv0dv9ay9upw
         p6QqJRcGhwS3K/4mQiiOUuacmRUDz+zqWi/jP7J38U7cEb8YrKdB+kda49TLI+TnkEwd
         NXuFJZG50y17g40xej+uYSkRfGEIAniLobYDMyuG6Dyxu9tYjwZHwrQfiFzaoNfMMpFQ
         gIqWr0t1Av/7wre2b1YUCGbVIqZA5qo/TKhA53eLD1sIdlvJsa/WjS5QGhMdTbF4uqBV
         c4dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tFRPR8Hn;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711541894; x=1712146694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p3ksABOBy8bTpWzZkVfKRR/DgA0vF1szVsESE6ebbGg=;
        b=KvzZW5Tgm96S8rlrCA9hetqSUTJ2Gc8dxiOg56lGdMnQ9ept0smFSSh+CIkdeDjASw
         0ADZrE8nS6Kx0QhMDXeQtJbw0k1bRUZllVAjyZSHmNrdYMRwa1vdv4mo7zy27BEq65Ji
         NjUtjIzaSNL8JVzGlunNBv5Sbw/bBmZMErwWfqXTKFc9WMO1Z1Q3aFrUB4tSUSMpyTPe
         Tvu/Aaae8s3RTqNxvvdzjQVEUkoI0mIL31LeR4E6CGHgC5U9bcxjUaJbNhdJXY18nyR/
         bMHkrMGZ299xMQI//7cnOhowR7iyP5mm5RBb2mBnSzBp4cbuOB+czU01xnROlKVweF/C
         VBsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711541894; x=1712146694;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p3ksABOBy8bTpWzZkVfKRR/DgA0vF1szVsESE6ebbGg=;
        b=NRgYLQhzyRKU8h1bdr0O6441o8ljjmeXf8cnpayM2wxRyGp4/0K/uo5TSFJRj35cny
         nWjUTrBzijRWWBdevmndWxew8to9x5Cswd4RGzvjpKDuItf883ggu6n3UC6UDRh3TbXg
         ujpHX9ShcqJhFz/VVNES8xo94vgSLsUrUwlBtusc6/jxxGzpVZzcBWcoeDaACiC9EnvU
         /o0+W5Gc1+wMyrj3R7p8tAdncOVLqIjjMVrEKzqLqOeVP5c+2QLqcFr/Onq67RhbvZah
         jVdyFhPz2ZLplKtZt0HhoOIegDpiotuBLJkQ5/Luw+oQtiVSdODc5FG83vHYz+g8N2A0
         7sXg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSLfLUG+kr/J74xOnv3kQhE1C3EJxnHimAPC8gYRVGDJ3sPHTICt3PP/2xk9tse+OgZwoRvGscDDNREWdjHv0fZYNKUXnuXg==
X-Gm-Message-State: AOJu0YxGQ2/i2omTDHDl8DfDL+4P9gvIJn58BdEb45hvg7RNDxWLV8E3
	2Jy6+qJLAE8iUMHos8JIm6N8Y82e9pxdJHjV6lhPU6ALUnbGgwNc
X-Google-Smtp-Source: AGHT+IHMe4+21nu54PoZFdUC5o6ow95l+ahvFRad1volnd6uMKJyaRczvinu+jafqEbTqb0EASHCnw==
X-Received: by 2002:a17:902:ea0c:b0:1db:8fd6:915e with SMTP id s12-20020a170902ea0c00b001db8fd6915emr4673309plg.33.1711541893667;
        Wed, 27 Mar 2024 05:18:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:230f:b0:1e0:b876:71be with SMTP id
 d15-20020a170903230f00b001e0b87671bels2669726plh.0.-pod-prod-03-us; Wed, 27
 Mar 2024 05:18:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVOxso1f7oOz5wAEzRsxjw0VH9W44PTeods0Cux5ZrqzUDCJxQpSUs8YdQ00ecUXIM9TsOQLyAl7hcE/KCDbRza1A4dKScswehvPw==
X-Received: by 2002:a17:902:f54a:b0:1dd:7485:b4c9 with SMTP id h10-20020a170902f54a00b001dd7485b4c9mr3193836plf.22.1711541891186;
        Wed, 27 Mar 2024 05:18:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711541891; cv=none;
        d=google.com; s=arc-20160816;
        b=mhSJ9ODgCFE7YOTfOY1BkMSEQGLksf9uQecaCNRiQrATuY/rQ6lVtQwwIUh0ECvk8L
         Pr3Eup3CbxhToy3LpHXJ8RGJbjZA4xU4plXgjSByK5K1ymwPB222gEA6mZO92GpLFdWa
         ItI1vxYixLYlHb6CEgTdMNl9bNqLVmli6DmCvFp1I5wfvf2EoIs1NfDH4tW6YsRev6wQ
         t3hfNPaZ6QtCNDj3CQvJaLg1C/PmHnwiucnYdjmQDzl9/ydnCfSWr8SFRX1I+exP3zZi
         KHHfdmXtMNfYjXak6KkU+2F7LRaRl0PitdMY4Erbha4J6c7mrz5ZlnH/QAkTmpOUeAg7
         eBkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5dc4QyZpJnqpxCMyB9x7RzSBuBxohplmczkvq2gXGXU=;
        fh=qBkFaWQOrnxqs/N6JdyMIIszgBjtt2b4Sv8dQ0VMb1U=;
        b=VtyoCZOW1YfCkssz3VFRAb4cdk8MeT5f/89XscT/+bW84fpiYChlrcLtPdhKyV51GH
         J7T7SfdOp5QhG9Dw9Uajx60+IS+00tlSy2n6YfRUdMwJEBKBrsR8XX58nV3FlV/6xi9J
         VFuFafHsMTr2nhUFl09lV/Nm6ktoX8RdlMD5VKweZ7EWprkHqeFfMFsh7VqSbrjEXAKp
         wWgdmX++cHOvtJ3+GnfTsRGnKMs3yIQwmoNgbcUyytSWW7mwebwEfceM592G4+ROw1V3
         g/C1gXPAEzM6oG1mrRp7ladJSZqeDswY+9mIs3bHVc7tikZPjJJwAkUcG1QqamF0NI1T
         CCfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tFRPR8Hn;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id y12-20020a170903010c00b001db63388676si526253plc.8.2024.03.27.05.18.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 05:18:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 145B8CE25AF;
	Wed, 27 Mar 2024 12:18:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 69AFFC433C7;
	Wed, 27 Mar 2024 12:18:07 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: stable@vger.kernel.org,
	arnd@arndb.de
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: FAILED: Patch "kasan/test: avoid gcc warning for intentional overflow" failed to apply to 5.10-stable tree
Date: Wed, 27 Mar 2024 08:18:06 -0400
Message-ID: <20240327121806.2834070-1-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Patchwork-Hint: ignore
X-stable: review
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tFRPR8Hn;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as
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

The patch below does not apply to the 5.10-stable tree.
If someone wants it applied there, or to any other stable or longterm
tree, then please email the backport, including the original git commit
id to <stable@vger.kernel.org>.

Thanks,
Sasha

------------------ original commit in Linus's tree ------------------

From e10aea105e9ed14b62a11844fec6aaa87c6935a3 Mon Sep 17 00:00:00 2001
From: Arnd Bergmann <arnd@arndb.de>
Date: Mon, 12 Feb 2024 12:15:52 +0100
Subject: [PATCH] kasan/test: avoid gcc warning for intentional overflow

The out-of-bounds test allocates an object that is three bytes too short
in order to validate the bounds checking.  Starting with gcc-14, this
causes a compile-time warning as gcc has grown smart enough to understand
the sizeof() logic:

mm/kasan/kasan_test.c: In function 'kmalloc_oob_16':
mm/kasan/kasan_test.c:443:14: error: allocation of insufficient size '13' for type 'struct <anonymous>' with size '16' [-Werror=alloc-size]
  443 |         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
      |              ^

Hide the actual computation behind a RELOC_HIDE() that ensures
the compiler misses the intentional bug.

Link: https://lkml.kernel.org/r/20240212111609.869266-1-arnd@kernel.org
Fixes: 3f15801cdc23 ("lib: add kasan test module")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/kasan_test.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 318d9cec111aa..2d8ae4fbe63bb 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -440,7 +440,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	/* This test is specifically crafted for the generic mode. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
-	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
+	/* RELOC_HIDE to prevent gcc from warning about short alloc */
+	ptr1 = RELOC_HIDE(kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL), 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
-- 
2.43.0




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240327121806.2834070-1-sashal%40kernel.org.
