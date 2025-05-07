Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5GG53AAMGQETX6KVZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7158CAAE88B
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:22 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-736fff82264sf129992b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641781; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jewa59tND2JPHb+SUy8ox1kBwpb+bqy9n2CSyQV4xX9uQH96cPje0OdJPLcC92Jd7A
         jXAZR7TL1fuRNJOBF0ybF2ou9ekfFfa0RwQ05BYkfgJ3DUjXMFVjH96VXtXJ2yJDZsFZ
         KPCmv8vWnOxNsUZOJ6hrnFk8psdBY9vJbsXxtDy3fZQ5b8jtpoet1KjtfUznAmbOwnfP
         rw9Asit5fsZfo7j/rd+7vJ+DdjuxJ+7hArImcOOiNmJqJm/401Jglc2/xkXtjgF4jKxb
         LifwVb/mCZJE6HitOQ+uTTfMB+GDbqTGjXqTZXjJP4TGKzyyDB0w4GQJEYNr9jlUfZ+9
         W1/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=mDycH4Mz58VZsW2gHE+3xrHh6p2CeL+jvnrPI47EkUk=;
        fh=eEOCdlLLFdzz2dNbhTqevto+PWe7qwV/6m91uMiKFJE=;
        b=iU00K6in8ySOUR7FHPU9167UDVezAK+Of4I78pZqkYK1QsUY5t02MaYodsfiMTlc4C
         xSEPT4pXXHLtSjPWL4ckze/IQe4D0SEWG5oolkPmHL3GHrpYDeM1RYCN6buVDH5Kjw/o
         0+oL4jABpyjV2Nb9Hbjx8dO4rjZBhzWadUOxiwinUKnm4bJHw5w/UwjG8JohieQu9LEN
         X9Ty58yTw2HdOf3ZhHMjhL44kcQsLAXMmXCvXKipNCm9hBxBtCXfni47M23bLko3T5SI
         dfB7ICSj+80HeUTWy0iyL62zeusLqv3tvj5vtMHUedvYgnLszuSA8D8R3DADCakszaKu
         5ebA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZKDyZKo6;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641781; x=1747246581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mDycH4Mz58VZsW2gHE+3xrHh6p2CeL+jvnrPI47EkUk=;
        b=SeALipkziOFj1ed5jWPJ71000Aq9SRBm5Z9RB2nQxyeF/IPq1zZSkQUU8dVnAAMGHq
         jO1bzdj60a+jGBIu9ZXC7lebdUjNHCjra5FobSShPpQoNdjuRymFhZPSTMm05zrAIL2z
         r9ErU8zVv2HeXWWPrUZD9rTEFNKPHswuI9oBFUgr2/PsEEul73zyuqjV4XGjryjIWNrw
         aXKcGgbtSJ/EOq67wifbvRSBsm8EDY8talLu7CFHDwcnX84xo8WFD9mTtQ/UkS5+JGJq
         brmpoRPHQ5XDpFyOzBChO57V7GEYx6W8+8bVdLTX6lWRH1drJX4gdIxZWjSoxdXttPIj
         wobw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641781; x=1747246581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mDycH4Mz58VZsW2gHE+3xrHh6p2CeL+jvnrPI47EkUk=;
        b=dqgcAf/qOd8VBQRn/OLy+KAPYpkcW1aujAqdfgpwhMjG43ueOn1urooSLNzH/bZ5sq
         lJroq8ZZuPMD/Ryeftcifrts7pqMek67zUdFlHb4av7WES1rrLIkoEzSS6CEknaDlJ44
         tf++L9JbXOMULPMNpBSOecM5oNou8oSUHsv4IQLbCTbuZ9HT96dDWuQ31Ng/oGfryMrP
         fRLrWLdSwdet1S5r0CfW/1+FzYDdSLV1+jdU2wm8VQ8TVfeaQnOssdcI8FyyD+4uXvTd
         Jx4Usl11xLdQFixv8fe63DXheg1vPmQ3VDruByVSS2okdTTWGz6aGBXQpGaA/5w/VpDZ
         6PeA==
X-Forwarded-Encrypted: i=2; AJvYcCW9Gp/+aKpZWoezEBPh5FTCIUgaKu1rjqfqlBxJXMcST3Yj/DCpm0KJJEiDxykl36vXbSA40g==@lfdr.de
X-Gm-Message-State: AOJu0YwxV8kmYuuuyKYj5YNsrBgZIRu3N5jKBqO1IbrwWezGHh/JaHGP
	5yZ9kUa/4gIMD2NjiE4nY7pJ7rEnJflzfjPANGKbM9BPZNlAei+3
X-Google-Smtp-Source: AGHT+IGm7FNwJDwbLrLHxBMWY3rNXqkptA48E72Edy9Tg2Xzd8InsbxuMeI2mCv0xPKLXsMBLBTVGg==
X-Received: by 2002:a05:6a00:4296:b0:736:4d05:2e35 with SMTP id d2e1a72fcca58-740a92f97bfmr690456b3a.3.1746641780667;
        Wed, 07 May 2025 11:16:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEvjJZYWVRgcDob5zx+xt9G8eqj+WbTX8Y/GYxLT3B7zQ==
Received: by 2002:a05:6a00:2e0f:b0:725:4630:50bd with SMTP id
 d2e1a72fcca58-740a8babd0bls104393b3a.0.-pod-prod-00-us; Wed, 07 May 2025
 11:16:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUr0tGPnfrg3DCxqjmoOaKTiC/ewvafqvwqmqYO+COWSQt2z3fTgKdDinX0fE8qxB7dTaPoLLo+f1I=@googlegroups.com
X-Received: by 2002:a05:6a00:4ac3:b0:73d:fdd9:a55 with SMTP id d2e1a72fcca58-740a9455df1mr741801b3a.8.1746641779325;
        Wed, 07 May 2025 11:16:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641779; cv=none;
        d=google.com; s=arc-20240605;
        b=e/VaTgAnSMeZCXDKya5VFVvQaUa4GmeeGuSI+kFDOpzoBvh5wKntjyHCyx466hSjWx
         tjvYpuuPmJaHbRmm4j5LCVyvu/EOkLvtdpVRmnO3DCm7Fu9cLcxOXqDc3pht3sIIOuzy
         JnyXvlb4L/3V67JT2Ji1t/niYAaf8Ie3YQaJHqfVdXzgVH1brwnexrSjKy8ELDUIqe0u
         mh2os7I/LF117BRtPtv6NDOI8jrndM6iQMGMluUMb82g4m2ZrGBHCImO+0CiP1eND0+g
         wbaHH3e/bXwdyiyt/wLfU7d8RU5z+wEr5TlgBd2vaikeapnnbgCk3COgxdTKXkvY8lHw
         ascA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xKpMhveG3McjKP1gZe4ReNJ/lPxnR+ZjwbZBUMSLjDo=;
        fh=POVWoUHYFD8gN6ZuPkedigXjewWeb9Udfw1F7wCHR+4=;
        b=Wd1epafknf7+WUMZymhD7V9WON0Wl4cK2YBrgVqSiT7zOTsK2NSrVzka6lW00sHbYk
         jD2t7P+YLvjB3YVkRozEvN19lzRFworY8ylc8BFdGC17+WTmMFI/JAe5Bph8Y6qifZTn
         OLIvBfZMVEoWEpZJ6kMPCYagfSsi8kvcGrnsMi3uev1hpMQeJif1gi8LKdr0Xy8NNRt+
         jxiyyTzr4Sbpv/YGovINC6IjZWZNkVI9aIvQIBJNC+FjIJMis7z3Oib+WHOXZKwRi8bR
         /+BgXBwWvomfuQ9baANcvHqqBzxRoXMrt7IDcTMI8ysgQpun4crzV47Z1oBoRJVBPQ2+
         Mmvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZKDyZKo6;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74058d76e55si525162b3a.1.2025.05.07.11.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7A1D55C5F2D;
	Wed,  7 May 2025 18:14:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40AD0C4AF0B;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	kernel test robot <lkp@intel.com>,
	Keith Busch <kbusch@kernel.org>,
	Jens Axboe <axboe@kernel.dk>,
	Christoph Hellwig <hch@lst.de>,
	Sagi Grimberg <sagi@grimberg.me>,
	linux-nvme@lists.infradead.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 1/8] nvme-pci: Make nvme_pci_npages_prp() __always_inline
Date: Wed,  7 May 2025 11:16:07 -0700
Message-Id: <20250507181615.1947159-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3008; i=kees@kernel.org; h=from:subject; bh=uZoSquFI+a0xjog8hTbmiXK+g9d2dTlbWp8mPmCNMg8=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi7Mj7qrfMsrM3fhoRaxL/rrABq9OocY766qs5dPZ6 ivypuR2lLIwiHExyIopsgTZuce5eLxtD3efqwgzh5UJZAgDF6cATMTQmuEPr7/VeusGR6sbc7It buppOJvwuvS7Pi3w0kt/kCT1t3wZI8NiFv+2ExmaiusX9TdKhKnkSqd63uoME9wpk/HmxNo9Tuw A
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZKDyZKo6;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

The only reason nvme_pci_npages_prp() could be used as a compile-time
known result in BUILD_BUG_ON() is because the compiler was always choosing
to inline the function. Under special circumstances (sanitizer coverage
functions disabled for __init functions on ARCH=um), the compiler decided
to stop inlining it:

   drivers/nvme/host/pci.c: In function 'nvme_init':
   include/linux/compiler_types.h:557:45: error: call to '__compiletime_assert_678' declared with attribute error: BUILD_BUG_ON failed: nvme_pci_npages_prp() > NVME_MAX_NR_ALLOCATIONS
     557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |                                             ^
   include/linux/compiler_types.h:538:25: note: in definition of macro '__compiletime_assert'
     538 |                         prefix ## suffix();                             \
         |                         ^~~~~~
   include/linux/compiler_types.h:557:9: note: in expansion of macro '_compiletime_assert'
     557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
         |         ^~~~~~~~~~~~~~~~~~~
   include/linux/build_bug.h:39:37: note: in expansion of macro 'compiletime_assert'
      39 | #define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
         |                                     ^~~~~~~~~~~~~~~~~~
   include/linux/build_bug.h:50:9: note: in expansion of macro 'BUILD_BUG_ON_MSG'
      50 |         BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
         |         ^~~~~~~~~~~~~~~~
   drivers/nvme/host/pci.c:3804:9: note: in expansion of macro 'BUILD_BUG_ON'
    3804 |         BUILD_BUG_ON(nvme_pci_npages_prp() > NVME_MAX_NR_ALLOCATIONS);
         |         ^~~~~~~~~~~~

Force it to be __always_inline to make sure it is always available for
use with BUILD_BUG_ON().

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202505061846.12FMyRjj-lkp@intel.com/
Fixes: c372cdd1efdf ("nvme-pci: iod npages fits in s8")
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Keith Busch <kbusch@kernel.org>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Christoph Hellwig <hch@lst.de>
Cc: Sagi Grimberg <sagi@grimberg.me>
Cc: <linux-nvme@lists.infradead.org>
---
 drivers/nvme/host/pci.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/nvme/host/pci.c b/drivers/nvme/host/pci.c
index b178d52eac1b..9ab070a9f037 100644
--- a/drivers/nvme/host/pci.c
+++ b/drivers/nvme/host/pci.c
@@ -390,7 +390,7 @@ static bool nvme_dbbuf_update_and_check_event(u16 value, __le32 *dbbuf_db,
  * as it only leads to a small amount of wasted memory for the lifetime of
  * the I/O.
  */
-static int nvme_pci_npages_prp(void)
+static __always_inline int nvme_pci_npages_prp(void)
 {
 	unsigned max_bytes = (NVME_MAX_KB_SZ * 1024) + NVME_CTRL_PAGE_SIZE;
 	unsigned nprps = DIV_ROUND_UP(max_bytes, NVME_CTRL_PAGE_SIZE);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-1-kees%40kernel.org.
