Return-Path: <kasan-dev+bncBAABBLEBV6QAMGQEXFGKHMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 47E9D6B55DC
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:43:41 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id d35-20020a056402402300b004e37aed9832sf9623532eda.18
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:43:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678491821; cv=pass;
        d=google.com; s=arc-20160816;
        b=JRVXl4QZQH2l2md0m95KaJqWdpJw62hx/XTM1VdBnw3OFkw70fsCU1qWgCcJ09Eyrs
         DZSbKDhUhxl7iFGC45fxEKKEKjkknae4PMtJ9JcxQzOtptVqfNemXr6fo6KOKd0mDain
         KhnKtNdLZbaeI2dnVgaS2hWyXFT3sgihx7Gq09cDUqivKTCvqnCwhb4trG8vPcKkY3vP
         wV+zI/HvUc25m5lcs6HZ7U3CqfJFnFgxh2JVtlcGyrzZY9drfutfWK4OzHEFINX6+w1k
         NWJFkTF/eNSEr/0kpGF6Hmiry58d4VgdSha9P4+HIYXWq3do48VgC0pFVqzwF9GY1Gkz
         7rcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mPQVYZzrH6WCOl8zb3IQM4on18/4/9nnN9Vzyp5bTeI=;
        b=tOmcNhOg25/k9XkUwqatzCwkUA3knzry4axEYnzhgrA1a0lj0I7XRiW6R5YNqOXxDE
         M26YQJG8PDEVgRZUAEOgXrPHYqk4HGSknz68H/Jcivzl924LmwbDaff+rXeSy48wy2dO
         voM3yMLGiDGlrtG6ZquOxnJsK74XOhx33h8/51VTLmoQZ2FJgeaEbk36all0cKZPW7Qe
         zDHVOAb80GuutuS47psZPNOTMJJltZB1WW+IevZfou+jPN5YZ8ET54GFzGSFKOdy4PyY
         gwMvC4BtdFNnyMK0Tge/ATNbCwVKE5Cs18Rzqm9gee0wo4Ndz6EDEi6jg+YLSSGTk/F1
         Vagg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KexIs4rR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::3a as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678491821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mPQVYZzrH6WCOl8zb3IQM4on18/4/9nnN9Vzyp5bTeI=;
        b=Oc3sjwXeYFG1mWmxyGQfoa/eo9unGRRCdJLtuk2DDnSnUmM5T0g/GTC9/wTD2EnuRz
         kDA6o3A1G4HHjUvBGJaDRCSNTlc+ckXbSIgZqxL65slullY/0VBCXYw6wlKagMPYCjOm
         z7UM0Cs12u4c3YUUWym4b8L1zoa0x5Gjtnu3sM0KAi5bYneCmr9VivheEWpteWMYrOWY
         uHOkTNI9dIXPWZlO/BOmSc+XTYA2Z0b1RX7up2MCNxQYgnzPWAwEqUd3SWPHsgfS5YoH
         ZOxvNCLE983qWrxy7pes6eVe1wDtwSQlYvopUQzWVRJvrL+oXIKA1D61z3CuUsB2Rz5p
         EgOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678491821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mPQVYZzrH6WCOl8zb3IQM4on18/4/9nnN9Vzyp5bTeI=;
        b=lVX2FHNRknfQKMiYOd4eQcEAc3Q5mAPBK7U/jYxfAAzdzrE59Bcz8T5g5a5PeAmyVn
         SHwood+2Mf2MW1NG7Xo4gqdkjsbJQRxMbvEEaHxTP4KwpFmdMklgUny82DBIutPrFnc9
         jUN1TM2Tx8sswNCwjfI6FFhriNYVWoeQL4KfIKLpBg1aprZ1O9qEO0dj550N1BhvCU8l
         6M/J2QerZMkYxglnXwKoWA7iZ82NsPQGuba5NkH4n0rlKEgcp4dECm1M1ZrYuGa+SLzi
         3R6zhyuG+I7lRxAsAHCbBJ4N5ym/ptM4u67sB1css7W8WdYSCJU/ZmLcpzFHDNuTzWEr
         jHIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW0YMJ7zZ5U7qgwAcWFk8caNyeDYdHYKSCfeM1XCd1RVhBX+RFH
	kqTwLo59ts052UWXvC1MHoI=
X-Google-Smtp-Source: AK7set9Ew3JKSm/95bfxygEHfKs39CNZUHDzR2zYiw7sZ5Js1RvMzfkl4CY0nrZXNK06ACqOnVMQfg==
X-Received: by 2002:a50:d7cb:0:b0:4af:70a5:5609 with SMTP id m11-20020a50d7cb000000b004af70a55609mr2137264edj.1.1678491820803;
        Fri, 10 Mar 2023 15:43:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:af90:b0:84d:1543:d10e with SMTP id
 mj16-20020a170906af9000b0084d1543d10els4615417ejb.1.-pod-prod-gmail; Fri, 10
 Mar 2023 15:43:39 -0800 (PST)
X-Received: by 2002:a17:907:31ca:b0:88d:f759:15b0 with SMTP id xf10-20020a17090731ca00b0088df75915b0mr31993736ejb.45.1678491819898;
        Fri, 10 Mar 2023 15:43:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678491819; cv=none;
        d=google.com; s=arc-20160816;
        b=aj94MgjeVxopXvNRNhp40qO9DQBEHw4vlCOxc+ltMHYCUjobXIJoF6DPp/oJItFb80
         rSUu4XvOiYI7y8CAHkf/7woHhz/ykSvJoIj3sDJZwKInZzKO5JqFh5H1llYzgB6lcXE5
         ge4fn6nagvn0dprnO6WDY1EYxMCOzlfvY7nTZZOwunuoCuCCMnP6rRgHYcbkfxmmJRgN
         98QlYxjLmIJu0duTFZwXxBFn2AlzVJZ2W45aA/qK6PiNyqVBF/GZiKAG7vXvtXMFItwg
         Noi95od1IkNlw5IRdD22jOpcwUHSZDHKXZ/MBtYl756EsTHA5y41gCK8S5XVkNygZOtR
         /6Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oDcuLSEdW7dG92xT5iE2ytpvV+VW7Ad9krPNXrfRPwk=;
        b=D8HaIF3mVg+lPGTwMe+i5xWd0oAf7varrFy6thLzf1L4DNwW3q7XjF0HqfSswLa+GJ
         SFAUcG87nBswEx/gVqZ3e/ZmDN9dTdlLJI4YaGsXGWLeDBV6gPVg2Ohbc+JlutjklxJ/
         Ktjl3Bb9zx4yiN8uwVfn69RFa/kVWjzl5O0Ntll1PzFkkVFMv38u+yWNoBUfRxjYpXh4
         v6QQNB8im2xMbiO7j334sFaoLwKp0RBjreGZeAs/OMI4Eq1ahZIGaRAKrT/NZ67XtlX/
         2if8yzzGAJn89ifJEmBLm1m2cSfJ1NrFdwxOlI5Kbxa6NaI+gUZe1q0FiOvCTCibTb1T
         VK4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KexIs4rR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::3a as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-58.mta1.migadu.com (out-58.mta1.migadu.com. [2001:41d0:203:375::3a])
        by gmr-mx.google.com with ESMTPS id h25-20020a0564020e9900b004bbea073a82si60596eda.5.2023.03.10.15.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Mar 2023 15:43:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::3a as permitted sender) client-ip=2001:41d0:203:375::3a;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 4/5] kasan, arm64: add arch_suppress_tag_checks_start/stop
Date: Sat, 11 Mar 2023 00:43:32 +0100
Message-Id: <75a362551c3c54b70ae59a3492cabb51c105fa6b.1678491668.git.andreyknvl@google.com>
In-Reply-To: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
References: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KexIs4rR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::3a as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add two new tagging-related routines arch_suppress_tag_checks_start/stop
that suppress MTE tag checking via the TCO register.

These rouines are used in the next patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h | 2 ++
 mm/kasan/kasan.h                | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index faf42bff9a60..26bd4d9aa401 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -264,6 +264,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
 #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
 #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
+#define arch_suppress_tag_checks_start()	__mte_enable_tco()
+#define arch_suppress_tag_checks_stop()		__mte_disable_tco()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a1613f5d7608..f5e4f5f2ba20 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -398,6 +398,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_enable_tag_checks_sync()		arch_enable_tag_checks_sync()
 #define hw_enable_tag_checks_async()		arch_enable_tag_checks_async()
 #define hw_enable_tag_checks_asymm()		arch_enable_tag_checks_asymm()
+#define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
+#define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75a362551c3c54b70ae59a3492cabb51c105fa6b.1678491668.git.andreyknvl%40google.com.
