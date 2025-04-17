Return-Path: <kasan-dev+bncBC7M5BFO7YCRBZFJQHAAMGQEBJ226EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 66D10A91101
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 03:09:58 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6ece036a581sf5835246d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 18:09:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744852197; cv=pass;
        d=google.com; s=arc-20240605;
        b=ksKnYq4gM0BIVrQwnX9dxj9B95SMzi3DJnHYUwIquMyuzIbvHGiAgE7sEe9IUlGaux
         v8gJ+55DcNwWMybXho8nQ9b/c40cQC4M01ZgB9N9l6UPAgfc/X4RazDAl3QD7BXfottW
         iGIs0lB+8BJIH09wOMoSE8HH0gxBFhSNkHO+cOj1LYbqD4NDRkNmeuMKqW/xIflT76l/
         yVklMkgh1mz51z6yc0HcsqmG8HI0GZ1eIUV9S5kC/4LRROXb1wE3TUerY+5dB/Z+MZnK
         875WUEKOWEy974W4+f1VT6J9lOba5hjAzuy4U8Wzfgee2XU4H+zmvrYGyiyZQ1nFjlrC
         BJyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Qp0DWSSlaLZs5TK5oyAMRu+gPtNrkbA0M4BbxsaVXho=;
        fh=2hCBwS5q/wBXN4PdLQjNh116ID44FJSuJpfdrcN8SBo=;
        b=M4Mma/NnEpqVmT0Bn0Pse+LgQ4ZGbH6/Qg8BVB90yIaF9FL5tXyqRPo1O3PPwxUfX5
         9KZwbpB459q/aDNCS2QM0uk88KH4m8nkv6Z/STKSnsOySRnRhfa+dhrMHYD6mn9ZU0tg
         BgEv4+v4kWnnznKZfkLJExPOaIoB1b3Q1gLfPKsff1GjPH6duLu4wPG9OH7J42NJ7Aef
         /54iT8aE+QF+TdVNDeJ+KtRRW8d30SwUFjpqY+dedJeLoD+NZEfNbqLjnAw5ywkCS81B
         qGfp99aHd3SzS5XKTfbXZP625jI0D16lg0cPcorykwW1Cv6ZYE5ZKehUAWiGUuuhQqMP
         IvvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KbdJ2Fot;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744852197; x=1745456997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Qp0DWSSlaLZs5TK5oyAMRu+gPtNrkbA0M4BbxsaVXho=;
        b=na475iZ2seBNUKP3snte1h/F2l83NPo2Z7XWK5IcrtIgY6ebwWRDY/dedrfmbp3hPz
         EHcm7mPDjYagcjCKRwgXLrI9VJxn6R2e4wqUDqb9Mu18M9lOr2jOcsXdqjD1YGQnxR8f
         yMpgwppf1LK2SiU+vVuxJEwDGD6CGrHq8tlIA66TWgZkvFC5I1kSDZ+tHqJxTRIw2EL2
         oMKWu+IYePBp4ek6E18Phibw+eHVvHAg3YwA5UEYp1APTd9eD7u8Uj7llCR16lpfFxYp
         rD6zz+HHjui1j3UMNNeVdqrywjFL2RBUvjp8p/ItKmgV5zNpLWUZJrOg0WcoJKFCTsm3
         alzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744852197; x=1745456997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Qp0DWSSlaLZs5TK5oyAMRu+gPtNrkbA0M4BbxsaVXho=;
        b=R3HXAUgQzZ3dR/3o3CnGOBZb3b/m7f4oIGM15YQWaov2nRmD1L+Ld8KyWCYXaOuZaL
         8cXvr/jTdVFl2Qrz+iV4XfNZwODSxKq36RcP/O8dFL6iQfRhKUrCmwIWtchwtpPvmA1S
         JnGhpTQd+4GMzj+tTIcn2yOl8CfuNSb5kaRaVLudGgrd+SBRdDeQwh7zNe3j6JA8lI1+
         yfdr9Fuqh37vZ/E/uszmYN5v3JsV3lMtmCya3Wx4JgqU8UHahiAM6z0S9tnfCkyrUPbK
         mIuF+xiGIelTiPSGyLx+hhopn8rgBamT5fvS1MXk8ehxgbszJH11KV9bYPCpLJ1DNBG/
         xC4g==
X-Forwarded-Encrypted: i=2; AJvYcCWxax0lt9MZrO+0REyYogIzoijFnB4JiumlMIMEFBCZlWWnFGHYQ7rDAOSCkktV8IHg4wu51w==@lfdr.de
X-Gm-Message-State: AOJu0YzqU6pGSfKBkaoyIhpOg3WNR2WoiGqqTw/CXnFzPBLrGkIiUGCl
	Z3HfwKU+TcIyG2JenW5iH76XfvKNv68oLSK9oxVBsKlxZGhu6qM7
X-Google-Smtp-Source: AGHT+IHN+P40JqFcPjFjYKxG9k+LXQBg/NUCRPkh6PJcauLVnJgzdH/7Qztl/eFnV9gjOkLqvpuEEA==
X-Received: by 2002:ad4:5f4c:0:b0:6e1:f40c:b558 with SMTP id 6a1803df08f44-6f2b30864cdmr59997486d6.44.1744852197258;
        Wed, 16 Apr 2025 18:09:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL/eF3vBzhn0LZh5vHSwAotmmSloFseJVC0uLYzQdKrPg==
Received: by 2002:a05:6214:2402:b0:6e4:4a16:b92c with SMTP id
 6a1803df08f44-6f2b9ad779bls8305336d6.2.-pod-prod-01-us; Wed, 16 Apr 2025
 18:09:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjA063m7lF7YDPz+lWGLMvFvd6V274tbBweZd2xY9iSHL+cl+LwOSTZf9wKIvw04j+CZKu+OOvAMs=@googlegroups.com
X-Received: by 2002:a05:6122:d96:b0:520:af9c:c058 with SMTP id 71dfb90a1353d-5290deea531mr3440770e0c.5.1744852196010;
        Wed, 16 Apr 2025 18:09:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744852196; cv=none;
        d=google.com; s=arc-20240605;
        b=ggnfWt6rKAwEFDm4B+IwOLMn6Nxu4g7yk6SZ5rXY6p7iO3A3nK9FxsnMP2B7F1PBk/
         lsfNKr+9tEoiVvr+e4Fg5Ls9zChZjIE9jSSyIVLzk2re/feVOs08HPjfikpcLuSRMs2v
         KsNglBgmDONE7lZVgZaFHBHcpMFG7KYzxWhrNpGOc4d7HG7nQ3p7bFMuUdL4D6cMPD6F
         C1JvPO80eL4B1aLMdI71klJLPh/AO6+/U4WGOH/dWQkEVRAHn8784h7PwZKhcMp6wSdY
         bx2dKUtpfg0TRhsaXey1gl/LS++1GDEMGobHc/Zb7L+SzZXszS9Rdt0aZAElGsJglsl4
         tM3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:sender:dkim-signature;
        bh=KsBDMVl4tNJg6O1Gee8OEApious2Fe54yEWMkZNyBdY=;
        fh=rKAfwKLk1I7raq4KPAlwahJ8ODdNX4IUEX6z+wLECho=;
        b=RWLcnUwIbwL1aDGjj3UwkCOt+F9/6GYXPuwmCexMjD5jX454vCrh0wrpFUIRxID5L1
         Ob39j0vj+xSA2TGmIOhI8zbCn3GnE7c8q2lA0X8L1veHGshU8IOc419pUfYLxSI9hxZ2
         FiQ7EuztWIFmOMsWdZlBJVxx0683IgX0yNuyW5GD0J9W15SOvT2QqDzoLsKNTJ+BnIjg
         IAhJROKtgOfIWJlW6TnfUWYS1TZ2X0Qh0xq7YuTLHbklWBnpWpY8TnEorQQ2BvPKfP1T
         8GmdvpTLzwEfzP0qmQnsc0eVO1lg8S1tAXojU/fTfe453+MNZOk3bD6TwoOKTypx9i6d
         P0KQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KbdJ2Fot;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-527abd7b8b9si153039e0c.2.2025.04.16.18.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 18:09:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-223fb0f619dso3148275ad.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 18:09:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW4WIB9bfHA3rQ+/5Li9nF/s4ybEJMjT3Xl51PdQv3ixkt0pTzAM3jyUA3NwUKAze4IHarJSyRYYTg=@googlegroups.com
X-Gm-Gg: ASbGncuM0VhnBypddhqYnvv/ZTUf8OcKnWBQC6mbRSgU954N4aKmWA9h+veE5hE0tYP
	sd4mqNus/D6EqD6JR5m7OApdXZqv5i1otVmcnGMT77Ou5/WSaFINGU8wNB+U/Pogs6IySKTlcQE
	vDnBNT10onYZ3H3Jmjn0oNq5Zck8d5uuc+45bcMbL7PUOuivcVn0ynr2QRgYh4ZFnp5KrM1YOvm
	o54RdhkkmTMYVheeGFlTljDdHWkPz/3zZohNr7W+YEAOpozGJG0y0gTkuNqA/mQN6W/uMIOu063
	fnV/c675yaTUWB+0r+YyB9wPUTJT4YEMadZmbzp+FJkL0Guj6O7HLQ==
X-Received: by 2002:a17:903:40ce:b0:223:fb3a:8631 with SMTP id d9443c01a7336-22c358ebfe1mr71952975ad.24.1744852194837;
        Wed, 16 Apr 2025 18:09:54 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-73bd21949e5sm11110095b3a.4.2025.04.16.18.09.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Apr 2025 18:09:54 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
From: Guenter Roeck <linux@roeck-us.net>
To: x86@kernel.org
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	"H . Peter Anvin" <hpa@zytor.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Guenter Roeck <linux@roeck-us.net>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: [PATCH v3] x86: Disable image size check for test builds
Date: Wed, 16 Apr 2025 18:09:50 -0700
Message-ID: <20250417010950.2203847-1-linux@roeck-us.net>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KbdJ2Fot;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62f as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

64-bit allyesconfig builds fail with

x86_64-linux-ld: kernel image bigger than KERNEL_IMAGE_SIZE

Bisect points to commit 6f110a5e4f99 ("Disable SLUB_TINY for build
testing") as the responsible commit. Reverting that patch does indeed
fix the problem. Further analysis shows that disabling SLUB_TINY enables
KASAN, and that KASAN is responsible for the image size increase.

Solve the build problem by disabling the image size check for test
builds.

Fixes: 6f110a5e4f99 ("Disable SLUB_TINY for build testing")
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Guenter Roeck <linux@roeck-us.net>
---
v3: Disabled image size check instead of disabling KASAN
    Updated subject to match change
    Updated Cc: list to reflect affected maintainers

v2: Disabled KASAN unconditionally for test builds
    Link: https://lore.kernel.org/lkml/20250416230559.2017012-1-linux@roeck-us.net/

Link to RFC:
    https://lore.kernel.org/lkml/20250414011345.2602656-1-linux@roeck-us.net/

 arch/x86/kernel/vmlinux.lds.S | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index ccdc45e5b759..647d4f47486d 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -468,8 +468,10 @@ SECTIONS
 /*
  * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
  */
+#ifndef CONFIG_COMPILE_TEST
 . = ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
 	   "kernel image bigger than KERNEL_IMAGE_SIZE");
+#endif
 
 /* needed for Clang - see arch/x86/entry/entry.S */
 PROVIDE(__ref_stack_chk_guard = __stack_chk_guard);
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250417010950.2203847-1-linux%40roeck-us.net.
