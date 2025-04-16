Return-Path: <kasan-dev+bncBC7M5BFO7YCRBW7PQDAAMGQEMH4YREA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B604FA90F23
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 01:06:04 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-72ecb7f4b42sf122797a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 16:06:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744844763; cv=pass;
        d=google.com; s=arc-20240605;
        b=GYoBnLFdIPkdJerVT5OqqHPNe+4kHVVLYQR2OjCvIO/Z+7FQbx0t4brsUBxjzCB5hp
         0YnSMDAqy9rPQw69Vfguu2iHZr99jeDC0JFpgvUvOXe74nQWfwem2MoncDKVtW5k3n0Z
         tMlvDzXN4G8f6P8C30GaJRGy/lf3zxzWKwFeV4vN8ea03fumBvu0gUEtCoQYZikqZXbG
         S5UBOOBvpsOBb4zlkiqIFoujg2LMxlMaxyL7KhabAM0VUHi7UPcjZGaZDi4MLHLpWWll
         gGcdB/pATxa92XtZ4FHwdCCZs+1pfb5uAtAjgLPQ+JDPfIwcQLaw4kMoYkRkhzu26dDP
         EC9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JC7YY+wwBcUqwIaYlO6JTcJSP4QrEloJ6p9+A0y3SfY=;
        fh=SYrJQqTj0g8jx+F9Bay8VQRt3N7oblxMVcMYruTCUYQ=;
        b=bldXPUVyMuNNSqDOtw33wd4gvGeM9kh+U4y3F2TqYuBBih2xuJvFwRl5pgRfMuvTkR
         ilcFeh8Cj3qJ22eujkang7kAZnFHXokGhtqKDiiElNo9c0h7swAo8UVgrOe0myuGYtoa
         84CmNSR8/v8oTYB4bJ/YEMdzjmfZjjHg/2iXy3EcnjCsBQrrOREbIvp5tpyl6uEOx5xH
         EMLWbbX4ISOXXShPX6rV4ySR1gfU8oNKGVwXut7fR9HWALDrUGDLehI2WyT/waHJlQZl
         fk78GKCruZdTMrG8Rn0OVZJAAqDz+ANlCCAUWl1e5BX3m0YRwyUfTlURfKPHfkjjVljc
         VnIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IHyg0BdF;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744844763; x=1745449563; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JC7YY+wwBcUqwIaYlO6JTcJSP4QrEloJ6p9+A0y3SfY=;
        b=BXpaX0xCVP40THOaTusJg4pSohkdMWSEbwqORqXDzuNhidXwETm6Vz/tQD/zI9fb+l
         5xTVivNtAF7R1q4UuaNPAeQ9tvCfF+644w14HVcBv5bL6kKaWzxd3zF7mdTGhjtfSzJh
         ODN4LVEVAM6J/bLwrgMYzPEhgaJlYPB+tSYFg7aO4RWKP0XlTw+UCnDdiSEtxyjdquAp
         /bA+cFFmcWJGOvIzjC3xb9jGsWT+6e5Btc4FCSS4T9FxxI8skK7/vGyyLQEBoy/jiSn1
         VFEsu0fhZ0V+ZLNzgp5bzWpUBXIrK0F9+DHssZc2Enr4peZE9ccTI7k0jDQ28j5whW2s
         t3Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744844763; x=1745449563;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=JC7YY+wwBcUqwIaYlO6JTcJSP4QrEloJ6p9+A0y3SfY=;
        b=paIkyBxlDVt/DVOGaMJAJ4mjfM/UEXNsjcHdZU5oWDdNvh395kMcmMw2wBb7sxaC8J
         G/SxdlJaZU67TciUTdGe0c4qnjT4YUQtqHbujJSRHSb0rCzFJgN+W4gVKRg33FiWVxUb
         5C3Y9KedPquyCQeomk9HiKCeZVd9Mlt8T8WlXlQqExe4zeVeF/B0YV2g7/xWTpki3dUh
         heFoiYCu0bk5s+gwQNx0UctS02E8nx7XIJG60Y2WqfIwaZRd6hm9fu7SDVlzmr5z+CLx
         +z4wX0WPKqkLxecyvVmolOiJ6jyZPORVGMei9eRaeHxS+DDQGCMDztmpzKMQJFJPO/cH
         hgRA==
X-Forwarded-Encrypted: i=2; AJvYcCVXNHJCcoA0BtvI19Q0KK1/jvEF3XIL7IML9TRBAu8njrmPA4htebpTR5fFbUPEYuSWF39tQw==@lfdr.de
X-Gm-Message-State: AOJu0Yycrjm6oj0KOj6YJszUHevoTKM1pb6K6BXrbPRFXPVlmHCvcf47
	kF1oG3m3Nq1XmovexmR/FymXJ6hReL1S67Tm2mJSccw7GFG7OSn+
X-Google-Smtp-Source: AGHT+IFjxZzAiScpN9niuUAAmvnWz4rMYZex9kNPZjq7CJaQh6nGrdmDF60+SZwlzCH5FjSQi3xKCQ==
X-Received: by 2002:a05:6830:3983:b0:72b:f997:19c4 with SMTP id 46e09a7af769-72ec6d207bemr2501196a34.26.1744844763295;
        Wed, 16 Apr 2025 16:06:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKqSStSFtdV10oTtSeyapUViL/kuFfxqflO81sdl9ynIw==
Received: by 2002:a05:6871:8001:b0:2c2:d749:9156 with SMTP id
 586e51a60fabf-2d4eb98546fls175525fac.0.-pod-prod-05-us; Wed, 16 Apr 2025
 16:06:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+/Fi9FbVrF00INHKCF42OtoZA/B+rLtI905LY8Y53dgumeAXKHEIAnWEr0CO6bODosDg83jU5Haw=@googlegroups.com
X-Received: by 2002:a05:6870:6b8c:b0:2d4:ce45:6987 with SMTP id 586e51a60fabf-2d4d2a66d41mr2566985fac.9.1744844762089;
        Wed, 16 Apr 2025 16:06:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744844762; cv=none;
        d=google.com; s=arc-20240605;
        b=gyMX6wEnpWMmw5MrE/qjdI0F63UrzZYuvz2QLtFo2szV2om1cGOVKESNj3BzZkCZi4
         TNfmqqi2mS/T8qx+tArR/B2McyX2J6wCwJrnbMUPGDsIwCDreOHxoh+ncORmMFioRpP3
         3dXyN9L/o49Yg/pZ4c4a+0abZOjEkgk6kTceyqlkhHCoQR+DuLe5uz5jSpO0fuTRdZ6j
         OQ2mHuLyzX3xIEWUKSYDckG81ClknADZeOzW1Je3YusM5Dw8D6QH1xQVg7w9Jjy4ARg7
         AfywJpzhJsRVl7TcqHQqt4KD5/rF0gVzF2l/Wm2e38FGM82UlBsgrSWm43q93b0h4hJp
         7oeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:sender:dkim-signature;
        bh=CdmSSsvImzYo0cP+z7F0QmEv3k5MRXxXAzSzF8bX4M0=;
        fh=96LrLScueX+EXnpg8U5vQanlZsFAWlnGvwouStV0laU=;
        b=JTUeDFJSb9Gb64ewMxqYIn2tih3Pw6ZrLv/biPSVAMyeBUeJuXstxS5MXPE8FWjETO
         KX8haM1x0vdDHe9l0QLODfGkVMZUifX4G8cEA+4Kq1fw+uCPsoVQbJgUi6jsygLqKBw6
         mhHLT3EQ2WSQGifZWFRhWZfIsVlGLj2vxO/trQl3Rq8Clop4LNBaJ788ji47BP5ou9fr
         cEu1sLDWStoJPPOOFUq7oMt58bchzW92Zp9znF4wPzJvZj544WKe9ojWdn3HHoXQfQcy
         cz/M2TdHhe5dbqrLVknssJT3MgzpQuiLbzEPshnyGf5yjNKHnkgTTP3sy4Fgt/XcbFVI
         cy+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IHyg0BdF;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d096950459si204013fac.2.2025.04.16.16.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 16:06:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-223fd89d036so2260355ad.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 16:06:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVO0sqXTrskbhyX6P4PpajaH6R7uEZzUFaAnrvsnKTyEMrsHBNWbmrw3hSsBJ2lQOc83O2cPfMqZH4=@googlegroups.com
X-Gm-Gg: ASbGncvigGh5P+0TJoJ9z7LzHwgklX9trwJIQh2ExtgMXWgs1Hy15VqvEVl7Cxx4g+J
	05fUeJcohZdVjGIANlZ+R+JPFNYNiPxrKvAwINgSVnMoTkCJXrY+fMiZpcwYkBhvjcpw0UaMOMR
	xpKihLp5ObKlS1MEZpo11LCBQHjW3se90PTSLjO5ABq/eNsSmc7td7BVpSZJT+dW+frwmj9Sza7
	emiNMZWmaDZafPex0gD0C596ImSZ7xhdYuX8qATreymmDOJozWHZ5JxxPShtn3GP/GGVIgHxbxL
	S4e15Jv8EISsFdYM6Hu1JJWcdAHND+MRVWRiPDehNqZ5jju6AZfzgQ==
X-Received: by 2002:a17:902:ea0a:b0:224:d72:920d with SMTP id d9443c01a7336-22c35973f3cmr44762605ad.37.1744844761237;
        Wed, 16 Apr 2025 16:06:01 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-73bd2199d57sm11048561b3a.32.2025.04.16.16.06.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Apr 2025 16:06:00 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
From: Guenter Roeck <linux@roeck-us.net>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Guenter Roeck <linux@roeck-us.net>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: [PATCH v2] x86/Kconfig: Fix allyesconfig
Date: Wed, 16 Apr 2025 16:05:59 -0700
Message-ID: <20250416230559.2017012-1-linux@roeck-us.net>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IHyg0BdF;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::635 as
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

Solve the build problem by disabling KASAN for test builds.

Fixes: 6f110a5e4f99 ("Disable SLUB_TINY for build testing")
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Guenter Roeck <linux@roeck-us.net>
---
v2: Disable KASAN unconditionally for test builds

 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..190297f2ff83 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -37,7 +37,7 @@ menuconfig KASAN
 		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
 		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
 		   HAVE_ARCH_KASAN_HW_TAGS
-	depends on SYSFS && !SLUB_TINY
+	depends on SYSFS && !SLUB_TINY && !COMPILE_TEST
 	select STACKDEPOT_ALWAYS_INIT
 	help
 	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416230559.2017012-1-linux%40roeck-us.net.
