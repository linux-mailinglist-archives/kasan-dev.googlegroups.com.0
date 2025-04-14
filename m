Return-Path: <kasan-dev+bncBC7M5BFO7YCRBUGC6G7QMGQESNPCCJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 16146A87530
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 03:13:54 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e8f9450b19sf77383896d6.1
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Apr 2025 18:13:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744593232; cv=pass;
        d=google.com; s=arc-20240605;
        b=GDA7UtYxnMdQwiyiJrizGDH2JpWrCHFKSwvZjSsTGOjmcwCaM+k3YRg9WY26b9pI9v
         cGdYlE4jKqJS87ayEAtcLpsl8wnhg9m33DxI5XjAcfRAz5Xdm8163K6g44X4eIw9Xw9T
         dF5A7NaJrSdRHa5ec4sA9SRtXgF3CpDW2MSuw4ekbLmCtfrL7KQv0rHzyl3LZcyEJHHr
         EqMtM0KSIgChOfem2ob2u6UsSA02Oy8oleet+O4rD7IEX3DDfLq3cJs8HOB8OQzMwDei
         SMJmgajJqvefnsBkgHuyqE6/wKTvnewqLkJr4r4weqARXebLEZ+WV2uhqv9OKBOD4wxJ
         ojeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=L7kSAjnyvxkZSIXldovNozsFs8y5AUsRP9g/+LIbyBY=;
        fh=wYiGNy5+ntw0BIEevtql0S2Qdu7yh3or8z0JoglEDPM=;
        b=MS7zRmRTIrgFaLKNw06hIanaPk7ldIVrFGXFgUScMcI7w9QSQUchlgeFB6pkGgkmV1
         HtgewWDLY0dOT114qgF+B7wfTS+7mManwuGtbwa1VM+xq4blqUO0k3gVA9V5Ty3vXhJb
         G1lhtTFd2A+vcmi14c6WW9ZB8R0eKgM05UmSJu+FZzA3eqcronAnYnmsSkP7xbDDKebs
         U7TOomG+OkcS56XHJggx5hrJfQIEllY0NghjY6e9B4SPv29CYZGqd6hi+uVjcj+H98hw
         wrFIet4JTwBPV8olhU69WQlPfWgJpMDDkwoW9/kHzZgbZnuHVeI/VbsuxcsxCozc4stE
         qpTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RFgjFHzU;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744593232; x=1745198032; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=L7kSAjnyvxkZSIXldovNozsFs8y5AUsRP9g/+LIbyBY=;
        b=m3T8Hde9XclmoHyvIIWqN1DwnswW7zpSrsEqxBVWNkw8Aa+hRgrO7318FVnE9Dm6QR
         Upsvwn7x/TK9VDR2WWjFJEq8Xi7zfxEb50ki/x4v7s3YUGAoeOK3EEn+/BLTGwuFSKPb
         x9n6uEh8qgvneL/P4YJ1wFE7Mr1ryuE9xvo6RzRNZvvq9UCyqYuPnmyEhT/XGKr8SmU+
         xFBLy22j7priCDYaLHsME2TPSv7crXgr/Is90eUJisJggCNx9eL6QE8rFT0ih6iGaB5d
         VpFV8TV9t9p1tBMgaqcDSS9mA4Kh894Z/D5SHdfCq2V7Ubb/qzWC2InxlmnUHTm9iIgY
         g50A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744593232; x=1745198032;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=L7kSAjnyvxkZSIXldovNozsFs8y5AUsRP9g/+LIbyBY=;
        b=Sf9jpHAGO7XZI1ASfPLPPyMsUy0uX9xuZ9XL6eojM0IvRjmgTEgPE5snvHshzGYSrO
         y6FhDnUNI3PeFj9HNqIRC9bKZpKcMnM06nfrGDbwjNA8ej3DGdsuwJtr596gRGm9W9bl
         XhmzPYIfWoELex7UtWlvnbRY4y/QW0XLlqCPxwCIt/CFzdWONhxco6juvULddNChDD9H
         A6NrZx8Sl4S5sBNgxEn6WBLi9fDxRN0EpENUM9iGvEbbQNRmmzTyE4lAXZYiXLSCr6qu
         7rFQfMVNSnKYJJcANt5PZFbVaLstf93mT5Na65FgkqY2vjG8uAIAokRIL7gQ03i9MVVG
         S1eA==
X-Forwarded-Encrypted: i=2; AJvYcCWTAp4tz7T1XYHoSw6vzGTdNJjA5BDn3M4jSRHSCirdZM9mYJls8Mbq7Gy38sKmY7IijPJAaA==@lfdr.de
X-Gm-Message-State: AOJu0YxB8WpwFtX0sayjvDQRFjgbre/S1bw4GdWUPOzu/7s1qjdx5iBi
	/emazkSadUQ4k4gddL5iFKwtXPaGC/2e84ghuB+N/EL80S/fdiuc
X-Google-Smtp-Source: AGHT+IEtKiO44E+2fLnHZugjblUP/MAWfrAKhCsW7iw00YZ2LgapjozJfl/+/jfLqu9I1Jx/qfXqgw==
X-Received: by 2002:ad4:5f46:0:b0:6e6:5b8e:7604 with SMTP id 6a1803df08f44-6f214188d12mr177647736d6.12.1744593232395;
        Sun, 13 Apr 2025 18:13:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALDnmrFWVXcxYKrQN6Qs+FhzNrtbnLMImvsID9wvjMAYQ==
Received: by 2002:a05:6214:110c:b0:6e8:ebb0:eed with SMTP id
 6a1803df08f44-6f0e4c173aels26335276d6.1.-pod-prod-00-us; Sun, 13 Apr 2025
 18:13:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3/d6UNJmP7sb8EeXNeGcFodhhMvA2T8O1oRmocr5ZMeT34cSLdYjaZLw30Gr3vWaHwZ5geysq/iE=@googlegroups.com
X-Received: by 2002:ad4:5aa6:0:b0:6ea:c5be:f21b with SMTP id 6a1803df08f44-6f21418727amr134208786d6.13.1744593231114;
        Sun, 13 Apr 2025 18:13:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744593231; cv=none;
        d=google.com; s=arc-20240605;
        b=XPtQPHqrTbTF/4FYYR68jeNQR129besZn3T3jgtarKANAlD4qihv5Lj6goq9WYvkIs
         /adN1/JwiDY9UDjZET+aVI3/HzuFkZI+uIK3vJel1HHCXIriVypNbyaJ9XqhMb6vocJu
         1CDKAx1yz6JFW7lQruTr7BRUJYBDIwjXSJEEsmu1feoMSekNA9ZUIf4zK6IX1GAUIr6U
         EWeizcIqP8oBusoYpczLDTX7mcRzXI1AAkbdV1uteyPgEa1/lbmAeEfLyX8HhVTziUoW
         797UQY88eYjAsf50jb/dREeRf1/zofMvazWqkqVZb+uIXO0Y0orez9kg66E1+G8X5cLt
         bzOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:sender:dkim-signature;
        bh=BdzdxCQ2boOJGAV0pkDm86ghGxjYuAwQcytLgVDzK9E=;
        fh=oIPWmhN1M4VZ0b8uucEOCYeJYn9/2kwG2KqIxLS+tc0=;
        b=e3GIJ/zQ/fq4kthVs/fQJJLKrlNQRlW/iEUKaJQmtkMit3pKPeLkUC1ktZJ/XUjOAN
         rqoVH8i/iqFw6zi64htXrccLuMUPepcPuEuJtXDt6pEocZBaCqQ4X8r7fc0Tix1wlHFe
         Mia8Q1seW0Sdw8K5kvAirAphr0wmivZdPbfxFtaywsn3xF9qIV8qBlLzZFOJMAjW8mfd
         ASmcdJxGX5eXHp/LT7MJDsbomOL/ZXc6eINv+uRT12jtIs9a0qEqMy/004abF6Oq1xyE
         bsDxxijuKRDm3DYPj+wLKSGWe81SrHBRPICy5ggJ7jMA2Tyf8boNj9muM1xRANYcOAC3
         v7OQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RFgjFHzU;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f0de9dc6a7si1159086d6.6.2025.04.13.18.13.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Apr 2025 18:13:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-aee773df955so3786135a12.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Apr 2025 18:13:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX+xu09kbqJ/Gmq0PpEufhoJBnlunqqXuE5kaZtBIJNmOqRbmTEyhbJ5WeF00dYKJbNyQSooKBY9/o=@googlegroups.com
X-Gm-Gg: ASbGnctoabXInZv9dUDlfsvwvgd+otBVS7JJsdQ1r+VA/oIgQQjcyKyIwXC6FjY4IyY
	R4V+jOsIjXw9isSuzBAVuOUEk8029Bgr/zAl7qUdDFFA+T+Zfih3etgofhpbhgh5WIEnuf7xYrq
	V6HzTN/OIBdPlWgFbsGou3fdsfKbHieAXys9uLL561l04iUYeWPBWfflxj/PEbgdWJpfMhjxP95
	O7ek7RrGQJi7Yk5sa0H5IkG5zVgCsXNgLNw/9xQLsBpjcNmv6aS5/FaDEQqyo9/6abDicxRrKBK
	yzVwy11GaJxrOjNKe7DzpAP60M++IELkZYBxj6q7om5ijK1rJY3G9g==
X-Received: by 2002:a17:902:cec5:b0:215:a2f4:d4ab with SMTP id d9443c01a7336-22bea04195dmr125880425ad.7.1744593229796;
        Sun, 13 Apr 2025 18:13:49 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-22ac7b8b158sm88447415ad.84.2025.04.13.18.13.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Apr 2025 18:13:49 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
From: Guenter Roeck <linux@roeck-us.net>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Guenter Roeck <linux@roeck-us.net>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: [RFC PATCH] x86/Kconfig: Fix allyesconfig
Date: Sun, 13 Apr 2025 18:13:45 -0700
Message-ID: <20250414011345.2602656-1-linux@roeck-us.net>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RFgjFHzU;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::529 as
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
CONFIG_KASAN, and that CONFIG_KASAN is responsible for the image size
increase.

Solve the test build problem by selectively disabling CONFIG_KASAN for
'allyesconfig' build tests of 64-bit X86 builds.

Fixes: 6f110a5e4f99 ("Disable SLUB_TINY for build testing")
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Guenter Roeck <linux@roeck-us.net>
---
RFC: Maybe there is a better solution for the problem.
     Even increasing the maximum image size to 1.5GB did not help.
     Also, maybe there is a better way to determine if this is an
     "allyesconfig" build test.
     On top of that, I am not sure if the "Fixes" tag is really
     appropriate.

 lib/Kconfig.kasan | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..fb87c40798cd 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -31,6 +31,10 @@ config CC_HAS_KASAN_SW_TAGS
 config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	def_bool !CC_IS_GCC || GCC_VERSION >= 80300
 
+config KASAN_COMPILE_TEST
+	tristate "KASAN compile test"
+	depends on COMPILE_TEST && 64BIT && X86
+
 menuconfig KASAN
 	bool "KASAN: dynamic memory safety error detector"
 	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
@@ -38,6 +42,7 @@ menuconfig KASAN
 		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
 		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on SYSFS && !SLUB_TINY
+	depends on KASAN_COMPILE_TEST!=y
 	select STACKDEPOT_ALWAYS_INIT
 	help
 	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250414011345.2602656-1-linux%40roeck-us.net.
