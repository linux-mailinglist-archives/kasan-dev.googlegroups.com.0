Return-Path: <kasan-dev+bncBCXO5E6EQQFBBH7JTOFQMGQE3L2ROZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 076E842C44D
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 17:00:49 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id q24-20020ac84118000000b002a6d14f21e9sf2264697qtl.9
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 08:00:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634137248; cv=pass;
        d=google.com; s=arc-20160816;
        b=evnYDDfQUPDIb6jWuyEvguZQqmkcMDZH3I5cfv9ouPAGsKq7Ic1mb0wFE6DINPhqBH
         GVaIQH8fwTLiZz8FNt8QJwc3EPghDocwwcvV9lczSHi939gNaKJlp9jDUHw6blYCf3c8
         zsdWA0C8cbXPWUUsqeyG+EhuyEtXxlFcd3IiUHn/P6VoGiAE/BOjhyGuZZPTl94Tqp87
         Tdhbqi8+0nRqzL/bFZsIj49n+CfjZ+RWlf4U0PEkX50ueixst6Jm5DX2Wmw/kwf2nh0B
         8YI3inKH3dohubDWdwo2/7xvb6wICFkqlylKMLLD54MtFlulafubgp20FyUJmMZdFrf+
         64gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0hA7RvoZOjQaU+zIvdb2huPvrC3iNhdGKLabXBxmRSk=;
        b=NLzfIIQwMqJVpbsyHiblBdqvzfX5H5mXE2a8vEzeNkAW6G9YEN/G4mwXm1naVYdzoX
         H5zgqckyBglj6Oex1L96BlwZOU3mfJeGBvRL2DB8HmNcvMHwoKnpZCV1Lowe5VLwy8Ry
         qfi5V1Oua24pw26tucep8+sj7wB9aOuo1s9HyIBWYMYCv7bMIraOXDJrZ5SE1aaee+f7
         Z+AbyUHj9V/eokNcyNmh3Zy4zZfBxm2Th174MGBPi4bQJCgR/7Qz5BY9qmum1ryrS23r
         XK7Ax9Xx2IUtaWkuVJElvn+hubptKWZ5mC6K+Kr2cFYH5WQt7nV3NCi5+VkoWyaru8NB
         mjaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uH+xXHDX;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0hA7RvoZOjQaU+zIvdb2huPvrC3iNhdGKLabXBxmRSk=;
        b=K9Jq/FAEpoSfQBxxO0rUdHHvYrxdCaZDsHGmTksz59TpQwNgup9lYgdUxn8+19oPZy
         P9wRZDBdFHdSvmW6Itk6kM4VPMbd5BwwruDp8fHgl+bQ84E2HhOg1vpCA3BhODv0HUGo
         XK6ZAf7lu32ifhlvDUSGwt2AZAYEvXLWzgJi+9NglDOs3Dm2/K5VhfWRKjI/OttGBqbJ
         a80Ni+3a9NkWRFZhM+j5Qx+eG16sNCgA1GP6fN+q3SEc+V5Yk58iFMWn3Nm+euQ4CvrB
         22AnfU9VF+8NVX1USxit/T0OQImG3jF2PR2mX8+gFkLHpQg0IvwGwEmzxVGv2mrSJIJP
         AwgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0hA7RvoZOjQaU+zIvdb2huPvrC3iNhdGKLabXBxmRSk=;
        b=aBpyKFd32/nUrP1cU65ttasChbd7gC9KAdHNcVYaWTUvrkPJQaTtp5t27GJPK9mInZ
         xoaJqzkC1R8AIvWnKzIsrbxcbS2EJHo1f6scy4bC9hpOn2p/KQt6CfYOWQKHmSztjzNu
         qgXC6S255F3C7nJduTWNDOZZVqbI924hkRVeuu/lquSwz4NGqLgfPekoManQKhfuwxwB
         Bz+bXbUZzE/YHFjFKzwfhv7c2XkB4p5iT7oUvYUy64RFbZ4idAfNoEM5c6US9dXbyRGc
         d0tbBcbN0Kwv3QFywYBBO93acaOaNOwwPfkkr6OwsEQosfjBqIqNpRoX76zbEhE3ACWK
         63Mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ieura5YacHsxbqYaem8frvlG5ci9nJtI7+0k4tHT1XmXOFAls
	E/dY42mxRQJPuzq6r7HpT1s=
X-Google-Smtp-Source: ABdhPJwC7b0abLvT21Ytn26krzHr04suef03zeii302l8NLJHFKU/5JItibdeZEhftWyG2cn80WSHw==
X-Received: by 2002:a37:be87:: with SMTP id o129mr25428264qkf.213.1634137247949;
        Wed, 13 Oct 2021 08:00:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4d11:: with SMTP id l17ls778665qvl.9.gmail; Wed, 13 Oct
 2021 08:00:47 -0700 (PDT)
X-Received: by 2002:ad4:530c:: with SMTP id y12mr27792915qvr.51.1634137247459;
        Wed, 13 Oct 2021 08:00:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634137247; cv=none;
        d=google.com; s=arc-20160816;
        b=vsqUE7EUds3YVTeG6CqqT1j0FC2vYhWD4leK4sBpLuYwOPpOIPSkz++24JAdT0vCFs
         ZmmKpsg/yDM1eF9i23uHWT67jPjyaV2TLym6CdPhJ+JJgd7t7C7YZ0D8xMsBi0JInVFA
         rPY7B9GoftgtWsTHQzUAfx+T3jo9miotPpdGVuib5uoioOp/xQj0EDDAafpOLY0ItHAk
         3LjSXoxjG8il0b8m842gYXd+n6D0Xe50WwjOeV1dfAqLfOewOsBNSmRz5qjif8T2Yn6W
         69iYWq9ke9glQlnN1NIdRuro7A/WxsoF3owedblo+QeVgRs8TAYJccJyY+vjBf2U6h94
         vSQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=31WeL90YITCFzlkNrK3r9CMM+4H0lxhkrKTwXk8Q7VQ=;
        b=SpqV/yy0iAjTQdljL2fT61QNOZY301+TnDDW+mw/4k8dKG/gvNSHccC0dX+ZclceIL
         MKpkFGxldaTVI7nfBRAB3nhTHkTuagOwBCrs1v2DAnjXEDXlBdojbHl5zOnPIWL+CgNv
         9fLS9zI4WDP07ADAraAJLPk0ElQ0Vaj8dqyHZwgYYl9uJpf0sHdXwKtz9DTMVKANUwSf
         Ct9+2SmhKYyl93h2kAAEb31B5Vmu1ckV4SFmRFwDk8+OFqka34pg8SfRNmDZdFxCkTHa
         xIrAeqwyK2yB21IQYqqGL3tJOvhV7tHu4OtzFyEGN7gV7Eja0cvkXxol6rjTLrkpwUmH
         1w8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uH+xXHDX;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m17si37384qkp.2.2021.10.13.08.00.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Oct 2021 08:00:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5A140610FC;
	Wed, 13 Oct 2021 15:00:43 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: linux-hardening@vger.kernel.org,
	Kees Cook <keescook@chomium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Cc: Arnd Bergmann <arnd@arndb.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Kees Cook <keescook@chromium.org>,
	Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Marco Elver <elver@google.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 2/2] kasan: use fortified strings for hwaddress sanitizer
Date: Wed, 13 Oct 2021 17:00:06 +0200
Message-Id: <20211013150025.2875883-2-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
In-Reply-To: <20211013150025.2875883-1-arnd@kernel.org>
References: <20211013150025.2875883-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uH+xXHDX;       spf=pass
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

GCC has separate macros for -fsanitize=kernel-address and
-fsanitize=kernel-hwaddress, and the check in the arm64 string.h
gets this wrong, which leads to string functions not getting
fortified with gcc. The newly added tests find this:

warning: unsafe memchr() usage lacked '__read_overflow' warning in /git/arm-soc/lib/test_fortify/read_overflow-memchr.c
warning: unsafe memchr_inv() usage lacked '__read_overflow' symbol in /git/arm-soc/lib/test_fortify/read_overflow-memchr_inv.c
warning: unsafe memcmp() usage lacked '__read_overflow' warning in /git/arm-soc/lib/test_fortify/read_overflow-memcmp.c
warning: unsafe memscan() usage lacked '__read_overflow' symbol in /git/arm-soc/lib/test_fortify/read_overflow-memscan.c
warning: unsafe memcmp() usage lacked '__read_overflow2' warning in /git/arm-soc/lib/test_fortify/read_overflow2-memcmp.c
warning: unsafe memcpy() usage lacked '__read_overflow2' symbol in /git/arm-soc/lib/test_fortify/read_overflow2-memcpy.c
warning: unsafe memmove() usage lacked '__read_overflow2' symbol in /git/arm-soc/lib/test_fortify/read_overflow2-memmove.c
warning: unsafe memcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memcpy.c
warning: unsafe memmove() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memmove.c
warning: unsafe memset() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-memset.c
warning: unsafe strcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strcpy-lit.c
warning: unsafe strcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strcpy.c
warning: unsafe strlcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strlcpy-src.c
warning: unsafe strlcpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strlcpy.c
warning: unsafe strncpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strncpy-src.c
warning: unsafe strncpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strncpy.c
warning: unsafe strscpy() usage lacked '__write_overflow' symbol in /git/arm-soc/lib/test_fortify/write_overflow-strscpy.c

Add a workaround to include/linux/compiler_types.h so we always
define __SANITIZE_ADDRESS__ for either mode, as we already do
for clang.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 include/linux/compiler_types.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index aad6f6408bfa..2f2776fffefe 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -178,6 +178,13 @@ struct ftrace_likely_data {
  */
 #define noinline_for_stack noinline
 
+/*
+ * Treat __SANITIZE_HWADDRESS__ the same as __SANITIZE_ADDRESS__ in the kernel
+ */
+#ifdef __SANITIZE_HWADDRESS__
+#define __SANITIZE_ADDRESS__
+#endif
+
 /*
  * Sanitizer helper attributes: Because using __always_inline and
  * __no_sanitize_* conflict, provide helper attributes that will either expand
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211013150025.2875883-2-arnd%40kernel.org.
