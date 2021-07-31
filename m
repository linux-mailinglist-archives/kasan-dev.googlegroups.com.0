Return-Path: <kasan-dev+bncBD4NDKWHQYDRBX7MSKEAMGQEEMVCUAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id D3FC73DC2BE
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 04:33:04 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id v2-20020a17090ac902b0290176b4310aaesf15468945pjt.2
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 19:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627698783; cv=pass;
        d=google.com; s=arc-20160816;
        b=TxQjwzPwoDq3PBV1KGxBpsTtiXZW6FnjtFJhYVIi9ErigLfY0m7u5BmsB8OggGW+vM
         1jiadI1KnX58tj1A016XvLcv7xyVjaA1nrav/uI/PJjSuCmUsvAAalqzFZTtKwG4MSRp
         S1bjza5yVKezrnuX/qmQtUGG7XX2xGHDdkZKIdbPEmOGmJkgo4lN8J+gsTa2zwlhhHJt
         I0Fu+WnQ3QJs/TxMNBuYAMvfBfNaLT0rI+pxWp69SJy3FaUXcnpJ5MHFoOz1tIZOdAcE
         u3f82Yb+tB5kM9ZHSX3znwYacXpnqJcEHRnea5m6ePUxDByEM05za5X5SkYphfPeFk0Y
         ZILQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t1u1o6lBz0FQNg6tz5xWHteE5Y5yiyiw7H7DFXcrJ98=;
        b=1B9cR6kuZktqVknWD5rFLPKQPMq6M2y80Y3YFkucA9bPG++gtMhkKc6watS0av2IWQ
         vnAAR/xIikf6IbnDatxSx6YRmF/UNdlc/CCh7diM/eWfGoD/lTB3Exxp+xPztp9XowMl
         yavRNK1qJMtvMlomZbBakDgzjjzluCamb7XHv52vmvKYLRALoQdn1ZNeFHlYylzM/dsu
         idsQK0U8Wb9s7al/27EALl86/r8JS4MKd/yU282nM6Zgcnsi2wjwnrSAgrGnnyI5WNDh
         aI+YHDsN7KuTLzPyuJ57YuqRm5vJQqchIwkd5pLf3ce7CsM/UhfX5LJqPMOjfaRRF2nK
         N8MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GcAdi55t;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t1u1o6lBz0FQNg6tz5xWHteE5Y5yiyiw7H7DFXcrJ98=;
        b=i93mcXr3X9LecR1RCaXdZwnKw/3eVmDp9yDj/jtpkZ7PPzj0Df3uOHiSvfsj8WQGht
         /TI9U1vNWdvhFq+WE/CzwL36gGlewYExJFAhQP4Me1iRRTWBIjU36RUHuXcys1IQWFur
         rOxS2CdTgSf3E2WBUdV/lb70IlpZ7epXbfbWKOrGiSEKnsHSHA4t7DKXSceobUpMMoED
         yGy9NPj3TcW9Y8CVNZes/52QNezJOyYHbQhVg/Q3edwccWWAaBEiD0I2EfOqaNjMfLub
         uQ3QSlUiE8kpzSBr7lbxHH8yeD3C6nscP1GK6D8Fz/i0pk4wQLi70pC40Rocol77sj4+
         d/rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t1u1o6lBz0FQNg6tz5xWHteE5Y5yiyiw7H7DFXcrJ98=;
        b=qdIKf2xlvEeHCB93IMg0tOVTIIeK8jHwhL4zIi4zgbqjuTD6kG1tzL7g43IlG4qHlE
         iQt+OW8SEWVmTsXyTt2PYpmq2qspDMLP/SC2JyoxNvkx2Sj5vLMKsmjD8ddc5VZZ5Tg/
         kO9verG29bLUzM13P6U6eo4nFICEIBpa8PTmeCYDphXBiDGhWDtuS2lGTeJhBLyKs8FC
         ZzhH0zz4DR1T3S/GT+jV7kYrsjGrFjQwTV92HrelAXEaMCCj+Ta3/Msi6pfdT+Sg4CGj
         xvk3wBMcUeBjo6wodI/aIA6xSA7/sC0JMNd2z0qoEzgYQJBnpNZdfj4VwjNv7pTAhAmM
         RZrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yanXotMKpBOJIcKFFNLFF9pMd/4L6GR3tZ4Nmri0xLXPJgIZP
	M6hyWkaVg2aNCpV3PbiaSxo=
X-Google-Smtp-Source: ABdhPJwGuu6qSCLWUHPWl31YKieR1gXccIiw235t91hru/qmZ1LUe6vfTAAUYTi9aKPZ6BQOlLVLmA==
X-Received: by 2002:a17:90b:3581:: with SMTP id mm1mr6030258pjb.98.1627698783414;
        Fri, 30 Jul 2021 19:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e787:: with SMTP id cp7ls1770396plb.10.gmail; Fri,
 30 Jul 2021 19:33:02 -0700 (PDT)
X-Received: by 2002:a17:90a:e289:: with SMTP id d9mr6039071pjz.186.1627698782922;
        Fri, 30 Jul 2021 19:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627698782; cv=none;
        d=google.com; s=arc-20160816;
        b=AX0e/ndmRSU7+RMw1MdKdmCOKx+zKKuAmJYAi36o8Pe+djZAoHaT2GsI86VnpMGCFv
         shK5b649wqKkupkY+TeLwlrgmvg/bzsU3bjCCOviw9WCC2jneyOOA0gx1y1YaZhtnbjA
         r1+x2nJX8oHWUFFr+EUJpUwAM8If76t2xbMnKjNsbDhg0lO9X2VQABY5fHfiNgETzcqH
         uxOBuspHCgwzr/D6/ssKUVRB3CzhU9VKiit6Xh7J05/oiVTK2naJlo8mrV8J7JmBFZSD
         80Jgs/j5WFPVna/cfEnahLAo4YDwg0M+8HjPiwTHpFbV2OKbriQAfdIPjBv7UpuHUR9a
         orbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9trgYz55yd7cJwSd77T0A0/Bhy1SVra5q9+sP/kcT3k=;
        b=b5M7CzJAJ/b3tTKIWmSEu3R9YeQ+JEHeqdarSFjORBublrYTwDSRm2XhVMvFEbHIc3
         105iwJGt//H3GB1hs6/9NOjN0z/jKnYbKzE0tRiLqZIwSIjKgRkBliD9BO0tRYZtImmQ
         I7zuQO9illvm7pO6huqdDyZkSF/2gscexBsCyZr1k3MUdXZRmOFxiQlv7aIf8EWVTaoK
         13VggdkpiIj/WrDceOa2oHBJ8plAPBOnvaqsgT0BAUVDHyq+4Nmy85FxSlA3F6SGTpPY
         cFCB5i3jLW0ufl5SG5dbO+3iXBTmwFyEiIthZ+lyYp1JN6FgVMLCET8QAy048DvUlIK4
         JWfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GcAdi55t;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g3si135729plp.2.2021.07.30.19.33.02
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Jul 2021 19:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8C86D60C40;
	Sat, 31 Jul 2021 02:33:00 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
To: Kees Cook <keescook@chromium.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Nick Desaulniers <ndesaulniers@google.com>
Cc: Fangrui Song <maskray@google.com>,
	Marco Elver <elver@google.com>,
	linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	clang-built-linux@googlegroups.com,
	Nathan Chancellor <nathan@kernel.org>,
	stable@vger.kernel.org
Subject: [PATCH v2] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
Date: Fri, 30 Jul 2021 19:31:08 -0700
Message-Id: <20210731023107.1932981-1-nathan@kernel.org>
X-Mailer: git-send-email 2.32.0.264.g75ae10bc75
In-Reply-To: <20210730223815.1382706-1-nathan@kernel.org>
References: <20210730223815.1382706-1-nathan@kernel.org>
MIME-Version: 1.0
X-Patchwork-Bot: notify
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GcAdi55t;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
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

A recent change in LLVM causes module_{c,d}tor sections to appear when
CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
because these are not handled anywhere:

ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being placed in '.text.asan.module_ctor'
ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being placed in '.text.asan.module_dtor'
ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being placed in '.text.tsan.module_ctor'

Fangrui explains: "the function asan.module_ctor has the SHF_GNU_RETAIN
flag, so it is in a separate section even with -fno-function-sections
(default)".

Place them in the TEXT_TEXT section so that these technologies continue
to work with the newer compiler versions. All of the KASAN and KCSAN
KUnit tests continue to pass after this change.

Cc: stable@vger.kernel.org
Link: https://github.com/ClangBuiltLinux/linux/issues/1432
Link: https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3fc08a59a01865
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---

v1 -> v2:

* Fix inclusion of .text.tsan.* (Nick)

* Drop .text.asan as it does not exist plus it would be handled by a
  different line (Fangrui)

* Add Fangrui's explanation about why the LLVM commit caused these
  sections to appear.

 include/asm-generic/vmlinux.lds.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 17325416e2de..62669b36a772 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -586,6 +586,7 @@
 		NOINSTR_TEXT						\
 		*(.text..refcount)					\
 		*(.ref.text)						\
+		*(.text.asan.* .text.tsan.*)				\
 		TEXT_CFI_JT						\
 	MEM_KEEP(init.text*)						\
 	MEM_KEEP(exit.text*)						\

base-commit: 4669e13cd67f8532be12815ed3d37e775a9bdc16
-- 
2.32.0.264.g75ae10bc75

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210731023107.1932981-1-nathan%40kernel.org.
