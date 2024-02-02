Return-Path: <kasan-dev+bncBCF5XGNWYQBRBD4C6OWQMGQEGCFWRTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 33F80846D92
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:49 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-42bfd4ae1a3sf11999761cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869008; cv=pass;
        d=google.com; s=arc-20160816;
        b=OH0d+VhRsd+1NyInsa+Utvkp1ILU1j04USHP/LpU9XEmrAIM+9X7x5/mpZWm+jDQAc
         h9NTViakNavsLDxTTHdHlPz5v+QmyuK/FE05dm/65UWRXlDkDiTQbeOl8slCFO1Beko4
         ON8zDuwZTpfxebq00kgJOTF4d0JbMcp6gUczR57FouKplPgamDbnKPe6x8x5F5mkTLmS
         +VmnxTyzHW+cjr0Q3C+/2FHHf5Z8u6xemu9S1MAdxZhngiDvrr78pE8AfBcAu+XLkk5/
         DPxnduiAPdEY8elgH+VTwBR9a9F3BtYOEqn8X6foA3UijXtmwzaFb6l3ivuLu9nMdMPL
         0m0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0IHiHGrdeqJGsnSus5tDqwEkufdsq5DhJ+ftEaCh938=;
        fh=jWwj8KjeXeA9XXmCgPMv+FXdgTKMHgyWgSl3/RphwVs=;
        b=klZlAUFNUItU85k5ILmPTeTwDXpWmYYsF+iTNTi0BJMHhQWwveaNm0uBWfQ2Mj03JZ
         tFvpsXHipLewDbaR0s449svXIDhuTLtUZF7LybmnCTOBXAu6U2sS+aCYuLbT4G6+iqBz
         Gy8xOFv4C4fXIT/8LSoqtdzuVTzGWPR3w/e9DRM6iHwBD1NySJnR9Btwur3vQz/5FnAS
         Tpco29maWf0KI3bHvoW/Ilc4lGnbhNeWgoLgyCCQY7VNiG77hCru2JZ2j9Y9yR/F2RvU
         K/OdfQsjuL3EuLcSE0E8lFbKV2TYJOMkbEUMe1OGBnr/5wC9ibtSigKCwz+nBqKFV8AC
         L6fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Yg8fq9oZ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869008; x=1707473808; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0IHiHGrdeqJGsnSus5tDqwEkufdsq5DhJ+ftEaCh938=;
        b=IoS9QRjfXGUqiEv7/w3czKhRUdrsmYvgXizrYu5+jwpabv+RwjI4LMVndEdS5VYeJO
         M53zySSu6qLvbwz5bjOMh6zI5rHoG29ufTk5YOUPoCbexv2o8rroYZhtSCLYcoUw9Ib/
         yGAjZ+UbVLYP1sT5YI+YL5s1VZy2dlx5T1DuayGBoN1sz/E0mL+AQamHkDEF11fCLYPg
         Svnu1YuMl/zO1rxgCUOuQV1mhebI/urWTttPLpnCSpzwoPuok4r64cA0lspN3WlsTIWn
         QAu9xYGBvSeV0mkcVkXnh03LsBMFTM81XzJ03JoZ/3lapRaym3MqrdZNmvl8VQPY9mlv
         ckdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869008; x=1707473808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0IHiHGrdeqJGsnSus5tDqwEkufdsq5DhJ+ftEaCh938=;
        b=Ce6trTqpu0VAHA1SgTCr1naRUROr28sBpHRw0kFm+1wz+meh9NV2k31DpB72r3yU+v
         VtnrXlrdrEZWidhZtRh5SDG6oIeJRqAUP/IdV+C/UAcRHI8lLJ8vs9GMQDn287wokeDb
         8rDqpYV4/HvQ3cE/p1KpFWWhnIcD4I4R2gtEnSy8mO17h3xP+ooSZIble4X5npkOIlKh
         JLxh6scMjYAT/HaXZsIPut5JanIaDhnZsorsWkSME8Xf82evlb9TtysxKsObPyS8pvio
         HYqWOQrEfQ2WMDtDlnMJPNaWWJUkSRB+EooJE0a7A//Wule682bOJSk0UYIocMoDzX0Z
         2ATQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YydkDvGA0e3nKo8/Lg2X7h/2f2hZKQrenN2k7s483XZuhX2/+yB
	2Z9NEC9EUxOW26KKmtc8mIJnm+m9HuPDGGud7Z+0SfC7dZLQO3sn
X-Google-Smtp-Source: AGHT+IFsCdKIqRHGLvhy0r6jdY77ffy8pLsLRp7xiU0qsM8e+XewnhKJG2C9CxW4EOzz+qlCia96Jw==
X-Received: by 2002:a05:622a:56:b0:42a:e92e:fd85 with SMTP id y22-20020a05622a005600b0042ae92efd85mr5903246qtw.49.1706869007921;
        Fri, 02 Feb 2024 02:16:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:11c8:b0:42a:a1a6:796c with SMTP id
 n8-20020a05622a11c800b0042aa1a6796cls2045778qtk.1.-pod-prod-03-us; Fri, 02
 Feb 2024 02:16:47 -0800 (PST)
X-Received: by 2002:a05:620a:2988:b0:784:db3:33ff with SMTP id r8-20020a05620a298800b007840db333ffmr6304515qkp.77.1706869007219;
        Fri, 02 Feb 2024 02:16:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869007; cv=none;
        d=google.com; s=arc-20160816;
        b=pcuEsvXzw4p8a/ZR0JCXbN6ncvdJLU6gz1rkOu8ThvecugviGNjBtlJblHlLa0yKxY
         jZr9aPwDhpT7C1C/uezXepJLHmtMfinMDR9XYrrJo/sRB6P+x5DFWOTGT02IzdVAomsm
         18+M5q+r2E2G6SuNJi6EijELLfL2vZ5px8PtfwfqDUQnG+YQ6m4miuWhV3uPW9HOCLGp
         uwDG57oAUk0I+W/PtLx/dt8DVGd7cTXSOam02FGD77XnX7fvsn/e94m+9aGLp7PLmw3W
         v5SXi/RxYzkSyDHpS/r7PdNXTtGOlBrHj6Q5wyB9FWSBALepq5cND5+dBA51ZMCFQnfA
         D6WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MZoPcgm2ExbWiklFnpgC7jG0zZ989QvpgVdI0GYP0N0=;
        fh=jWwj8KjeXeA9XXmCgPMv+FXdgTKMHgyWgSl3/RphwVs=;
        b=goWmHiLLL9miMdLc1C1NatOksLMwweKykXSC1yojkP5XTHkMcKJmqpq4KExk42IZFR
         NWVxo/rotaZxd937vEqjMx0QH5c7f8OsSEyW0FuBbgza4+es4wQ8ysE6LZk+1+azrtRR
         CA+yCXU318cNZmsqp5e0VGKS4ve5UeajOqa7X3bayb8cGaCZ80b1YLvzg82+Sk1qn8Ld
         nmqXSpvrCfQCoVtGvhFQ9CQg/bT53UkofWDWPrNqO6aDWbwJMjI6phtDyVWlo/9k22sb
         d+1lsrYU4zswICcqNXFPsgK5DfqhyNAfgJHRz+rf5PaLlEkyk8ejFbopzn5HzqSGgU+5
         02LQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Yg8fq9oZ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCUX8nVw3bkmG/vdwDCr4WhBgP8D/nVY8YfA9TFELr1qvV0GsYqKbpXvh7V/qyZxaLtnDJCxdmr9qzgqBdUgaYaCFOSxwFl3Z5kOYA==
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id g13-20020a05620a108d00b00783f804d14dsi97039qkk.1.2024.02.02.02.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:47 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-1d953fa3286so11490305ad.2
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:47 -0800 (PST)
X-Received: by 2002:a17:903:11cc:b0:1d9:4c1c:1982 with SMTP id q12-20020a17090311cc00b001d94c1c1982mr5628058plh.50.1706869006293;
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCXOeMEwTCrwVTk9AQndfLYbmDNRylcw0o2ibKbDnMznrN7x11BigeKNplTpQlrOOpph7WEjjuxpE37XcuRQfl/0SHfol6HMQr+MqIRtGDONtHO6dAl1jMs/Tl6W9r24YET09T7hCL/DO0FDFGjcrC72rvm4mB/vmqOvh1vxDsJyuLRWvJWw3/w4z5rtvEuZRPkMbGoipZgtg8rcJ41sXsdo3angUjuj0G8ec7QYPFYuwWy+m68cyEe81OcaIe8sLbj/3O4jmRH3AzegBGuGr90yL+ibNtmBIeC/OVpGpHJm2gVK0NWlmoly6bhTYXr6L9BOCB0Kg0OH0RhAQsjB8f7xNDxL3As4UhLZ0YCWsC0g+VHBc9hDuym9JMTH9yaR/XOKFsvfd43CsTc7PwSMu3sdUPXjMz+pCj9jczZeX5BQcIdGiFX5YT8STUPN3jjkdQkl2FR2og8L8USVcSWVqrGvoZz86uYU6tZqLZFUyIvexgzNZUgHwgBhfGx3SWl2sTnvtJiFkQqwa+BsspRXuZQwFGIPxhj3qP6TvyotG6foKdxoC+FcQSYbhRLIL6CX/nulbU7pIr8Ch9Utkr2d3zpj+PXBtF8WdCCWg1Y=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ks14-20020a170903084e00b001d963d963aasm1247928plb.308.2024.02.02.02.16.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:16:42 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	Fangrui Song <maskray@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Bill Wendling <morbo@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 4/6] ubsan: Remove CONFIG_UBSAN_SANITIZE_ALL
Date: Fri,  2 Feb 2024 02:16:37 -0800
Message-Id: <20240202101642.156588-4-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240202101311.it.893-kees@kernel.org>
References: <20240202101311.it.893-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=7713; i=keescook@chromium.org;
 h=from:subject; bh=ChqR4pwLOMRrvI2mwMAhvrmBk7bFBrYJU+84/NDgMjc=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEHFqznRoc47f8x3QBqsx9X6BtCiDiZKmRIR
 0EaK8ZbstmJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBwAKCRCJcvTf3G3A
 JongD/4vXj5YeywVHimPvNTkjtoy7sRY1cQ7zCQ+0Hictm2B0DGz5Xk+fYxqkuRfc151mQ9m4RW
 hP/Nu0vNsr27XyXjaTp9nQ6ahzuF10bljtgK2IkLDZcNMmOIIyYoeEiQP77LDx8eSdT8g4BAsMh
 RWVq9uL+azlAB7GshQN1aC48YvnG3+ilmBoUryzPZq44ElHQ3imdRFx0QIB9uvCOHalfj0OEFzm
 LFFkPuCcG03ZQliO3kdl1J1rKlnJ2NScx4Rv6golBOfRozWCYjp1R5BTLDAotn+wLbFOshsHTir
 VSRCVP+LlRDHI0x7gdG8KFNrj8lcD4TLoTjz7pAlDq1AYVyQ1d2Nrob2lnKfNA8uzLgs8SoP8yo
 YkCJj1Gt9TvyIZZKqnqd6JgPANTPlc/uyAdyafJYYew8mAa2ts04DSpqWxna1uiTLUj3PCd8u5k
 RO2KY6Z2qcIsyanyIH3xHV5ivXuf1VL6vd2O568ewYuMOrPgrY0dGATL9aKYAHsVDlr0Y1iWh60
 WzYRH7kF4CJmKRh3Jmz19lehP4zo61sK83NIUBMxauh91KIEpurKTn9z8sRc82twKvcKOPv2IRD
 DMVj718hh+eiK507UGiwiIBqJY8/lm3ljxl+5UzgkmZhmTAPeq4I1i056gYcFjcE4J5ij4SVemG geww1McF0NisgJA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Yg8fq9oZ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

For simplicity in splitting out UBSan options into separate rules,
remove CONFIG_UBSAN_SANITIZE_ALL, effectively defaulting to "y", which
is how it is generally used anyway. (There are no ":= y" cases beyond
where a specific file is enabled when a top-level ":= n" is in effect.)

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>
Cc: linux-doc@vger.kernel.org
Cc: linux-kbuild@vger.kernel.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 Documentation/dev-tools/ubsan.rst | 28 ++++++++--------------------
 arch/arm/Kconfig                  |  2 +-
 arch/arm64/Kconfig                |  2 +-
 arch/mips/Kconfig                 |  2 +-
 arch/parisc/Kconfig               |  2 +-
 arch/powerpc/Kconfig              |  2 +-
 arch/riscv/Kconfig                |  2 +-
 arch/s390/Kconfig                 |  2 +-
 arch/x86/Kconfig                  |  2 +-
 lib/Kconfig.ubsan                 | 13 +------------
 scripts/Makefile.lib              |  2 +-
 11 files changed, 18 insertions(+), 41 deletions(-)

diff --git a/Documentation/dev-tools/ubsan.rst b/Documentation/dev-tools/ubsan.rst
index 2de7c63415da..e3591f8e9d5b 100644
--- a/Documentation/dev-tools/ubsan.rst
+++ b/Documentation/dev-tools/ubsan.rst
@@ -49,34 +49,22 @@ Report example
 Usage
 -----
 
-To enable UBSAN configure kernel with::
+To enable UBSAN, configure the kernel with::
 
-	CONFIG_UBSAN=y
+  CONFIG_UBSAN=y
 
-and to check the entire kernel::
-
-        CONFIG_UBSAN_SANITIZE_ALL=y
-
-To enable instrumentation for specific files or directories, add a line
-similar to the following to the respective kernel Makefile:
-
-- For a single file (e.g. main.o)::
-
-    UBSAN_SANITIZE_main.o := y
-
-- For all files in one directory::
-
-    UBSAN_SANITIZE := y
-
-To exclude files from being instrumented even if
-``CONFIG_UBSAN_SANITIZE_ALL=y``, use::
+To exclude files from being instrumented use::
 
   UBSAN_SANITIZE_main.o := n
 
-and::
+and to exclude all targets in one directory use::
 
   UBSAN_SANITIZE := n
 
+When disabled for all targets, specific files can be enabled using::
+
+  UBSAN_SANITIZE_main.o := y
+
 Detection of unaligned accesses controlled through the separate option -
 CONFIG_UBSAN_ALIGNMENT. It's off by default on architectures that support
 unaligned accesses (CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y). One could
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 0af6709570d1..287e62522064 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -29,7 +29,7 @@ config ARM
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG if CPU_V7 || CPU_V7M || CPU_V6K
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_KEEP_MEMBLOCK
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_MIGHT_HAVE_PC_PARPORT
 	select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_OPTIONAL_KERNEL_RWX_DEFAULT if CPU_V7
diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index aa7c1d435139..78533d1b7f35 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -107,7 +107,7 @@ config ARM64
 	select ARCH_WANT_LD_ORPHAN_WARN
 	select ARCH_WANTS_NO_INSTR
 	select ARCH_WANTS_THP_SWAP if ARM64_4K_PAGES
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARM_AMBA
 	select ARM_ARCH_TIMER
 	select ARM_GIC
diff --git a/arch/mips/Kconfig b/arch/mips/Kconfig
index 797ae590ebdb..9750ce3e40d5 100644
--- a/arch/mips/Kconfig
+++ b/arch/mips/Kconfig
@@ -14,7 +14,7 @@ config MIPS
 	select ARCH_HAS_STRNCPY_FROM_USER
 	select ARCH_HAS_STRNLEN_USER
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_KEEP_MEMBLOCK
 	select ARCH_USE_BUILTIN_BSWAP
diff --git a/arch/parisc/Kconfig b/arch/parisc/Kconfig
index d14ccc948a29..dbc9027ea2f4 100644
--- a/arch/parisc/Kconfig
+++ b/arch/parisc/Kconfig
@@ -12,7 +12,7 @@ config PARISC
 	select ARCH_HAS_ELF_RANDOMIZE
 	select ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_HAS_STRICT_MODULE_RWX
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_HAS_PTE_SPECIAL
 	select ARCH_NO_SG_CHAIN
 	select ARCH_SUPPORTS_HUGETLBFS if PA20
diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index b9fc064d38d2..2065973e09d2 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -154,7 +154,7 @@ config PPC
 	select ARCH_HAS_SYSCALL_WRAPPER		if !SPU_BASE && !COMPAT
 	select ARCH_HAS_TICK_BROADCAST		if GENERIC_CLOCKEVENTS_BROADCAST
 	select ARCH_HAS_UACCESS_FLUSHCACHE
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG
 	select ARCH_KEEP_MEMBLOCK
 	select ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE	if PPC_RADIX_MMU
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index bffbd869a068..d824d113a02d 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -37,7 +37,7 @@ config RISCV
 	select ARCH_HAS_STRICT_MODULE_RWX if MMU && !XIP_KERNEL
 	select ARCH_HAS_SYSCALL_WRAPPER
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_HAS_VDSO_DATA
 	select ARCH_KEEP_MEMBLOCK if ACPI
 	select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index fe565f3a3a91..97dd25521617 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -82,7 +82,7 @@ config S390
 	select ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_HAS_STRICT_MODULE_RWX
 	select ARCH_HAS_SYSCALL_WRAPPER
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_HAS_VDSO_DATA
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG
 	select ARCH_INLINE_READ_LOCK
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 5edec175b9bf..1c4c326a3640 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -100,7 +100,7 @@ config X86
 	select ARCH_HAS_STRICT_MODULE_RWX
 	select ARCH_HAS_SYNC_CORE_BEFORE_USERMODE
 	select ARCH_HAS_SYSCALL_WRAPPER
-	select ARCH_HAS_UBSAN_SANITIZE_ALL
+	select ARCH_HAS_UBSAN
 	select ARCH_HAS_DEBUG_WX
 	select ARCH_HAS_ZONE_DMA_SET if EXPERT
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 04222a6d7fd9..0611120036eb 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -1,5 +1,5 @@
 # SPDX-License-Identifier: GPL-2.0-only
-config ARCH_HAS_UBSAN_SANITIZE_ALL
+config ARCH_HAS_UBSAN
 	bool
 
 menuconfig UBSAN
@@ -169,17 +169,6 @@ config UBSAN_ALIGNMENT
 	  Enabling this option on architectures that support unaligned
 	  accesses may produce a lot of false positives.
 
-config UBSAN_SANITIZE_ALL
-	bool "Enable instrumentation for the entire kernel"
-	depends on ARCH_HAS_UBSAN_SANITIZE_ALL
-	default y
-	help
-	  This option activates instrumentation for the entire kernel.
-	  If you don't enable this option, you have to explicitly specify
-	  UBSAN_SANITIZE := y for the files/directories you want to check for UB.
-	  Enabling this option will get kernel image size increased
-	  significantly.
-
 config TEST_UBSAN
 	tristate "Module for testing for undefined behavior detection"
 	depends on m
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index cd5b181060f1..52efc520ae4f 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -175,7 +175,7 @@ endif
 
 ifeq ($(CONFIG_UBSAN),y)
 _c_flags += $(if $(patsubst n%,, \
-		$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_SANITIZE)$(CONFIG_UBSAN_SANITIZE_ALL)), \
+		$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_SANITIZE)y), \
 		$(CFLAGS_UBSAN))
 endif
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101642.156588-4-keescook%40chromium.org.
