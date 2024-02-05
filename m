Return-Path: <kasan-dev+bncBCF5XGNWYQBRB3GIQKXAMGQE2PUQLTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A17728495D0
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 10:03:41 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-363b685b342sf20855235ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 01:03:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707123820; cv=pass;
        d=google.com; s=arc-20160816;
        b=lIkL1HxrAe8znBEo9f987ahY4iy8zDaTXDxFFZ5yxGzMjyqgR9O+6MkSzNP+LptBgc
         eeIusIjJRJOlEr02r1PDT/ESr70iuvDG6aU52pCF6om7uFJQb6+MdXX4psFhDeZc6QHK
         fSG09CVGhH+VjWZpREJi/+9FojmKBEYSOz52L86+Go2ObQDRAKrOnmUxGoOutHIGdP89
         5mx/1WCHGFSohjJx4dTaDl30hkhHdC9AL3a198MhxuSNJeozg1jxNQXgUs+OWCEyS86L
         SuHDRfgvzKZZALVF59CCvGHQFzJ3p2UMxyaUyA5jBKjBGTocAMySPVat4vdgM3xAlkAK
         ILvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=AfGPPg3KBHsirKGHAvwHPt9TRZ6ozUomDuvNs6oxg/I=;
        fh=sYvCU3p1t9bFUs1ipoWnUW2g7BGFkheblTrw8V6a5mI=;
        b=ThHfEOdKaBbQy63Sk1Zc4+8ZyAs6glSQ/RNrlk0XBXUrkvOrncNqFFXtDJAyFCEVkP
         H4WW90jWPmWGpFqnKcBRlcM1f2/Dl8E32ktIc6Wh7EmaJllxAu49chMYjZDjYY500l9E
         /+/aItBC5hlaHoWbJDhGQcA8pKvRfzTjj9D3kHn9kvNNJPXvXAKFV1HJTRuDNUlY/wAW
         0JmeNG3dk4NaOKDZLN250UTBXNlcQ0r/lmL6URQlyRl/CJjqMWcfiqXc2eVm5/86mnH6
         ISfCfDzI5G761suCKy0LgKP+XxEG7jPt0AKfQV4yP6i58wYbCvDijOqh9RYcpx265ELM
         D84g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eph3eprd;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707123820; x=1707728620; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AfGPPg3KBHsirKGHAvwHPt9TRZ6ozUomDuvNs6oxg/I=;
        b=H1a8vLFnGMnweJLBuJ6qi9my2r1Llz5K0GutUQ5n0REUKLW3R1SIE/NPFLn4FbXgIG
         G9Y4CgEyguXzjuj5aax/Zbd7oJKlxU8JG77EvSCki0gcR0WtzWh7pF5JC1riva6Hrrqj
         e01KiNmXi3hxxklDroIUdgLmvmt/HJtMMyBmjUbt/sKgDTwj0oY+kFdt+0QZP31zwd4n
         lJTqrL/RKzYJP2K00QIZCVuy4EGIpsLDsaRepfYP1XZ1pfxVjxOPr7U9vZbLggrv/Cyj
         F3663E6oLeAVUlLI5N1v1I/3f7Aii9LVWm/KZhKVxuBRdb+JLIv9AMi0tzEeVzsfK0dV
         HBbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707123820; x=1707728620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AfGPPg3KBHsirKGHAvwHPt9TRZ6ozUomDuvNs6oxg/I=;
        b=hzYl3fHUvbqMWw0xzE/bo7vJUAxzTBE+a7F0ssB9ysMXvvnMkpZCJbe3haLcG/ol0a
         uLde84sjQDYuQgrEJ7ceb6FSxgDBnvDH0JuEn3Ip9dJS4RUcL6XNzFP4ATa8XeWd72Ru
         klibN3hd6+Um0TOBAksgBLeNRu4qHhYi4JjP2zpk0GI3GLQWzrS0MWDlXWBCUD4lQPKz
         iiGlPsAnlkG7aa4o+2YlU4s+O6jaVttVa+iIolbs9EDBNZVnuYZv3Nj9bP+O7xi9rCHx
         +UQCcjAFGx7Am/KP5JgNrbaad48P1r/TfsGq+xngpQwfUAPA1KXfyfHsv/HAIEVyT6ok
         HEaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwbBNzjE2p8jA6eT8D/2CdHuNq0+q5MrwKHcIoNERV8hHvcobhu
	VxLfOm5JJQTEr5R0NKtMP2UG/qwJ0riA9BzX9g3BhUARe+eqtgVH
X-Google-Smtp-Source: AGHT+IEp9vrrb8FJaXC0eBnNHYbOP4i5lSxIMYekS/Iwpzd74ffzZQrkPzBWRrlYj3kFjyN+Sa9hKA==
X-Received: by 2002:a05:6e02:5cc:b0:363:c041:154d with SMTP id l12-20020a056e0205cc00b00363c041154dmr4393932ils.16.1707123820290;
        Mon, 05 Feb 2024 01:03:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:32c2:b0:35f:a8a4:e425 with SMTP id
 bl2-20020a056e0232c200b0035fa8a4e425ls1637875ilb.1.-pod-prod-03-us; Mon, 05
 Feb 2024 01:03:39 -0800 (PST)
X-Received: by 2002:a5e:c241:0:b0:7c3:e397:23da with SMTP id w1-20020a5ec241000000b007c3e39723damr1255239iop.17.1707123819158;
        Mon, 05 Feb 2024 01:03:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707123819; cv=none;
        d=google.com; s=arc-20160816;
        b=rvBiSbgfkGHRgmetvyQi7xEe3lVRzwP6daRo5ur7ICgYsgygCJOgXBM9cda8WnmOHg
         6MUu6bzCmTUn0nnpboQK3zvzSU7g1VuhWegyDS97erpuA9Bj9GlIzDO7ezKoPkaFmbd4
         5K0v3Bf0VpFZMuJvoNPo2HPHSEb00NtRGm3eWEUhYrJD0WDNtQ3Yq7GEQHcFa67VSOYO
         0eFc9XX9cNbgd5LDzumdfGXfUZbrEHpuEBa+COnSpuTworRrv7HwjS0wne7ZASqfDMxR
         P4EhjYARLnB7bk43FWMowK3Jb8GsrBisEgipvObXAtbPGrQA7NzZvTRyFehyGDaV+7Ty
         Cphg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=mp3IqjV4mL2aPdf1tPNFMiYIaoCwoYk+bStjGqy3K98=;
        fh=sYvCU3p1t9bFUs1ipoWnUW2g7BGFkheblTrw8V6a5mI=;
        b=s6zgBu1LOlPftM0eoGHVT/VPGd1zjp2QOE+68oqTOVnwx/eWIUUIEUSuMFPwCAMto6
         r3qt4Zc82kSR3sTy7FdXwWbZ12pI/QkOGPAvB8KHh3HKDHmTj7lkX2TO3qHJ6nHqHyaF
         v8qyzhJQo94n0sZllWlJ1noiPZTNyGMS5JjND6xT8bIzadukjVFHCUEb8/7vKjp5RfYs
         WSLYH0OwKMsPuJUPxxlIEJeCJk8p0slXEg4F1RkYgO+E7Su12Sd1HjorA8xgpbN+EuAM
         z3CKBsPIKLdKbF2D/ct4u4fwlHc/VaJCs4+mkYfgk1uCKPFqtCCpfGJoqthQlQKDkp8X
         ksyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eph3eprd;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCXg+yD8r5lhchJHfLe1R9kDp/Iuy1/h9FI0f//RcBpytnndserlVxUr5Q93ckxH7m3PCx/++pUrAnOmN/dYgC2pE4678CArrtbXuQ==
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id u2-20020a056638134200b0047132697a1bsi80215jad.1.2024.02.05.01.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 01:03:39 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-295ff33ae32so3508643a91.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 01:03:39 -0800 (PST)
X-Received: by 2002:a17:90a:b396:b0:293:ed23:c2da with SMTP id e22-20020a17090ab39600b00293ed23c2damr11932866pjr.31.1707123818477;
        Mon, 05 Feb 2024 01:03:38 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCUq9BeWx1VsVS673oyYEwknMfep8C7cQ3JgH5JRfz2kue0NgAm6Ezy6xS+aPAzwHzBIfOvYupY+YZG4TU2fH6u0kOMtkwYhn9OUb6R2IcCXs1FgVW9F19ZiEZSpXoGqfFGjFt5Sja07XbhobA27GwasIa2kjhZhlHl2zDKLANllLbPrqbpQV5haY2lwjL0G2SksHjrUBDFrJRgj6l/2vDrVEHDXd0HN6G1rMiAbOQI=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id c11-20020a17090a8d0b00b00296b50bb21asm145311pjo.27.2024.02.05.01.03.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Feb 2024 01:03:37 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	kernel test robot <lkp@intel.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2] ubsan: Silence W=1 warnings in self-test
Date: Mon,  5 Feb 2024 01:03:33 -0800
Message-Id: <20240205090323.it.453-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1751; i=keescook@chromium.org;
 h=from:subject:message-id; bh=U0IaqYEgUxaoMI0fBY1yJtEGvGyAUmEfSrUJjZ33FhA=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlwKRliQJ3Zrj4Gq/zti8TCPet94FjB/Zy9OG7l
 x66V+/rIbWJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZcCkZQAKCRCJcvTf3G3A
 JjSgD/9lepgY25jHskT5SrVcPjJLGvkdPADYl6m4jH2xPgQDdn6CSFODj8EWE5GmvpcOVMJgwC6
 7jBV4u6voWcafB/4ANNf+bNgP+8EVId4RaGpxmP3NqGhVF4fstE6F2WdpdKdEfcVBoYKC4JrrxC
 CyxsVPhvzOOxjiUVPi29gpOw+DJ8Lak4MTF4GGb6UO7RqcW7xvWY6nmekydhfZog2Gg52Orl65q
 nrcUa0Gyn931e+soRLtInewzTR+nHwTrXHu6S/mQtqGh3+L5qxEPzjs/02+LBNSxH1Jm9cj2jWF
 xElVm8Bg4JY4jmMqErpWNhde0lL2VnZmEEk5kUp3qhEoXknvT+j+36gihOlLS2kz6PAoFX9Ejoc
 Ry1EFw5tQnArOVi+P4I2ykYbm6warowICK7N1POFwG0h4liJcjYdt/PuHZE6GRrqZlvabZIk3l5
 XxcDJZ4vRdIMs4+HyrMI9ucsvgqER2zSpjFrrowoHX+Uum2zrlLTeKDNfs6b+5gyn2WFx4Rudt4
 D9GvS1zUOt69boYoUR3nKDQBzlxFon520tI+qJgPQP13AYafZyVTAq4T6Cndf1lh/v79wZlG2NI
 jqpW/1XbdMw2wxFLNI5N5E/ybq5bUy9LGjrXv+I9ov+KKidB5mAc8ee0ulimvA6qOIRYZ2ujySl
 4U4UVfi GEUKzg2A==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eph3eprd;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033
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

Silence a handful of W=1 warnings in the UBSan selftest, which set
variables without using them. For example:

   lib/test_ubsan.c:101:6: warning: variable 'val1' set but not used [-Wunused-but-set-variable]
     101 |         int val1 = 10;
         |             ^

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202401310423.XpCIk6KO-lkp@intel.com/
Signed-off-by: Kees Cook <keescook@chromium.org>
---
v2:
 - add additional "volatile" annotations for potential future proofing (marco)
v1: https://lore.kernel.org/all/20240202094550.work.205-kees@kernel.org/
---
 lib/Makefile     | 1 +
 lib/test_ubsan.c | 4 ++--
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index 6b09731d8e61..bc36a5c167db 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -69,6 +69,7 @@ obj-$(CONFIG_HASH_KUNIT_TEST) += test_hash.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
+CFLAGS_test_ubsan.o += $(call cc-disable-warning, unused-but-set-variable)
 UBSAN_SANITIZE_test_ubsan.o := y
 obj-$(CONFIG_TEST_KSTRTOX) += test-kstrtox.o
 obj-$(CONFIG_TEST_LIST_SORT) += test_list_sort.o
diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 2062be1f2e80..f4ee2484d4b5 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -23,8 +23,8 @@ static void test_ubsan_divrem_overflow(void)
 static void test_ubsan_shift_out_of_bounds(void)
 {
 	volatile int neg = -1, wrap = 4;
-	int val1 = 10;
-	int val2 = INT_MAX;
+	volatile int val1 = 10;
+	volatile int val2 = INT_MAX;
 
 	UBSAN_TEST(CONFIG_UBSAN_SHIFT, "negative exponent");
 	val1 <<= neg;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240205090323.it.453-kees%40kernel.org.
