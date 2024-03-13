Return-Path: <kasan-dev+bncBCF5XGNWYQBRBCGZY6XQMGQEJG4PB2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DC6087AEE6
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 19:12:25 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3662dbb587esf1568215ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 11:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710353544; cv=pass;
        d=google.com; s=arc-20160816;
        b=g4synPogy1H8m3rP31G/dpeAqBSA5TQ8Ga2DwRPPpd7doQKhICjN9z1mnJdXsxto9E
         JLkze+DOyYD8dZA7eHcYMoi90fgBcb9XfTX60Xnjb8hOfEBVzo/goVLeQZmVZUayWKmJ
         WtTiPVARIs7x1qk86oeBcVFiK7nkRO17v4XqWBEfh23uvs3dCn8tw24v/GoFHOPIM77/
         musH9DrNUUuuA3UXbLz3TLg5H6y/KtTQYXuUPuPKvpzAhm4LVnwXDW40nglsIBzyEzkF
         /9h4k/6nww2xND+8WBezY8/8I5OEhwGg4muRcGXQgs778dy+AwtalY6DLHub8+6wcA4L
         xvVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=gg2uDieQx5eSU66Uf/l80nd7XQJEZrBd9q9aTjZCgC4=;
        fh=qhS2W8wwpQaO/WIDNHm9kLe/GCw2zOlF9U+cajmI9zY=;
        b=dMGxzVzX5glgSB6ANf3v3b1su2UIxFPo3/dpQivdW1WDkGIhPv32lphucxMWRztreT
         o9tu/RnMGqYALW3iWwPmAsNMvAlRJZcrhuYPCbvrGWhasqW3vG3E0STDD/I11Sfv7roL
         oAqU90TRT6blrErAA4OeJNtyFzZbc19ezsBIrYfOut98rdTpMdotd/KNljINAoa061Tb
         UYeF3xjwpY+Co99aGJiVqM2kVA8rZ/TXydBsp2od4w36w1L4zTcrykeRNVVYZhbspXs5
         rPGQ8Q02SFgJbj3XR5L6WAU52gYIR70O4ZxZ2hVXOLfBnNZJLhYz+JO+NXhqkBfHDlEQ
         6cUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EYEtX0hW;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710353544; x=1710958344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gg2uDieQx5eSU66Uf/l80nd7XQJEZrBd9q9aTjZCgC4=;
        b=ap7baNAQH3ah1PWrzByyD7h42k99i59i6VSvBoYB8A/z4cbNNWknCACZNQBHyscNt3
         tpasj2sjjC/OsAhoWQoYaS3HW+6ByR2blbYWpA45swfvnZgC3xYu+8KU1U2r2/IldGT0
         poaOWRcxBd/LAlt2Dbe9y9blpwo4JaQcKNXr6QF8LVDxAiX1HolwP/xdsnXVDIaX5zvs
         iWYN7aMmH6cV0G+yXWC5HvEfGZzEvc1yCa+P2qghgDq+8/2hLOooJIBO9PKDd34wxFp6
         4Sr1J5RUM02Kb1oclyOKP3ZawdnqMriZPQ3IpdpNN8Qvx/Bl42hfFq6bdRPsTAYq+7wq
         Xxrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710353544; x=1710958344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gg2uDieQx5eSU66Uf/l80nd7XQJEZrBd9q9aTjZCgC4=;
        b=IOgZOdci45v31TOdxtCq9God1AaYy8oNrZxZdxJ6hNzd63nXoJwiHuBPxey+mu9+mv
         7xc5UzJvxWHl6A91C0n444zZdkQjfm4kpvl/A3+JIFgdiym/M365JAYQqeSVV6l4Zgg+
         96qOxxA5CSGBpvCKrnNyvb4Y2l/ul19WivmUnPOW67tUAXQmjF/Wq/gd+EO0Bxv98fw9
         POBG+uci5HetWDbvORqrBwJFi9GEDVrjXVD8SRoWY7yDOeXXK4zbAAf1T69hori/nclS
         rul1eOfIEnSMOC8U5h9+ZU+aCY0ySEkvzxkRKEq+Nt5XjBJD6clV4hamLMPbvSwa+mzD
         reZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMNHgQ0wWu/sumot49f9ivLKZbWXCOXGt6XAYHNGdSTuRaE6ySX6CWze/pKcj2g++iyWnBhOMDfzeYGVRz/kiM+RABmcSVUQ==
X-Gm-Message-State: AOJu0YyyTabnwRrA4jM8WQb0zfsvQEGuYJktW22N/+cL42gGXudRV2kh
	K8/J6bsbg/oAyTuURN29iIBmhdkRK91T+9tBdQH1yzZ/lCM5c6vb
X-Google-Smtp-Source: AGHT+IFtRCbz4sa6ZPp9tPGrcnZB/Hbff4me/4h68IDlF5k72GyIk6VnkyfghBYfCX/M2nRj48spDw==
X-Received: by 2002:a05:6e02:1a8c:b0:365:d2cf:a46e with SMTP id k12-20020a056e021a8c00b00365d2cfa46emr842366ilv.30.1710353544406;
        Wed, 13 Mar 2024 11:12:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1547:b0:364:f4f8:1f07 with SMTP id
 j7-20020a056e02154700b00364f4f81f07ls85286ilu.1.-pod-prod-09-us; Wed, 13 Mar
 2024 11:12:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1idfNidYJduNNJCtqVjGVpkkV9ZUJe6+Q6ECfwblYJQ6DWrHeUsckdQK9zq7RW3dm+ElVFXxlYJvL/v1p7sS5NhlIwXW5YXmN9g==
X-Received: by 2002:a05:6e02:214b:b0:365:dd9:62fa with SMTP id d11-20020a056e02214b00b003650dd962famr930638ilv.28.1710353543469;
        Wed, 13 Mar 2024 11:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710353543; cv=none;
        d=google.com; s=arc-20160816;
        b=ZS6QpGVTUhdWpQdMMBuzR+2mcowK2k3ISI7Q9uuE5dU0CDUVfFIvmR+WoLOE/u5RJz
         l04wy3T6LEw2Elh3dzy3N4xnSjbU9ZLMfcYiYUNDz0tgOoyFFa3wmlb3o1aFzdZUWunP
         /TxK4H+lj95GgEO4wjhusjmNSKb0VL4xM3ZI35XugiMKqoUb3VKE58Po6j+KDL997UsN
         9Q2ZBFDYSdTj0bm4q09Lh8W9poaBGPw58XrMdWG1Hja+uezyJDKx0JK4CmWJdKzRy3iS
         L0cbQmt7OJHn0JWokQFfsK8IpidL58yhX0EiXo/87e9EMXszPQRkZhgSIMekLtgjMAga
         nhXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=zH16D+dx0oQl5CujF1HkbTVT0zJku0/wsGqqINARPF0=;
        fh=mXi0GXogjVtAUln+ogwn5MsPJulTIDlYuOreOPGiFHU=;
        b=LNrs+3sAS3ZJIBJb8UQUctwSWF5fhpvGa63ZBLY8gt7C5qPmr1Z4K5nAzdEhSJaUxp
         3JXgs8Fh5QPalPfgKdojrhzfuZZ8wtGkX6tRJ+iK3ix8uH+WXd7zPRm4NtJyj2SX825k
         /002s9LbdkQTaWt9DC9saLtStGqbpxSBmNlqpFQzKWE921SF7nnEc5Nmx7mBLhV8uT81
         CDXau1VjbtqiKzC8az2AjFz/Bv+GX0JS0YcLAbfHYWz50TAXGy3KF0cgOOG/CMFxFZLn
         fZZ6z/FyZG9Ix9/43HSaqnU8pjwy0qtpOy7X+WC1iUtIt0OjzPYK0AFoabeDOcGWnOKk
         a9Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EYEtX0hW;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id o22-20020a056638269600b004770c2e6beesi322104jat.5.2024.03.13.11.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Mar 2024 11:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1dd84ecfc47so897215ad.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Mar 2024 11:12:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZPLckNEUH9eRL6I1AYx4DqO7B9MOFJaRTQPcseWK3qu25Kpkj2fQ3LKpJvobWaCisoN4aUO7TdoiAinU45YHJL2xQWzTvvkCPuA==
X-Received: by 2002:a17:902:e849:b0:1dd:5ba0:e0ee with SMTP id t9-20020a170902e84900b001dd5ba0e0eemr6961805plg.9.1710353542738;
        Wed, 13 Mar 2024 11:12:22 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id p10-20020a170902e74a00b001dda1e9f510sm6006486plf.92.2024.03.13.11.12.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Mar 2024 11:12:22 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	kernel test robot <lkp@intel.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] ubsan: Disable signed integer overflow sanitizer on GCC < 8
Date: Wed, 13 Mar 2024 11:12:20 -0700
Message-Id: <20240313181217.work.263-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1242; i=keescook@chromium.org;
 h=from:subject:message-id; bh=Juz30sNn9Vm/o0qmgqL6ej/+Db1FXC/0PH8XbJPugnI=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBl8eyE9J4yYHWBRmDSdvgZpqfXhVx4eTZnYonIO
 C2r7NDdWBeJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZfHshAAKCRCJcvTf3G3A
 JrdUD/9PrK3mREHrrRuyLF4jhJgBAkp5b4PysQdaAjPjzZYkJbyTnujbjqdj8HsfbcKdySR+sQ5
 onBvzW2mCRKGIevgEPgGaRJC+9qZWmUP/EBSa0kkQJAhA/WkPe297pALLimV0ipGDra9dQnJaR9
 AvQE/QiFBgiUxzrnIEwLqsVsdHIjudciaLu4aWyg+CwfuW06MV82wAfjptQQiKIr95CuFOJ4ykm
 lF7cpXA5NH/v5B+wjfh4iJ4r2/zjaDi8TpGU4HQ+oqYCTNH6A3+x6qEXwuOdzPSO4kcJ3AvfOis
 UW7pd7rW8+O25WJaEyMo0Npxvs+3gKMwDx6G/DgM+PcE5swxdcPHZAqIX1UnL+T0KeQdIBEdgKt
 KqopeblJVpbLxic2Okx2HQDLQQXTec0V3igxfc5msTovLOhTkdlprYSH1pwYC7/Mriht7U+TTUj
 cDewZRRncSAgwMs/EMALchw3L1ZtdIYMifMrnHMMpQ8PwPsptTatZ+WxpQ9T7fAezSb5jgNJCgy
 edDaC8i9zMq3eQHCZcP8W9ej8H3sJ4ywMbbnRUTqD0VF9hE5yBQrwo818Rh3+sU3VvaueK3fVV7
 +j/OFiy6wrf5XSH/dPltWckYZlHgYO1pxaoskP/k/XZiTJUOpJY+DN7ISRH6KiOOBmk8gXBvTgg
 88J3E9H MDnG3kmA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EYEtX0hW;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c
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

For opting functions out of sanitizer coverage, the "no_sanitize"
attribute is used, but in GCC this wasn't introduced until GCC 8.
Disable the sanitizer unless we're not using GCC, or it is GCC
version 8 or higher.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202403110643.27JXEVCI-lkp@intel.com/
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 lib/Kconfig.ubsan | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 48a67058f84e..e81e1ac4a919 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -119,6 +119,8 @@ config UBSAN_SIGNED_WRAP
 	bool "Perform checking for signed arithmetic wrap-around"
 	default UBSAN
 	depends on !COMPILE_TEST
+	# The no_sanitize attribute was introduced in GCC with version 8.
+	depends on !CC_IS_GCC || GCC_VERSION >= 80000
 	depends on $(cc-option,-fsanitize=signed-integer-overflow)
 	help
 	  This option enables -fsanitize=signed-integer-overflow which checks
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240313181217.work.263-kees%40kernel.org.
