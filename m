Return-Path: <kasan-dev+bncBDCPL7WX3MKBBHM22XAAMGQEIRHW4IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D9F38AA7C76
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 00:54:22 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3ce8dadfb67sf32714285ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 15:54:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746226461; cv=pass;
        d=google.com; s=arc-20240605;
        b=V8EYbjhDjqTui4ij5B9a1pnROKpomESY/D5Fvu+tMOu9SpQF4uPuvUSRbojYFcs9HB
         sqeFRyWoBSnBkU+LpNsEMLOUS9Zi1QL9QNSF9Phnu4gP6v0OO2HExl75wXwL1a1VKIFO
         VBRETi6h+/YThRHs8g6UICZLUw2YDSLlv7Ozbvuau6IQmZqdUGBICZqu1s3X4vwtpiHa
         +L83Mw/xmFNHSbruj0X4n4wYrN7VU/oiJg93yOV0VaGcrnLIdI37VjWCktfEHVmYCKK5
         9wq1ckkzm0HobVX914kBMd8lPVMsfjBjIngiidErxLq8FJbqubGgoq/0Dn2BQSI24jEF
         4LEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=cBu5eAVoHequftmnFDNnJdGzBD5W0OhP+BWwMqxWlGo=;
        fh=IJvfmttquGJNI5ElL9XdutDHP4haDtu3GX36Xgoy/aU=;
        b=IOCg1CrLvlh6sx/8njzAQ5iYGSBAlu8hoZck99zQm7xCRh3Y6xaW5AONAgqug8dqSa
         u+aypR1JSqoMuZFPmKlurSuHd50m7dK2TniOcWKopedQN8n83TgeMME79OlXyCM2wgxU
         8Og0HtRiTvE25L1BZ5rxFqd8phI1+PtyuAlnTPSsoOzfCr5Fxk7121NorB6Hfxbpr0Ho
         2xUtXYHldbBijm4x2N0uu9DHpJaY6x3wijGFHDgHWmyKjlEF653eRhVaHeXWfa5QidVL
         jnkRICCUNc3JTuIlWS4jA3DyaKr8wwGpSvhs99MpvuAd/m3iNxsakaSx0ZYpNGq6+s8Q
         BVcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Xw/kqnMW";
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746226461; x=1746831261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cBu5eAVoHequftmnFDNnJdGzBD5W0OhP+BWwMqxWlGo=;
        b=Fb8gWgemgqJmMV4uEmZ6QbZ6BY8rR55HlbCg8DgSeJaP7yVsIR9BJSVGtu56vBSINk
         wXfKcBMPnvZ+AUP3XPC4NHs78WcEMlb0OW+Ywd1+XnqgmLgAHK9LaMZ8xKbLdeoaCN4S
         wZ0gD7GfkE3shV7FktJKn9611eTN3jv2jg3VLA6aN5sa96w9gLqN2l5g92oSYuYWIFhb
         IRy/tud51UoLXBMEJi1YdnsYSz2itOaFj6//Yb+v/xb3eI/dIoU/yQLwSh1D2eITbEyX
         r5Ssd3Uhsab3f5qlywvLwxXCBWXuH8oFbcfxFBqjoNU1FQ5YWCxpQR5LPRwsSSgX+vaG
         7cFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746226461; x=1746831261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cBu5eAVoHequftmnFDNnJdGzBD5W0OhP+BWwMqxWlGo=;
        b=Masi8GWoOdTlPOSXVJv7I7/+Ay8o9lC+CHVdK0DPoIknuQGDhj1f1cJeBVEoFPuIKz
         1YeV6qt64ZnLiD24C2QkDS5F0mA9FMUAyxHVRB4R14uODTCd4qtlUUGPncNPCJOG6FHT
         B80Fj55oCEfDeWoEb1ZCsCSdHvi+4E9CUgkV6mLkkihTf2bcepBT7IgBAP8sL9e3Qosu
         9mPf52PjnOCLzlwo50sI87ORfu7qbX5vol8F0RJUmcs7zlE2jwsyDQSlFwbJ3QSoysHO
         QdGuUx+kRapHyUPNmaoQfpizDwR5hGp+elAudBBvkAY0uyCSqqXixR8A2uXWvy5efFVB
         6wkw==
X-Forwarded-Encrypted: i=2; AJvYcCUw6hK+neasvpivKImdlKatwSRyQOOqxFI+Bb8uvuqyrkWWQIQM7dub8CnuC4O0+2w9s92now==@lfdr.de
X-Gm-Message-State: AOJu0Yx9GR06GQCyCTs6d+ynG45uBgFzYI83wH6cK3upxd7xose1IT3C
	jS0IKMq1PVq4Vx71plYLLQ//hVEoaM7wPE7tw2L08An++ydzOzhj
X-Google-Smtp-Source: AGHT+IEuujTrwbIRbLuPJBFAGU5D/mDNuoi4nJvHIMAMKS2WwjWu7HQm8sRSzZ5YWqj5ojpqbd2aLQ==
X-Received: by 2002:a05:6e02:1a8f:b0:3d8:1a87:89ce with SMTP id e9e14a558f8ab-3d97c147d40mr54084015ab.3.1746226461514;
        Fri, 02 May 2025 15:54:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHCDc8TKzd/Hwjxnr8LMRXuTNgKcpkwTfKOXQW6SScX2Q==
Received: by 2002:a92:c26d:0:b0:3d8:fe92:af4a with SMTP id e9e14a558f8ab-3d96e7f8326ls22214435ab.1.-pod-prod-07-us;
 Fri, 02 May 2025 15:54:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXyd8NZfVvkndMwkTlTmm2DAqEN9MXdqrOMfUzfJvGZuJmQMDdbm9F5wJ5QHfKBIqNt6E14wX/cCI=@googlegroups.com
X-Received: by 2002:a05:6e02:180e:b0:3d3:fbf9:194b with SMTP id e9e14a558f8ab-3d97be4405cmr43842095ab.0.1746226460638;
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746226460; cv=none;
        d=google.com; s=arc-20240605;
        b=LuaNuzgKazF3dzBCYVEYW3Yu1cOMYxvIVT875zfj2b+rqQq1Vm5HnOxTxhjBv+WY1L
         qyxSXMstey33hcUG30tHc9+ojTCtrBTieHR97ba/TtVFUneoxXI8m677R5xeTZUa2+wV
         zsezqJpeMXZoNdAVySHYkYwjIhsjG4JGbHZeX8O7y58lSlhCYIVF3Oz0Sfc7N7K4x3UH
         i91v04MOX4ogc/AomC8PhxW0g0Dilxw1yEDHfjtvc7oibfPM2N6MnOFtMv1m+lRaajLr
         6bdIijspplF5vmbYcLgMeGov+QfS+Q6vr8uNEG/EdCOJJyVJBbTxqMQlu5ZQZP5GaOPy
         3ofA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WuuHrObSToYmmq5bi30yOyMaR0MYnSQn63tQZA6LxII=;
        fh=0aEppIE8otrB5zBk28Chvbfb/ssZUyUc09PDXWtYs4o=;
        b=XqoxOSOyaLRZKx96Bq1MVSEn7YIA3T+tWnWmt7RiQhcMmmb1xz4nXjDa/s9I3xwgM+
         UukTa4iyk/OoOqneJhhkwkwmIRCHuq1uvAxnnSGnZMGYcO56orPNswvG1kNb/cFU21vc
         RU5C1dxoZJuqFYtBqMRXDqoiOc4aX9KmQPSLIguDegRuP1eS7MMF3pgOFwJ7KcsWk00+
         xyexaqloyioTUf/HLLu9z/jROLoZW24+/3janfpHRmxek5/NruCS3qCqxIL4HMjkVwn0
         ozIC+PkB0Q3RxbXgLH55/wlaRW/F2EPxzl2Gg4Yi3p9xts5ii13wAcT2JBVSFIqrR470
         lbFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Xw/kqnMW";
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88a9e6c94si92807173.3.2025.05.02.15.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0431B5C5C63;
	Fri,  2 May 2025 22:52:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C102AC4CEED;
	Fri,  2 May 2025 22:54:19 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org
Subject: [PATCH v2 3/3] integer-wrap: Force full rebuild when .scl file changes
Date: Fri,  2 May 2025 15:54:15 -0700
Message-Id: <20250502225416.708936-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502224512.it.706-kees@kernel.org>
References: <20250502224512.it.706-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2695; i=kees@kernel.org; h=from:subject; bh=xF83aDmqFbvCUaXo7mxg1j7TWAuDRl3V3C44XfenCBQ=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmivuI85U7N/WzzlN9cqLGqVdC53L/oHwfbLf9DF++mi ConLW/pKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmMj1P4wMPZc1RZaLnRXVX3on RnbKtpciUZ2agRuunHxVXLxk+rfnpxkZXieL9fE5qE4+yfT1wdwJO8OkNG0SBQw4Ojzm3NpT65j BCQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Xw/kqnMW";       spf=pass
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

Since the integer wrapping sanitizer's behavior depends on its
associated .scl file, we must force a full rebuild if the file changes.
Universally include a synthetic header file that is rebuilt when the
.scl file changes, via compiler-version.h, since using "-include ..." is
not possible in the case of having compiler flags removed via
"filter-out" (which would remove all instances of "-include").

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Justin Stitt <justinstitt@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-hardening@vger.kernel.org>
---
 include/linux/compiler-version.h | 3 +++
 scripts/Makefile.ubsan           | 1 +
 scripts/basic/Makefile           | 9 +++++++++
 3 files changed, 13 insertions(+)

diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
index 05d555320a0f..9d6b1890ffc7 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -19,3 +19,6 @@
 #ifdef RANDSTRUCT
 #include "randstruct_hash.h"
 #endif
+#ifdef INTEGER_WRAP
+#include "integer-wrap.h"
+#endif
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 9e35198edbf0..653f7117819c 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
 ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
+	-DINTEGER_WRAP						\
 	-fsanitize-undefined-ignore-overflow-pattern=all	\
 	-fsanitize=signed-integer-overflow			\
 	-fsanitize=unsigned-integer-overflow			\
diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
index 31637ce4dc5c..04f5620a3f8b 100644
--- a/scripts/basic/Makefile
+++ b/scripts/basic/Makefile
@@ -15,3 +15,12 @@ $(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
 	$(call if_changed,create_randstruct_seed)
 
 always-$(CONFIG_RANDSTRUCT) += randstruct.seed randstruct_hash.h
+
+# integer-wrap: if the .scl file changes, we need to do a full rebuild.
+quiet_cmd_integer_wrap_updated = UPDATE  $@
+      cmd_integer_wrap_updated = echo '/* $^ */' > $(obj)/integer-wrap.h
+
+$(obj)/integer-wrap.h: $(srctree)/scripts/integer-wrap-ignore.scl FORCE
+	$(call if_changed,integer_wrap_updated)
+
+always-$(CONFIG_UBSAN_INTEGER_WRAP) += integer-wrap.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502225416.708936-3-kees%40kernel.org.
