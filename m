Return-Path: <kasan-dev+bncBDAOJ6534YNBB5UN57BAMGQERVSKZBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id F2395AE7E0D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:52:57 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3a4f3796779sf738490f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:52:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845175; cv=pass;
        d=google.com; s=arc-20240605;
        b=bC2zMlQGLzKwahSoxDhN414evIXfoLz7CphPc4pMbx8yCCVpOtQRNsz04a1HTNimhJ
         gVx9CLARbtilgKnDNSC3Rzky2md7Kw22hgsmIu0BPEStYvwMi7M5EQOTaZiHwJQHpunw
         WauGJXMu5euxxEWUsiHYxy/5uaZ7IbzWWQpu91a+bimzeBZ8g8751gXBYT40Cp2GQ08/
         bz1CYrBNy+VvBx7cG/Qq1tE/ypC/mHptgGmQ46wzpUda2XJLMqSXPXQxh2Jv71dceTjC
         87G28k+u/UM2SRE0LlIsWcu9f1xKtO8btaj+lynz9GFUXAUJDPNlRamcaANI9D6p4kSl
         +vcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=DlNGtYjpjVejOHzl8Bc/NuqyBPjjG+tx6HPNgbqiceE=;
        fh=oB224/n0fCDgngdXRWCAooGoQV1ZFoAC2cdBqTEcUzs=;
        b=eqmOfKa8o0RZnuhzmI/zr+N0LakwsxUacK6AMMN9+cPtFtHo0AU58Hxi1xIzY1ZMFG
         MCL/+lQtFHMflEt0MjuAnkAOC4K/F7fWosBj094Fs8TBamIdKS7C+qTYN+CP0V6ldWLT
         Rz8JANOiBRwsi4+pB9STKqSx0L+m3U+Pkxwfac6CHmhF69x52VdbTKl5Yrow88MZ08XK
         qvRw4gG3kxDEaDQ3PuAYcUvQSfMqHKHleGevlKNq+li0o47MzC9iKeMBchn8XGyUpo7F
         SlkucdCRKCnYaT4whp0sqwn+4+0ctp8uRLqfkCOl2/BVc560rnHPLfW5c5LF2qZ9od1e
         VFow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OsMk0Z2D;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845175; x=1751449975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DlNGtYjpjVejOHzl8Bc/NuqyBPjjG+tx6HPNgbqiceE=;
        b=DQZ0glTpN7KcGO4a+1Xq/JNm2/vCtUVbyHCENRpN/BUksioPUiT2PXDU1Ll56Hef01
         LwmRUjn16MQt2g+0Of6Ft6qpm/zOxKUUtxZRgFvNE9Ifg6OsnD3n+H53ZRa7a0g2guBP
         QHNQsgjOIGnL8zJPIHX7cTkkVcBfTxMMt3WGq36gv8k26efdhRituJ+P54VNOyRlPtWj
         A66qWqtCS60i1UGxghltRr2cVBXEyL/Mc0wFGM+GlKy0kizk7MxMz4nNkgtwN6yAu1vn
         8ql7S+Yrx64vi6hEQ1AMYikBAz3yZ3qMNl+6akwh9ACxrGhOOzMGVlq5X2VaDNLTpf8p
         9tAw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845175; x=1751449975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=DlNGtYjpjVejOHzl8Bc/NuqyBPjjG+tx6HPNgbqiceE=;
        b=iFWY6mQ4m8031oAPnbbtWtC8FZIMrAQlENMTdpyduQIcchdpZi4Vq5pZUmH6uw1wge
         Y2JryJ7Fg+JWswDVRcbiBJQwoO0Chm5wmYBzxDTIzucQNRiRWR/ylzJWK8dQ1Mvm/Qky
         Y/7nJk2ezUT1+GItc3Azz4eIFqIF/ouqNBqRFsl7OgPD54bRPEziF1bYcO7HJHr+UJAX
         WbSEsLjYD/U93LMTByPPMmMAOzcPFiWiYnZGsxD4mALgvkDlC37jGqd5Per4Sya2q4Fv
         6imnFp1YK+xsw8pH+oIQXz6o/RPrrltOPhKaiUzvdMfZptLYYDA/SxD5KMTkJ4HaH+xW
         +Esw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845175; x=1751449975;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DlNGtYjpjVejOHzl8Bc/NuqyBPjjG+tx6HPNgbqiceE=;
        b=PfU8zpOLuYF0/htVQq/QOJ4wSfVgyzYJ2v2Lqr6MqJTlz7chVe0pcA5WMVluDuF7JL
         5wqhYhbxbXTcbcPc4zpmwGy5wC5E0h10G1Hjtv5Ft5KeimrlA+FdEW2OWjYxZfDRCdwE
         8PrK6KKyiEOvNYXdMjR0/isdrDtSqTDbThIgfuP+1cPl4IlHP0/SnNAF1+MPuEllnvQ6
         ZiI8RAtkyvs6SvJxcBtk1YeoAAyA7YzKiURI+UXqUjNRpyF8zTu8/UZi1lMX9YLjazQ6
         b8Kc412XEBnT/8d0Y5uo90dkEZkQWvtO8HHpY9kG3yns7AA3Ke5lZjbM6vfyPRZn5Prj
         gUIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVF7ZkQNngI+/8JY1Ep7lcf5PLNFzEVZXM3PxRNNAQsJUcq/9oMtzu4mWuqJf357NZl/BwNQw==@lfdr.de
X-Gm-Message-State: AOJu0YxOVYpa1JC+DZhnZNCXBkaURGXFuUQPqFpDra6elCvFfj5u5LTf
	QwAFxuDEsBNXzlDUwb9WK17QYcLfeD88SGfGbreszNGZ436zPEReFoZD
X-Google-Smtp-Source: AGHT+IG/NfkosMwvOr+PmsVxH4WMPVHQvs5HgmuDWLx7oaxS5Wy6t9sewX/AJPbQLuWc7OvH9I7G4Q==
X-Received: by 2002:a5d:5c04:0:b0:3a4:f6d6:2d68 with SMTP id ffacd0b85a97d-3a6ed652de9mr1782477f8f.56.1750845174579;
        Wed, 25 Jun 2025 02:52:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeu3yUYUVR0saBcr/hA4Y4nPzq/ukowzu/yEtZv/KEBwA==
Received: by 2002:a05:600c:a012:b0:43c:ef03:56fa with SMTP id
 5b1f17b1804b1-4535f26e5f6ls37686605e9.2.-pod-prod-02-eu; Wed, 25 Jun 2025
 02:52:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+wCqF3A6+aKmZpNeh6kfOrhAqb8aJuAqN/9Cgz7EXQu7EQMeAT8g5qapWkB42roXiaKg/3YrziLg=@googlegroups.com
X-Received: by 2002:a05:600c:6096:b0:439:9b2a:1b2f with SMTP id 5b1f17b1804b1-45381aea028mr23577035e9.3.1750845172236;
        Wed, 25 Jun 2025 02:52:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845172; cv=none;
        d=google.com; s=arc-20240605;
        b=cBhNqIt36oRi0bqdZfv8mmt4jiWKcl6zKbZ7kjBoV5AqYH8gdR5rCbvFTjiLQyCcOP
         pjsSXboGQzJpi/KLDr2WV44rqfWtapPCJW6GAyYtvYRpwWymDacpSWYZkCJ2kBaJo6ET
         /OHnARp6EieY0pArgcKR9LCdic2DRalAVk5rwKhbgb1Mwg2Pj4lc5eG7C/2HCj3pT/9m
         wI5vXUg7LMzjqYBBQwk+3y67XVCEiuIkDj5hrW9M9a1FIxkJAdMOUT5zc4YuvpWnBusU
         bBrXmHOme1rA13Ir7oDsTy2eu0SUotT0lm9y/g28aghrgfxmWyV+23Qi8kBwJRYY0tJC
         54hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U6SFM5Ezspiku172UK6Utmx+P9PfAPP964pKgViV7lo=;
        fh=AhKSBv9Xxd0pXh+Br78M/+uLUG2HujOyQ34nxon9+so=;
        b=Zym0Zq/5MToSsmgn+4YEXSmppr6sTxvoXGMXbS6DJNpet6V/pYlmEciv6woWG9V1h4
         KzRsjzjcqWPu9Q+R3GyWHZCSrxPqn55wSbNsPDzYgI6GNTsHcq0okrDD9a5jmiom4qxV
         ilGrIeS2UtKqH9I5GNpxyyicjROEZfCM27ELy97hVdPyFeNWpImVuOkiB/X/0yTa2EwG
         mfX4V/aq8Os38G1XYxPSwfcFMtwZMMGARSCJ95DK1zdlsh5IToqQBRBzZeAy2m6fSpgK
         lqWZdHs8UHT+97renvQ5BLrV2UMlruzVGceVV37usCNKj2kfLdIvKBUrFtdLos644pCw
         +owg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OsMk0Z2D;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a99f3si663225e9.1.2025.06.25.02.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:52:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-32a9e5b6395so12340441fa.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:52:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWe62n5iAcoU2ueM5itd5QN2h4HNGVLkWhjidEYVsrI3Q0SAG4b2MUWENw6MWwbPo0qbs95tC+Bo0w=@googlegroups.com
X-Gm-Gg: ASbGncs/ETf+m0l/SA3QJ5S72+u3XmVVp7omL4SKNW5W7+Uq/u640wrj5Dp7qDehryp
	6QpUvW2CnG4xHfUgnSmTaxwLWwtBGU/L7cuAK3Jb/+PGhy3Lw3q8ZWsjJBIV4p6/ARRAoXtwog/
	Rq0RyMjxXTY1sf9LAMcF9WAreKAsULF12h7/JSVfhtpLvw6JgT58xb8rbzfhDsgcXN/dScdSOF/
	er74o5KqiSLwUJkUr0IzPWmrQff2lv2Bl5xNp08IMBVNOaQd8zQ1PyMgvWP4W1rMMlf7T8dteeD
	0ZPjj5YAbnGsGX/w/0ezowOaPDA2K2YklLK68A9i0JDzdCOte0VQK3is50zFBxyw6pegaZRaii6
	qNs8hECCx9idTQAAZ2O5LuUgjy4aUgQ==
X-Received: by 2002:a05:651c:f03:b0:32b:93fa:2c0b with SMTP id 38308e7fff4ca-32cc64d280emr4286261fa.11.1750845171079;
        Wed, 25 Jun 2025 02:52:51 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.52.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:52:50 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 1/9] kasan: unify static kasan_flag_enabled across modes
Date: Wed, 25 Jun 2025 14:52:16 +0500
Message-Id: <20250625095224.118679-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OsMk0Z2D;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Historically the fast-path static key `kasan_flag_enabled` existed
only for `CONFIG_KASAN_HW_TAGS`. Generic and SW_TAGS either relied on
`kasan_arch_is_ready()` or evaluated KASAN checks unconditionally.
As a result every architecture had to toggle a private flag
in its `kasan_init()`.

This patch turns the flag into a single global runtime predicate that
is built for every `CONFIG_KASAN` mode and adds a helper that flips
the key once KASAN is ready.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 include/linux/kasan-enabled.h | 22 ++++++++++++++++------
 include/linux/kasan.h         |  6 ++++++
 mm/kasan/common.c             |  7 +++++++
 mm/kasan/generic.c            | 11 +++++++++++
 mm/kasan/hw_tags.c            |  7 -------
 mm/kasan/sw_tags.c            |  2 ++
 6 files changed, 42 insertions(+), 13 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0c..2436eb45cfee 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,8 +4,12 @@
=20
 #include <linux/static_key.h>
=20
-#ifdef CONFIG_KASAN_HW_TAGS
+#ifdef CONFIG_KASAN
=20
+/*
+ * Global runtime flag. Starts =E2=80=98false=E2=80=99; switched to =E2=80=
=98true=E2=80=99 by
+ * the appropriate kasan_init_*() once KASAN is fully initialized.
+ */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
=20
 static __always_inline bool kasan_enabled(void)
@@ -13,18 +17,24 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
=20
-static inline bool kasan_hw_tags_enabled(void)
+#else /* !CONFIG_KASAN */
+
+static __always_inline bool kasan_enabled(void)
 {
-	return kasan_enabled();
+	return false;
 }
=20
-#else /* CONFIG_KASAN_HW_TAGS */
+#endif /* CONFIG_KASAN */
=20
-static inline bool kasan_enabled(void)
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline bool kasan_hw_tags_enabled(void)
 {
-	return IS_ENABLED(CONFIG_KASAN);
+	return kasan_enabled();
 }
=20
+#else /* !CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..51a8293d1af6 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -543,6 +543,12 @@ void kasan_report_async(void);
=20
 #endif /* CONFIG_KASAN_HW_TAGS */
=20
+#ifdef CONFIG_KASAN_GENERIC
+void __init kasan_init_generic(void);
+#else
+static inline void kasan_init_generic(void) { }
+#endif
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c75..525194da25fa 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,6 +32,13 @@
 #include "kasan.h"
 #include "../slab.h"
=20
+/*
+ * Definition of the unified static key declared in kasan-enabled.h.
+ * This provides consistent runtime enable/disable across all KASAN modes.
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
 struct slab *kasan_addr_to_slab(const void *addr)
 {
 	if (virt_addr_valid(addr))
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e7..32c432df24aa 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -36,6 +36,17 @@
 #include "kasan.h"
 #include "../slab.h"
=20
+/*
+ * Initialize Generic KASAN and enable runtime checks.
+ * This should be called from arch kasan_init() once shadow memory is read=
y.
+ */
+void __init kasan_init_generic(void)
+{
+	static_branch_enable(&kasan_flag_enabled);
+
+	pr_info("KernelAddressSanitizer initialized (generic)\n");
+}
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..8e819fc4a260 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
=20
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tag=
s().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b9382b5b6a37..525bc91e2fcd 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -45,6 +45,8 @@ void __init kasan_init_sw_tags(void)
=20
 	kasan_init_tags();
=20
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=3D%s)\n"=
,
 		str_on_off(kasan_stack_collection_enabled()));
 }
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250625095224.118679-2-snovitoll%40gmail.com.
