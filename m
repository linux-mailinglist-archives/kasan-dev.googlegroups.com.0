Return-Path: <kasan-dev+bncBD653A6W2MGBB6GXUCUAMGQEXEK64CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id ECB197A4797
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 12:52:41 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-402d1892cecsf20476355e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 03:52:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695034361; cv=pass;
        d=google.com; s=arc-20160816;
        b=KOIvb2jYCVJTInlyDeUvANMwBrVVOcS/A7BIce+zch6e826yx1/76iBb8vXbTPV23I
         Luy/Zw2DqTCE8wPC4ed3Tg5hO6Rf41+Zf5x75f1cVVzDgAHzvi9ZHKg1anKQoSqiEET4
         01ylZ4yESYb++txnwE1q4tfLY44Bqs98kWZlV627Xcr94okPb2ieBDYMYtandXYdqUdK
         XkJ2+s08ydB2Cls7a5SDGdIV3R6Ozpt1Em+/ORLr8NcJyKv40DZjgvZyqfUPx8y9gQ2N
         H1C8bpat4zDZ5HqIc78L2gSS1yy84f5M2CfNWweWcrEBQB6IhRa8KwlIvIYZNOkHr5DW
         qorA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=2+0NVGLVsysC1KTYI8wjOjQHDDhHh0dqCOdiPcek0Q4=;
        fh=/BsWuqvqe3eo0r5JRt58YrKg2sVLpkLk+6gUJtF4R30=;
        b=OLZR+ZJSLDQUkQxJnTXxfYq7aRjFdoahDTGlTmK/1St5APlKv89RcpgCZZoAyNb6uj
         wRvy0PmRzZDFvSpwjo1xJJX26dz3Gi2uWbrJyzNlB84Ufr4LDYqISdpG9YnBiJGdQne6
         /isBHmD1ARF/PqVATi62cOqGOYf4gbIQZV5GV6BRZIbppXHANyzH5sHcfKQap30lH5mt
         sxQSBelujV+xcdqEk5oZ2jnRFArXTDxSfslj70aKUtzZJQdBTI9LBo806TKip5QwvVX7
         94lQrfx/5R49CIYjthWXgc+1brxlJTVasToxqdr4UuHlXvg73KNIX0qVjdomyd1z0vOL
         YR4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b="GZ/VyETV";
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695034361; x=1695639161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2+0NVGLVsysC1KTYI8wjOjQHDDhHh0dqCOdiPcek0Q4=;
        b=KCMjZONECQAmkGIA9gasxXsk55yzdLknJkiaQ2SFpPpeDKwKtcDbXiIALNLmPP9cgr
         k/Mug4P59LWxhpwNVTOLURpbZIhTEd3ZiZF7nThDDWafSpQhKylfLiKN7bFSxpPYWgyS
         etrVIakHDsS9U6pJMGNRB3U9M02ObE10v5C/o3zm59liuPqOD7lyErvAHIPWVo9bAGA0
         mvgbzstN6z5IxhIAc9OE7C1gMYWlnN4TM0IVgAn8Je7B0LhgPokYcEVjyVJJG2Lu7u+K
         k7DxO5kA3y2ze2moLY0oRHjY/lBr7+iPVkedxu3DB0wLIrJdrDxFfDIfXITyCMyWgEM+
         UEyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695034361; x=1695639161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2+0NVGLVsysC1KTYI8wjOjQHDDhHh0dqCOdiPcek0Q4=;
        b=OfRXC7jstXL51q++7NbSQx1XvP2gfIPQdJkJq1Plh3rFC0ZycSsUwsxFFIlVYeCqYT
         u+b2+vBpXwP2pP2Q/B8LpE7VJHrxsYt9DCUATkD8y4l0RlHUsZit41578b9jw3WIVvqV
         wKNz4p/BAzXhVtUQdEDY706nYFY5UMCmZKqm0SnxtGkjwHlxxmZq9P7G+6pUs83AyLot
         6C6c5YYDUADi+wYillb6Tcg9LFBGZ1l+HfEsNm7cPL/bL7/BWJBBwC+iuwAX9SVaCF99
         6Jkg0vw3/kKGW/OhnMLfW9KnoJxzjb2hucTYFN6myWYMBZqVuVKjVKJMM+7WopZpVRNv
         xhgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwLCn+V46I/OOvKWr+WcfohnBefZvRBZHqALx87O3Frt3ja8//P
	rpFYEGwbLaKBSnwhomkNsjo=
X-Google-Smtp-Source: AGHT+IGNl5ta17TGe47PocGdeMUwsGGDzwot57ts3ubfR/kg+zYlfukN9TIrkninLSn6Wlwt0BJKbA==
X-Received: by 2002:a1c:7914:0:b0:401:cf93:3103 with SMTP id l20-20020a1c7914000000b00401cf933103mr8813621wme.0.1695034360555;
        Mon, 18 Sep 2023 03:52:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c0d:b0:403:e69:9cf7 with SMTP id
 fm13-20020a05600c0c0d00b004030e699cf7ls1074458wmb.2.-pod-prod-00-eu-canary;
 Mon, 18 Sep 2023 03:52:39 -0700 (PDT)
X-Received: by 2002:a05:6000:a14:b0:314:1096:6437 with SMTP id co20-20020a0560000a1400b0031410966437mr5309970wrb.19.1695034358942;
        Mon, 18 Sep 2023 03:52:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695034358; cv=none;
        d=google.com; s=arc-20160816;
        b=pvg6H5/yfP/mDwTNjz6zm+n9ZjeYb2y1fkVN4YY7fA+AMGEaMA3va0e97mm5CJaXnB
         0MC24zsHZjJiNhAEsR2IyvsMLSmu56qxc0FfflaGiAY049u9sgNI4C6Tueyfd/45rYTb
         JxIZ/3JRX9UROgyFleO5amkmfqHDUhmQHs+A3KJXCLiMnfEI1xAW8tYiaSbRSoHh/Ycw
         oIXilTge0wgaI3wpXPEIEDI37p1qU+GCMQf+yPXS+OW4P1DkQ+uah7sH1Vtl5ZA6gDlQ
         ttEzSFEcl2sPGjxBuGcTPgIOxMC2AAm/a8n33oMrE3va0lpHWwrX/2lZngvqY6UPbfBw
         u2Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=bOsEzjVQKBPn7rGdrNw3l2iC/L1VtxB+euAZfU+U4zs=;
        fh=/BsWuqvqe3eo0r5JRt58YrKg2sVLpkLk+6gUJtF4R30=;
        b=b4ICyxA/qMqYiQhxba5o0jCz5ChHqomHXGe17sWmOO2z11sCNSzrtJXikr+x3hut+Q
         /4/63NlNkfr24ppAl3Q3fPtFmfjFKih0RSM1ukZjcLy+D2IagmHv6KyJZwpbWZma6GBG
         zPtyhB+nUlx3wrH3/VUy/vt1YxRDAc6RrhSt2JNWlI2g3DE7mtyytFpFtoaUZ7uWLb+O
         ZYPP+VwW99/fPmBSuO3Gm5gx1DZpCc2LaL3pRY5GW6ji06zGIh3do/BTv9z0teAxilyo
         4iJPSZxDxj/eKipUIALn73QNPPSi4c3TO6sfHjQ30nZv0ES8MLmsYybr4EC/Q3mF+P5u
         ZnYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b="GZ/VyETV";
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp2.axis.com (smtp2.axis.com. [195.60.68.18])
        by gmr-mx.google.com with ESMTPS id e12-20020adfa44c000000b0031acfc2c473si1191061wra.3.2023.09.18.03.52.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Sep 2023 03:52:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) client-ip=195.60.68.18;
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
Date: Mon, 18 Sep 2023 12:52:34 +0200
Subject: [PATCH v3] x86: Fix build of UML with KASAN
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20230918-uml-kasan-v3-1-7ad6db477df6@axis.com>
X-B4-Tracking: v=1; b=H4sIAPErCGUC/22Nyw7CIBBFf6VhLYZXTXHlfxgXFAZLtNCAkpqm/
 y50YxdmVudmzr0LShAdJHRuFhQhu+SCL8APDdKD8nfAzhRGjDBOTkTi9/jED5WUx4xLZozQvGs
 7VP57lQD3UXk9VMOGwGo8RbBu3iaut8KDS68QP9tipjX9V54ppri1SndGEGmEvajZpaMOI6olm
 f1ESdu9yIoIlpezwlIhduK6rl9voZLC8QAAAA==
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Frederic Weisbecker
	<frederic@kernel.org>, "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
	Peter Zijlstra <peterz@infradead.org>
CC: Richard Weinberger <richard@nod.at>, Anton Ivanov
	<anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>,
	<linux-um@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kernel@axis.com>, Vincent Whitchurch
	<vincent.whitchurch@axis.com>
X-Mailer: b4 0.12.3
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b="GZ/VyETV";
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

Building UML with KASAN fails since commit 69d4c0d32186 ("entry, kasan,
x86: Disallow overriding mem*() functions") with the following errors:

 $ tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y
 ...
 ld: mm/kasan/shadow.o: in function `memset':
 shadow.c:(.text+0x40): multiple definition of `memset';
 arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
 ld: mm/kasan/shadow.o: in function `memmove':
 shadow.c:(.text+0x90): multiple definition of `memmove';
 arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
 ld: mm/kasan/shadow.o: in function `memcpy':
 shadow.c:(.text+0x110): multiple definition of `memcpy';
 arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here

UML does not use GENERIC_ENTRY and is still supposed to be allowed to
override the mem*() functions, so use weak aliases in that case.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
---
Changes in v3:
- Add SYM_FUNC_ALIAS_MEMFUNC() macro to avoid ifdefs in multiple places.
- Link to v2: https://lore.kernel.org/r/20230915-uml-kasan-v2-1-ef3f3ff4f144@axis.com

Changes in v2:
- Use CONFIG_UML instead of CONFIG_GENERIC_ENTRY.
- Link to v1: https://lore.kernel.org/r/20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com
---
 arch/x86/include/asm/linkage.h | 7 +++++++
 arch/x86/lib/memcpy_64.S       | 2 +-
 arch/x86/lib/memmove_64.S      | 2 +-
 arch/x86/lib/memset_64.S       | 2 +-
 4 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/x86/include/asm/linkage.h b/arch/x86/include/asm/linkage.h
index 97a3de7892d3..32cdf1e92cfb 100644
--- a/arch/x86/include/asm/linkage.h
+++ b/arch/x86/include/asm/linkage.h
@@ -97,6 +97,13 @@
 	CFI_POST_PADDING					\
 	SYM_FUNC_END(__cfi_##name)
 
+/* UML needs to be able to override memcpy() and friends for KASAN. */
+#ifdef CONFIG_UML
+#define SYM_FUNC_ALIAS_MEMFUNC	SYM_FUNC_ALIAS_WEAK
+#else
+#define SYM_FUNC_ALIAS_MEMFUNC	SYM_FUNC_ALIAS
+#endif
+
 /* SYM_TYPED_FUNC_START -- use for indirectly called globals, w/ CFI type */
 #define SYM_TYPED_FUNC_START(name)				\
 	SYM_TYPED_START(name, SYM_L_GLOBAL, SYM_F_ALIGN)	\
diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
index 8f95fb267caa..76697df8dfd5 100644
--- a/arch/x86/lib/memcpy_64.S
+++ b/arch/x86/lib/memcpy_64.S
@@ -40,7 +40,7 @@ SYM_TYPED_FUNC_START(__memcpy)
 SYM_FUNC_END(__memcpy)
 EXPORT_SYMBOL(__memcpy)
 
-SYM_FUNC_ALIAS(memcpy, __memcpy)
+SYM_FUNC_ALIAS_MEMFUNC(memcpy, __memcpy)
 EXPORT_SYMBOL(memcpy)
 
 SYM_FUNC_START_LOCAL(memcpy_orig)
diff --git a/arch/x86/lib/memmove_64.S b/arch/x86/lib/memmove_64.S
index 0559b206fb11..ccdf3a597045 100644
--- a/arch/x86/lib/memmove_64.S
+++ b/arch/x86/lib/memmove_64.S
@@ -212,5 +212,5 @@ SYM_FUNC_START(__memmove)
 SYM_FUNC_END(__memmove)
 EXPORT_SYMBOL(__memmove)
 
-SYM_FUNC_ALIAS(memmove, __memmove)
+SYM_FUNC_ALIAS_MEMFUNC(memmove, __memmove)
 EXPORT_SYMBOL(memmove)
diff --git a/arch/x86/lib/memset_64.S b/arch/x86/lib/memset_64.S
index 7c59a704c458..3d818b849ec6 100644
--- a/arch/x86/lib/memset_64.S
+++ b/arch/x86/lib/memset_64.S
@@ -40,7 +40,7 @@ SYM_FUNC_START(__memset)
 SYM_FUNC_END(__memset)
 EXPORT_SYMBOL(__memset)
 
-SYM_FUNC_ALIAS(memset, __memset)
+SYM_FUNC_ALIAS_MEMFUNC(memset, __memset)
 EXPORT_SYMBOL(memset)
 
 SYM_FUNC_START_LOCAL(memset_orig)

---
base-commit: 0bb80ecc33a8fb5a682236443c1e740d5c917d1d
change-id: 20230609-uml-kasan-2392dd4c3858

Best regards,
-- 
Vincent Whitchurch <vincent.whitchurch@axis.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230918-uml-kasan-v3-1-7ad6db477df6%40axis.com.
