Return-Path: <kasan-dev+bncBCH67JWTV4DBBEPVRDYQKGQE5NAAEDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E70CB14145C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:52:01 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id y7sf11132461wrm.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:52:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301521; cv=pass;
        d=google.com; s=arc-20160816;
        b=zNDOag+eXtr6nugievRa8FZyEudC6b/PwwAUxvd1aZ/yvLcU34k1Bi01OuJ4Ux96ZR
         QIkYPW7661eBP+Ll51nd8xTM6FZ625N6Yy6U5PrLU97hau2J7xgyYdS0JaL9jYL941mN
         5Tz7Xji4MBQNw3WQI3PlpOQqTlj38MlbO3vSQVnvDMYM0NQiFaOWW8O7/M55CaeTpqgY
         7lmgO/S1q07Y9t0wOdPpmBy0b7JoKVsZL/fD4jXJRMxPgQOxu84oLXKksavMYAGqEw0Q
         Mh5nQHjsphwF3xNGH9xsw0Ga1v46T5LjKyqxPgD0kbo94VlXuXepLx04/X+RkcWUHgL6
         hi/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0q48eUpxiB6VUQ92JW8SbwusZ8N5VpFY97aqxlwstgQ=;
        b=vXVoeYtoOcv3nWlyF0Y6hmLT7ljVsPysDHpmDdmlQzoStI51zDIIWpVeNqvZmTvF4D
         KA3qTlSxUHH0x6eDuU8sR+gq+rb4Fip+Kobx/4dvuoenDS1/ImR0w9KLkHjkc2eSyU8E
         rZ/M2MHmEiOga6l9UeqI7AX3xpm5or3A5hT/qccrb/qBZrqJHqV9SdTDanITztnJUuDY
         bV8WEUDBGgqSqTTLVCWyPa9uQbgAKIGDPZTc0MpdiDnumJ5gS/TMPuoKC1VGbWELoFal
         jrtIBeYcA5Wlz1OlTrg16VVHjVrDBzsJ2K8AdnHTWpvsDCo36/ZTtoz/JToE16euwl4l
         8G7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Jl2CZQOT;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0q48eUpxiB6VUQ92JW8SbwusZ8N5VpFY97aqxlwstgQ=;
        b=fXsnBlVw37RA4wD0N0ligHmMp7uVYhHgNORvdICUYyko6lsiTNkRumkQD5YUL+1Jt3
         gwLKvWm8Kamyp2ATwCyQIEuSkP3hPh0XCPccZaVe02h/TJB9pF/5YLyXCWdvXHpgMLAG
         Ss11xJCIOFB5DJsYDAb7OGcPj6vhnK624+1/F/DVlSKt/B3rdyUTQf0v+8Q44ma0dRzk
         PntLzM+uUYzsQ8IUq1wJSQiBbYQefm/rfyZlJZFiDDiwMWi9rlcyizC3vaAeq9wLhjAg
         jIinXa0P1wWdto5/cC8UT/XAsur36MVWWBarcKL9yTpJOIh1czuSM+Q0bhQPPfozOaR6
         61jw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0q48eUpxiB6VUQ92JW8SbwusZ8N5VpFY97aqxlwstgQ=;
        b=gaAhtzHt1Bkw7LZLI6cGuzJkHTvYEDwHRFoqLwz9kLf56KM0ij643Gc3v/Axz35gtI
         H/h99FYrsCPYW1SfaaL/40v/PiG7PxbMV/QJ4hluySFxXvtPRaZOV+/fqJk97KI0BesT
         vPVAVcS1B0ucbtY3sRUYseY/eoS9L4XFIkJQ39n0nnNFt5Xa5HEMfpM98oL8nfl4xnkU
         rACQibVWYX3Vax3JoIRFogBGFSsBCzF7DoMyWxDa/5CG9/df8ab9e6YlP8BDDRTUwoeD
         n1GtopBwC7bavPZtOF7avV7T1R9CGzvEiN8qYVKJzzfUam1K2io/9rSZ4EvRL4Vdb+Oa
         il7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0q48eUpxiB6VUQ92JW8SbwusZ8N5VpFY97aqxlwstgQ=;
        b=DwJ1WkaNop/003Hj9v42xl8lk4mdEhhpSYc9dbMUfr3HZHHHsIfLAPnICDCFpftzdr
         kFygDjllKcym9hseQmJfk0/8OtX8quim24TR0bENa+pJnnE3gfheMbs5lQqw1At/erwr
         nomDuIL9wte+ytAGyEnh5DGWraE7XaCGhsEloAdjZE7LF/nhsZDFIUQz+Dsi+QjPuzr1
         GvB1nvReh2InkKjoeJ9GR2D/PuHjkCtqRWB0FVVWuMG6ROw58DWgsQgmQ6Ls5Wytba0N
         Ci6za7VgWJhdreP9fGbL14ce1zILBiAdJM39DOVDCJ2kl/dpjbwBf0lpvLAp/Sb2FR85
         0PIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVN3DKphVQc+u/nF/mUp/CXHM4+cSu0de/Zu8x8QXbc65d0G3qE
	zugJkcLEQM9Te76EbhBi7MU=
X-Google-Smtp-Source: APXvYqzlNLOMq15VfPMSlhZVDk9wTd3dd3XRxXUozyy1XtbtW2p4Z6DQorYxW9sudEIFqrNRkMSFAw==
X-Received: by 2002:a1c:4454:: with SMTP id r81mr6895161wma.117.1579301521618;
        Fri, 17 Jan 2020 14:52:01 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3d8:: with SMTP id t24ls3129315wmj.5.canary-gmail; Fri,
 17 Jan 2020 14:52:01 -0800 (PST)
X-Received: by 2002:a05:600c:20e:: with SMTP id 14mr6884294wmi.104.1579301521031;
        Fri, 17 Jan 2020 14:52:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301521; cv=none;
        d=google.com; s=arc-20160816;
        b=j+tvXWF51VA3/180GqjtY/6llBa4Hhg3u5oQvFBcbQYiXYoLku+08Ak6iwUNB4FU+K
         XL+EZ8RZByQ5SEhfwex4KNxuXkoSpD00s3xg1UgXXVqdeK3OSZDsLRC0F3yc7zk2feH+
         7kwc4S6kt7sVof8n01CV3Go8r5EqBOArxtU07ePm4hvCL+JhO9QpPHgvM8B8zX9o4Nw6
         9ZU+ZsOGTJb7cjtfZHtu9YKf75/UkkdVSV0OJ9IMIPNttC3o5+w+/nWggc+QOw3Zn0i2
         gz4UzCqb9AHNRkvzyDz5+8qqsxExLvo/9NBlSbO90NsYifaFZHYoRjQZiKaXzHFfW9xJ
         prxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=5VgjBgp4uS/kw7oEAWwjC3t7HIV9i9IPmgfuwHpjxc4=;
        b=R+UYXUxz+4/3o+9E6H900W6bPszSgJgjiqS1pq88iATG9Qzs2pL5UXg5AkdZIOA3cs
         2TuxcmFsukjdUTyfzDQsPCzmon5rJcrHc8jThpCtzxR3tvPodPPgJsCBj2nmTZdqkLbE
         j9bdRlZMpTHmBphnUXtJ8GyVH1Qzsk0kQIaI9+hZZx8oBJ7dAjA7JMAcgB9+kv+oLKVT
         h5ppNZwrACgWs3aWPmhEoDL7cH5IZ79JbU3WWFif5pqJ9CMAqebr8r4tA1BMUHlq8Tj6
         WBHf3KrO1orsoXo1t4ocjm8b62leMEomuhtkmHAhzMnolUvld3ScTvTTg9LxhQNvh6Ju
         6/ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Jl2CZQOT;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id g3si1075858wrw.5.2020.01.17.14.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:52:01 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id w15so24250487wru.4
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:52:01 -0800 (PST)
X-Received: by 2002:adf:f605:: with SMTP id t5mr5239723wrp.282.1579301520539;
        Fri, 17 Jan 2020 14:52:00 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.51.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:51:59 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	bcm-kernel-feedback-list@broadcom.com,
	glider@google.com,
	dvyukov@google.com,
	corbet@lwn.net,
	linux@armlinux.org.uk,
	christoffer.dall@arm.com,
	marc.zyngier@arm.com,
	arnd@arndb.de,
	nico@fluxnic.net,
	vladimir.murzin@arm.com,
	keescook@chromium.org,
	jinb.park7@gmail.com,
	alexandre.belloni@bootlin.com,
	ard.biesheuvel@linaro.org,
	daniel.lezcano@linaro.org,
	pombredanne@nexb.com,
	rob@landley.net,
	gregkh@linuxfoundation.org,
	akpm@linux-foundation.org,
	mark.rutland@arm.com,
	catalin.marinas@arm.com,
	yamada.masahiro@socionext.com,
	tglx@linutronix.de,
	thgarnie@google.com,
	dhowells@redhat.com,
	geert@linux-m68k.org,
	andre.przywara@arm.com,
	julien.thierry@arm.com,
	drjones@redhat.com,
	philip@cog.systems,
	mhocko@suse.com,
	kirill.shutemov@linux.intel.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.cs.columbia.edu,
	ryabinin.a.a@gmail.com
Subject: [PATCH v7 4/7] ARM: Replace memory function for kasan
Date: Fri, 17 Jan 2020 14:48:36 -0800
Message-Id: <20200117224839.23531-5-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117224839.23531-1-f.fainelli@gmail.com>
References: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Jl2CZQOT;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

Functions like memset/memmove/memcpy do a lot of memory accesses.  If a
bad pointer pis assed to one of these function it is important to catch
this. Compiler instrumentation cannot do this since these functions are
written in assembly.

KASan replaces memory functions with manually instrumented variants.
Original functions declared as weak symbols so strong definitions
in mm/kasan/kasan.c could replace them. Original functions have aliases
with '__' prefix in name, so we could call non-instrumented variant
if needed.

We must use __memcpy/__memset to replace memcpy/memset when we copy
.data to RAM and when we clear .bss, because kasan_early_init cannot be
called before the initialization of .data and .bss.

Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/string.h | 17 +++++++++++++++++
 arch/arm/kernel/head-common.S |  4 ++--
 arch/arm/lib/memcpy.S         |  3 +++
 arch/arm/lib/memmove.S        |  5 ++++-
 arch/arm/lib/memset.S         |  3 +++
 5 files changed, 29 insertions(+), 3 deletions(-)

diff --git a/arch/arm/include/asm/string.h b/arch/arm/include/asm/string.h
index 111a1d8a41dd..1f9016bbf153 100644
--- a/arch/arm/include/asm/string.h
+++ b/arch/arm/include/asm/string.h
@@ -15,15 +15,18 @@ extern char * strchr(const char * s, int c);
 
 #define __HAVE_ARCH_MEMCPY
 extern void * memcpy(void *, const void *, __kernel_size_t);
+extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMMOVE
 extern void * memmove(void *, const void *, __kernel_size_t);
+extern void *__memmove(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMCHR
 extern void * memchr(const void *, int, __kernel_size_t);
 
 #define __HAVE_ARCH_MEMSET
 extern void * memset(void *, int, __kernel_size_t);
+extern void *__memset(void *s, int c, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMSET32
 extern void *__memset32(uint32_t *, uint32_t v, __kernel_size_t);
@@ -39,4 +42,18 @@ static inline void *memset64(uint64_t *p, uint64_t v, __kernel_size_t n)
 	return __memset64(p, v, n * 8, v >> 32);
 }
 
+
+
+#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+
+/*
+ * For files that not instrumented (e.g. mm/slub.c) we
+ * should use not instrumented version of mem* functions.
+ */
+
+#define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memmove(dst, src, len) __memmove(dst, src, len)
+#define memset(s, c, n) __memset(s, c, n)
+#endif
+
 #endif
diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
index 4a3982812a40..6840c7c60a85 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -95,7 +95,7 @@ __mmap_switched:
  THUMB(	ldmia	r4!, {r0, r1, r2, r3} )
  THUMB(	mov	sp, r3 )
 	sub	r2, r2, r1
-	bl	memcpy				@ copy .data to RAM
+	bl	__memcpy			@ copy .data to RAM
 #endif
 
    ARM(	ldmia	r4!, {r0, r1, sp} )
@@ -103,7 +103,7 @@ __mmap_switched:
  THUMB(	mov	sp, r3 )
 	sub	r2, r1, r0
 	mov	r1, #0
-	bl	memset				@ clear .bss
+	bl	__memset			@ clear .bss
 
 	ldmia	r4, {r0, r1, r2, r3}
 	str	r9, [r0]			@ Save processor ID
diff --git a/arch/arm/lib/memcpy.S b/arch/arm/lib/memcpy.S
index 09a333153dc6..ad4625d16e11 100644
--- a/arch/arm/lib/memcpy.S
+++ b/arch/arm/lib/memcpy.S
@@ -58,6 +58,8 @@
 
 /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
 
+.weak memcpy
+ENTRY(__memcpy)
 ENTRY(mmiocpy)
 ENTRY(memcpy)
 
@@ -65,3 +67,4 @@ ENTRY(memcpy)
 
 ENDPROC(memcpy)
 ENDPROC(mmiocpy)
+ENDPROC(__memcpy)
diff --git a/arch/arm/lib/memmove.S b/arch/arm/lib/memmove.S
index b50e5770fb44..fd123ea5a5a4 100644
--- a/arch/arm/lib/memmove.S
+++ b/arch/arm/lib/memmove.S
@@ -24,12 +24,14 @@
  * occurring in the opposite direction.
  */
 
+.weak memmove
+ENTRY(__memmove)
 ENTRY(memmove)
 	UNWIND(	.fnstart			)
 
 		subs	ip, r0, r1
 		cmphi	r2, ip
-		bls	memcpy
+		bls	__memcpy
 
 		stmfd	sp!, {r0, r4, lr}
 	UNWIND(	.fnend				)
@@ -222,3 +224,4 @@ ENTRY(memmove)
 18:		backward_copy_shift	push=24	pull=8
 
 ENDPROC(memmove)
+ENDPROC(__memmove)
diff --git a/arch/arm/lib/memset.S b/arch/arm/lib/memset.S
index 6ca4535c47fb..0e7ff0423f50 100644
--- a/arch/arm/lib/memset.S
+++ b/arch/arm/lib/memset.S
@@ -13,6 +13,8 @@
 	.text
 	.align	5
 
+.weak memset
+ENTRY(__memset)
 ENTRY(mmioset)
 ENTRY(memset)
 UNWIND( .fnstart         )
@@ -132,6 +134,7 @@ UNWIND( .fnstart            )
 UNWIND( .fnend   )
 ENDPROC(memset)
 ENDPROC(mmioset)
+ENDPROC(__memset)
 
 ENTRY(__memset32)
 UNWIND( .fnstart         )
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-5-f.fainelli%40gmail.com.
