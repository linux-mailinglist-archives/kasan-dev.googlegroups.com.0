Return-Path: <kasan-dev+bncBCH67JWTV4DBBJFAUDUAKGQE7P7CENA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id EE1F5494D4
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:11:49 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id 145sf7829080pfv.18
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:11:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809508; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkASaRSJMfOnp8DqfNE+6SlWcgJyWz11IImGu8vD+7uES35zV2pjPZqpXIiGgwfD/s
         kg/BWzr/qlP9etVO47ORY0C7ePpd7hBZ+N+1qh5Bd1OTpnRxv5DvjxnJo+M1jTraeWMi
         gvjOyycM5+j9LukGX6fKKdFfUGXwsw9lo4LCR0Nz2eF3MePkS/NP4E8sdJ4TaCNGS0tx
         4iQrdGgopu2PLBXKLA4tEr60carf0ujIhJn1TIymu0wk0Y3xOZC2xZVu0d/TR/+EllMX
         aaElB7EWGXZkhzAnTpH14wa1TOQzr0l4ePIhm3d+cHtX1kK4rWA4tt6/EKamdDug5S3Q
         R5nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=yoCOiV2OER2zbTdbEAWsHVccmfa8UMrgrasemEBvj2w=;
        b=jLnBFdpxKYRP5KgIsFhVGWPgq6S1j16KJpcmfAlPoIS9+Y7INbqB666a5l61GMI+PS
         UWPaDjLOCxJyV4ueNwn2BiQq5O/jpq0/09Ma+VwNT4Ku1N8SwhW6AGciG/wfPMAQK6gg
         sdU23hLdcQ4zdLXtQb8X3rtMp/zMWTvX2tP1lHbvwF2gLID8SJLytUgN5d8bJeds3kvR
         Bz+Y9WFnHEaIui19Da7o5TkAhOtYBJKmtUKS5xTqwE0GmeQNSKkNItaDSm6FGKdxgQ6S
         K/2ceAECbb8XV8x5oMQKNMKS9EOoCAL7na80PAKo6WjqPmj0K2SMpOWlXwfaWmsaNc2t
         S6BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RoQtqypU;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yoCOiV2OER2zbTdbEAWsHVccmfa8UMrgrasemEBvj2w=;
        b=mjS3cjX5TUjIqQcpXYDAE78GZNEx/neTv/XwEloIfbrJahnNI/c33b5gkmDaLFEQzg
         wHZIYFr2YaRZ8fU9kT4HIBZRJqZMilbs6cim0bDprwYXv09rMXLnfr863Q8jn2XQ9lFI
         36gl4oNbUA/Y5mQ+BYezsgGK0B6OcPWShlfRRbszGibsSDLnPaddWb3IKukgqP8rJwib
         yswibrmvYtuQrSN+j386Ri7EqWx0y0nDSGeIVGuXH8tzDSzHtSkMn570QhOQj8LablYE
         AK24V92svMFf76zvN3kWM1mXnBFDBySFaQJrIGBRxgRbHdYGMqFOeQxv6Y8M+n76YEmI
         YOzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yoCOiV2OER2zbTdbEAWsHVccmfa8UMrgrasemEBvj2w=;
        b=qyK+K4NHxsZZXak8W92xZh14W7QtOs52svf2BxiC1cMlu5rxvoQYSFd+fS1sGn69e4
         Hg7Sf8tp5Dw8Cju9gQNz6S+x05XGSsqbsKj8wOP8IiPGxD4TYAOsLzRPqedi+7DkJ36l
         CZgJ3M/51rbWyKGVhBmAUDoLbfSkI6lzxb3Rjvz1jqc35/XEwERpDs2HvVKHCAzX1XmF
         S3yRVARMuRGDaumvX5b1PHxH38Ct1vJsd4hFkUuBLOFcAz1xdIDB4I6Vn7GrdA8GxuD0
         1FcZwqdqetxVCnOZNcjAGEUMrPOeBgtRFCJUssnt0bmXmpwoK+MW5QDRt1iyM1QWxWK6
         514Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yoCOiV2OER2zbTdbEAWsHVccmfa8UMrgrasemEBvj2w=;
        b=KEQ2ZWWBK3c2eSbVXxbIpylPa5lsjoOcAs3LFN0juOoH2muqtwjwfURF48Z3wTEORj
         XGwZdLK3YNL8yNUa7Wn+4yVXEWLPK8jWFDHjZRCHr4VpXobIAwfuLui5LYi+T2QYgmtt
         YKeg7lNyFwQqrg30Zb6GLMYdFYKUg3WI3ESqHeuExfyBA0Vn2NxDFrpjOmcC0pYcT0XU
         DbHbKoWUmB3sIFKbOnb0TfJpkZFv/8m6HgHNjNdAxiRx8RhFwdStzMjtQVuIXhUm812p
         NFmghrlpBfqr6/aeTOlYb/6VeWjjbjiyhPOI22P7nF/Lz2LkV3sTqOeEXs6N428io1gU
         aL3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWXiTqt6tO4voDyb1ok8N0Gwt7qqYaouck0qJBXzY1Qu9cqpddg
	xjrHn/7A40xX9wkzjH+IRIo=
X-Google-Smtp-Source: APXvYqyBxFxsd+vzuJCG0OKqrOVkhZK4zZHPzatEbz/YpbTDgv38Btz2KB/RgSmXrguRFECctmUcOw==
X-Received: by 2002:a17:902:bc43:: with SMTP id t3mr43628992plz.250.1560809508669;
        Mon, 17 Jun 2019 15:11:48 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3aa7:: with SMTP id b36ls284422pjc.5.gmail; Mon, 17
 Jun 2019 15:11:48 -0700 (PDT)
X-Received: by 2002:a17:90a:cb81:: with SMTP id a1mr1328319pju.81.1560809508300;
        Mon, 17 Jun 2019 15:11:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809508; cv=none;
        d=google.com; s=arc-20160816;
        b=RsCR54UNl344NwQu+uBvmL3qqqYPx2HMFlPEb4jwY2+aRBM0uKcmMW7YrVsU2DF1GN
         VrBZwrOorvxe3xL71u9rJjYcvxjgFBVswOB55JIaa9oP5RyDRpJCYO2eojuK2STBmVcL
         yD3ltUmFa6Qg7QFc5Bnal0F9D1HK3mCQtjNl0JxQeRbQbgmJykujMwUWbuSw7H6W42RK
         oJ8dhDyOV5LHxhZl4ZGuERBTNEwlA6A3DTnInDJIOuDagUQUYRG8aoV24IPrkZKkdQ0J
         S5RYOuG6DnqQR0TM38Rtg17H4JR858YzXWUTxtKTQ9dPbWemY0cw2qvhljX3gg0XU/ZO
         klMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=yPilZaF4h/dGO9ftIHQBkXDAqkrv70KGQtrlQh5r36Y=;
        b=xiKkmr+TChyjB9ZLr3VtEkNYwrybmdUGW00epIV60RzaJLlVg8TWSPSAFcnlbfZg7U
         1y+e/w8iqnIaMP8XNlllbHMi78oWdkW0Cj9O7sU78hkN3Lpcv9Xc0QDH15F4ik/WvVtw
         TzqFPj6WkWhxU8Bl+oAFrQrNv9aODNUrQNDaLOkNSJUIQS8jEV6DrYdQP3Zf+iWR5r+I
         02NuDjQySsH+FDuqKE5aYed3ykfAAxBr7De2iewlYl6zOlMd91D3Y/B/NFh0RuV6XuWo
         bbTshYncUorOS9yI9JXRx09WSlSImrM/KAd1rkgLATJnKNXOTKtG8Mk6ihLAwnStzlrL
         BsCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RoQtqypU;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id d128si461404pgc.5.2019.06.17.15.11.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:11:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id a93so4756947pla.7
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:11:48 -0700 (PDT)
X-Received: by 2002:a17:902:42d:: with SMTP id 42mr105482899ple.228.1560809507937;
        Mon, 17 Jun 2019 15:11:47 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.45
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:47 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
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
Subject: [PATCH v6 3/6] ARM: Replace memory function for kasan
Date: Mon, 17 Jun 2019 15:11:31 -0700
Message-Id: <20190617221134.9930-4-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=RoQtqypU;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644
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

Functions like memset/memmove/memcpy do a lot of memory accesses.
If bad pointer passed to one of these function it is important
to catch this. Compiler's instrumentation cannot do this since
these functions are written in assembly.

KASan replaces memory functions with manually instrumented variants.
Original functions declared as weak symbols so strong definitions
in mm/kasan/kasan.c could replace them. Original functions have aliases
with '__' prefix in name, so we could call non-instrumented variant
if needed.

We must use __memcpy/__memset to replace memcpy/memset when we copy
.data to RAM and when we clear .bss, because kasan_early_init can't
be called before the initialization of .data and .bss.

Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/boot/compressed/decompress.c |  2 ++
 arch/arm/boot/compressed/libfdt_env.h |  2 ++
 arch/arm/include/asm/string.h         | 17 +++++++++++++++++
 arch/arm/kernel/head-common.S         |  4 ++--
 arch/arm/lib/memcpy.S                 |  3 +++
 arch/arm/lib/memmove.S                |  5 ++++-
 arch/arm/lib/memset.S                 |  3 +++
 7 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/arch/arm/boot/compressed/decompress.c b/arch/arm/boot/compressed/decompress.c
index aa075d8372ea..3794fae5f818 100644
--- a/arch/arm/boot/compressed/decompress.c
+++ b/arch/arm/boot/compressed/decompress.c
@@ -47,8 +47,10 @@ extern char * strchrnul(const char *, int);
 #endif
 
 #ifdef CONFIG_KERNEL_XZ
+#ifndef CONFIG_KASAN
 #define memmove memmove
 #define memcpy memcpy
+#endif
 #include "../../../../lib/decompress_unxz.c"
 #endif
 
diff --git a/arch/arm/boot/compressed/libfdt_env.h b/arch/arm/boot/compressed/libfdt_env.h
index b36c0289a308..8091efc21407 100644
--- a/arch/arm/boot/compressed/libfdt_env.h
+++ b/arch/arm/boot/compressed/libfdt_env.h
@@ -19,4 +19,6 @@ typedef __be64 fdt64_t;
 #define fdt64_to_cpu(x)		be64_to_cpu(x)
 #define cpu_to_fdt64(x)		cpu_to_be64(x)
 
+#undef memset
+
 #endif
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
index 997b02302c31..6e3b9179806b 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -99,7 +99,7 @@ __mmap_switched:
  THUMB(	ldmia	r4!, {r0, r1, r2, r3} )
  THUMB(	mov	sp, r3 )
 	sub	r2, r2, r1
-	bl	memcpy				@ copy .data to RAM
+	bl	__memcpy			@ copy .data to RAM
 #endif
 
    ARM(	ldmia	r4!, {r0, r1, sp} )
@@ -107,7 +107,7 @@ __mmap_switched:
  THUMB(	mov	sp, r3 )
 	sub	r2, r1, r0
 	mov	r1, #0
-	bl	memset				@ clear .bss
+	bl	__memset			@ clear .bss
 
 	ldmia	r4, {r0, r1, r2, r3}
 	str	r9, [r0]			@ Save processor ID
diff --git a/arch/arm/lib/memcpy.S b/arch/arm/lib/memcpy.S
index 4a6997bb4404..a90423194606 100644
--- a/arch/arm/lib/memcpy.S
+++ b/arch/arm/lib/memcpy.S
@@ -61,6 +61,8 @@
 
 /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
 
+.weak memcpy
+ENTRY(__memcpy)
 ENTRY(mmiocpy)
 ENTRY(memcpy)
 
@@ -68,3 +70,4 @@ ENTRY(memcpy)
 
 ENDPROC(memcpy)
 ENDPROC(mmiocpy)
+ENDPROC(__memcpy)
diff --git a/arch/arm/lib/memmove.S b/arch/arm/lib/memmove.S
index d70304cb2cd0..aabacbe33c32 100644
--- a/arch/arm/lib/memmove.S
+++ b/arch/arm/lib/memmove.S
@@ -27,12 +27,14 @@
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
@@ -225,3 +227,4 @@ ENTRY(memmove)
 18:		backward_copy_shift	push=24	pull=8
 
 ENDPROC(memmove)
+ENDPROC(__memmove)
diff --git a/arch/arm/lib/memset.S b/arch/arm/lib/memset.S
index 5593a45e0a8c..c328d701b7a1 100644
--- a/arch/arm/lib/memset.S
+++ b/arch/arm/lib/memset.S
@@ -16,6 +16,8 @@
 	.text
 	.align	5
 
+.weak memset
+ENTRY(__memset)
 ENTRY(mmioset)
 ENTRY(memset)
 UNWIND( .fnstart         )
@@ -135,6 +137,7 @@ UNWIND( .fnstart            )
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
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-4-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
