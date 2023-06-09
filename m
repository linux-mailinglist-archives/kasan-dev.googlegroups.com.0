Return-Path: <kasan-dev+bncBD653A6W2MGBBJUVRSSAMGQEOFHRP3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2885C72980C
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Jun 2023 13:19:04 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2b1b44bec2bsf12269471fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jun 2023 04:19:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686309543; cv=pass;
        d=google.com; s=arc-20160816;
        b=sMjZENDJ+2yBNGJw8IvuHzZMol+Wjkhq+8+OhkRA4D/bsjtHLB9UEd+8MKxLUWWRsv
         K8rkzxw7GQh3UfaPUY51f4vVJfpu9Z3MiT9Idw6+oPggtgLDCB5S5BLCzh+Fw3RBycnS
         FQ/qCqUlsVrGm4ze3Y/BZmBVFr5Jv7YXwFbQ7LP8RaqFKwJYmtdMcsm1Q6zLzZhD5haG
         60Or08kF5HEB5+YW1jua5ogRlFtyz+rzkDzHgqZRsDEOXRxvi3cwCDgsi7Oxlmb7uSTL
         qkdzJRxJpZVjIWnNtJeog9zXrBCkZk3ZE0zFSVpPDKCxLfmgMf5VXeT786lwgirpbD0G
         mlMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=UXXZS23NF+gVC/Hbk+z8+S3oU73A32KeW7rEwBYESS4=;
        b=EqdvuPptNZ3gV58AxzEtsAmMwjRcIITUqaacg+Jj3b2GVtsM8bwPS5CRxJY9eNGvCM
         UvfcBK6CFEAbbrJrmS+zUEXlyZOXTpK52dW4fek1VQbJhHMm17xnniX1Y8K9M+aKoHAc
         /CXIf15JIAgnG5GywD7jj3sUa6A4qyoQ4pEim79H7SEbCDtmFRLF+cDJIOtt1+bhwKz4
         2sV6Uh4xN4ewVQdE1L/4ku+1VjlwdowDcSq5K6s2ddDQYCN2TNIh0O4Cl1W9FA0I5UOj
         Mkce+qqYvRr5oFOsq84embJ/m9mF4ohfz3pgY93ys9yftPwpYQkIOZGpFXWOkeKXeECK
         7t6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=ond8TiTg;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686309543; x=1688901543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UXXZS23NF+gVC/Hbk+z8+S3oU73A32KeW7rEwBYESS4=;
        b=iXRgqBk+NIQjAaxblfTi+Hzat5/Gf/+UIEW/glClixonrGZtZSrzwfVqJS++ws/48e
         kfQXREFnaSokT7taNe3VTOf6I0L0qqReRopBRvUBCq+t19IRerYBEg8LOh7rlZEo2IzB
         fTGc+3nf1z0f0sB+GZ44fIuWq9X4bnIvA2lEIOKj+k2tFjN4haXCqUzcTVfwfMNRJniM
         iDsqEDB+8x8RfgBPum9dJxEBfKpHQ0KAPhjZOR85PAOmqKNjnbNgtJS90+MFK1kvOmyI
         H6NcD1K29xU51lqqU5YoxzZqsETQfdcyB3BmKXi9KkmHuwDaVDS4Nyu7CopY5udcpi9A
         n6Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686309543; x=1688901543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UXXZS23NF+gVC/Hbk+z8+S3oU73A32KeW7rEwBYESS4=;
        b=h5xdyfekFNen2Li8bgJ+qA4WDoUP828zpcIFxeBCxPc6FNpbSCW/F+8hwkFN1lcaoS
         UBAyKQHZOZZPQzDiW6O/S6SX4ZwwA2Pp2+yBto96J646VYbpSgZp2gyqN7pRiITx830m
         MxuynIDSsRd1YVglS0cQqqS0WmxyDeZTZ/9bkeYhcHJL6IRYbxdSkzJ7qkpApxnV+hhM
         zV0xCvFIMSx6MyQl3zFcvLt4YeV/+PUr04CSq7v/FxZZe/bcVqwK+VT7x7p7zG/XL+2G
         WsYmgNWPTgdvnXvOenV60PkZTZkiM1Lg0YPflQ2kA31eZwH8rcZJirP1GUoxntaaNMtx
         +ObA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDya6IY8TSN5HDCgVQedOaiD94rxP6Cec7qz0IVT5ttqCqlliLM0
	iKafHE6YQFjAoMr83M2PiPE=
X-Google-Smtp-Source: ACHHUZ4USMrffstN09X88a1kOPtpC0MrjkTWgNOMXfRisKyDHHbxtfKu8N+Pk+75d1uRA1JMuS1eBA==
X-Received: by 2002:a2e:9958:0:b0:2ad:94cd:3cb7 with SMTP id r24-20020a2e9958000000b002ad94cd3cb7mr836834ljj.51.1686309542721;
        Fri, 09 Jun 2023 04:19:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:198c:b0:2ac:81ce:1bc1 with SMTP id
 bx12-20020a05651c198c00b002ac81ce1bc1ls132748ljb.0.-pod-prod-04-eu; Fri, 09
 Jun 2023 04:19:01 -0700 (PDT)
X-Received: by 2002:a2e:874a:0:b0:2ac:78b0:8aef with SMTP id q10-20020a2e874a000000b002ac78b08aefmr769781ljj.16.1686309541088;
        Fri, 09 Jun 2023 04:19:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686309541; cv=none;
        d=google.com; s=arc-20160816;
        b=JMJXW/ZNauz8CSYVvQpBq+UvSxvKYXKSuzNthH6B+NzQZrhP03iV3sE1NogTk+aIrA
         gu0TGeLxqv1D+8w8K74bZISQUf7CBmPQI6PZy5iHJLiFBz3wU67jSvFQeBBYjrCwplR1
         ZYjaQrYnvjqXO8adP9/2se3D0AZW4zuWH1sPzZH6BE9XQ4W+H7uEVYvcT+h1yHvLlC6D
         bx7es/SBwQIzQ0To6+eY9BVGP5fGTOow5owNAcVDW4oGpPTlzXCsBOp2gHCbNH5npOwe
         vxQ7m6dPXpenEqGdfua8MBPUcAFCOWA/EfjnhgYFalZWybdjknjt8DWoauOJGd138+0K
         YHig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=7XMigKyzIzkGYn81G4evNo2KHPOOkw2Qm++AiRLE9eM=;
        b=EAEJ5GaiHdsHQtH8J0N+EBXBcJAsEURvSTqUNADQoaxcTY3EUZX/OfoYZY4jIxGY8r
         GBVqMQSrYuPCeRJqMrIU1xMbKhVwvcpCMzA4GuJiFXCG04489/Q9bKMUAPXs9c6s/ogp
         fLJV52Qre5C8Kd0mkLQT5sLPKhSCLTDtO2D/0rZl2osuJy0nWOL19lUL57VBjcTX+ix1
         vrfDdSIPrQTMhnby+Us7gx2GgRoig64mre79r/0VqvfE4A99T/JaXBjRat5dM8QFIE4n
         B7A2TSmH5hLwBysqjezjSarnb+S3y7EhCjNBcRYpOcVLE6QL+EY+ybBUVkxbzEo+VlXu
         5tUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=ond8TiTg;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp1.axis.com (smtp1.axis.com. [195.60.68.17])
        by gmr-mx.google.com with ESMTPS id m11-20020a2e934b000000b002af15d1ad3asi157346ljh.8.2023.06.09.04.19.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Jun 2023 04:19:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) client-ip=195.60.68.17;
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
Date: Fri, 9 Jun 2023 13:18:54 +0200
Subject: [PATCH] x86: Fix build of UML with KASAN
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com>
X-B4-Tracking: v=1; b=H4sIAJ0Kg2QC/x2N0QrCMAxFf2Xk2UBNnWz+iviQtZkLm600KMLYv
 9vt8VzO5axgUlQMbs0KRb5qmlOF86mBMHF6CmqsDOTIu6vr8fNacGbjhOR7ivESfNd2UP2BTXA
 onMK0P8acaZ/fRUb9HYn7Y9v+0FOpHXIAAAA=
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
X-Mailer: b4 0.12.2
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=ond8TiTg;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
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

If I'm reading that commit right, the !GENERIC_ENTRY case is still
supposed to be allowed to override the mem*() functions, so use weak
aliases in that case.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
---
 arch/x86/lib/memcpy_64.S  | 4 ++++
 arch/x86/lib/memmove_64.S | 4 ++++
 arch/x86/lib/memset_64.S  | 4 ++++
 3 files changed, 12 insertions(+)

diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
index 8f95fb267caa7..5dc265b36ef0b 100644
--- a/arch/x86/lib/memcpy_64.S
+++ b/arch/x86/lib/memcpy_64.S
@@ -40,7 +40,11 @@ SYM_TYPED_FUNC_START(__memcpy)
 SYM_FUNC_END(__memcpy)
 EXPORT_SYMBOL(__memcpy)
 
+#ifdef CONFIG_GENERIC_ENTRY
 SYM_FUNC_ALIAS(memcpy, __memcpy)
+#else
+SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
+#endif
 EXPORT_SYMBOL(memcpy)
 
 SYM_FUNC_START_LOCAL(memcpy_orig)
diff --git a/arch/x86/lib/memmove_64.S b/arch/x86/lib/memmove_64.S
index 02661861e5dd9..3b1a02357fb29 100644
--- a/arch/x86/lib/memmove_64.S
+++ b/arch/x86/lib/memmove_64.S
@@ -215,5 +215,9 @@ SYM_FUNC_START(__memmove)
 SYM_FUNC_END(__memmove)
 EXPORT_SYMBOL(__memmove)
 
+#ifdef CONFIG_GENERIC_ENTRY
 SYM_FUNC_ALIAS(memmove, __memmove)
+#else
+SYM_FUNC_ALIAS_WEAK(memmove, __memmove)
+#endif
 EXPORT_SYMBOL(memmove)
diff --git a/arch/x86/lib/memset_64.S b/arch/x86/lib/memset_64.S
index 7c59a704c4584..fe27538a355db 100644
--- a/arch/x86/lib/memset_64.S
+++ b/arch/x86/lib/memset_64.S
@@ -40,7 +40,11 @@ SYM_FUNC_START(__memset)
 SYM_FUNC_END(__memset)
 EXPORT_SYMBOL(__memset)
 
+#ifdef CONFIG_GENERIC_ENTRY
 SYM_FUNC_ALIAS(memset, __memset)
+#else
+SYM_FUNC_ALIAS_WEAK(memset, __memset)
+#endif
 EXPORT_SYMBOL(memset)
 
 SYM_FUNC_START_LOCAL(memset_orig)

---
base-commit: 9561de3a55bed6bdd44a12820ba81ec416e705a7
change-id: 20230609-uml-kasan-2392dd4c3858

Best regards,
-- 
Vincent Whitchurch <vincent.whitchurch@axis.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230609-uml-kasan-v1-1-5fac8d409d4f%40axis.com.
