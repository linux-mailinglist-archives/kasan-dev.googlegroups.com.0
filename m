Return-Path: <kasan-dev+bncBCH67JWTV4DBBA7VRDYQKGQENNLHZSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id AD96E141456
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:51:47 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id b13sf11043904wrx.22
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:51:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301507; cv=pass;
        d=google.com; s=arc-20160816;
        b=JXPZ+LnoEEXPtjzLpmhjLKqQYUJ/c3A/Sdeg1EE6SQLRsVi6FwEZV6XwIHhpHmW4BK
         sE6QrvJL1UOxJ90p7dFFql5rf1dkUzfAfa+bPtdmNyNWj2f8/aQ8Yyo/v+rMM5x2z/M7
         3eVKr9PGHpkpiwnPrdCYc/aWKg3O0WxtHmv3OEHjLDhKAu+6TXMO92RAcnHqwVWRJnU2
         PgfmcMyr7wNqhELdjd4IhDFKYLC/OzOeRz3pJtW1MzrcnQLBKxiv6APVmjXv/X9H2UxA
         OjsTig62L/MIej08GnHagW3ppvl4Tz0FZh8l4xlDVcCsYvpjojB4tGrc7su0FWMgIX7e
         D9pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=WqDabtFJrHA0vRSmcKDQoeY5/Ll8Sku5uMX5cEnWObQ=;
        b=vWQ3dp5Adlhbap8BGDaWkKNMo3f6vfToAz/idSM7a1QvsJkAbe+I0ErGQe9NE8LqTQ
         dqsmwz3kHhyuT/lih2fHIEMwaozA5zbXomeXtRO5mMobQ+rGdhjG48fITrBxdWgLalhe
         OZKJDfmGpGeHIoIMsPShUBh4Rkwgf/EpoVeAmeDSZe8UZm6UczeEzbNVszNk2UIQTl2w
         3hfq+XHrHO3ynpFISM4+PKjif6a08JU++v4r0IwNNaza8nwKjno0Yghfoykg16qhVIrb
         8Ay7ljFnLmRgyHQvsN2qJ9ssMj+vbLaBWMwyPpBY/JoIhUqrnIBhrLyK5SWAKFNOR8xd
         2N+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=e3FGV2jB;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WqDabtFJrHA0vRSmcKDQoeY5/Ll8Sku5uMX5cEnWObQ=;
        b=lfhonV2L4SGX/um0AmrC3HB+fRFhfcSH4axYmtrZnnl6dhi0kdK57R3vjhgf12DKMR
         2tcPq+ZbOiK8AtPcTIiIMX3qgDR9MOAixQq9z3JoOJD/vanyB0SLItYXA/5SLy3WLv0f
         V0s1A0gpe2pswBkNIlMTdJWUSBFhY+J4vJfetHyQ4dy5OvemrVhtFgfzDFvTB/XdP553
         D0Vm8vlwhr3qpZUrYKqZmwJlaodCKme0h49FtRQvl3/h4IizsyWKq7w1Sj3Dz7f32JZV
         +pnj5n7uy+MHWguOUnYqnM33GlzPvKoyJmagiPKaUNeKyewbaZaXELxqgVz0r4RKZQ9+
         OPcQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WqDabtFJrHA0vRSmcKDQoeY5/Ll8Sku5uMX5cEnWObQ=;
        b=NMih3buatMklheITUYLKddHUaEgrM58dUEJRgVBVchVonT9jmNMlCqfCrFSR3SK+sZ
         /wVy03HnGSBDQQEz8/eyjmwmmOqlKKOVWqOVAJgThOK2CoV8iz4nU8haUDBfoOHMOlEm
         aXuh+SBvvKUnmY0kvZ/e5wyrqnInwJ2BI1KT7O6LwFdc+iSPtYIelbgpCSwqVZATCph5
         CqZcpTbSVwm8B0k17D4HMkeFStuu3eyKIJPKNynZkpIRU2snx4J43W59vDLBv/Lh2pV2
         EsqMPSdGeaNFDiGm7V6/Uk0VsKdY7ArFiZJxpJRmJBH411c5FllxcHbcD9KqtCEFE/J8
         u2kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WqDabtFJrHA0vRSmcKDQoeY5/Ll8Sku5uMX5cEnWObQ=;
        b=Aw5zM04hMkIkIA6r+p8fm27MUeKGGsu9eXGaFmc47mCDVSHMXvclraPwqzgv2M78Tz
         kUVYqNBGa4fDEK4RXbatuz0txTuQ7yJ4oaGhRzbAxY8X7jphzhtuNMP7QnYnHn6xjSeM
         GYsplMuYFpd+NFnKpPhy+GQydGyUEiqpqhW45Qr1PBUTVOirzpZB89O1ZaZxnJzQcyTE
         9dKDyU5VJXeaALiO/SsK8MROH2cCKGjdCVMRBrQaSq1idwMgo2+8+kwCvRxRt3YuLLBt
         Pj6VvZ5/V4gVzv25xu+ra0ORj2GaNE4kaD9Ct/3SQpkAJTIGbeZkOMuHC9KYslO6xiF8
         olVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUTWQZ/GbF16KuS7FaR5XRTN+I3oqNGU+38dm1Q26lrJMT+1fJ1
	2ONBV3pGKh9utknQGsySd0c=
X-Google-Smtp-Source: APXvYqw7GLmnfGd7dY6DFn/+2PZDcWKqNJbjAsL9Rfxiyv9+MGGwjke+YeMYzmEjPs/rbetpg/uW4g==
X-Received: by 2002:a7b:c318:: with SMTP id k24mr7149419wmj.54.1579301507360;
        Fri, 17 Jan 2020 14:51:47 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9808:: with SMTP id a8ls3140449wme.0.gmail; Fri, 17 Jan
 2020 14:51:46 -0800 (PST)
X-Received: by 2002:a05:600c:220e:: with SMTP id z14mr7060502wml.114.1579301506575;
        Fri, 17 Jan 2020 14:51:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301506; cv=none;
        d=google.com; s=arc-20160816;
        b=xFVHUYJ8C4brXWxs4Is+o57Pnb/mkUSYOpoCgh0fICr0SSEaD/E8GCGHlBHUs3dMkg
         kzVhBjlqGFP8df29QrM39Z0eDxXMxKDFYFCEQ3IEA0z1R4EEyT+etgpggFvrd7AmLjSB
         gFOPU1GGKQ7sXRBdnth0WBESLOIpfDZxQNX7V2mzkB+LS4BRlGbhHBlf9Jfko2bundxi
         VjDpjXbFq6rtmYdexEv65+XSSbCunubwCfXRW6AMSkeOP+5mLGbksvPzEdXDqphNpeb5
         krcop6leKKJFYvGMd6dAPCHywU+2DcLnUXPtL6HB848gvp39QuBAGBRCi3PpD1ahvVYU
         VpYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=DBsPSSqYKmu847AC4mw5h2lhLIA5doaDQKnFj+vKRMQ=;
        b=F/YwH1ONOfabbFyXRaFHiG4CgmsjHJDwAjpwdgbfRVNpHf3xmx60KiyqerG8WKXJ0P
         ++qFTlZqRVtNWOuD6on4ZFRyS/hX3mNlCDuOeTmt4E/sJgWq+5ijFpi69kQ/Ty+ORdKF
         Vf0i7n5pg+/OvELMaJrxgVwoYtNiLXnPNPAlXVpIsoD0A8Jx5d1JzhCWldJAuEMpXgOn
         UoAfqSpAamox1DdusfN133HIWD+/ARYDD76otFXLvY/ORsK01W7CVmWAXUBzNYLzWcRq
         /JLOTsGUPirjpVoEiRN8/kVTNXkJZLygxdrkWE7wKLNdQtWAsMzAb4NhIZwysxe5DlKw
         wugw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=e3FGV2jB;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s82si422708wme.0.2020.01.17.14.51.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:51:46 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id c9so24195731wrw.8
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:51:46 -0800 (PST)
X-Received: by 2002:adf:ea0f:: with SMTP id q15mr5554706wrm.324.1579301506172;
        Fri, 17 Jan 2020 14:51:46 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.51.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:51:45 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Abbott Liu <liuwenliang@huawei.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
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
Subject: [PATCH v7 2/7] ARM: Add TTBR operator for kasan_init
Date: Fri, 17 Jan 2020 14:48:34 -0800
Message-Id: <20200117224839.23531-3-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117224839.23531-1-f.fainelli@gmail.com>
References: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=e3FGV2jB;       spf=pass
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

From: Abbott Liu <liuwenliang@huawei.com>

The purpose of this patch is to provide set_ttbr0/get_ttbr0 to
kasan_init function. This makes use of the CP15 definitions added in the
previous patch.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/cp15.h | 50 +++++++++++++++++++++++++++++++++++++
 arch/arm/kvm/hyp/cp15-sr.c  | 12 ++++-----
 arch/arm/kvm/hyp/switch.c   |  6 ++---
 3 files changed, 59 insertions(+), 9 deletions(-)

diff --git a/arch/arm/include/asm/cp15.h b/arch/arm/include/asm/cp15.h
index 89b6663f2863..0bd8287b39fa 100644
--- a/arch/arm/include/asm/cp15.h
+++ b/arch/arm/include/asm/cp15.h
@@ -42,6 +42,8 @@
 
 #ifndef __ASSEMBLY__
 
+#include <linux/stringify.h>
+
 #if __LINUX_ARM_ARCH__ >= 4
 #define vectors_high()	(get_cr() & CR_V)
 #else
@@ -129,6 +131,54 @@
 
 extern unsigned long cr_alignment;	/* defined in entry-armv.S */
 
+static inline void set_par(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, PAR_64);
+	else
+		write_sysreg(val, PAR_32);
+}
+
+static inline u64 get_par(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(PAR_64);
+	else
+		return read_sysreg(PAR_32);
+}
+
+static inline void set_ttbr0(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, TTBR0_64);
+	else
+		write_sysreg(val, TTBR0_32);
+}
+
+static inline u64 get_ttbr0(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(TTBR0_64);
+	else
+		return read_sysreg(TTBR0_32);
+}
+
+static inline void set_ttbr1(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, TTBR1_64);
+	else
+		write_sysreg(val, TTBR1_32);
+}
+
+static inline u64 get_ttbr1(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(TTBR1_64);
+	else
+		return read_sysreg(TTBR1_32);
+}
+
 static inline unsigned long get_cr(void)
 {
 	unsigned long val;
diff --git a/arch/arm/kvm/hyp/cp15-sr.c b/arch/arm/kvm/hyp/cp15-sr.c
index e6923306f698..b2b9bb0a08b8 100644
--- a/arch/arm/kvm/hyp/cp15-sr.c
+++ b/arch/arm/kvm/hyp/cp15-sr.c
@@ -19,8 +19,8 @@ void __hyp_text __sysreg_save_state(struct kvm_cpu_context *ctxt)
 	ctxt->cp15[c0_CSSELR]		= read_sysreg(CSSELR);
 	ctxt->cp15[c1_SCTLR]		= read_sysreg(SCTLR);
 	ctxt->cp15[c1_CPACR]		= read_sysreg(CPACR);
-	*cp15_64(ctxt, c2_TTBR0)	= read_sysreg(TTBR0);
-	*cp15_64(ctxt, c2_TTBR1)	= read_sysreg(TTBR1);
+	*cp15_64(ctxt, c2_TTBR0)	= read_sysreg(TTBR0_64);
+	*cp15_64(ctxt, c2_TTBR1)	= read_sysreg(TTBR1_64);
 	ctxt->cp15[c2_TTBCR]		= read_sysreg(TTBCR);
 	ctxt->cp15[c3_DACR]		= read_sysreg(DACR);
 	ctxt->cp15[c5_DFSR]		= read_sysreg(DFSR);
@@ -29,7 +29,7 @@ void __hyp_text __sysreg_save_state(struct kvm_cpu_context *ctxt)
 	ctxt->cp15[c5_AIFSR]		= read_sysreg(AIFSR);
 	ctxt->cp15[c6_DFAR]		= read_sysreg(DFAR);
 	ctxt->cp15[c6_IFAR]		= read_sysreg(IFAR);
-	*cp15_64(ctxt, c7_PAR)		= read_sysreg(PAR);
+	*cp15_64(ctxt, c7_PAR)		= read_sysreg(PAR_64);
 	ctxt->cp15[c10_PRRR]		= read_sysreg(PRRR);
 	ctxt->cp15[c10_NMRR]		= read_sysreg(NMRR);
 	ctxt->cp15[c10_AMAIR0]		= read_sysreg(AMAIR0);
@@ -48,8 +48,8 @@ void __hyp_text __sysreg_restore_state(struct kvm_cpu_context *ctxt)
 	write_sysreg(ctxt->cp15[c0_CSSELR],	CSSELR);
 	write_sysreg(ctxt->cp15[c1_SCTLR],	SCTLR);
 	write_sysreg(ctxt->cp15[c1_CPACR],	CPACR);
-	write_sysreg(*cp15_64(ctxt, c2_TTBR0),	TTBR0);
-	write_sysreg(*cp15_64(ctxt, c2_TTBR1),	TTBR1);
+	write_sysreg(*cp15_64(ctxt, c2_TTBR0),	TTBR0_64);
+	write_sysreg(*cp15_64(ctxt, c2_TTBR1),	TTBR1_64);
 	write_sysreg(ctxt->cp15[c2_TTBCR],	TTBCR);
 	write_sysreg(ctxt->cp15[c3_DACR],	DACR);
 	write_sysreg(ctxt->cp15[c5_DFSR],	DFSR);
@@ -58,7 +58,7 @@ void __hyp_text __sysreg_restore_state(struct kvm_cpu_context *ctxt)
 	write_sysreg(ctxt->cp15[c5_AIFSR],	AIFSR);
 	write_sysreg(ctxt->cp15[c6_DFAR],	DFAR);
 	write_sysreg(ctxt->cp15[c6_IFAR],	IFAR);
-	write_sysreg(*cp15_64(ctxt, c7_PAR),	PAR);
+	write_sysreg(*cp15_64(ctxt, c7_PAR),	PAR_64);
 	write_sysreg(ctxt->cp15[c10_PRRR],	PRRR);
 	write_sysreg(ctxt->cp15[c10_NMRR],	NMRR);
 	write_sysreg(ctxt->cp15[c10_AMAIR0],	AMAIR0);
diff --git a/arch/arm/kvm/hyp/switch.c b/arch/arm/kvm/hyp/switch.c
index 1efeef3fd0ee..581277ef44d3 100644
--- a/arch/arm/kvm/hyp/switch.c
+++ b/arch/arm/kvm/hyp/switch.c
@@ -123,12 +123,12 @@ static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu)
 	if (!(hsr & HSR_DABT_S1PTW) && (hsr & HSR_FSC_TYPE) == FSC_PERM) {
 		u64 par, tmp;
 
-		par = read_sysreg(PAR);
+		par = read_sysreg(PAR_64);
 		write_sysreg(far, ATS1CPR);
 		isb();
 
-		tmp = read_sysreg(PAR);
-		write_sysreg(par, PAR);
+		tmp = read_sysreg(PAR_64);
+		write_sysreg(par, PAR_64);
 
 		if (unlikely(tmp & 1))
 			return false; /* Translation failed, back to guest */
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-3-f.fainelli%40gmail.com.
