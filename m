Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDXYX7AQMGQE6XJHJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C76C6AC1B08
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:44 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b26e38174e5sf8658483a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975183; cv=pass;
        d=google.com; s=arc-20240605;
        b=Yxz6sWQ+JjIHWRkaq4eqeOqJuuhM26ij0t8bRN77fsmCEtBeX+mG9arzr8R/fwWmdu
         Gweagn7TbmdFVibS+DahYmFl9DksGsxoXR2pY+QLGoyavZSb+/GjOoSJ0Ot8WFl8gPow
         4Cz6LqPEzxfs05Uqiz2MjthCqYMG2xMHGKWIuBxgMXyaYxWFJSmcG9HmjlkG0YTWkvVx
         LaxrXM3dMWpNwENwy96N/bWVUWA1t09mpYEhO6vjI+Lp7iXzO9bYSDhDO6FkkjwHnBvS
         oTvFDEl8S042GXmKStTJ3l4oxlcC4WqxoqlfR7qMS/s+Bk+FTZOEygvoUUYg2r/o1/S+
         wVDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=j3+P0GQmgfISooqb1isIzBSzjPWn/7YWq2BU6F2a1pc=;
        fh=3PY6vEYrSYW6TXzO6gU/4YWTijA5s6nkaDcykc4/rRY=;
        b=gPysi6roF6NQCPzsfvgOfmoXTIt0iryODCmvYnHmxJ0qPviopNtMM239/31KaCSmWZ
         RWNvJoXm6pvAb5/VDvhdsYbKav0mncv6FK7WGPLSVOoY6Fps9NCDAOy5EzhEQz3CgiHH
         O9soj6PaFYpfhlAxioWK0V3tJoUah2vr8DoRC4ki3kkvKO17CHiBdxeVQTPx6ZtqSL6i
         X91J0PDd5qy+RWJRJuKUegoR06PzlnEeBS7zSdUljsJxCTdqlWW5vsHPCSdRwjiW4E+f
         0GB/T+kVnV63oso3x716sDyH3hK/0LNVBLgo5pe/sGxkZbQrRBHZmD2iAto5YssgqK8+
         6ceQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uE7AaIXp;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975183; x=1748579983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j3+P0GQmgfISooqb1isIzBSzjPWn/7YWq2BU6F2a1pc=;
        b=nu93iSWU2rCZWMLE8JrXV/IB5owUx9Ab6G0fqpyRpmr9qZjmKSkqtsDRtcx+dc7Inj
         sbjg1mG94oVBLPhuRNfsJxBEI9ijpk7Jhc87ejl7KJiSc6IrNnd9HoAEiEFn9mcdGaVh
         bC01goL3KksDIHq8RzGwhHDLUFSxCb9zuCAtuDpHeF1f0gsMjY6eMx6ztddxY3fke0cE
         tejhPITFKkuSUCilJnwgN9t6aXxHkmHidaI+78a8NLbFhfpRowisrKgEzmmcCWAk9d0K
         sYRWOWosOXVUxecxqtzZvyDfj1INksWzb+is/SZ6zzsx70BFQUyWuQnf9a2uo3kxbGtU
         riFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975183; x=1748579983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j3+P0GQmgfISooqb1isIzBSzjPWn/7YWq2BU6F2a1pc=;
        b=v+olhavwXCvsDyG/3papsnDs16R9rcsSyIxtwSQJOtEzEQ5yA5ZSXkc1lQoUQd4BRZ
         d2U8yAfe5fyYWUmi9PpInM/lJl3FuXHB8YufFjXAN+WfSh6AexMuCVFRn7ZJ5ez3zNNA
         WQ+GlORQPotnnZoGquvcE7lZmamEoBSlEPnTZZ1Cmbpz1Hog3P7/EIFrQj9sJdJpc3cI
         e4Rsx+FgDpKtrNfx1gd5nPXnRlveg0cHJNilcrJepvE57bcQzpD+IBm8rOwvInNUH5Px
         pqJE3RMRfl456kSoNMaP1tjvAnv7Cx4jFthZhqUi8Ao1rFNRgTrOLQUFPuRQ1gbFIdI2
         vIVQ==
X-Forwarded-Encrypted: i=2; AJvYcCXtur1oFx32C4bG9MhDPBqinR0mfHtJEaXv1EuwPAeIkXfohWaUFrsrpXdmEEdTx3WfgmdDtw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8n8SUqM3jE3VE57WkdxyU+mIRpemqmIqfjkZ3j3+tmMklgE/g
	QENShvOKxrVu06X4fNw/Ei/Mcr6OkLVsNj8DeHu6mTdif4IL8uvJOX4F
X-Google-Smtp-Source: AGHT+IF8ZNygqvATvRYofksvBypdMWQvQMuwjJ41GktdSImZqSp7wXxLQwJolwmj7HoJGUTnRNSpbQ==
X-Received: by 2002:a05:6a20:43a5:b0:1fd:e9c8:b8c3 with SMTP id adf61e73a8af0-2187a5807e6mr1936285637.26.1747975182890;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEndtpPzixIEiU99PMNXwnG0HYz6CaSaibDROC/Ky+kAw==
Received: by 2002:a05:6a00:1904:b0:736:dc82:1c47 with SMTP id
 d2e1a72fcca58-742968ef5eels4080774b3a.1.-pod-prod-08-us; Thu, 22 May 2025
 21:39:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtlsPo9StHDdOTm1WyeQ/sFrBUjGSox0RoWqpOaoKAtZaG7sWB7/gS+29GfkVos+ClGZ/VzuCLj3U=@googlegroups.com
X-Received: by 2002:a05:6a21:3182:b0:1f5:8eec:e516 with SMTP id adf61e73a8af0-2187a580ce4mr2406267637.32.1747975181661;
        Thu, 22 May 2025 21:39:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975181; cv=none;
        d=google.com; s=arc-20240605;
        b=Ea4L3/b8v8FCUjSPYK7wWzzuFdtEDsctvHeXq97Rj6s13hlpRV+hbrxz0SnM1auELA
         hXpfcl7CkYmxkYF+go0VbTkgxnNi3bPGz3ANKQLjXpKtsq661fy07v4+7idtxs02VaAp
         Brvza0qTp3vuSYniLOeObjyqwsj/XpLQ5I1hv1bMV/aurX0DJ/Wz4vbvf7sQrsmb05kl
         05Sn/xDCgBH+REHoePMoZ1bRt44dM0812RdTroxcdU1LqLWGbT20RYGJASH9Y/XM1Vou
         lZr6bwj0St5k5z0Hr8TEAt1LQ3+Al6eDQ62yhA+PD+NecfNQUI9bKMypQ2ViBnyyO2GN
         fL4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yTTuFDULLlXHo29rEb16kTtXhwZm7ZhsK1So1LQJfmQ=;
        fh=jau/UP/1lfx8Sl6pPnv4kCg2wo27VleiE/VdZqyptjM=;
        b=hATD0SdRLFdPKgD2omUWOeQBtNlAP67gXXVZ4ppJwV0E21qmSTu1rjC9WeVNUYyRhH
         FfewAAKbnjs+8+Fa9kFSIgPvinprbCcTOIJ30RQxAmAyEosPVsMKAFkrjvlqLtUUN4VG
         K9E4cl7T7MhmidaMtwspiLeaegTvXiXN3DRrDaW6msQRV8LAyqQVcO+MLuX9dLlGxuVQ
         v1yRvpmI/TaCbhmQ2STUOUOK7FzeIn28pxGhLtBBOA32l0eV2Rhl7vB8f2g0pPm5gvhU
         OwsdBV3+4eVb20sYZBHIPTO5FXpRw2UsiVrKENgxninJBy7wsrL0dil7ql6ENHQ7ohtk
         uRUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uE7AaIXp;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30e7b104971si1273650a91.0.2025.05.22.21.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6FB234A968;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 45D20C4CEF6;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	linux-mips@vger.kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 09/14] mips: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:19 -0700
Message-Id: <20250523043935.2009972-9-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1052; i=kees@kernel.org; h=from:subject; bh=Jd/sB6oZ8iltvnfrQDqGbUKjd0Ro3QNhdkLI+vDUogY=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/Zi0kce6axcl3IlGXXv7dekvhyRPSBTort1tP1K SyVtX0ZHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABOZysfIsPL2U8Z//9ZLv1JP aV33p2xj+sPc5oXl284XsjnqZc1ZtpPhf9Cv8pC7KxeE36nZ/nr2m3tGE9NjZ03f/PFc35H9N+K yTLkB
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uE7AaIXp;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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

When KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we have to
handle differences in how GCC's inline optimizations get resolved. For
mips this requires forcing a function to be inline with __always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
Cc: <linux-mips@vger.kernel.org>
---
 arch/mips/include/asm/time.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/mips/include/asm/time.h b/arch/mips/include/asm/time.h
index e855a3611d92..044cff0e0764 100644
--- a/arch/mips/include/asm/time.h
+++ b/arch/mips/include/asm/time.h
@@ -55,7 +55,7 @@ static inline int mips_clockevent_init(void)
  */
 extern int init_r4k_clocksource(void);
 
-static inline int init_mips_clocksource(void)
+static __always_inline int init_mips_clocksource(void)
 {
 #ifdef CONFIG_CSRC_R4K
 	return init_r4k_clocksource();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-9-kees%40kernel.org.
