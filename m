Return-Path: <kasan-dev+bncBDCPL7WX3MKBBZEM43BQMGQE52EAAIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9640AB09745
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6face45b58dsf22478296d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794724; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rg3QosJuGRJRz9jxXM5DGCfB2N7N1GqSIv6J2B1oyUFmItrUCqa9icNbu28Z0zLyJ5
         dxSYBLeOoQ0QcMhMZzN62gWftu+vYfvURPT3c5lKI/AWu8x5mp0J0x0CSssthi2plP/o
         QfdzrfjmGvWZQzdTyi/EgMqLJw73h0mTcFX9r1w23LEDnEvxGgxtM4H5PK5UqsEV/QDB
         MbSr1UqRn8ZjW4CPzwJdxAoXrCWtluklWLVXdnDRVjQGeSWn+6ZWQ6VOFBPldIzIZKaN
         gosNbqGtO9N8ipxZTCbcItUyDuYWm3R8zOZVoxs5q/kicZtaFjYLEMrzvET7gYzdl7Cu
         WeTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ugmyFFfVTet6OYS8T0h9/XKnLhyZKO0fYkAneLE1YqY=;
        fh=1noOrwwhgox48py3q+dsgXMikMWMuoGfHGJRJkT+odQ=;
        b=Eb1PP78G5yi83iTl2LlV4eD0etaRmbJreoinb+GsZ9bQBObguuRDXV1n05HaGK6blE
         kkusoEjNL4Hv3s0lrZlQK4I8SttQHtMGssJ0nhsuqxLOx86Wrz9txAU34qeXow2RldUL
         HWTKxuVxWFZkWA29AfCOzdHp47FYl/nCngeQpAyPG1XlLjpgilJX9XSwMTHU10mjaVHd
         GBx+d94MSWU0agq6IFpii01M6JvzfiiqckXiUd/FzG8Fds3YQNwhyAH/ZqMuAmj8E8yT
         ci3eVZNKr805NoLm77hTSMYVWn1k+b7lfhou77VmL7f0dAXEVO+A/Rc0nqIN4QVXw7j5
         JjcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TDQPJoue;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794724; x=1753399524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ugmyFFfVTet6OYS8T0h9/XKnLhyZKO0fYkAneLE1YqY=;
        b=VPGb8YZHRxpraBDOSLZISTvtt/c+KRbOn9+FxqaFqTP3mT91dbbo1qCwQV3779HEH4
         vRlB+fGJzGOHxMpR9WWTF+1eMAuEogtP4qbCdZCdDX+4cshNUPTVXKB0X+dgKwu+jSZx
         X/yFeNt23JXcJXX2Nr+zQrQpblQe4R1VSFc91zNgCJRunqPC0m0bTJ2UBaCZWjfS5egf
         VPbtJvQZiSpBjp/kKxf/YBtvWtwhaMVkLelGq/qq8eE/64MEt0sLx1oT2jHDGoxPSwZB
         szAjmvyzgQ6BNOZi6PJ3Myuee3x67ciRi+sCdTWKCuRqkONf14QSMV43M+yFnivFI00b
         FomA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794724; x=1753399524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ugmyFFfVTet6OYS8T0h9/XKnLhyZKO0fYkAneLE1YqY=;
        b=nUWzQjarYhW1oq+3p6kTE1m9464Ib2uGPe5F+nghaxZus379/FRKUDwRBEPZmzpCfY
         odXAEITr/E1CET59NQMirLrM/jVfJ78PZVyWgMAT18lCd23swr/lK+d9p4yr9mwVyzVD
         lS1WG/fm8HHHR5OnQr9lm9wfRPJzdYXR0Jd8DcZdGKPaRiT5NVod+RFMMeT/0+FFdVyl
         RouvwYfgkSEWPm3uMjc+qBimImhbTON9fzGl7j393hr/XjiiV6CQTM6vA5StqS8t+LKO
         OONP2skfBMVHvHwvRaxeuIMkboySVyjLbO5mXb6OrlpHCWgzb4K4lkwHFgPmAS+Vk5pF
         2SAg==
X-Forwarded-Encrypted: i=2; AJvYcCUwF+HC0YPuUyffMlrD/rqCjnA/NNqMG6v+XjYOmR2SnL5oPSy2GNFh+/k14Uz/LA3BEmWPCQ==@lfdr.de
X-Gm-Message-State: AOJu0YzYJlaIPFkJNOtApxW5z5SS70S6OtYa+BVuJqNuTxY5taq6XKG6
	2TtGaqlQR6oziMukI4mn/HOgD8wHLX1zpCD1eyiDvq5eUPHZoHSdp9Tg
X-Google-Smtp-Source: AGHT+IEA2ykmd25ztEQbQIX8bUKr4Wp/lKAC5f9AvohRp87r/fVve3g2rruGvVsZYXSTVU1Zp4sWEw==
X-Received: by 2002:a05:6214:419c:b0:6fd:4cd1:c79a with SMTP id 6a1803df08f44-704f6adc103mr131452296d6.21.1752794724208;
        Thu, 17 Jul 2025 16:25:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdz+yR2GK5Rlx0SBNrcePEjCvc1h61z6HP7TNd9KIy8Uw==
Received: by 2002:ac8:57d6:0:b0:4a5:a87e:51cf with SMTP id d75a77b69052e-4aba1a30000ls25372291cf.1.-pod-prod-07-us;
 Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5Axpgq2uvP51oFaFmTiIA6O5RZ8vR+bcQMHCHnoMgtUbYivCPPpmtcnYgm7/yZymfz027q3b0qX4=@googlegroups.com
X-Received: by 2002:a05:622a:4894:b0:4ab:67fd:e323 with SMTP id d75a77b69052e-4ab93dd739fmr100642641cf.44.1752794723243;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794723; cv=none;
        d=google.com; s=arc-20240605;
        b=GzkCFBovfS65vblInRllMfZaoH+1wnS7dq9f+USPYLIofylLqRu+1cjFaSN6xycxwT
         URU6V8m1gOT4owyB8WsWy+Yb0QLu+/5a70Epj0HilPOIoSuepEyeRf701z+cPZaWG3js
         3ZFxcoa68h3xgmL9Xo313nN5MzLKygLEIdXqAlZLD+6VJrAWjsE5lmDgXd/cemcmwbOu
         WrSpsxdcTr2kQ3RmdeL3ZstVNCE6BNt/JfU4CTnvXaIrNkbE7/gBgKAc0mxtMk74iv6l
         0cf0gmk8RAithFd5qrl/6aI9k+5XaNDV62Atvcfc6Jf9eI4DbAMN88BHHpR+8N5ovwzQ
         7O+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JaXnETxdWqbmIbvIT6H5WRFYzJ05uVw7n70J2uUzaFQ=;
        fh=2KRsr1RfR9429D69ZCh/hINX3/tl2fq5IwJsvWO12qI=;
        b=e805UW9LvefzR49ORT+aL343I6VJPJRE77537vvMEd7PCaRGHRqVd1YJpTI8JTZMsL
         oT7gMtnyzUUbcVZdpd2IaoHiXXv/VQ+pCErsleG2hCXQ41/2QuMFpabGeUbypLlv63I8
         fC6YzefWFiVaCnf3G22scfrIUWqiK/CNN2Y4ncHC0fdywPhYye7THH4STtaAMRqIuk8c
         3a0RQg2gigeGGTr/9nJ6HiRnpKAdwjge9u/ps1xuDT23ZgF/Pnkbu/Rfp28vQaQNR1Xg
         nwTvsI/IQzXAoeQfArbwUoityxBF71oO+BM9fg1v6ozaDsvDh77OMmy9XeE68ibClZfH
         P5pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TDQPJoue;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4abb499a51asi108201cf.1.2025.07.17.16.25.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6AD8D45D82;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B75F1C2BCC6;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-hardening@vger.kernel.org,
	Ingo Molnar <mingo@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
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
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 13/13] configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON
Date: Thu, 17 Jul 2025 16:25:18 -0700
Message-Id: <20250717232519.2984886-13-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=961; i=kees@kernel.org; h=from:subject; bh=qfrc6vYarbMRQKv1a7xZvSfoxfkNIKlLJL8wJGuWS5I=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbbGrLRYky9XJyFyITXiqam157PKKj7mdDyYc/Xw7s uRv7WSGjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIkc62Vk+Hwt/L3Rbm1tn84l unrT0jgulm5lD+LgcnL+WfbLeJOREcN/7/17erb+Zmw+2dikfKTxS9XuurzmRR6/80+FfF6/xlG FFQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TDQPJoue;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

To reduce stale data lifetimes, enable CONFIG_INIT_ON_FREE_DEFAULT_ON as
well. This matches the addition of CONFIG_STACKLEAK=y, which is doing
similar for stack memory.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 kernel/configs/hardening.config | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index d24c2772d04d..64caaf997fc0 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -60,6 +60,9 @@ CONFIG_LIST_HARDENED=y
 # Initialize all heap variables to zero on allocation.
 CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
 
+# Initialize all heap variables to zero on free to reduce stale data lifetime.
+CONFIG_INIT_ON_FREE_DEFAULT_ON=y
+
 # Initialize all stack variables to zero on function entry.
 CONFIG_INIT_STACK_ALL_ZERO=y
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-13-kees%40kernel.org.
