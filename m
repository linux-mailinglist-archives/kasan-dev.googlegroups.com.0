Return-Path: <kasan-dev+bncBDAOJ6534YNBBYUQ4TBQMGQEURIN7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 671B2B08F35
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:27:48 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45611579300sf7110325e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:27:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762468; cv=pass;
        d=google.com; s=arc-20240605;
        b=C3gYaow6AnUOK/qJD19Zvo+3lcIuBohqMsFWtNrsDTAAVHtwfNOKQYHgt8iRxZDkU1
         Msm5of0E8X4AyqOKh0TeYe/GJ0UMNOQ6bH17nGtA5zNJKGarQuj3wFjd2Y0vMM5EUULP
         J4c/3YKb64opIvYKNX4xgFo6zxrCLqm5AhQUkXOv4TOtWIdIYPrXqsyZsG1EzKcTACOF
         wq1LQbD/L5Xbp4qC8wM+NJAO9h8MZpxQbns3zt451MBMP1a+/bQcSwMEfUj1Fa/nUYTx
         kEiEeDMVKFjZOB8g9RVe0OemcxtPrTfkERv4fejq5ZhcSBxOmUHZgtOyvQPBh6qfFB9/
         UhkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=acqNDdMMCDBIzL8R9xyjcBoCG6A0dPYco9bALPEaw8w=;
        fh=61qY86cvYXNzoaeMoEBNLaE51frSjEF6wznnkiQdjh8=;
        b=EijQjFQlJzZWCrLolD9/mzmPFzVpOz2jsHfoTMvw+d+qrryBU2hudkK8Rmj89Kqepg
         Dyc3lHCZYaaq+lIRxPow8IX3Bz5jx/chf0K/sAAdQRRKrH2EqLyOj8eXIzSJHlt04ukl
         TrVMRwu7GG0OlHPERTzoZkKs2gV4+8cEZlOmO1mmAy1aueNlON6mB457ydftuWFKuaoB
         oAHG6dSYymGvIce3MZInOGc942tL1Mm3lw4OkFR3z4n2St57tpZAlLpWf/CmLd1Oc7wy
         NHqDsTe9w2Z7a3pI3yQeN5V61tQdOkUDaGOnvelFxuapCJBwbBgwQeq6e6F9dFycp9iq
         rUHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AqvB9NVe;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762468; x=1753367268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=acqNDdMMCDBIzL8R9xyjcBoCG6A0dPYco9bALPEaw8w=;
        b=lrLVE2BO12+F2LGXfi8zVIUKyAWaaOmN+i0GxJ1SWXSMIh9KnHoCP5pHMLyhapN13n
         QCXp6OqCK+rp3HITGFextMx1ReJawg70zmK6wXWrrXf222eMRhEwNkK3CzsW4gWkrZTK
         HsmwcZbaURDarQkwGzYs80mdBeA+ZzMLxYt/ZU6xEZirpc9n2+hf1UFPsNm6qU2/cUU7
         1nOVZk32Cng0AsYuJxxPuDv3xaYO/YRtrG8bzhgiGMM1bRj/xF/oHqYbX6R55fbQJR5G
         JjjSrk61TpEXe6rdJWC461TB6AMq/YiwXQ9xPxcfze+952QNFHu4UkWVa9TVpALOvALU
         gfYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762468; x=1753367268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=acqNDdMMCDBIzL8R9xyjcBoCG6A0dPYco9bALPEaw8w=;
        b=G25XvDudRiRE0tSMlVs2K78WstRZaQb3qxA4Q+rll9FgaOffdD6cM80+ZjJYipQg4p
         /1XqR88AfpAjIzz/UDLZKZapJI7cCv8KJjF+oZky7rg4uJ7LAcB8LxIqlEqtd+kF0uqf
         DE0RKdejBGnVBm9Yo2wLS2vpo1mw5W3mBrru245ZVd4z7Trv3m0RqqUUmz8Y9fb0vK/Q
         /+bjur+d+zYwWVyYVwOAz6Wb3IA5LzJKqiwiCtQB9cb4ujAJe/qO0LDTcIfvxWvEZ0Oi
         EaQHiYjdFb5W0g6rqEtanF++BJKQUqS/3lcTSW1XqamXEC0tfm2Gt+a8TXM6iPt+lK6N
         rX6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762468; x=1753367268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=acqNDdMMCDBIzL8R9xyjcBoCG6A0dPYco9bALPEaw8w=;
        b=L8T97dWVQjCyf228As3UN5RudoRdP22rvSkq4As8bgz13FZg1euBx8/lC0CNxTHIMd
         39tJ3sYZBPd7eIWxaQcZQVRBHvVZM/jasEsfNxh4Zi64J8/Wd9fzD6r87zZ0w3w5i9cV
         C4RP3InNMrtLWU+zpM5j6eSaIe8w30Yimf+3S7j1RK4p9jxYhHlpWEOQYdHLTU6KDvxm
         Qjsz95Wi3TaMgFEF8t8rl4Y+bw1kTolHLqJ5qpLMEWe+1Bo2Sx1h40Fg7CmOgdLm34Ti
         E3Sjv8GfBSy51MEaqP9DI1+ELvkcDhE+UARpCLWCpaj0sGIVoYNnz+sTleR4dUMXvLcc
         vlLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVNzzTgrKfZm1HpE7thz34sEOMXFuOBy91Alx/X2iGCQcyqCZ3JtwRHdPuLYyeJ9LenSaTMQg==@lfdr.de
X-Gm-Message-State: AOJu0Yx8mT33Ga2sPNYdmh+EA33xU1A7FdUGB+DHYmT8/WD4J/1Yj5rT
	x6aKNLGro/lY6mDVEeLlMmxViTcsQC63IYCCF1OEiEOU/b7B1u0hmZ57
X-Google-Smtp-Source: AGHT+IFe02WraJC6qv/QhXkOKrMI9P+7Sk9xtQI5i8jaGiWt08Jxp83f3Jb0kkYpBpNl2ZGziPWTTw==
X-Received: by 2002:a05:600c:c0d2:10b0:456:1d93:4365 with SMTP id 5b1f17b1804b1-4562e32e2dbmr43559375e9.5.1752762467473;
        Thu, 17 Jul 2025 07:27:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeM6FDSmm1/euHo8gtggWPzYqd0PmU7gC/qHO0KAOjrNg==
Received: by 2002:a05:600c:4e4a:b0:456:136f:d41f with SMTP id
 5b1f17b1804b1-45637a13d6els3439045e9.1.-pod-prod-07-eu; Thu, 17 Jul 2025
 07:27:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCur8JdyK4QuhzU+P8O45SHs0zrrbqAB0a6cH37ZFtLYtzwD835bwBJJKDUxFs91DDMtIKuDZjqOs=@googlegroups.com
X-Received: by 2002:a5d:5e8a:0:b0:3a5:8a68:b823 with SMTP id ffacd0b85a97d-3b60e4c90d0mr5671473f8f.23.1752762464737;
        Thu, 17 Jul 2025 07:27:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762464; cv=none;
        d=google.com; s=arc-20240605;
        b=hLwAl8YSAsCP6MDHSVSAu56I7acHkslwQ9ZL7isg0HchG0nwOMPuBaqa0Kk7DXJzId
         uhLROUIzCpIh2CAdmnYZZ3h2E5VViMdaZe8r5r0iwMq8uUffn9ZbvZy3fMQi8W/t3Bcs
         gR5fNV3JqOHrVTtqltevj90L1mYfNqlPrqjijpH6rx47MFKuycWSnO6+WODP6W688rQV
         KkV15LYzAJ4tNAuLR82zljSxVnpMiXrDfhb1NcdutGWvT0qMcZOLtk6z2ZjgJa0hHnm3
         btlGCegXpToXemyHVZ1QLO5ltaKzZw6BJ//yJqTeY4KVuhuV8gg8hVPUpehYqB5hlzJV
         B1jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y3WcQqYlZ+nGmkIZO7BZjNBhDOM5R3Ju7Hd0Z8GcHCU=;
        fh=sUj0jLBBCrBzVm0gZkHASlxgfKJVykFky5lj4iwwkNc=;
        b=g3+yMjBTBwYwhW6wqbZPbNpiB0YaIKj8CX/vlyvjkVyh6ECQXzidcdmdHd8YcnfZmu
         ZLleBhsjsixtwcSEo2JdnYcq59HWKICWIT9eyeSYoevbVkHye1PiZkHpTUYOJ2l+WfLD
         6lw8Xw7OF4wLc+1zwVkfvTcAWeNA3wYHbZJ2yHegBstAI/FBgxAXrPQzqtBU/yUlQLt/
         UMTLna1v8hjkjEXxZDqGkMZVul6FxHJzNTKKnaHuz0FZZ6xsC0aH4kWXrcVaaOTmIzbI
         0z6veD3JYqPWCYm6ix4Xt/le2WmOvGt/g9raFNk5fRwogOzSZhhaBLGs7obMH1pwA/tj
         HxFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AqvB9NVe;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4562e570043si1377495e9.0.2025.07.17.07.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:27:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-55a2604ebc1so1000120e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:27:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/chiNgP4VLagG3VzV4ixSGiCuIhO4gViABkplrlXM7Vgz1Yfh6KSjneROqyapqTpxZGfs1c60dO4=@googlegroups.com
X-Gm-Gg: ASbGncsok/xd2mnBhL0oPcZClsxcrKwpeGhUluPbYRr+ML16zUqPH8Ccmvm3U/Jy35t
	CHZZv1I7xzX12W07683RgdECNDCimzloM5jWN6BtZlN87bJ6WlIQXWKKkTAn6belZ/nxpq59sBa
	o5/abEATzbpa90S5ZtckWy0DnvtZKu5KWW18jbdrdK3JgXhbZmvmnHbN9/5S5Roq7yRB4rFFKZ4
	T2T4TCiJMUFEj7sff30MP2cSXDVfQLUl63QJmG73dtqbwKcpLDenduhUPn5+V/rJuIrHqGpWBN/
	J5xH/iJ/tBSw6TH2HxUq/gdOpJlU0f/EpDJsjC/2iJw5PPsTaEuV0esSRAehXd68LQWwDWhykcE
	V7oa6tJrUPX+61rn786h4yrJ9CMkXd8A5JAWYZs8mjRE0OZWdi1zn62ZfbCEouTEIAXhH
X-Received: by 2002:a05:6512:15a9:b0:553:2421:f5e3 with SMTP id 2adb3069b0e04-55a23f1f963mr2211249e87.19.1752762463801;
        Thu, 17 Jul 2025 07:27:43 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:42 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 01/12] lib/kasan: introduce CONFIG_ARCH_DEFER_KASAN option
Date: Thu, 17 Jul 2025 19:27:21 +0500
Message-Id: <20250717142732.292822-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AqvB9NVe;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
to defer KASAN initialization until shadow memory is properly set up.

Some architectures (like PowerPC with radix MMU) need to set up their
shadow memory mappings before KASAN can be safely enabled, while others
(like s390, x86, arm) can enable KASAN much earlier or even from the
beginning.

This option allows us to:
1. Use static keys only where needed (avoiding overhead)
2. Use compile-time constants for arch that don't need runtime checks
3. Maintain optimal performance for both scenarios

Architectures that need deferred KASAN should select this option.
Architectures that can enable KASAN early will get compile-time
optimizations instead of runtime checks.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v3:
- Introduced CONFIG_ARCH_DEFER_KASAN to control static key usage
---
 lib/Kconfig.kasan | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830f..38456560c85 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -19,6 +19,14 @@ config ARCH_DISABLE_KASAN_INLINE
 	  Disables both inline and stack instrumentation. Selected by
 	  architectures that do not support these instrumentation types.
 
+config ARCH_DEFER_KASAN
+	bool
+	help
+	  Architectures should select this if they need to defer KASAN
+	  initialization until shadow memory is properly set up. This
+	  enables runtime control via static keys. Otherwise, KASAN uses
+	  compile-time constants for better performance.
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-2-snovitoll%40gmail.com.
