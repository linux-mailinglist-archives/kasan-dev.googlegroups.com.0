Return-Path: <kasan-dev+bncBCMIFTP47IJBBOEV5CXQMGQEHW4RCSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 253B18806FB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:22 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5a486a8e1fdsf4031106eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885561; cv=pass;
        d=google.com; s=arc-20160816;
        b=PCxQN1N++1nXCbnkhJTc4FgJYH0lYJAdn3UXod6vC6mvRVemTeusXX8sT610VbUzMk
         GFKUeMkncZ1/oehs9QajpntzpgQKWW++9gNS8kQx/uTCfk8o/NjQF4U+HHu46rpaiJo9
         bdTAHyvqdYoPhA/I6W60Pl/j6j71J7rvvyzcvWo2HGDyvZTi/SJU0oWKwJCSq1j95dFx
         Sy1kDL+Xn6krFjYRVXHJ60bZAnqIjCsc1F+3QTZZ8lo1Ry3006ZEabjEH0CzjUakH0c/
         2QImVoVgyBMOfkkwox1MG4GhIoJ8/HZbbmt2uY2u+xY4YeZ6h6sKucEe1kRG2l3IIV6m
         0RTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=N8zRKN78VP40ZuSNxDp/6HaDJs5D5SKmuLQ6IIARSko=;
        fh=Ptx7DP4WQGY1DhhrL1aHgSgWjA/zR0lGNiEuu7ovCqo=;
        b=cueu7Ybh4l9ga7W8l9Ql6Prvi/KDkLKlhhqJ41hlj8TbEtJjJYgR4fb0Wz4kjHh7br
         832jIE3jnAri3UJuDMo3AfjgKeTWWp8wrlJqaIT0HYulrzmjgITWzosKAdoFJBqJyztb
         HmbvNzUqEIlwoMBTbP6mTx23ZQNyvvHKbo+GzZG3EnGtyytq8170Po4Xarjd0C1Z+p0H
         58CYtS4C1KE4d+sHgN8PHol42OPPNSk/JCmVYHqQZmUHR8nX8bS+Cn4pat3a6sQN8Mw3
         qO7B+G5qdiW7eRa+KonAK8dYQx8ypKcLfEKyAyVnW0eoWuXLXGhzSmkeFq+mNxhIW7q/
         6qvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Wo20mv29;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885561; x=1711490361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=N8zRKN78VP40ZuSNxDp/6HaDJs5D5SKmuLQ6IIARSko=;
        b=twzCqlzk5M30SceHftouj31kfx0aD2mtBz9KDgtoaV7x30xkFbogrC9gI33V1/9yQy
         SnqbVMebPLqeivQ3QyN3yLycs0Zb+KAByh4bfStbETRGcq+1SOiIH18wnxZSzL7CvhK4
         DfGuO9a1yPGRxV6DtBgKf88j39GCYwTf8fFHVAvrHFnQyDNJURYuGHtgYfZFQfznVqMA
         u95PhDY1GWeyk2LMz5LYR9sG98DD1bCm+W0HqdkD7LxZyOR3pPU9j5h94dFLWPDMBRSR
         efrGkNrs8jTH+HgIbwB01/9viBMnTgs3OIwCiQZWH4rl7buvvYfwYsGy/rCv+eFj77cZ
         Vpmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885561; x=1711490361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N8zRKN78VP40ZuSNxDp/6HaDJs5D5SKmuLQ6IIARSko=;
        b=VjixkzqoVgHHHdPaxIWMkMsGaozom5ycTkKa5BArZK8UF0MlHenmrfgVy+rgqrBqqK
         YqDhlCA6WZrW7+M5Faf27gzerGrEVel39wnsldpFD4+Y9NyNv72L4mxDEX3wm+CKFyqa
         PYALBDuMPbl2r8q+te/fQ+8BW7cstuEDmQxNzOP8SIcQZhebVsINEcTN9nTmzCF+3Vt2
         DHkVVJM1MVqBEi/5gGc4xJ9lYC2ZCEiJRIPkTVCIwZcSYcM8fwEzCXMCVqGqRj85FO2d
         pxdAGcfftEZlv6zMKxuPQEUtsu9XcTkchVp9yMVzO48/F85neHWXdcl31SGky2L03604
         6tfw==
X-Forwarded-Encrypted: i=2; AJvYcCV/7NqvLgMNcZGV6V0QoMZ4SEUOSa0Dsfa7+S5E8OKYLlajby+A99mZc+2VKeejSsVZ7KGH35b701dCyPFPnFwl9KOF5JpAMw==
X-Gm-Message-State: AOJu0Yw7WNPRkRNyUhUIanYzSXr/j/nu0OW8VSzp9cXKuaGhk30dTwDz
	p8WUB4M7q2V1KgjiuaBf1fJ5tf15JoF+UyfKh/v4wSoqXNH9xSgv
X-Google-Smtp-Source: AGHT+IExtgQOY3YLeE6vnNPLc/43tg8IW7I0FEUhI/anUbKMPpHE1mwVB8gBnyGHJmNBIxinGdliFg==
X-Received: by 2002:a05:6820:80c:b0:5a1:d84c:cf79 with SMTP id bg12-20020a056820080c00b005a1d84ccf79mr15578632oob.3.1710885560777;
        Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:6c1:0:b0:598:c95b:c3bc with SMTP id 184-20020a4a06c1000000b00598c95bc3bcls2094184ooj.0.-pod-prod-05-us;
 Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnE7V5PzHTgjazBymIYr9TFZEc/7K/UmfwHggu+ptca0Ckozi7Dmtw7O4wDKeoqYUKa46ljhMvJgs5wZHlmz5NhNoxAej3DUn2KQ==
X-Received: by 2002:a05:6830:164e:b0:6e5:22d6:5197 with SMTP id h14-20020a056830164e00b006e522d65197mr16627030otr.23.1710885560000;
        Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885559; cv=none;
        d=google.com; s=arc-20160816;
        b=Sg+qWIbOj4e9ttAGRQviu5CJrGQnTfcsILU+DVSpxH5TJ3Qd6Kkm5tYpwIjtwHhdeE
         xvTmJFZX73etazAODQgH95H8A5jGV/XkK34X/EBQIVLZhlyTQNIGQO8bysF7gz98VF5c
         TjgO6HGkfQQLx+eWkTOUWmd+n69X3TRL9q1OmYZvqoEq9NQ4pnbZP5UAL2o8yaD3SF73
         Pm+H2l0FsgBUvyn684VIfe5fdu5MiqWYv1AZVvnkldWjXk58AQv81eHarxKCJ0xZkmaU
         Li6j97tUXf2sabwPs0izO+J+fgvwWXozYwJikoG5uJxD0dT+p7NXQ9FjHOMPb4330KxK
         7XCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=egqW9CgCHR/h+XnNBIYYSLcc7kf3PBZY4lOdjowA6vA=;
        fh=uaoHmuhC/1KAKqwcjfEe0EoMMKZLGQG/dHpF/1NDiig=;
        b=f3xCnZJyUJghZ9xKZL5MLd9eR/8B/rV59sIpfhoM0euUhvMAadgaYlKPwhvIAUI8we
         rz3ePWr/IM79VWbmOC6ARZBJveW4jq/+d52NRbrDfmRQ9wDxttW5oWlnTA+OMXDZIy2T
         yOg/TW0x2Wvgdv+n9D0T13ZtPNAGsQ32BNe08IDNHUssGxT9OMQHDi81gwmR2QltXnTK
         bnxeDhtBonu4UFazridTgzYlvBUtklLqwVa7YWxOrGsTQDLVt9t6R8b8KC+d2sUB7gGZ
         49xHHGXfidI8zKjuj2RzVciotc6zMWOOZMjKFiAfl3ZlU2Al8fWyxfubAB2MlrxybAYM
         YaJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Wo20mv29;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id l2-20020a9d6a82000000b006e6a1f0ac32si149202otq.1.2024.03.19.14.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-5e4613f2b56so4648797a12.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXck8/EIxvi/5cf+5hCiHJEkZwWBrRhk5+cEl13Kuc061yLIT5hpGYSVmDxRRr8YYzx3S8kAgeE46zazVD3wcXOvMutNeCAbyEQtw==
X-Received: by 2002:a05:6a20:9f8f:b0:1a3:60cb:8172 with SMTP id mm15-20020a056a209f8f00b001a360cb8172mr9089470pzb.39.1710885559375;
        Tue, 19 Mar 2024 14:59:19 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:19 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrew Jones <ajones@ventanamicro.com>
Subject: [RFC PATCH 2/9] riscv: Add ISA extension parsing for pointer masking
Date: Tue, 19 Mar 2024 14:58:28 -0700
Message-ID: <20240319215915.832127-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Wo20mv29;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

The RISC-V Pointer Masking specification defines three extensions:
Smmpm, Smnpm, and Ssnpm. Add support for parsing each of them.

Smmpm implies the existence of the mseccfg CSR. As it is the only user
of this CSR so far, there is no need for an Xlinuxmseccfg extension.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/include/asm/hwcap.h | 5 +++++
 arch/riscv/kernel/cpufeature.c | 3 +++
 2 files changed, 8 insertions(+)

diff --git a/arch/riscv/include/asm/hwcap.h b/arch/riscv/include/asm/hwcap.h
index 1f2d2599c655..1a21dfc47f08 100644
--- a/arch/riscv/include/asm/hwcap.h
+++ b/arch/riscv/include/asm/hwcap.h
@@ -80,6 +80,9 @@
 #define RISCV_ISA_EXT_ZFA		71
 #define RISCV_ISA_EXT_ZTSO		72
 #define RISCV_ISA_EXT_ZACAS		73
+#define RISCV_ISA_EXT_SMMPM		74
+#define RISCV_ISA_EXT_SMNPM		75
+#define RISCV_ISA_EXT_SSNPM		76
 
 #define RISCV_ISA_EXT_XLINUXENVCFG	127
 
@@ -88,8 +91,10 @@
 
 #ifdef CONFIG_RISCV_M_MODE
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SMAIA
+#define RISCV_ISA_EXT_SxNPM		RISCV_ISA_EXT_SMNPM
 #else
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SSAIA
+#define RISCV_ISA_EXT_SxNPM		RISCV_ISA_EXT_SSNPM
 #endif
 
 #endif /* _ASM_RISCV_HWCAP_H */
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index 79a5a35fab96..d1846aab1f78 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -311,9 +311,12 @@ const struct riscv_isa_ext_data riscv_isa_ext[] = {
 	__RISCV_ISA_EXT_BUNDLE(zvksg, riscv_zvksg_bundled_exts),
 	__RISCV_ISA_EXT_DATA(zvkt, RISCV_ISA_EXT_ZVKT),
 	__RISCV_ISA_EXT_DATA(smaia, RISCV_ISA_EXT_SMAIA),
+	__RISCV_ISA_EXT_DATA(smmpm, RISCV_ISA_EXT_SMMPM),
+	__RISCV_ISA_EXT_SUPERSET(smnpm, RISCV_ISA_EXT_SMNPM, riscv_xlinuxenvcfg_exts),
 	__RISCV_ISA_EXT_DATA(smstateen, RISCV_ISA_EXT_SMSTATEEN),
 	__RISCV_ISA_EXT_DATA(ssaia, RISCV_ISA_EXT_SSAIA),
 	__RISCV_ISA_EXT_DATA(sscofpmf, RISCV_ISA_EXT_SSCOFPMF),
+	__RISCV_ISA_EXT_SUPERSET(ssnpm, RISCV_ISA_EXT_SSNPM, riscv_xlinuxenvcfg_exts),
 	__RISCV_ISA_EXT_DATA(sstc, RISCV_ISA_EXT_SSTC),
 	__RISCV_ISA_EXT_DATA(svinval, RISCV_ISA_EXT_SVINVAL),
 	__RISCV_ISA_EXT_DATA(svnapot, RISCV_ISA_EXT_SVNAPOT),
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-3-samuel.holland%40sifive.com.
