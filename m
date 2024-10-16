Return-Path: <kasan-dev+bncBCMIFTP47IJBBZGDYC4AMGQEWFY4FJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 19B279A13C2
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:22 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6cbd3754f4fsf2695236d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110501; cv=pass;
        d=google.com; s=arc-20240605;
        b=bw2KyD98X8tTvRb/sIKI/n0UiV/ej9Au9S2U4UOnYfEbOz/O+HhX0ZsneXPLGgog+z
         83BPIZeqMMEsww5PSwJZwIvjoDySwj6qYBI7pF9VGxbGVFahxCcAnDWibSqDF9C53k/O
         TQB6CXR5xOwI354YubAyB0Pn+tvgYNci1IolWVWG1V0ZySvyRXqAfb4c77n+2GYYq8um
         q0XjPQgQ1I547A8AMxFXreFv58LI/pxnvU/QYl1Zy5Lm5fmDFqX61WxQI7TFrDnVL4nu
         OKsIjFoz7DumQqkYhllBSr3o4wJx9hgxwuSufiEsaD/EbvL9gG6eDD2fDSyXEiXgRCWw
         QqGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MwBgDWCVdgn2+7WDwNo2BO8dhvqpOJn+0666UM0oGaQ=;
        fh=Ryk9jppgwL1Pznsln8HK53mAKF6pAGtsMoqdzsrj85s=;
        b=KDkEcM4vbZxhOKjfsvkp/BzTF8WNcxQxTm6HO0nHriij7vDzK3FEXDfRtGIF8vTTMO
         j5m2vSgTowUJYmVh9tpWxbHU3bvsCQ1BQLil18zjjCXJdHj1iwCv4Px6GTMpMTft8sDq
         R6mwWr3oTqhjez9nb7rrstJIwQQrrWRAXncqIrwMT0UaoIqX6yizszdE/TgU3csVor7X
         xC6naVH4dSbQGXJyU9NXR/+cYmI/1xhWjo/5OtTWsSAqra5zDMSncFgsbY2uDCc9aOGU
         q+aL4tRna5HUS8eKzPH6CdqFJAiJggfEL++wDAMtGhTiBC8wbomEfbFRTjd0KW6wlR/K
         S12A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="DgSj/+B4";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110501; x=1729715301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MwBgDWCVdgn2+7WDwNo2BO8dhvqpOJn+0666UM0oGaQ=;
        b=ZKkHqYu9+coXgfngvvAhg8PaC+if5Q+6TYnzOyfIwTnudsaVVPAdNzjzSv8KSDUTC8
         pVqLMOM0IfVQnS7fU7Vsv12sovOPmUq7JYgBqgUV8rm4dH50fK3nRFVuvxsN+Vzmgo7L
         bCLNB8hkad829JOuqyPxr7cuAmEbqaUH4YexrWxfXM6+QUFChC73Iy5c9AoJaHMyVdBt
         XGLlK9FtSnD/x+OrGiBOgjY8bD67JhB1GPN8t/VeV9E/ldgOZXuB3HmjeV03Kp2mm1Qp
         mLgyZm9lQ3KgIkoIj8XrsBDXmV3nuVV9UHfevF1GYiKxaZXCC+SxWpUcwcrQeE3CBmmx
         D0WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110501; x=1729715301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MwBgDWCVdgn2+7WDwNo2BO8dhvqpOJn+0666UM0oGaQ=;
        b=MexEBDmtj0KvELIm9pAgXsuIOseIZt5jEj+6aOUkjo7IXBwkcW8WCro/Rp3yYlJFyQ
         CkQXuc0f1BcPXufbkZ6/+l1laqcnfQP57xYOtBivXfgVaTJMBPN3eVGUwPJFthozQWnB
         nQ3TcsaSaoJ3/I6jZ7ghZu1JPkdOZhCKtts48E9P4M3KugljjcATt5rhe74QTG6FMgOI
         zxpq9ade8ciasX1y3Ehb60TEoSdNFyOtL29I1zB383Te7ICntj8ALynDVu1SHRXOC0oB
         hLIjqq0dMekL2nuwkxMHBUeT9jVH4aEpcGW2FqSsyaaUK1viz+pZ3aDUeQXN1vQM8mMi
         +QNA==
X-Forwarded-Encrypted: i=2; AJvYcCWiSTqVYv9Ap4cpRhMzYqL1Ya0eW8y98M9bB61yXXXq2/hhpgXWMD+tdVgYe45+wOCtq5GuTw==@lfdr.de
X-Gm-Message-State: AOJu0YwEOTlG3ND3PsewTiGHJU5rO+qteODufUmkMy3oewoNXkDk+Ch+
	7KotyhX+KEN8OugedjcJfDldGDrJCTtnYMmqfWvettFFKycvjj2N
X-Google-Smtp-Source: AGHT+IEUvYElTTNyS4hpCI/Q1ZM+CW1rDtFHm9l4L+RYMzzN+7TMzJSa2kf8OpPkMwzyFTcXUHy2gg==
X-Received: by 2002:a05:6214:2f10:b0:6c3:5496:3e06 with SMTP id 6a1803df08f44-6cbefffdfe6mr318190816d6.10.1729110500884;
        Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:260d:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6cc3738029els4503446d6.2.-pod-prod-03-us; Wed, 16 Oct 2024
 13:28:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnNldrCYVK59+t67FvHMECJt52A53OM24nPuaH1QQNRhQ7iG/JVYDNAMvsaYnHNHbzSafsp3E58qE=@googlegroups.com
X-Received: by 2002:a05:6122:32ca:b0:50d:4285:1409 with SMTP id 71dfb90a1353d-50d428515e1mr12446196e0c.6.1729110500112;
        Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110500; cv=none;
        d=google.com; s=arc-20240605;
        b=j94xC5FCg8cOruh7yyppReS034Z/unsKCVl+998rCkJQGOl1iicA68XKrZYj/+FjR8
         Ubdxq1ronvYpy4omJ+A2ihvCQkWD4uXUl9Hi4Dyd29pCzMsQmj+i55NLn9HsSoPHoH58
         MXEqGBLmMDCYOXyI6Ys/f2gcxG9vEOCzBybnV76ve/Np4w8k+2uk7KUBsaWKSTkC864w
         2onTN3vsc7sNZO1M2M6q9q5zBpt9Wi2J1USh/Vwpymm0OnXFeZbl9MFgGoD6hDraZ0oJ
         u1MELFAoygGCjvY1C2hrdliV1UL94fOpE3Yae8nvZQxfdnxumUAouPGtSyCHXUZAFy0/
         ZUjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=olAKLc1ubtUo3zWjyBg9w1ODcp643i2ah+QLaW6GItw=;
        fh=+cAqfqYLKl2kygGGyIsFCwY+SMxlXc/fvjqi4pi9yLg=;
        b=fRiDXGTrGC243mRMqqhyvjhZZg6SZ1SO0IDOsCSijlGyle0pVk6w7QcfeerMiuNfc7
         h7NYT/qJP+w+Xj76ZRIs+g/kl4PpF+10PMLA8kFuZZkjnKO/fvYofDY8AajB5azAHGJe
         85Gy6Mvr2qH2ifmHYc/auectatB71fIGeHqQ02LaphPRRquhodnxzshjIxrqt77vjX7b
         3FzPjB5VttCFvgpfGOHIc2+ju1rRRmCh29fuBduv3Hd2RPB+ZbAGPJ0rOCyXN1hLN0iy
         /NA22XURUYGROod9K/lWrzklH7Dq32vjprX8eIiUPYJffGJB8zMGGqyYhCS6gfx6Ybsb
         xHRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="DgSj/+B4";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-50d7b3193c2si200083e0c.5.2024.10.16.13.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-20cb7088cbcso1769545ad.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/UHzqXh7W4z78dm2OXgRlQ1rKky4VnuxXHVdyB3+cS3oqlVb99lgpb3EvTXuu5+ua12cgFhGWvLI=@googlegroups.com
X-Received: by 2002:a17:903:1108:b0:20c:ea0a:9665 with SMTP id d9443c01a7336-20cea0a98aemr161412995ad.32.1729110499094;
        Wed, 16 Oct 2024 13:28:19 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:18 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Atish Patra <atishp@atishpatra.org>,
	linux-kselftest@vger.kernel.org,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Shuah Khan <shuah@kernel.org>,
	devicetree@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	kvm-riscv@lists.infradead.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	Evgenii Stepanov <eugenis@google.com>,
	Charlie Jenkins <charlie@rivosinc.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Conor Dooley <conor.dooley@microchip.com>
Subject: [PATCH v5 01/10] dt-bindings: riscv: Add pointer masking ISA extensions
Date: Wed, 16 Oct 2024 13:27:42 -0700
Message-ID: <20241016202814.4061541-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="DgSj/+B4";       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
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
Smmpm, Smnpm, and Ssnpm. Document the behavior of these extensions as
following the ratified version 1.0 of the specification.

Acked-by: Conor Dooley <conor.dooley@microchip.com>
Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v5:
 - Update pointer masking spec version to 1.0 and state to ratified

Changes in v3:
 - Note in the commit message that the ISA extension spec is frozen

Changes in v2:
 - Update pointer masking specification version reference

 .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
index 2cf2026cff57..28bf1daa1d27 100644
--- a/Documentation/devicetree/bindings/riscv/extensions.yaml
+++ b/Documentation/devicetree/bindings/riscv/extensions.yaml
@@ -128,6 +128,18 @@ properties:
             changes to interrupts as frozen at commit ccbddab ("Merge pull
             request #42 from riscv/jhauser-2023-RC4") of riscv-aia.
 
+        - const: smmpm
+          description: |
+            The standard Smmpm extension for M-mode pointer masking as
+            ratified at commit d70011dde6c2 ("Update to ratified state")
+            of riscv-j-extension.
+
+        - const: smnpm
+          description: |
+            The standard Smnpm extension for next-mode pointer masking as
+            ratified at commit d70011dde6c2 ("Update to ratified state")
+            of riscv-j-extension.
+
         - const: smstateen
           description: |
             The standard Smstateen extension for controlling access to CSRs
@@ -147,6 +159,12 @@ properties:
             and mode-based filtering as ratified at commit 01d1df0 ("Add ability
             to manually trigger workflow. (#2)") of riscv-count-overflow.
 
+        - const: ssnpm
+          description: |
+            The standard Ssnpm extension for next-mode pointer masking as
+            ratified at commit d70011dde6c2 ("Update to ratified state")
+            of riscv-j-extension.
+
         - const: sstc
           description: |
             The standard Sstc supervisor-level extension for time compare as
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-2-samuel.holland%40sifive.com.
