Return-Path: <kasan-dev+bncBCMIFTP47IJBB4WO6G2QMGQESALTMHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FD05951647
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:44 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-81f8489097esf794479139f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623282; cv=pass;
        d=google.com; s=arc-20160816;
        b=FC8N0wDjzkcxtQt1YrMnpAcS3Dn64HK2j9Q5dEsBixjoiv1tZ129/jef8y7lrfQU9Q
         cvqAb1w5VhBqGRRHGvSqcJWmd5TXLgM4iYshw5WbX8VyZ7dgYWOUxshk12JQVPgcnVQ1
         lwW52hsG1Li6HlthqW4cOE1ErSQTBZKRcbYkfa323/LGuNRq6Tg4WBhrJm5uTs1q/nIF
         ajvIPDZ6FmqNFi4czEcpk0MlLFj//KLkcTS+/ft/byuApc9w1kzihLhelJeSjVixdfnR
         mqbywWFWpl0eE4eOhkosisOPOXqLk+YzE+ghz4K2C7HDpCFPC8BVtJY5vnckdKfrWd4B
         e3Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=m+vtjtHXSRsFZOIhJGFFsZKEiUCI4Pc1b8CU1s5WDrc=;
        fh=uEakiMoCuzYoOBZEVdYQmQYqV42kxAHaxQRFJn3xqIE=;
        b=FCM9fubShowU35UtQ+yfbi0/m8VZIrubAgl17MciX+bp3YNOIscJbXJr0gYcOl8I+H
         D+nXA7Gs59RLUj3wNunTr0DxYuaJvTDzD+Ciz1HKIuYUXpAJNgsdS6CHTC01xy/DNSM+
         quNQozBwzbKvPjk0P/9ASEunismMSV+pTKb/hB8nSwwJjeA5WtIkq15Cqzzlli/tvb2T
         hx0qpsUkRPXKgFiEZxXrua0Hhr0JkZM76qXhZUz93UUgBf6MwYot/HhOU7yBjZW5V6p/
         6uUFkdzpHTNBc6AjKQ4gF3BHSiC5n7kvYyXE1UylR3WPD6ylE2W6FYzzuFxmdZOdSa1t
         bTwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=OcSRAdAe;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623282; x=1724228082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=m+vtjtHXSRsFZOIhJGFFsZKEiUCI4Pc1b8CU1s5WDrc=;
        b=DbS/KqchzNzoLIJjHYKFeUmeepNno7caz3cXWS/lQekw/PPVMgIE/00ut/F421QT8b
         1yGF15L9OUoXqv55gV5LtlEXIirC2rgmRg8256Rzq5KuZLLecaq/IzmYuoP3+M5UkgBU
         PHX5ZzrbgcwphM4qmY3OXhKkjp4mAeQ6aTTAbSoQiVIg9vowc+txVbsjS1WA9vD2i8Nc
         NJCJlfxmmk/vACjy4Ugx612Zzzdjj472SnfXnxfjgG1TMKOlmUwcAKaBstz0DT/Bv/qW
         8O4cvEMlvoiYWNTfQwxQOSWGJsQuReJjuFQFF1ak+IBUqoUoCFgUQk452coPdRrrS1jM
         QsZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623282; x=1724228082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m+vtjtHXSRsFZOIhJGFFsZKEiUCI4Pc1b8CU1s5WDrc=;
        b=ju6ei3ie+AEViqN+dn+jFSoDZ+9Bpbcv+dYdl/wWk0hsrZ7nI7+w0H8yxtorHf77lG
         nQ2vCBQFAGp78yEppbecMgOVVBTDMhy+R2rx3gylhCBdFW09fpdQqCVKEdzuQ7ZeNW4a
         SejtOYe/rTbvtJPEaSWHogxCdnle0BHaNuiH+5Tqn9fL00qlrSxl5W1o5OEbSZgEoZ+m
         80b54xu1RuV81XRwQTxZJX+F22NdiQD9xKswnY5GPMWVQKwg/7xp40G+9+7cMx/aQOSU
         8Ie4VjDGxQVBWZECPsQO4BCYKTFoijSLg2STUgcxa4hvfNISlUmcCL2mBoFSK+WGuSnR
         bvzQ==
X-Forwarded-Encrypted: i=2; AJvYcCUo+ZJRCH7Q1Ra93G1+w/wrQKcXtYMiX5QxtSg1B97UlQPLXeStOuI+tzdFe+6ExGVJjvmCGNNEm/gQHCFfN7e+6na94uZ3wQ==
X-Gm-Message-State: AOJu0YweUqVobw3rRLrtk1cx5YrLCpxo4KYrVvrMMydsDNaoijHRk9cu
	KIXKCC+ElKrLMLfSu0S0DCwV/La+8zJUVpzmLbtp1j4RzV20wXoQ
X-Google-Smtp-Source: AGHT+IHN2c/2USF3l2JFRjHCpmO0jFCf5aZV2XzmBv/4p1b/x46xqBvjkOY3Vfp99VCEQCcReq8L8A==
X-Received: by 2002:a05:6602:6408:b0:81f:e0a1:34cb with SMTP id ca18e2360f4ac-824dad03986mr310228239f.10.1723623282577;
        Wed, 14 Aug 2024 01:14:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2801:0:b0:39a:f5fe:27da with SMTP id e9e14a558f8ab-39b5c99446als16744995ab.2.-pod-prod-05-us;
 Wed, 14 Aug 2024 01:14:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMaMxVGt+QrXg0lTpz3pCWhnKGHBqFb0RB/ijLYebBsLtcOY7nDP3IeeMw3Q/xQnrNoKh5HJT16gTUn4dDLHnQRu7GlL2Pk3sFCA==
X-Received: by 2002:a05:6602:6c09:b0:81f:8920:e770 with SMTP id ca18e2360f4ac-824dacf956bmr260859539f.8.1723623281807;
        Wed, 14 Aug 2024 01:14:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623281; cv=none;
        d=google.com; s=arc-20160816;
        b=Fq/lKTZSvfBTWCSTpCaORNyHULY97Lnt8sqfpaM4XmYx55Xtz1a53U5Se73ssbncmD
         k4iEHdECH5d0gH46m7m644zefcLQ9siZte1HKWjrCo0p0vC3RH8pQP8mjACloYVruGYX
         n4yvMJGJo6YvIdR0t4SEWDa6N+XB0EUF6A+N0DI72Dm3L/1vDrbONzj/glEnsT5ZsNjE
         o2tMBVQcUHS7m2/h4HQWmfxryVG+kOgOlg4SHqN/ZncRToLZ9X4IRy+xi46KKVSwqsxd
         lWad4zXipAN4bHEL7x00zUs1Du3UK44nJTZNFHm5ajxCC8K43Omw9sq/li5AZaHRpLOA
         q50g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C80mIDHR/SSEQvshL+evnKrl0xyN36hJKjVYwlCZpxo=;
        fh=9TrsfqqQC2oUpGNGi/1PvStmnG03bqrQet0XxidiKxU=;
        b=A7yEQeG3eh/FY7cS6/2GRU2fKKpKCplzsNVftHVdst8tEkv7NJZro5+MnaiNYrfoC4
         lv5l62SwYO05jZsXjJN3ke5scKxlW2I8wHXpXECLZuD0cH3bXCWDeLT8N/LBxvRBmii3
         vphrr77pO7cejKd5hKCNDJ5Sao6VESOISR4eX+pPabGFd64oHjtSdg739HkHf5wOk6Sp
         AqPQdf1OOVINj7KERL5kddKvelxEicDwxUN/ENxxkyzIHGIeM/hgKkTzhoGDHukdml09
         6uHkf5zJSHsNjDmS8JWExGKU0/0DAWxToufpl5TNyrE/ncL8EnFHmeRL/426Wl74CLA1
         MCKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=OcSRAdAe;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ca769f0419si323950173.4.2024.08.14.01.14.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1ff4fa918afso37296735ad.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdWQ+2zFuD86GmpvqgAlS2bsUfhfWTkXXHVu0UDbklgyMNjpr+gEalEFcVmEMkb8BHGpsDt5/wh7Umw+RmDc+GMwTTryVPtxg1Yg==
X-Received: by 2002:a17:902:ec8a:b0:1fa:7e0:d69a with SMTP id d9443c01a7336-201d64b1542mr20521085ad.46.1723623280985;
        Wed, 14 Aug 2024 01:14:40 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:40 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Samuel Holland <samuel.holland@sifive.com>,
	Conor Dooley <conor.dooley@microchip.com>
Subject: [PATCH v3 01/10] dt-bindings: riscv: Add pointer masking ISA extensions
Date: Wed, 14 Aug 2024 01:13:28 -0700
Message-ID: <20240814081437.956855-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=OcSRAdAe;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
following the current draft of the specification, which is frozen at
version 1.0.0-rc2.

Acked-by: Conor Dooley <conor.dooley@microchip.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v3:
 - Note in the commit message that the ISA extension spec is frozen

Changes in v2:
 - Update pointer masking specification version reference

 .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
index a06dbc6b4928..a6d685791221 100644
--- a/Documentation/devicetree/bindings/riscv/extensions.yaml
+++ b/Documentation/devicetree/bindings/riscv/extensions.yaml
@@ -128,6 +128,18 @@ properties:
             changes to interrupts as frozen at commit ccbddab ("Merge pull
             request #42 from riscv/jhauser-2023-RC4") of riscv-aia.
 
+        - const: smmpm
+          description: |
+            The standard Smmpm extension for M-mode pointer masking as defined
+            at commit 654a5c4a7725 ("Update PDF and version number.") of
+            riscv-j-extension.
+
+        - const: smnpm
+          description: |
+            The standard Smnpm extension for next-mode pointer masking as defined
+            at commit 654a5c4a7725 ("Update PDF and version number.") of
+            riscv-j-extension.
+
         - const: smstateen
           description: |
             The standard Smstateen extension for controlling access to CSRs
@@ -147,6 +159,12 @@ properties:
             and mode-based filtering as ratified at commit 01d1df0 ("Add ability
             to manually trigger workflow. (#2)") of riscv-count-overflow.
 
+        - const: ssnpm
+          description: |
+            The standard Ssnpm extension for next-mode pointer masking as defined
+            at commit 654a5c4a7725 ("Update PDF and version number.") of
+            riscv-j-extension.
+
         - const: sstc
           description: |
             The standard Sstc supervisor-level extension for time compare as
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-2-samuel.holland%40sifive.com.
