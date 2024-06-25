Return-Path: <kasan-dev+bncBCMIFTP47IJBBE7E5SZQMGQEZA2NN4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B0219172F1
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:41 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f9cb7b4fdasf1890615ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349779; cv=pass;
        d=google.com; s=arc-20160816;
        b=UMWc2WqZ8bXdTWKWgF5nZw+hdBUPjNmk4AXXKkRu5Z2DS+ml/66A5YBrzxmrXqZ7yN
         x9GV9BHcxRnqMb5yfpg5RR1gaFiN6cELc1fUtHcEvOOz3J54SESlwqRclmFmmfDqeUuu
         Q478j2jdVmvSyfm2YC1QdXvvSttkMB4nPF9nV+d3jrY9bWgr6Ggm1rAn3UfhG0yjxL+9
         JkIY1fKCz6VqKdbTpQ26f/oKzgNLnbXcTlUalMjgWtAQ/EjOS/wBCqrO/TMDzjdHf/Tn
         EIOwlSP+8oJVYlogI4HtBLzOmrTjmiSBiJ0ub4HHrDnYIDQ1i1CnkdmGaFlwywQt2ybu
         55LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Hn7qkBfCVDSJ3eqGTTQFeqS5FWujI7jWgCPhmKe9UhU=;
        fh=Ll24tsYgd8dD76Ekq4AI1WL8ttFjuo5qe2i/rWRAo6Y=;
        b=ZjgzHuXLTg3iuQc+zedavptRwN15ZgAERSnjOQ0eAwcm9L1d2gVOXk7bJWZRT/C7u4
         UapR+PQr4UI+fnxf6nym/ptBxG9IN3nE76f2szodDMA2qDCtaWBUAzT77RY2bIwkQPC+
         zyco+nIFd/tP/JFDqCCmKgso5qBBU+8KLLkmi4BFJ/UJDcKqMTT0r+og7mgfGvbZSOWf
         vaY8E26mx4ZJE514GYv8rx7AyVADKzlza9yzJ5hA7sHW7ys/6DH8Trkb38JM6UVaNhUX
         DvaKerhRcaQSOYMx89sEUojzkE+YUd0WjAkVKsj3X4O1ezeS/otv1rEEGWPf+xwTwK38
         9/8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gFx7aAE1;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349779; x=1719954579; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Hn7qkBfCVDSJ3eqGTTQFeqS5FWujI7jWgCPhmKe9UhU=;
        b=df0Hz47eiiQljozjj2+wWDXDM0xqXbIWOuUmlr9SYwLpDatkj8gslgfO27yWVVYjms
         QcpQ9tskue7Gy+K7U1NSSkpIaNitoqQIYTVniJvvsITAQMGWJ7N9K5L5s5q3LCrN0xEU
         nLFglJQ/8WT9eIFmPNOQeZAgJF9oG7dYYItNB82cTkn9WQFZbxkB/9zzSvW4eGLGrgsc
         FAmIaM3lVOffabe5+K3grgXJJIF240M8g8x81IyHOcuDuEWEOKAFWiEkWm4UfN8o0eVS
         czbC1xNTve4U2B5TwEUHCI233mlzFAK6SCsv8BSgy7FeLlTOJOc13NxGibmHbmM8fjBI
         1zXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349779; x=1719954579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hn7qkBfCVDSJ3eqGTTQFeqS5FWujI7jWgCPhmKe9UhU=;
        b=JnSzLPmlO0N7u+a0sszNVdDw8KFhwc1kbs53sEOe/6Qw1kK5v5mn0zStTSrO8rGpJ9
         LmkeYHSFHC6JArtz47cEYDx68Vrxe9rNG9FmmR6RUpo7XyCiCb1VXvBs32P3A5qyiwev
         kTd0NkUxrZ6ycMNTlq3iFeAgIxo4iXzuMTyz9ffxRkinlstURXrSe7ThyvkW2LjwgHfs
         PH+PWVsweCH4X3wjqPuQoay55fteT6lpNsWGVL+IdxBpqCnN3JsR959daJlNWoiQlqjZ
         JB3dQUv6oQ7gnJhdpKqqBbildngLmlOLhg8PyiPq694nGFBI4n51l6CiCoXF8+j5wkuf
         LKvg==
X-Forwarded-Encrypted: i=2; AJvYcCXANNR4bBfM3Qzio7+QyYT0vIlyyGXM1OPL83P3nn6guYcHhQHOJDZJvY1cYt1Y4Tfxj/VyfqRSRwV5zLSMaCnb4Cvm8OcOSw==
X-Gm-Message-State: AOJu0YznvUZ2PgUphMgagZcyQuHqgQ138mCE153EA+y/AnYckGO6+cl/
	2k9IKVllSLWWZGKkbHBnXaXAKIUZ6wCQ/8X+GZHZrd8rnU0coIzW
X-Google-Smtp-Source: AGHT+IF51MxBwBIqHwXfkb0RwtMJZ4HcdVsgQUhedDzcWQW5TnTp7PPHiKEzYoUVWIDoxrkPD06GIQ==
X-Received: by 2002:a17:903:32d0:b0:1f6:d81e:cf3 with SMTP id d9443c01a7336-1fa0d70d342mr113961225ad.1.1719349779477;
        Tue, 25 Jun 2024 14:09:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:1a9:bef5 with SMTP id
 d9443c01a7336-1f9c50c0e3els43715825ad.1.-pod-prod-09-us; Tue, 25 Jun 2024
 14:09:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUYNLtNSWloP/3kohmXdbfpLkg/Kgj2D4H1CXFMggtD/RgSxpJBSmc8Sha+RTh3kgb7LrlY/rMMGJTq6Xo4O9C3Hkk9N/wNXKbpQ==
X-Received: by 2002:a17:902:c40e:b0:1f9:db1e:ef9d with SMTP id d9443c01a7336-1fa23f1d540mr93222405ad.49.1719349777858;
        Tue, 25 Jun 2024 14:09:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349777; cv=none;
        d=google.com; s=arc-20160816;
        b=pd/agUEMU+isuKMzPlSwEkev17anI68KYPPT6+k0HM3iXUr0KdLo7BIgBJpBycE7Zg
         WSkYH7To6i/evBkzvwY3YOkGnP5H3te0Khmrn00FGuRWLah14EVnYeB6cFCkq3Oo6WXQ
         dwypOl1hmRBabmdEu7k6IpQAMtulfLtiU87JRaS6mS9HoQMHb1gTzZwASV+ih5q4bVvM
         3K+l+Dv08+fqzWR8n0lB2igCjMo+kJRVTTkQsrUcvXRiI6kesGTJYdUEaYRLCZMenUA9
         U7GX43cWMZFvYNxJ5Dbh8lQW1U9p1xX7OXd5TFjFxgpBvMaVAW97ez1R8rqwxlJ/+52g
         znMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RApDUBWnH8dOo11vUms6fSIyGurtiCmTLAn99yajCOk=;
        fh=WWVEVietnUlQ5Jo0MXG5tKUB4hVN4AYYb7rYwmiI3JU=;
        b=zXi75FPfEkwAZiZScP5v5Lw0dkGOvXILRFEXb2wLeuwipvWUP6SEIMgLvIplnkcsde
         UQLTqg/5j5RPXfEz/711QbCUecx49CGoJDNyc9ptB9xq5rCh4iMOI4bYVSboZS8CF+iQ
         yUIJrMvDNW5k1AfVyei1o4w/9AFnbApIbbuDmSRwjdtIobQV7DnymtwZDEO1gn6Besdy
         6BORfS7/16zbsvSUcICNBWiZ0/UWUmRqPfuaxZym3PM4bOye299PcPt2u2JbhSue8V2e
         egg13tx+leeRSW+TLV7p+wZkDKNLehIj8cR6BlYjLS9A5zyMQVyiojyu8AfF9PlSREtA
         zG2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gFx7aAE1;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fa2a1b1e23si2288025ad.4.2024.06.25.14.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-1f9b52ef481so48999035ad.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWsRXpsFmaMcimXHyiykZoGN3tqsH3ofymeBVYvp8/DIHWU6Sr7BlLHLVBjahXVygWX3uazpkPPAFFEUxSY6gjpaL52V3HqLYNM0A==
X-Received: by 2002:a17:903:230e:b0:1f9:c3a1:4b65 with SMTP id d9443c01a7336-1fa23f1d44bmr113141665ad.47.1719349777431;
        Tue, 25 Jun 2024 14:09:37 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:37 -0700 (PDT)
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
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 01/10] dt-bindings: riscv: Add pointer masking ISA extensions
Date: Tue, 25 Jun 2024 14:09:12 -0700
Message-ID: <20240625210933.1620802-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=gFx7aAE1;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
Smmpm, Smnpm, and Ssnpm. Document the behavior of these extensions as
following the current draft of the specification, which is 1.0.0-rc2.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Update pointer masking specification version reference

 .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
index cfed80ad5540..b6aeedc53676 100644
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
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-2-samuel.holland%40sifive.com.
