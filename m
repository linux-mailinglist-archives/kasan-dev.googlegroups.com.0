Return-Path: <kasan-dev+bncBCMIFTP47IJBBN4V5CXQMGQEMDQGMJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id AC16C8806FA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:21 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6e356790f94sf4120639b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885560; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRJARW1WlI5Cmgn8d4kb3Ewe6bAa4dkJLs3gMGlZVxrkv5tTjRGPfzTIBL2gmVuXSz
         lYSULcliq/cea36Ysh88nLExmwShvCIMEjB6+bmzeWOuTHgRydZk3BZvxn8iXw2ikCMt
         GIEAeRGPv+IFDI+aU1U3ZBBAdxj9yjrf60QbgBhie0AY8w+Q5EvZVxXNIuoKMdgDsI26
         o0Pp6TIv/gjyTlU4ugwPL+Rl/kiNt5jwR5kPAkUxzsucit6/j72qSxI0ImDFSYbxvV0q
         x5iu6rITk4XQ3GOBVhPPbG5xANsIx/FBxl0BJVGnQFFVcI5VbX26K1LZn4yPbUPrtZRc
         +eUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZZR3YvWQ6l91h67ic2a8G5jg/it915+rarr2yyM/SEs=;
        fh=vdSpaG9w2R5CCDlajSICW7Gmq1Kp20W4V+ISp3OIPYE=;
        b=J58JQgli/cC/F/aCJyS6N48jGoq8KSF1/ThoPz0DpOHrq8WdvfJ0osgGFuzpOgxzug
         WbaOId29zTh7j+OWrm32/49/KC/FH+rrU7lLSA+9vx7iGhN1fZm8TJBHrrWZ7EZW7hI/
         sXKFFfUNqZonYQG8W9Jf/h8ONNz7HPBzPe9CgSZeCVSkh8z2qf+aFBXduLMe2lQi+7MR
         6XFN3AFsNo8RWfU7Xi94Jx2fCbloF4nQeyJz99osv2MYzEAUnvg2WkgMAgjuJeSkswcM
         43PfXNp7nlFE8oe7eSIJCmVmZ1KgGLDcJeyeYWe7rXPhf/8YodvnRmUhlbxcm3BYHJhU
         l6uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=hzO1ahTH;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885560; x=1711490360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZZR3YvWQ6l91h67ic2a8G5jg/it915+rarr2yyM/SEs=;
        b=vf9azFTHGaduCXO0BwfOQQzb9u+tZ91dF8KKmTR1hKGWcFjdloNK5GRJ+6hZ48yrFO
         j+7BJ55thuU9acdaNunKHAeQRrWHW89iXk/389Ga2aYtdD9OKAwPxMoRBipJKKceL9E4
         MbvGwWd1cClvi899JkiBs0AWrjSapoG2PVRVNY3+xVgdD4u1ooAl0U+bcmONwbq6LF+q
         ubuc9pXSioZOr/0OPzeFYzMBGqis2WM1LkVt0sd5n7adCz18n0Ey+omxMvtw033B5a0Y
         Azx7/HJAyAhLtJQbmjY26yAl1c3IZserfor5usoSKUK6dyorZEnJpDk9wmrq1SwcUY5v
         GXmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885560; x=1711490360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZZR3YvWQ6l91h67ic2a8G5jg/it915+rarr2yyM/SEs=;
        b=PgVVtajND+fIGaFK+24dvMFESlxcwBmw2dqKsFtuODCWFZ0D35OduHjQaQtOY4k+Ya
         YvLH0t9rDFlxK/CiSinvVWaI0+mdY0bSW+Gu+wSC8uPSaV5oLO5nLI0hw50skqOWruoz
         ZqtYwxgk3Exe7yw5dIabfMTti0sapCXdtb+/qahGNX1U3MEjhvYkep6CJLsPEdyrmBTZ
         t+QaQYVQu7S/uiLmYZz/3d1QKtfoTUpf5/813aAk1tpUeyxMnBpUzeL65D7PiUIjbPtL
         /QRE3U9bcLX90scr5tdG1RZ6yPq2wp+vdRdISmxLN9mvnFNBxftSARpJtdbIG/LpcpyS
         SA/g==
X-Forwarded-Encrypted: i=2; AJvYcCUVa+WIW8srlDZDopmzB0GOxMVkI/vDE9VZdTm6RqJmC5vkvqWXnjXCSCf57+Ng0HiWqX0mVkBOP7evIEdEZils6T8NrV9Tnw==
X-Gm-Message-State: AOJu0YytwJ9bZC945hUaEOZYTg1vAO+S4qpbOaZN9Mv7KHqL5nwxzIxX
	Y+i63ax9as8YS7WqftyCsm+LMXVWCZv5MB+oU8NPljj5slRK0x18
X-Google-Smtp-Source: AGHT+IExWmCrHdgnHarPF0i4ax/J3y7udbb7SYhCVJV9s+r3d2EHGmoh1ccphbjfsIDnAO/3J+Fe4w==
X-Received: by 2002:a05:6a20:914a:b0:1a3:6954:77d2 with SMTP id x10-20020a056a20914a00b001a3695477d2mr423056pzc.31.1710885559674;
        Tue, 19 Mar 2024 14:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1610:b0:29c:5a19:1c32 with SMTP id
 n16-20020a17090a161000b0029c5a191c32ls3871276pja.1.-pod-prod-06-us; Tue, 19
 Mar 2024 14:59:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTo8UKj9YuYn9Zw1WajnMTNFxoQ2gMrRb2LfdpocWSipnQaci5FDAUQZdF7otdosjs6MveMl2RngrjLuTEjCdVWseRiNGUxzk2rA==
X-Received: by 2002:a17:902:ed4c:b0:1db:7181:c5ba with SMTP id y12-20020a170902ed4c00b001db7181c5bamr431963plb.62.1710885558577;
        Tue, 19 Mar 2024 14:59:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885558; cv=none;
        d=google.com; s=arc-20160816;
        b=zTMQ1VqXFtS+ZeIPPy5sFWjTRKw5m3FCw7T3Gt0oYBLtXkquxKpcgmEJZzsP8PDBJG
         LS0tISJkAHytMxqj+hCs3qYkk1A/A/3XY2SnHMlmQS3JHHgqIl7Cpk8meg1fq3RVZH84
         3ByP6TfumPImaWowMoeEXqQpXGVo6b12alUwlJvY1NV5h0xV2WWvF0Zg9ayacn+XVboW
         j/wteqitwjqVf4phYamHFIEb1nt9B7RLyt4dJvkPkf5Kim01lkvjC+c7ZA+CXpn4fWhL
         Mb1MnRRD8X01grWNpUZJN/+tCYv1nJYhQYyKvXLC8dg2Qa3UTSL5fICHMAyIpprsntnN
         6fDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mf8TbChjgkUHpdp7I/ykwc/bJc9eIQRGH4wGpVTxw4U=;
        fh=R7yw5W9B3WvyDYIPJT1JJ4vaR13ZHcv23NhKx05i2y8=;
        b=VG4+cqUsxAtGK8Jhvp4uvT9JNGMUcATsUts3jr9CjR64Njo4I8hhPPwvfJZWP34k7f
         UZmdu8qKqJ5weWjkZ0Zgzh9nAn5p6tOG41s66f0fr/f/jSo3aVpMdm3/xW0R4MN1LTQG
         pzsI0dcJVOko5wrTPD7TV2LxV8wxnh2ANW+q/pakGkY7VVHqNx8fFuqEbNfFpF/RcuY3
         Cnxx/+x6g5RYUQzlNxcrKATXVUcRwjTL3SGdNSk7GR47JGwyBeOjXPFyjQlmukiQGxC0
         soJFkUNkoA6MVS61yIkElYe3lEzRP+Kg1dBqb8tHdAPAeCWmmVosJRTC4KQID4plZf8m
         IeAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=hzO1ahTH;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id e9-20020a170902f10900b001dddaace148si997567plb.7.2024.03.19.14.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-6e6bee809b8so5628189b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWz4Sf86fmv9zxmDARk0o16gKjea9Gtr36cb8jLIbZyOuyoPXynCExYMJ+BfPo2s+YSS54El9qdDLvXKxPRb8jL0e9hb+wR5+NA/g==
X-Received: by 2002:a05:6a00:cd5:b0:6e6:9ac4:d501 with SMTP id b21-20020a056a000cd500b006e69ac4d501mr443835pfv.25.1710885558184;
        Tue, 19 Mar 2024 14:59:18 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:17 -0700 (PDT)
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
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: [RFC PATCH 1/9] dt-bindings: riscv: Add pointer masking ISA extensions
Date: Tue, 19 Mar 2024 14:58:27 -0700
Message-ID: <20240319215915.832127-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=hzO1ahTH;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
Smmpm, Smnpm, and Ssnpm. Document the behavior as of the current draft
of the specification, which is version 0.8.4.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
index 63d81dc895e5..bb7d5d84f31f 100644
--- a/Documentation/devicetree/bindings/riscv/extensions.yaml
+++ b/Documentation/devicetree/bindings/riscv/extensions.yaml
@@ -128,6 +128,18 @@ properties:
             changes to interrupts as frozen at commit ccbddab ("Merge pull
             request #42 from riscv/jhauser-2023-RC4") of riscv-aia.
 
+        - const: smmpm
+          description: |
+            The standard Smmpm extension for M-mode pointer masking as defined
+            at commit a1e68469c60 ("Minor correction to pointer masking spec.")
+            of riscv-j-extension.
+
+        - const: smnpm
+          description: |
+            The standard Smnpm extension for next-mode pointer masking as defined
+            at commit a1e68469c60 ("Minor correction to pointer masking spec.")
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
+            The standard Ssnpm extension for next-mode pointer masking as defined
+            at commit a1e68469c60 ("Minor correction to pointer masking spec.")
+            of riscv-j-extension.
+
         - const: sstc
           description: |
             The standard Sstc supervisor-level extension for time compare as
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-2-samuel.holland%40sifive.com.
