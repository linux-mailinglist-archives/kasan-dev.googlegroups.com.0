Return-Path: <kasan-dev+bncBCMIFTP47IJBBBURX63AMGQE3E4TLFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EC6496372D
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:00 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-201f45e20b1sf1164415ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893319; cv=pass;
        d=google.com; s=arc-20240605;
        b=LoQOqtFVj2tsIH++zX/i0w/JPYt090e4kvzCDxQXrJUDznh8KiZwaJVHf5rDyFWI2A
         DKuaszkEBfRtKMtk8PTu8xm07Rixs/C3pdEg61wO+FIxWLK2prnefv1fQ3QwXD6keItZ
         r2NrpGdVcmqdzbKha+6erax7Xuygxx/sM/Q9hZaDObAI6DtLtf2893/Jt1zBSCun1ZPG
         nuxr+wznUP3VFFizuEOjwMkwgo5RcekdPRAGpPOe+YqJypiqRt9d4qopNz3pVPX2muel
         1Y/Mbo1BLSIAoifB3Jr+QVMy9L+dfB1rFlLc13X1prkGtWIQAgOmQllFIWWksn23tbnk
         1+Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ur9Cm+nlV8nvl11sV/wEcMh8pkOxTkcZGpTZyk78vtg=;
        fh=vKjUGZZZrsuKZFpsGLpwehKWkAuPcxC+BIReUBw4p/Q=;
        b=XYntaDNWJXBhIqsHkQuKvDpwpAiMHotmo+BukU/FnTiP/rwFvCB+Mkr8UP27JLB7DU
         tW4b1DdwWA+wf1/5eVrP/otgW/goO618voJ5ME24XAEUYk82K9RxAhBoM1qYrnFxe3aT
         JlD4KBigJ70j+GUPEoDj2W+dIoCnmVOfQ2WZRhvagha2HdLhOAKxIv/LcVROo8enlQVO
         uggtOQsUsxzMIEk7xE7XaxcMUe8GhyFMdB2ZYNBiTQEFoOhHWtLmKarKUEBzaDrssCVo
         /Wef5nlI7fLtFYXIwKebzOI2oVsCv5r1QEaxQ15xEJmxArt4n6tCBjbjCVirFRnFdM0x
         ROSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=EDPE8W7v;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893319; x=1725498119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ur9Cm+nlV8nvl11sV/wEcMh8pkOxTkcZGpTZyk78vtg=;
        b=UoJ+FwDs0L4WFUPjX7TRILK85aqqW+cV8qlXyMo69Bd3PAPENdGP9e3m4Hwtd/2sGb
         bdXEa/TDKqBACDCkTQctYePBrujdE7uJBmzRvnXla3fFbsuzm7yDP2jvqVPZtlxjMcDa
         qnAMzgrJi2w3fUqB++86hEFQQlK6lfspuctlEURs836yPcVRDfsdvsSFEqUvocw+nx2B
         bBKj99n07CG55xBOFcuRTQ1jjJS8spDbwuccnr58pmpnTajM6hXZN/RRYhQdTJf48iuS
         IbUxgYJTQCwrV8s/YNiPpmX70o0WrhmqVyWtt3Y4auRTSR7DrM0KE76mlza1WzhjbrEr
         yEfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893319; x=1725498119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ur9Cm+nlV8nvl11sV/wEcMh8pkOxTkcZGpTZyk78vtg=;
        b=fvP5MO2UH1faoS9/ZlIyb+9DJXQWNIYU6YJDZCoyuxeQGl0YPqkuJpLDJNKLTmcBcl
         IoGo9bPL/w13pIdb5qQAF9CCfs9CYZ/tcJWcz+Eh5UilvQhAb/cd7d79HvtkWjr+eMdb
         XTK2EWDlCRU1/WAtGDb7L9WqJZDq+rEzBL41Lf9RSZwTw0csq4RJw/m6A3xdWSy8sv86
         Fpfk3Qy9+jmuh0ItbZdJ6EbYcX3nwrmC4UIXWKjUJ7XCTzNq6mO3RpnTFurSB2f3EuYN
         dd2P38qhkoJOEUUm/9MS81gq19YUYkYcMxCsO03Ogx5fGSQIAadFrA7XvkGRt+lyIfex
         yVcA==
X-Forwarded-Encrypted: i=2; AJvYcCUxi6NfI3hMLOwXHcT+I1LkYk2QWp1cYRKNDZbrV3bbUbc7wuyDR/U+ItnVIOjfyZdkIgZRLw==@lfdr.de
X-Gm-Message-State: AOJu0YxBVB36SsGYOG62JduzPi5LhHZa9SBiO0E0MX5czWZUzhW47bxV
	uHVgHIn3dGBR9Y7xC5U4+BaA8+JL01fWhW2rkyl+Y+SSz949yNS7
X-Google-Smtp-Source: AGHT+IH/l63tVg+fAr7pXKcXo7/aV7yqrAFnxs5PdQtHCYprJ2YFX4EI3eWLFsPQ4jXQ8qCAIbJeZw==
X-Received: by 2002:a17:902:f693:b0:201:fcc1:492a with SMTP id d9443c01a7336-2050c3469eemr14148675ad.18.1724893318735;
        Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80f:b0:1f2:eff5:fd69 with SMTP id
 d9443c01a7336-2050ad5f371ls3664895ad.0.-pod-prod-08-us; Wed, 28 Aug 2024
 18:01:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOv5BPJ7p+XzYeE9hJ9svH5S5aKj7kcF40o9RrQB0NkojQOIvz+N782DyUirYXOp4ToFPwrsVTcIs=@googlegroups.com
X-Received: by 2002:a17:903:2a8f:b0:202:435b:211a with SMTP id d9443c01a7336-2050c235d56mr15464865ad.12.1724893316971;
        Wed, 28 Aug 2024 18:01:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893316; cv=none;
        d=google.com; s=arc-20160816;
        b=U7v7l69aqKF2uY75bvHaXaF6BJ+KJ5Da691b8Yc+TEi7N6p9bJB/crWLfGRnDcoznO
         OPrPF2w1jgUj134GbFOYKRgPdhsyzI7yvqwlkGHOvFYAu15MDL13C4MO7X1KqZr+VtTk
         Xeh7+yAvec6q6cZqxPF3XjSFJpZk6veBhQKm12Mjr9gyAPj5WtMls/fO59SuvII+6X3H
         h3QevZs3FNcTpmuY8oX2X6Tfna8ShnZUQuMJfwOMcTCUwsLXZ46987wK164wCj0IVdm0
         5TbFeXvhOgFCG8kamE2rBcFRcx9xlnBk/9TaDm50xzghkUx/DvLrnGkhf/jFRwfXG0q9
         rrhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gHFcN3ChX0djp1RepjgsjW/fBWZ8xhYPoH7rbGZfY6g=;
        fh=he0QWrstyAGTTAEae63oP6HYwFNIXObHjs4OKo4tdU4=;
        b=JEzVl9pcklgKrdvZBA6vwFqHvrEooCTH9gAx8gHgPU7cy3Vo3/f+sVH8M7EArrEQW0
         uspDfqqS4pAzM2ZjY4cl2p1R0ZD+4jHpQJHmVwFEM1IG/OteqdFK3eByMaGpWmAwoNUU
         SqScql9v02NZYgdI56Ed3R+6lXXWlMbZhiwfOZeqMVFLaJnSiuIMf5iuWO8JFd+usCBH
         ac2ygySbFhRlfqK5VOBEvLoEls7eXO54oXYoBu/CTChsda+UQ4JjHNoA25l/shgx9q4E
         pK6U73KYHGfH5358eX22USnz6r0GW1F8V1cG1HPU/Qd2gl9XjdK1SMLtA1EEZ8Ejv0+x
         3XHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=EDPE8W7v;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2051553e048si63405ad.13.2024.08.28.18.01.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:01:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-714114be925so100264b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:01:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWEHlFXQgj19yaeosaVdLSy09B2XfVYW8xoW85ORTTTzoZmiTV4Aw9SGYzntlMMW2ur+Qspqocn/TI=@googlegroups.com
X-Received: by 2002:a05:6a20:d8b:b0:1c6:b45a:df51 with SMTP id adf61e73a8af0-1cce1022303mr974109637.30.1724893315562;
        Wed, 28 Aug 2024 18:01:55 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.01.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:01:55 -0700 (PDT)
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
Subject: [PATCH v4 01/10] dt-bindings: riscv: Add pointer masking ISA extensions
Date: Wed, 28 Aug 2024 18:01:23 -0700
Message-ID: <20240829010151.2813377-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=EDPE8W7v;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

(no changes since v3)

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-2-samuel.holland%40sifive.com.
