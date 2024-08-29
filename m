Return-Path: <kasan-dev+bncBCMIFTP47IJBBEERX63AMGQE2KXVDTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id DA18D963736
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:09 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-270333dbeaesf129834fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893328; cv=pass;
        d=google.com; s=arc-20240605;
        b=WKhJgzFbcS6y2o6QF8mcSXBs73hIsO2NWz6aQpY82aPhh6ZewHb+vv428OEniahG8j
         zZJthYT3l4C+9T10Ndh8NQU+T+O+rs3eKe5EJnYsErRYGY82iLN0zZLlF7rj2XUtT8zF
         UTAHBoaXp2Shjjt8PCrDs29Fwr+kNMn3Zk1nZKAo7+ULMVXB9XhS02HPYSv7iNwOpRRo
         9lBlEPEbAhkf+A8Rh3zuheP1oERSDVfZGGvDwOxVpEVwAuwPTFU68Pqug/8iHCgYupnP
         MjMnJg+eCKs2tkRMy9LeazFK1HLBVEa7VbAgaSCFLDS4PXl/EcMwr/w0mOautyKdKvg0
         FEew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=swsuwFiP7gUNvzS525HUmk9Lfubp9NjKKQaub/esknM=;
        fh=/fKh1brNyLoAjCvr+gSBDHOqMKvHxs2UujdBMStQaRY=;
        b=UUlUwoglhwRADt1nhUK8cIB6HQge14zJgdjLy8f2i6oIpdf1qCP2V7FELjH7D/nkpH
         C5m0z+t9WND7HrnuXgcOcQzsxxLtOHXrnTIIBVvbmLXdPe5vgbW5oJnl8IWBEhTpDHNb
         NNeqBUYtTni+ToVoIDqSlkWhFcx11M3V/4ZHlrnLFSHlqG+VRLZSrbJLH37dJx0YYwWX
         /FINOiZt2MTHJm6p7hIuZWdHxhODOsbq6OB16KSGN9EjX7D4uslh0gDJMvWFXJfyv1rc
         XIzH4lDP7TSOcDzSE/OLuc3hm+k7g3ug0BeC6lw2b9p96WmVPscLDReQaa15i5+UF4QP
         4ISA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=JPtulRBA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893328; x=1725498128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=swsuwFiP7gUNvzS525HUmk9Lfubp9NjKKQaub/esknM=;
        b=ds/xTPFosOHxalHuOVVTD5zdx8RLBk5SxlNay/hNZYcwY4VHbM8c0AACqQwIYbr0yk
         QUDhu1QohYB6TSMVb8hgsIrBye0PbgUOCv6I5l/1tHgnCle3+Zp9o+wuGRg8qM5X8kNA
         1pLRJ/IVyiv4lDZysidGmdvC/cGxJaWWyfaJ3WYDttOlD++fzM5yXJmC7vcHGzrZlVE/
         fAxp3PQACVw8KA9lw8mESqMvK+SOSvOqA1lGygzlnlGgJT1pIP4t2s27e4RkNLFm5F7t
         OGNJ6pGu6SFOfbuoNGRn1mz+smdBohUohr4j+0UKXVRcSGhShBR3jc2cw625WvWxAt/4
         Q9vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893328; x=1725498128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=swsuwFiP7gUNvzS525HUmk9Lfubp9NjKKQaub/esknM=;
        b=Sx9PHtMyOEMlr9XB7ftin7LqIxk4G1vvqTXSCaHz7gSM0R45wduQCYrTBLrCMYteKU
         t50XBAL7hN7VqWkNFKVLwnJySwOm209gdBOLjcieUFnUCr6Jl7PEhePLwwrHrt0kYjnW
         KImOHruCpGsoMftt3WG2UY8oggISAqg7eKOxGMT1FEmp1rZ9NKk1dmceC0HMs7Ib2gCR
         tg75yDIAxu+DCiySabazOgaW7hIwuGJ5O3cqFqAKh44E2uRB1YzmaS+ZposYXugwfzTK
         +t9yjpHb4D69pwrd39+NJIkk3mgAveH4TqTA+1yvDB4+54aM5Qr10SICp7j4MBe0Xy/b
         nBOg==
X-Forwarded-Encrypted: i=2; AJvYcCUZ+JldSDbv3IgRewQdr0bLuIrEe5D/ywk50xUIqRyHnZ78QjKYqUjtopFkXeJ7J24V2cR+jQ==@lfdr.de
X-Gm-Message-State: AOJu0YzxGbYsEVsu4Jphafq2gru3VducYfR/HvrZEbXF0qU+TqU3VsFN
	iWRjDJhWSq812YlphxyPIKKKcnj5gtr5y6QRCr4Sqs+IDZJ3zljP
X-Google-Smtp-Source: AGHT+IGb+Fk98OKQKxnH5vUEJk+Whm5VDi/2jDCoyQM57MG/DCtpRli4NAducKu+zRWM1nMGO/JzRg==
X-Received: by 2002:a05:6870:2184:b0:258:5143:a21a with SMTP id 586e51a60fabf-277900ea349mr1624473fac.13.1724893328702;
        Wed, 28 Aug 2024 18:02:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ff91:b0:24f:f4eb:3558 with SMTP id
 586e51a60fabf-2778f5468d2ls584299fac.2.-pod-prod-01-us; Wed, 28 Aug 2024
 18:02:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrJicI3J+/+9Dg0rFAON8r/ahfuFazxcMNFpG4yZYbEuiXDj8e50Paa2FL5A5fbz8LgBi9UOTUvzo=@googlegroups.com
X-Received: by 2002:a05:6871:e28b:b0:254:c7f6:3294 with SMTP id 586e51a60fabf-27790367c68mr1280358fac.47.1724893327766;
        Wed, 28 Aug 2024 18:02:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893327; cv=none;
        d=google.com; s=arc-20160816;
        b=co0VgpSxMBfHKNqHugW/Wf4r0KSAzJb73Rj5a/Hgwbf9kVs7Uvo4v1kuf0cHrtRVQK
         6Ku6laDzEt6XFC66xxMXgM2eJNY8/cfMS7oBHawlrwBfO+UjxSnL4Lqwy/2UBUcRxVf5
         zSdemDwu5Fm+Rg2/SiyfOuOIBCAOnZx5W3Yf7PjsZBfw/Pe/jMOX+hoRXKzPwqROd+2E
         +WMIBlxex47AVvIGwQxwoKqwVHxzJUPuArRi1W4YvszLz2L0R+FohW/AgLmp3ZuDd8si
         nZ+KMDu97OeAlrSJM72XVr8uY5ZiywFzaQR8CHIAYR4F2AQpmJYvBWs8FB7c4xZlfHah
         HqZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fidSIArz80o0wKmWpcFbdk3lLWLuSUf3Uv0hxlg4FbY=;
        fh=ASnE7Y6QVwYZdgsm7gTbIxYupdNbZ69W+T2lfYD4WE0=;
        b=xONqWrdE/N3kNxgiw50Z+E36GfOyWusEubeytVmx0XRYmSjZkU0CrD+lYXLjClAErk
         L0e/oewRGQQl0vkNMIyNtoFcFGscqXrJdPH6qD46tSjSLVx5no5SLtwW1egaFYaPV4h6
         oE3TlPwbSTXCwaqV1jfgxgQ0tKb4OLEY9G9tDFVQ75Ag7rmdgXiok/GOhb5xYRfmLxe0
         s66JpRtjL42BNBCc13qkTYlMSuhFnYK1M8zrQaYlbemKETlZGiizKxfGpdV2lJugGwas
         v+oJROjHv0LY9cX6c8cvOvfVc3NfwEzQpO96W6qdi8h+MyF/tFK9nIfvLydz8SQeKcY8
         ml9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=JPtulRBA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-70f60b20bc7si3593a34.0.2024.08.28.18.02.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-7141b04e7b5so66738b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV3oHKZ8zLXQIPduIZrCRfhV7JOJJLnQYQ5j415kJu+2y1+li68aE11RNaUE5SAPhEp2tq4XvUejxA=@googlegroups.com
X-Received: by 2002:a05:6a00:198d:b0:714:21f0:c799 with SMTP id d2e1a72fcca58-715dfb26b96mr1439189b3a.12.1724893327118;
        Wed, 28 Aug 2024 18:02:07 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.02.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:02:06 -0700 (PDT)
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
Subject: [PATCH v4 08/10] riscv: hwprobe: Export the Supm ISA extension
Date: Wed, 28 Aug 2024 18:01:30 -0700
Message-ID: <20240829010151.2813377-9-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=JPtulRBA;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Supm is a virtual ISA extension defined in the RISC-V Pointer Masking
specification, which indicates that pointer masking is available in
U-mode. It can be provided by either Smnpm or Ssnpm, depending on which
mode the kernel runs in. Userspace should not care about this
distinction, so export Supm instead of either underlying extension.

Hide the extension if the kernel was compiled without support for the
pointer masking prctl() interface.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v2)

Changes in v2:
 - New patch for v2

 Documentation/arch/riscv/hwprobe.rst  | 3 +++
 arch/riscv/include/uapi/asm/hwprobe.h | 1 +
 arch/riscv/kernel/sys_hwprobe.c       | 3 +++
 3 files changed, 7 insertions(+)

diff --git a/Documentation/arch/riscv/hwprobe.rst b/Documentation/arch/riscv/hwprobe.rst
index 3db60a0911df..a6d725b9d138 100644
--- a/Documentation/arch/riscv/hwprobe.rst
+++ b/Documentation/arch/riscv/hwprobe.rst
@@ -239,6 +239,9 @@ The following keys are defined:
        ratified in commit 98918c844281 ("Merge pull request #1217 from
        riscv/zawrs") of riscv-isa-manual.
 
+  * :c:macro:`RISCV_HWPROBE_EXT_SUPM`: The Supm extension is supported as
+       defined in version 1.0.0-rc2 of the RISC-V Pointer Masking manual.
+
 * :c:macro:`RISCV_HWPROBE_KEY_CPUPERF_0`: A bitmask that contains performance
   information about the selected set of processors.
 
diff --git a/arch/riscv/include/uapi/asm/hwprobe.h b/arch/riscv/include/uapi/asm/hwprobe.h
index b706c8e47b02..6fdaefa62e14 100644
--- a/arch/riscv/include/uapi/asm/hwprobe.h
+++ b/arch/riscv/include/uapi/asm/hwprobe.h
@@ -72,6 +72,7 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_EXT_ZCF		(1ULL << 46)
 #define		RISCV_HWPROBE_EXT_ZCMOP		(1ULL << 47)
 #define		RISCV_HWPROBE_EXT_ZAWRS		(1ULL << 48)
+#define		RISCV_HWPROBE_EXT_SUPM		(1ULL << 49)
 #define RISCV_HWPROBE_KEY_CPUPERF_0	5
 #define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1 << 0)
diff --git a/arch/riscv/kernel/sys_hwprobe.c b/arch/riscv/kernel/sys_hwprobe.c
index 8d1b5c35d2a7..b6497dc0e7f1 100644
--- a/arch/riscv/kernel/sys_hwprobe.c
+++ b/arch/riscv/kernel/sys_hwprobe.c
@@ -150,6 +150,9 @@ static void hwprobe_isa_ext0(struct riscv_hwprobe *pair,
 			EXT_KEY(ZFH);
 			EXT_KEY(ZFHMIN);
 		}
+
+		if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
+			EXT_KEY(SUPM);
 #undef EXT_KEY
 	}
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-9-samuel.holland%40sifive.com.
