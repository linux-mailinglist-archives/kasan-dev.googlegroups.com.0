Return-Path: <kasan-dev+bncBCMIFTP47IJBBZWDYC4AMGQES2ETPZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 83AD49A13C3
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:23 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6cbeca2b235sf3440646d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110502; cv=pass;
        d=google.com; s=arc-20240605;
        b=LL1RhNwrmnaXOgzVCUy3xwiygGKuL50+bmmZtJUrnaIsDlplKpRgr0J5KVVRhxa/If
         Nw5jKReJD+DWF0ypvTZ1GryVpi5pZZfBVXqUSsgPwZWWX6a2rxcnLH9oav1guyq7a+Hv
         LxCiCI75sDBEjhVOCkDWFSz7Mz23RdR7frM5a3vMYHw1NJrT65ViKPN+MhJfPxt8cvs5
         5oDe8TJBNyF+CBdw1JGhzW2WU0v04lAzjoJPeuUlHO/9J3u+rJFD2k2oVqkHPBVm7CuC
         j6v+SBbJXfdRFmgK3Sw+KrjdjxL0nI95194c7jsZRD0tvef9okPSzK9Q65iQJHSWmVxR
         Squg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UQwa892mpGgzk+UwKd9gg+gvNArZVvGstrZL5J0gcIY=;
        fh=WHy35dPjo49FdAAUAweEhXSi1orHflpIqf/h/vYL6tw=;
        b=IVFtHH35JW1lmApozwRcGk4vvhWgAJF1yP6Arm72A9T8QICTt0oDAgkPubOtw/FjM+
         acl/R7kl/zM+pA7piXCFIQJAPEzEn7DtRdaYl9+njtq0dzY/m4NwnEm+Y2bqU1JAMW15
         4rze0LfAfqNWPrem0OxevGgyhP9hPS8ND0bVR/tkbq/7LbfQvUXTvqkVhsLYV3Hc6a86
         dKrXVdorR5JAi+++hGFXqVwbFiBGO9HBJRKI897ZE5K81u6RM8a3Rbhmqy+NDgjzj+wX
         8vTAWY6Vt2fzg2hv+Po20OVEOT9RuuTNzGr3bnFtPJaHm+w6zIJvSHe/h98hXt8lv5eY
         Ea+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=GDuL4kKm;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110502; x=1729715302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UQwa892mpGgzk+UwKd9gg+gvNArZVvGstrZL5J0gcIY=;
        b=BUXKTwc4rLsjbP937whiBcZ4cY8dI4uVO7BY5NmkLRXDcEngnf7k6dJIkqBOfCKcOv
         bhYI7uCUeLCdP0XduqFYFRpA0z/mAgoKsooN2y1bK/9Nb28fmNS6JzPgdbS1byxYmvZh
         LWxL9VqnRRnFRX7L8dlFBJoDriigt/PcYoezyGxPERwIDgg6GEUrN7GmfUh+v6rF8bAM
         4opF38qnrwzOTc7zZohTRUCDGLwLXtI+BABFLrFA0FRcA/uHcYVg+SHb32RT/qet8Eqm
         BLbdlqvIdgE9T9qGwMXAEg7Ms6hmDqtyWd4kjzSHXvEyjp2++DCI2WBGwv+uYjwbVQt1
         BcSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110502; x=1729715302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UQwa892mpGgzk+UwKd9gg+gvNArZVvGstrZL5J0gcIY=;
        b=uVr2uccX4er2Qx0FttiyPF+11djvfkfTMRJgNlEkvPzuQwjQiWBX+FnYoZacULNhXl
         tZO0VmFKnw20NwWUaq/gD6Vkwxx7Xr4asoP14g55QXJZeIZAuV5yT6hAC82+iujp+urp
         os/FlVDYVj/SMpskR7hDOiZPi73pa0xdj0IjeozRxndKJ273LSIHg8iXPn0mAxzabICp
         akujo00ZciQDu+fYsjr0FPP24NYinOF8GNZPupJCWfh9LOemqmd4NTMZnZ+Da8lUSVHE
         bdoF/h/sOdqVoDH+bzWoheR7z+rIMoKUiQnCxIT0Fr8Cn1C0hqHac8ce1ZLoJiq9CHum
         tvDg==
X-Forwarded-Encrypted: i=2; AJvYcCUJAO3BINHXIDJ16+qhsnXvb10iFxqu4ahUVVpnfkL/8GSFPw4UjiOPhUDzdMnlw+lPdfWkhw==@lfdr.de
X-Gm-Message-State: AOJu0Yz4vaHx2Jr7vJduhH/RZgxm+COOsL+ma3lN7l+8bGoa9ulW5WYq
	IfAvaPxdlYTf+FffEmbhW86eD/BnOiKACotiYi4Jy6TvstzbNA6Q
X-Google-Smtp-Source: AGHT+IGRFYhmF26qvYN+f476Txi/HgVQq31aICqGTrZerD6efXOOXdQVNLB3/1nVctpMKtcclaqDRA==
X-Received: by 2002:a05:6214:5505:b0:6cc:2ba7:7f7b with SMTP id 6a1803df08f44-6cc2ba78074mr85472476d6.28.1729110502435;
        Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1bcb:b0:6b7:8ba3:a39a with SMTP id
 6a1803df08f44-6cc371beee3ls4585306d6.1.-pod-prod-04-us; Wed, 16 Oct 2024
 13:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXrq8IOn0rfR0Uld9iK6NE+l5tviDM+KkJNhVW4NaXcBXKAXeyyRS2qfslUrbEzQTlsAdaOzRKBaX8=@googlegroups.com
X-Received: by 2002:a05:6214:4386:b0:6cc:232a:ea0c with SMTP id 6a1803df08f44-6cc232aeb69mr97567066d6.44.1729110501825;
        Wed, 16 Oct 2024 13:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110501; cv=none;
        d=google.com; s=arc-20240605;
        b=S22Oz8TzKgxZjeqb6OO5sWvwuRaAvXZuDSucv3Xs0JXb9GIMRI0830sOScjcSk2NR8
         82iuWg7VlfduHff/RT2g83tMlADQs0g7/1wjFrUQ3FzZGHGsL1T2jOLIbjlZ6fHcWehF
         bDmmvPqfArJC3qFyZmCW3J+svz9dM33nWsNXwyjhK2avs/C4TYy84BiwWjmBEOmtIzVH
         +qoBueZ2sTK1iQ4wtwhfoz+CiX2bIZzCZ9o3Mv+Qrmjr6z4SWDEWh2svtwZpGnW+8C1m
         /ErV263au1JAnOdQzfwBONNNzXJgxIKfztA7n7CuL20TbIcs5BLdXR84SQyHBea/oj74
         RWww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6UwuohaBpRoU5PwojE5+Gkdri+a8AExwGUOzfsduKVM=;
        fh=hmp/R4prv47+NqYDyjCpg5Tgp0jhlyBScpT0iptZZqo=;
        b=i/yiMZfJQGJLhNo/t0nkBVR53Sy2/pP1s8jBos8FuUPMr08Xvm78Rd9M+BqH2rkwBn
         Up+meB7OtlR+PeeubZJMo6FWXTZMLqkwYEdOYMt2L2p2s2jSS/961msG02IHSAdSnTet
         BxommTVS/MUF1xGCBiteC8SJF3o1j8ZOZDW/c960xZnjBQBm9dshvXqfEgs0SL3+oF1x
         FOaD1kjSXmKNhzGqKpo2RuAfc9YUzWTDF2pdnXg9YfZ/NagaQknK0P/65IJMULZms5VW
         PKC3LUVV9UC1Gw8ySrXtxUHhOTXvApndg/dGMuIhKkfeXIUnL0uRYitUQq2MgoX3VI+9
         NLbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=GDuL4kKm;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cc229fc8b4si1702776d6.6.2024.10.16.13.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2e2dc61bc41so164729a91.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVVcKNFOesqz2e5fqlBCrge3iBekd0Bn72gr6mXLnWtLrsNy76VaOvThGLcMXXMuNyiLw/v2m2PyDA=@googlegroups.com
X-Received: by 2002:a17:90b:802:b0:2e1:ce7b:6069 with SMTP id 98e67ed59e1d1-2e31538f1camr20096245a91.33.1729110500826;
        Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:20 -0700 (PDT)
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
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v5 02/10] riscv: Add ISA extension parsing for pointer masking
Date: Wed, 16 Oct 2024 13:27:43 -0700
Message-ID: <20241016202814.4061541-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=GDuL4kKm;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
Smmpm, Smnpm, and Ssnpm. Add support for parsing each of them. The
specific extension which provides pointer masking support to userspace
(Supm) depends on the kernel's privilege mode, so provide a macro to
abstract this selection.

Smmpm implies the existence of the mseccfg CSR. As it is the only user
of this CSR so far, there is no need for an Xlinuxmseccfg extension.

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v3)

Changes in v3:
 - Rebase on riscv/for-next (ISA extension list conflicts)
 - Remove RISCV_ISA_EXT_SxPM, which was not used anywhere

Changes in v2:
 - Provide macros for the extension affecting the kernel and userspace

 arch/riscv/include/asm/hwcap.h | 5 +++++
 arch/riscv/kernel/cpufeature.c | 3 +++
 2 files changed, 8 insertions(+)

diff --git a/arch/riscv/include/asm/hwcap.h b/arch/riscv/include/asm/hwcap.h
index 46d9de54179e..8608883da453 100644
--- a/arch/riscv/include/asm/hwcap.h
+++ b/arch/riscv/include/asm/hwcap.h
@@ -93,6 +93,9 @@
 #define RISCV_ISA_EXT_ZCMOP		84
 #define RISCV_ISA_EXT_ZAWRS		85
 #define RISCV_ISA_EXT_SVVPTC		86
+#define RISCV_ISA_EXT_SMMPM		87
+#define RISCV_ISA_EXT_SMNPM		88
+#define RISCV_ISA_EXT_SSNPM		89
 
 #define RISCV_ISA_EXT_XLINUXENVCFG	127
 
@@ -101,8 +104,10 @@
 
 #ifdef CONFIG_RISCV_M_MODE
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SMAIA
+#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SMNPM
 #else
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SSAIA
+#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SSNPM
 #endif
 
 #endif /* _ASM_RISCV_HWCAP_H */
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index b3a057c36996..94596bca464e 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -377,9 +377,12 @@ const struct riscv_isa_ext_data riscv_isa_ext[] = {
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-3-samuel.holland%40sifive.com.
