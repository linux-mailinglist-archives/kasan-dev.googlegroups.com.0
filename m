Return-Path: <kasan-dev+bncBCMIFTP47IJBBAOP6G2QMGQEMENHAHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A5CD951651
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:59 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1ff192decb8sf56119135ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623297; cv=pass;
        d=google.com; s=arc-20160816;
        b=sHwGTLNZoOqOMAFDXh5V4oukTz7XxN2K3uDf2b4YK0KG2/Fgv76MaqTfOmmPIxFJoI
         rV0+esAb+S6+rZpeOU2BIpjfDxgG84nZy++gdRViS9pS/MgvjSwm7Mc5nEblp+HmEdHy
         WKS5OX6cC5yyaiPdH1VGSDjaOzpl1zoY/VaRZ9IOITmQ1dQ9IMAdX4YFvJRq2qscdAwN
         CSyYj6iEqI9/UvcNWOfrmEWs+YwY7ec87boJ8e69Re9QLpIYn2ht1NH5YF0scH5hUgK2
         TtmEzBoFBXKPcLC08nvC7M3RchCdih0GgMKovjou7xF3Fn30hCujk2/DA0jXX/ShjFuz
         0F+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4jLQwob/olEeNkfdz21pXY8vC1lGZTPhSpCeu0vA4D8=;
        fh=zAvtnaYkS1Embw4zRWDXJZ232mrVnyFeE9+Pmoyyf70=;
        b=j4B6GnI2N8MRY8diE00R0Q3zTV/ziDJFzp1WB1+CgB7tQFD9H4GfY4/ta8IgvbvNN/
         577AxadCojzYXgusvCHxPXir/DZT2S0LkdkwLuEO5pXFxv0QH5seiv9WHgVe6w+7JydA
         02/E+7obGrhZZZZ2bJ++zT+iuL9sopMZLMMXXHKVAzvknYAKTMTXGu8Je+qi6oyS/jsc
         DOlIul0U8+v36uDsR4tMPoYw3xX+XnStcdX4D49AFJB001lefRXs6jS2h3R207rMAlsh
         tQcaU058snrIz02Qrop6Zol2/yHY5r1H+5riPpk5Ws23xsDqPyK+dwfvEgIyjny3o9Pe
         QwMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=hgAolyvA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623297; x=1724228097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4jLQwob/olEeNkfdz21pXY8vC1lGZTPhSpCeu0vA4D8=;
        b=OW4jZI1HHFPozxkpSQY/0q+qgen1Oiq6pNs6Mif1/jzeclwplWzcMzxzY0xtyXD2fO
         NJsZGqxYhZwT88n3WE94n73rZhJ3B7mfPdGv9V+86w5m2cDIf04qpCX3eIwuI1Hb0Ec+
         Qgdx50Nc/qPUYi0WqIY60NoJQ3ZNwJXsumFeiBvc10bd8dClhxavEBtJnHMTg5f9bMs6
         ElhYGgMeYe9MMybW9yUYDe2iWx9T3gKOG8yJ4EsBE4Eb4SUMoKSXruruNZo1nm2lGj8v
         NyZn5G3BACeEK6TmAFHHDTcn2YeyE8hJDjDjTGnXxAuJKrINCaFJd9PtwI1C+Srd6Gd+
         786Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623297; x=1724228097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4jLQwob/olEeNkfdz21pXY8vC1lGZTPhSpCeu0vA4D8=;
        b=h4QN3DKvvniXEQ7o9633WoEvilvyfNc4eDNHO2n4XT/HOPQXIBjDXvZHF1j5RUC4KP
         oGEpokuSmbaYjTMjzcncdcocVNb8QmlpSDS46RLsrxnNK34+N7fG04FsMTVmfDbE5ucx
         jpElcx8E/QoKutydz6vDwzds4UJ+kRsgo+jM8XrTldfXYBB8o9cSUEh7XvjjwozKAgHA
         MAZqeSr7W2ihqC68Au59+4oFJsm6QMnRNu/5/51dMU3w4qSx72+/YBMKSfPxyJtPXNwz
         MMxknjh7jFd7LYfuz0pfgn5OCW/0aeufIMVytgfNtTqBtm+cvEUGAZrV1NC7FCnnEVk+
         4YTg==
X-Forwarded-Encrypted: i=2; AJvYcCV/MU4gxvlQIIuzyBvjDRC96npUtGtmX/v7dDaqukro1ThbbzexzKMeNXCq8VjY3tmimI+aXyT/Z2EuIa/79iVUi7d1OslMyA==
X-Gm-Message-State: AOJu0Yz2LrMO+jsDnG1GwXNlEOOmrVVANQ8Jk/iR+dJTpJJ/tzkpnI+X
	dXq/jD/HyphWwpJTxG1XQpQwNhiQ89/8H4AbdbrthYLyvrIN5y0U
X-Google-Smtp-Source: AGHT+IE2Z9VdJKsn1h4QWi78ddtuygxWh4eEl26r7f1csqaiUxggLJPJgAQLd/fnUug1T+aJ1Gzh4w==
X-Received: by 2002:a17:903:1c8:b0:200:ab8d:f817 with SMTP id d9443c01a7336-201d63b263amr23353175ad.18.1723623297426;
        Wed, 14 Aug 2024 01:14:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:1f7:1d41:9224 with SMTP id
 d9443c01a7336-20090625167ls42534025ad.1.-pod-prod-05-us; Wed, 14 Aug 2024
 01:14:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGFQSIfbMc9D+CXwo5WKdEyxrG+QkhwlschLBYF4Zdr87vCiuRVbBUN2QQOBtYABsJ3jZaf+y78n8OwJxGZyjjj9FWyMf+qH+AmA==
X-Received: by 2002:a17:902:d4cc:b0:1fb:81ec:26e5 with SMTP id d9443c01a7336-201d63c4246mr18731995ad.28.1723623296298;
        Wed, 14 Aug 2024 01:14:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623296; cv=none;
        d=google.com; s=arc-20160816;
        b=a1fS0foj5iDdJiIRfxsxDV2jkQTf5I+Nk/SZGPVhM9rVYn0sCS8QJmnS1t4VqRTKpe
         xQNuqu283MY0RPQvMGRWXgdlKPEJUnaM+rhywmjsGGrIn3UuHywlrUIKebSifgSwIfoQ
         yVUqm75uGZN744IQ0UW/Z/hb93LgfjDd6CLzE6Q/ybuBLEs6xbNgr9/PH96xuHuhdRZj
         xoMO4hw0IV4Et5ecIBYZ53fxaiQ4qK3K+XMKp35o/wf9bJgCfcNET1VGsAl0HX9gu9g0
         M8bSsQCPK0piKVpIPvKskAqy5Md9kf0Q77AFCxh48h36Q+B+Yncs4FqoY26iTVs7dtf4
         2VQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UZ85hK5DD6/7RMQg7pUyZ001ybckvLWjPJtkX5mnwuQ=;
        fh=CVrtTDg8C9HciW7+irxJJYDtjmigMFKPfcCtXSyyI90=;
        b=h31NeInpk/67n1bM/wWGFF1VgzN/GcBu+jQybWxvNnNn2XnN5AhWZRXm0yzgvsdYMJ
         +LvcygLihQ9fJVayC64ULuFArJ7eHXPvxCp4UkzWcm1xujS/HwkNtTpOq6NiXouXs0a0
         0o/GzsV5gxysPkX19b+h8MTKeXyVd5UZgpl2BKgUehx0rdaxIkUoa9xOHdNvA1gHCl60
         tdW7H3gvuec+JVWq/x0ojy4ULsGuGC32LlE42KVGsH+gfd/2/fTrH89f0FSi7A79hj+J
         x6C9DapXEfi5YWwwyXUqGA84W/mkf7x4wK4Onqyi8OxbwEeAZGEoFLpQ40PN/MhQ0TTH
         fUTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=hgAolyvA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-201cd18dcadsi1472155ad.10.2024.08.14.01.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-710bdddb95cso3833782b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPxQ6OJCCbe0qfWRLnAxj2lOgPkjv8HIFcFeht0KqAiDyCzp+sSw/E6Xb8XW0xCcO4oKvmSskqnyyXS0/4VzK96XXkpHII9VOpIQ==
X-Received: by 2002:a05:6a20:d04c:b0:1c0:e1a5:9583 with SMTP id adf61e73a8af0-1c8eae6f542mr2858028637.17.1723623295864;
        Wed, 14 Aug 2024 01:14:55 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:55 -0700 (PDT)
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
Subject: [PATCH v3 10/10] KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test
Date: Wed, 14 Aug 2024 01:13:37 -0700
Message-ID: <20240814081437.956855-11-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=hgAolyvA;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Add testing for the pointer masking extensions exposed to KVM guests.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v2)

Changes in v2:
 - New patch for v2

 tools/testing/selftests/kvm/riscv/get-reg-list.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/tools/testing/selftests/kvm/riscv/get-reg-list.c b/tools/testing/selftests/kvm/riscv/get-reg-list.c
index 8e34f7fa44e9..54ab484d0000 100644
--- a/tools/testing/selftests/kvm/riscv/get-reg-list.c
+++ b/tools/testing/selftests/kvm/riscv/get-reg-list.c
@@ -41,9 +41,11 @@ bool filter_reg(__u64 reg)
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_I:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_M:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_V:
+	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SMNPM:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SMSTATEEN:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SSAIA:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SSCOFPMF:
+	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SSNPM:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SSTC:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SVINVAL:
 	case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV_ISA_EXT_SVNAPOT:
@@ -414,9 +416,11 @@ static const char *isa_ext_single_id_to_str(__u64 reg_off)
 		KVM_ISA_EXT_ARR(I),
 		KVM_ISA_EXT_ARR(M),
 		KVM_ISA_EXT_ARR(V),
+		KVM_ISA_EXT_ARR(SMNPM),
 		KVM_ISA_EXT_ARR(SMSTATEEN),
 		KVM_ISA_EXT_ARR(SSAIA),
 		KVM_ISA_EXT_ARR(SSCOFPMF),
+		KVM_ISA_EXT_ARR(SSNPM),
 		KVM_ISA_EXT_ARR(SSTC),
 		KVM_ISA_EXT_ARR(SVINVAL),
 		KVM_ISA_EXT_ARR(SVNAPOT),
@@ -946,8 +950,10 @@ KVM_ISA_EXT_SUBLIST_CONFIG(aia, AIA);
 KVM_ISA_EXT_SUBLIST_CONFIG(fp_f, FP_F);
 KVM_ISA_EXT_SUBLIST_CONFIG(fp_d, FP_D);
 KVM_ISA_EXT_SIMPLE_CONFIG(h, H);
+KVM_ISA_EXT_SIMPLE_CONFIG(smnpm, SMNPM);
 KVM_ISA_EXT_SUBLIST_CONFIG(smstateen, SMSTATEEN);
 KVM_ISA_EXT_SIMPLE_CONFIG(sscofpmf, SSCOFPMF);
+KVM_ISA_EXT_SIMPLE_CONFIG(ssnpm, SSNPM);
 KVM_ISA_EXT_SIMPLE_CONFIG(sstc, SSTC);
 KVM_ISA_EXT_SIMPLE_CONFIG(svinval, SVINVAL);
 KVM_ISA_EXT_SIMPLE_CONFIG(svnapot, SVNAPOT);
@@ -1009,8 +1015,10 @@ struct vcpu_reg_list *vcpu_configs[] = {
 	&config_fp_f,
 	&config_fp_d,
 	&config_h,
+	&config_smnpm,
 	&config_smstateen,
 	&config_sscofpmf,
+	&config_ssnpm,
 	&config_sstc,
 	&config_svinval,
 	&config_svnapot,
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-11-samuel.holland%40sifive.com.
