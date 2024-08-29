Return-Path: <kasan-dev+bncBCMIFTP47IJBBE4RX63AMGQETAZFS6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 969EB963739
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:13 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-715c530f80esf184548b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893332; cv=pass;
        d=google.com; s=arc-20240605;
        b=CDDaSsR6ZO/TTa+Q0ZTcaWluYaD3Gm4dSvX7fwRa99S4gCaYFSBmOwd8ZIqLSTycmj
         hn9boFdWut0dTFX2ftEOAw18QoLpQIxP0+c0GfgIROlZh3fr6O9uuxp3Gilqlz86Qdoe
         tUs4ZTe34zJdhnHBS2fmTzBmh7TX7xtLJdBVpi5I+vAmlqkQMlWgN8H/Vg61Vzlqvl2G
         Vt1wY/eCFTHyz8il2Mr3RtKBbgf9dnHPrynqoFvz0h5tx2R/YyZuDhrEs9H/2tIHftu/
         j+3nqmgpVrNDvbvRKLqdVbvRDsfE0bbJYFfKNpKJEAUvP01JU1UrMA3/26GTISlK7WGK
         GL8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=wspIFN/ebTvPssMdUfEdMVwItTWRywzJ+x5bHgOGQxA=;
        fh=KRu6a2WeLJ/aiAhRoqWbqcRHXKTClC1CHa9aTMDf+50=;
        b=AcoCrOFZD3yrkiX4b6IjwtbLE+rKa7LVtPH3tmRPVqUs5RrTyhvAF3BWw4/YpuI78p
         0vcuzyJea8PFOyQqgIsOf4YYrRU3ydmspAuDmDpIFHMQvuMWF1zgek2G40WjDHRpuBG1
         l40fd8R1e10d9xIsY7TEQVHzQiNwL95JwsDnEoPcbvFgcv+WAmnQcFRfIS1MwGMZWFSy
         Yg27t+pAl62VEbzI602BOD6Li/P7nG3MNvbSMtmaay1L5hDp9RxQ9WR/RXloOTyKhvvX
         dSwiKGfVJKaHN3zb8txLp/6Mr490PIrx9OqdadpKiA8b0tem6PFPkoXVewhXoNrMQqzA
         mxsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=dVqhK2y0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893332; x=1725498132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wspIFN/ebTvPssMdUfEdMVwItTWRywzJ+x5bHgOGQxA=;
        b=sOBjYVPKBa1UM9q6RG3/2Wmu1+XEEpByQtPo83Hs+Ubs1JvvKt1jjqLC394zEv/wQd
         YlqyRmGRM57+8G19hfAJ5Lv+xLB2B+QfVoFll7qFLb2eb3GDwZZLuUBhUJ/u07ABYxY2
         csja7JIHGOjEtFmytmFXvH9ghnb1n2JDknymdSE6V6Phlp2NvYeVLObmrFAi/PIK6xHV
         xKMpuUPT4yw20kY/9HowRumrnjRHm/3385bZrPAhF4vo5PgCUHHDvwGousiMhM1yMIDa
         4Rs546qcQRYu0h/dxI/l2niBshrskJDX2f5SNM6jNl7zoFi0bGmPf5r3ShOZCKEsIEay
         hLuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893332; x=1725498132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wspIFN/ebTvPssMdUfEdMVwItTWRywzJ+x5bHgOGQxA=;
        b=qX54Fh3MQA8e4AGwTlBPSfp4OY7NV247GdqVr0Cycac8kjhxI1AEj9ekm7ey8CV9El
         PgtHN2k6zjJypmRqQUHUq+pDOBB7QliDLvpcvh+LY1I9IheX0FhTmzRBBiDuyY79Dd8p
         Ry1+6vLw2+W2Zi73gmnre4hk0Z/6l/5qAfp9sqEC5ifLuJhEyHuSS9ADwu/QfLQYs98V
         tYzfnfi66N+YolIIoJk1I6wEhKEOyQcEpQQhvSKfC1ZFKgDSsaCH/S/ZfcCkFMfknM/q
         tuxCKg4/MDqTgYvMdapFZybT1FWeGwwhPRNqy9YZX7NTf1zpEqioVec6PvPBdCIGDZWP
         QFtQ==
X-Forwarded-Encrypted: i=2; AJvYcCVyjQUHkTkC1P+ugbJKRHCN5UdAHnDrlBC9sRfIGfhdfg0mjixhwHJnfa64ubzExKmpzIkqbg==@lfdr.de
X-Gm-Message-State: AOJu0YyPn5aJYW4gh6MkYlHfzCWcdg/oqsL7x7Hu4CCafk8NGJbqUvsQ
	ZXO872ABC05M5ra9SVc50VqcJY9nEFNh816h9/wG8iZXkGe+0hJo
X-Google-Smtp-Source: AGHT+IETGeaJ5tgHSKjmCZWwD3BXtohu/gSPoxFT0RKzbuwLeT+/ypd9rWLiuvUhbH9Zlc80p82uiA==
X-Received: by 2002:a05:6a21:58b:b0:1cc:dedd:d904 with SMTP id adf61e73a8af0-1cce10e8918mr986116637.54.1724893331862;
        Wed, 28 Aug 2024 18:02:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1803:b0:70d:34f0:218c with SMTP id
 d2e1a72fcca58-715de43cf83ls326952b3a.0.-pod-prod-05-us; Wed, 28 Aug 2024
 18:02:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHr6hdscgzM+ku1eaSq4QFf4XhagUzpno/qatcInb3mNOFZcIBZlogbiqiRbhabNLxPSSiI055GvU=@googlegroups.com
X-Received: by 2002:a17:902:cf0a:b0:203:a0ea:5f93 with SMTP id d9443c01a7336-2050b4f09ffmr16755865ad.0.1724893330644;
        Wed, 28 Aug 2024 18:02:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893330; cv=none;
        d=google.com; s=arc-20160816;
        b=iCqo/CbHV88+RBmLVZKaP2RVR/NixyjVW1/8mM58KDm5cTqUIxi2VADL1AEodM3lY6
         sQWzoA4I9H5E9uI6bT3s7h4AhVRaM+94Inaq3n72Ywy5Kdp6PHIB2Dqiy6qvVj14w+nZ
         NGGaX2BZCY5PB/cia5hLXSInqNk38KWCSfDoeCf/WFnDQuHJh1IPPCis+sOyDQOt3qdz
         1lPC8c/QnGxDBIv8ZW/R4+xe4fQxwq0sIITsekrPiQYAmdVpNniPySFLAj+Fj1qfHb/p
         TbIgYOhOgJHmSaUp0vzrqxx8j6JpvqdwZhcwP9PXsbr0DmG6rtTnbivg6NKNLvKJyB8H
         DE7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UZ85hK5DD6/7RMQg7pUyZ001ybckvLWjPJtkX5mnwuQ=;
        fh=/WDrKDPyLOzeVqN88bsO0ALoLSYPAgZ2leRz0q/yH0I=;
        b=n5zAu4EdZmXt5kS7edIFWBExfhSt5tkypZsDlThd/YaYxCYbYVq7e73woGY4RR5xTd
         5D4yCK66Gc2DtA33JyNzqUDwZ+ISkdJs4LsDSG2qWT2alseOvMsoSeKE/PIdhbHeExma
         A8NHEEp+lgF4zgqe2L7XEO2IeyKk795bz0J41WzeXHFMGVd87GebeRY2Qw+OkHndunP5
         sRF5E6Gg0oB4G13UvWTHIe0OErZbYiMZodWb1sNHuNUzCmkcaFC3vFIB8nXiJKApX7ft
         KSrLRsbQHOAyf3IGbrgJ/jIIkRnITEFJkPbMrZRbhDlJQugBa8TIuozOjk9Eve8ayRex
         VDdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=dVqhK2y0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20515522762si65645ad.10.2024.08.28.18.02.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-7141feed424so107950b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU8sj4h0SVfb302vUOhUverqdaNWscRgkgnNzXWFE/rZFxCzCiMHxnzfskALc/azVRy4ZBRXFx3l70=@googlegroups.com
X-Received: by 2002:a05:6a20:c890:b0:1c2:8d33:af69 with SMTP id adf61e73a8af0-1cce10a3b9bmr986022637.41.1724893330253;
        Wed, 28 Aug 2024 18:02:10 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.02.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:02:09 -0700 (PDT)
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
Subject: [PATCH v4 10/10] KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test
Date: Wed, 28 Aug 2024 18:01:32 -0700
Message-ID: <20240829010151.2813377-11-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=dVqhK2y0;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-11-samuel.holland%40sifive.com.
