Return-Path: <kasan-dev+bncBCMIFTP47IJBBEURX63AMGQENJOJPXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5180D963737
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-270617b90b7sf132671fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893330; cv=pass;
        d=google.com; s=arc-20240605;
        b=R05FNQsUuBncibCDP3BIaK7PoIxNSG1sn6NyfLDTm8g5al8+VZHn+plDWt7R4EEReM
         9NT8al1HBs1UnyLMyAiDnL+40K9LrUSiek2fCZixb0q5TGo8SfsmvHA0vzmZvfcSByKA
         nSuxQ9Gyu8+br724u6hVEOKXOvW3zXYUGJDzisOsIrFMrauTqxe8zE4Cl9va6DXNt2vo
         q++zWalyCUYe6lEtJvvEKKYsTtLEcjmcDMal9JJyWml7NQ9vrF+s66gT/EDJmQyrqJY5
         FL/8SqI7togPoiFY//8Kg/o1uPwv98btyLCOhI6QniO0d++m2rjv4MX7ZC/ag41+rpWW
         osAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2kD0sIJiTxwPsjrRKw+hVWvK2GzXSq5Yu2ocLmJqTyY=;
        fh=HG4+l5og60edg9y/KfNNlMWc/Qim207ccwWKGoEd/n4=;
        b=W7w5kBRkpAt4LLzFK9yjQX9sR9jaiNXS+Z89x2Q98GAWDta4bpCBCdss/yiC3N9H1X
         7gPCtKSMT9TJm2fp/8DMTJVyE486VTHfIkJwhTa/CEMVFJP5EPJvpnkdNLVi7KzCu8Cm
         sjxB51sNW0jd1o03v8Pecos7XKWiTgljwxyOluKjE/jNURD/KnLUzednJB5wvscqdy2m
         f8U1LkB97sVDJO8DkbzXASbNag7k0y1HIjBkt95h7KzoZhMJoPkbrPwH07rr+1oLx5Ir
         mKDN4daDArx01McecqkPYx2RFbKlEJoq6f2ph+sCA4RAiu5AIoeEJ0fh00/PdBFwjeiQ
         r85g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=afDwNbGc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893330; x=1725498130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2kD0sIJiTxwPsjrRKw+hVWvK2GzXSq5Yu2ocLmJqTyY=;
        b=WbxtNN0ZsuH+7ZD0WhwZ9LNBvcQEizTbgny2hie5Zd2v73Mtc5u+mGzfWD9l6GW4hM
         ihZilrkvXt6nIPPulBcLhqmEw/YNqYHtYKSGK+4hrDZ7MJOoZ+6hLj98MxCGX+A2T693
         BcrM+8/xqPF/JH6W4lb9yvrADqRL7fTr+3deb5op7Ml8GM1ngoB9/aCQ8i/UVCCwdPJ0
         OZPMMG7WhFZWUiEH9QFTH9rmp8T7fTZaDOt1x4etDS3DP4VwlqrAIOIoD8YHx+aDA9mM
         L9VTW9x22hLbhLmMvSq1aFkMpNGfBd4MAx1CLOhODY/OhHMI+1C6rEbTz3ShBgcbL23n
         narQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893330; x=1725498130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2kD0sIJiTxwPsjrRKw+hVWvK2GzXSq5Yu2ocLmJqTyY=;
        b=rls1I7XAAiEBUkVw5FWzO9IpEWKC5qZd1AOz9notgQEoF04ixXrfjZ2RrM/sXCccGA
         C5Yy3ogp9F957tSY2Lz4aU+4FR45j4AQRXIQTtBLvriYsZaIR//TFuwDCMjquTQsVj4A
         wyjE0N+fklsxC67odCUzWmWBU8DVGOeEheuImKh9dAXKEY84BLimjPdnZbRlLdRtJ2sn
         4vjW08DpkcwLam/HgaJhUHFgijoUJKiSuyUnoCddZICNWKjE6jQ8A1YRGaGdXchrTJvu
         0J8YCHtTQNjmtm6McQ691abho9K4xdzO0WR1XM+l8ll+4G3hjhJxzePEnh7zN0dFR/YW
         qscw==
X-Forwarded-Encrypted: i=2; AJvYcCVPtQxUz1Cx75/2XpPpwCeTfBYoR0l3bFeVtCQAywFdLiO4LC3Ouw05EgmPYbEmqMW3JvugvA==@lfdr.de
X-Gm-Message-State: AOJu0YxKI5Al7qE2hsP7VTcsXW7aNHngGBLwm65EfrFiECTce79LNnJc
	FyCmaVXSm/zO48H5d3PefopCCL5OJHbK+YgH6+g9KaZSztAwIt84
X-Google-Smtp-Source: AGHT+IEb9Ye/LJODsa8reCttkaYrjlMhTy1L40v7jpFpUh8ajEZXVlJVrGPhGU3/cmfLZIhjoZqtsQ==
X-Received: by 2002:a05:6871:79a6:b0:25e:fb:af8c with SMTP id 586e51a60fabf-277900edeb3mr1558915fac.18.1724893330189;
        Wed, 28 Aug 2024 18:02:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1ec3:b0:24f:6f0d:5f4a with SMTP id
 586e51a60fabf-2778f0b1d63ls546554fac.0.-pod-prod-01-us; Wed, 28 Aug 2024
 18:02:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWa+ekWhuk3T7FDRenkb41tOfAaZB1eIGBan0qP+szZg5lD8EWXifD5ejX6rT77sU8Jyy67aRxV33E=@googlegroups.com
X-Received: by 2002:a05:6870:6106:b0:270:6dfc:b149 with SMTP id 586e51a60fabf-277902e31d3mr1603733fac.40.1724893329456;
        Wed, 28 Aug 2024 18:02:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893329; cv=none;
        d=google.com; s=arc-20160816;
        b=SYhe58vjWs9OOWdp0cH6GkjfAApLu4FBYM1bHPSArjsdxa0ip4sH9HIC8i67EM2G0c
         JYwswak6r8WT/2vtMJWrS9d4xNX6eXVD95MlR8iEbdPUevnrQeva/XokLTRorPypGwfT
         Y8cy0eKF/d5j8Wn8cV2wctX854BcKS/wC4eUZQpGB8LuxVUA2E/nqsB2AnkI1H2NAasl
         9u9slIX24DYqNf5T1fMkqRtRUS/V13RIbrIHfhB9/TPKMbJY7GtV4uaez56zgmD6yFSN
         tCHTxKQ5iUFXOEGxydQm/WqZtrFVFg3QCbGhyzyE8kBPeUfQAOFECyYkrMPz6s0Uc2JZ
         S1tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UVeUN5Mn4knmfhlWREJV6zJkPuiqFserRZxouOs1BJI=;
        fh=Fd8ZxabsItP0M7A+zq8ro1jUUWJOkb+WLRtXej/FxDs=;
        b=E0EJQ/uk3WwYtIp9S83A65sRMMtYemqqNbLDHSvlluiNabTMrab5O/0V8BiSb/b1Dq
         ArmTNv5kphmX/mN3R6kxTnm/VFqQYkvHtJY9Ofo5kPxDnVHWk1+INV+3CzTFpZQX7Pm1
         HkLriYyuC3Ie1hYv461rCk987epp08gRYPGeF5emzv3mq4I186M8Cj8u7jPP8cySbytm
         NQ4VZWwqiOL5SweuOui6NRB1VnqQKNp0sQVes8b+mWqrCTPPXfj/00j+jQ4+3dqyGQrY
         12/+mlb7xVZiBlPSfEDvNqG1TlcZU0zpuGR1IrOUb/g88dBbCIroUg+tHvtaE/V94WU8
         0+2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=afDwNbGc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-27799f915adsi4012fac.2.2024.08.28.18.02.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-71446fefddfso106621b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPQn9ZuTwE5QY2FtUf8gdkDCRv4fTiNI8P2fXWAxGozD0URQy+tC9q4oN2LFWedG4siJ7kOM8IPl8=@googlegroups.com
X-Received: by 2002:a05:6a21:e94:b0:1c0:f315:ec7e with SMTP id adf61e73a8af0-1cce101e3eamr1074001637.28.1724893328672;
        Wed, 28 Aug 2024 18:02:08 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.02.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:02:08 -0700 (PDT)
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
Subject: [PATCH v4 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
Date: Wed, 28 Aug 2024 18:01:31 -0700
Message-ID: <20240829010151.2813377-10-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=afDwNbGc;       spf=pass
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

The interface for controlling pointer masking in VS-mode is henvcfg.PMM,
which is part of the Ssnpm extension, even though pointer masking in
HS-mode is provided by the Smnpm extension. As a result, emulating Smnpm
in the guest requires (only) Ssnpm on the host.

Since the guest configures Smnpm through the SBI Firmware Features
interface, the extension can be disabled by failing the SBI call. Ssnpm
cannot be disabled without intercepting writes to the senvcfg CSR.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v2)

Changes in v2:
 - New patch for v2

 arch/riscv/include/uapi/asm/kvm.h | 2 ++
 arch/riscv/kvm/vcpu_onereg.c      | 3 +++
 2 files changed, 5 insertions(+)

diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/uapi/asm/kvm.h
index e97db3296456..4f24201376b1 100644
--- a/arch/riscv/include/uapi/asm/kvm.h
+++ b/arch/riscv/include/uapi/asm/kvm.h
@@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
 	KVM_RISCV_ISA_EXT_ZCF,
 	KVM_RISCV_ISA_EXT_ZCMOP,
 	KVM_RISCV_ISA_EXT_ZAWRS,
+	KVM_RISCV_ISA_EXT_SMNPM,
+	KVM_RISCV_ISA_EXT_SSNPM,
 	KVM_RISCV_ISA_EXT_MAX,
 };
 
diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_onereg.c
index b319c4c13c54..6f833ec2344a 100644
--- a/arch/riscv/kvm/vcpu_onereg.c
+++ b/arch/riscv/kvm/vcpu_onereg.c
@@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] = {
 	[KVM_RISCV_ISA_EXT_M] = RISCV_ISA_EXT_m,
 	[KVM_RISCV_ISA_EXT_V] = RISCV_ISA_EXT_v,
 	/* Multi letter extensions (alphabetically sorted) */
+	[KVM_RISCV_ISA_EXT_SMNPM] = RISCV_ISA_EXT_SSNPM,
 	KVM_ISA_EXT_ARR(SMSTATEEN),
 	KVM_ISA_EXT_ARR(SSAIA),
 	KVM_ISA_EXT_ARR(SSCOFPMF),
+	KVM_ISA_EXT_ARR(SSNPM),
 	KVM_ISA_EXT_ARR(SSTC),
 	KVM_ISA_EXT_ARR(SVINVAL),
 	KVM_ISA_EXT_ARR(SVNAPOT),
@@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(unsigned long ext)
 	case KVM_RISCV_ISA_EXT_M:
 	/* There is not architectural config bit to disable sscofpmf completely */
 	case KVM_RISCV_ISA_EXT_SSCOFPMF:
+	case KVM_RISCV_ISA_EXT_SSNPM:
 	case KVM_RISCV_ISA_EXT_SSTC:
 	case KVM_RISCV_ISA_EXT_SVINVAL:
 	case KVM_RISCV_ISA_EXT_SVNAPOT:
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-10-samuel.holland%40sifive.com.
