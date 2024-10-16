Return-Path: <kasan-dev+bncBCMIFTP47IJBB4WDYC4AMGQEBREXT5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D84A9A13D0
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:36 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6cbe4fc0aa7sf4213746d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110515; cv=pass;
        d=google.com; s=arc-20240605;
        b=PZ99qG6RWGP3f5I+12pLsP+Oyq0B37fhRAQmVuKBjLyXuPsy9jStqvQuybYiU+L1aR
         Cgqz8NeTdU0fcCwhWwYiZuzQyoZrKERl0WAgE9fRb8KowGFmfeCsCM6SDJvwb34Ux9DS
         R68E+60rRE2p4uT+gyUVunoEsLp1FLJLZn6G/biPtJUdliND/YUQzMzrQvxnZCpL+1AR
         K7kk2iuZQQeWOWUqtNXHEvSD+jr09+kkVPZyGqXGoVO/OZTPuTULGB5Cd6LCdq9D+TWr
         c22dTJxP+RCt12Jwu4OfwkO3PZCATekAtDRPu+NCU6v+Y01TYwLWXHLKN92+Mv6X8Oin
         90CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BsO+TII0/OGaZe0OcpKO44NEnu5XPSyn4PnEBWbQZSM=;
        fh=r/Fu8lNb3w6mprOKtvIUxkYHlQ9YjDTV8P6Ql4bX/+4=;
        b=PiDtfBnu7YvR1bA3W+AlnS5iaVWIDHfqEdAvQUvj59luFM0fMg7NnRN/dWfKGdkyBt
         eOPn9GvN6DgqWdN3aYAmuV/nb8RiEnz8/0+TOXBYurmt5XI36iENIsc/ySEkc20Jmro4
         RANxtYbzGICfBBwm4Put2XAu+9y7XIHc8IoM4hXVD30kakM2g0B7Py834kx5fLKe6nuC
         XvTE0CSowjBPcMwhAYZppYV3nRdqRj/cXqd+jByi+D1OxHv3XRFh0qZKUscqlHvv2cq3
         qKvMCa8rtw/QJAniry3tvMCz8sYki81GCFT6oWjtnvYmlxY7awaijfEYz4yqCflRkHG6
         xEig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=KY5tGq+V;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110515; x=1729715315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BsO+TII0/OGaZe0OcpKO44NEnu5XPSyn4PnEBWbQZSM=;
        b=fqrZyaqCYOMhGuC6PUQjmFBde4YgqtB7smk2g9sITg4iF2KK5i+A19X1TPhKuj8rc8
         7YpPm2IMLXs2N/1uO0oDbqWe9ESuXz1mQN5ytw0hoBnDkXW9dDf2hutmEkKymOb1OH+w
         UKJmj/UT2ueAj+zPDzEvjSb/qyhY2HNeubzqFkSdxC9FL7P+4ut2ee/Y+iTmLkJlNkcJ
         2dSUIr6yc0cLyXj75lCKIy+cVxEhmP+V0D1oTy29DoBCWMVK21H4alpWZSgX4at6H8OK
         w/I0apJWz3StssGgPT9kxRBdqt5MRB80GjByE6QS1N90jC7aNIuDCHtE8sueVuSpZcz6
         mVLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110515; x=1729715315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BsO+TII0/OGaZe0OcpKO44NEnu5XPSyn4PnEBWbQZSM=;
        b=BZP2LDM1hRQ9rdyCaXWzi3tl02+cq6HzBHYTLkoSTAycAsJhXEQndAEEa7jc6HndZo
         r2lMSe8/e3LGAx8w8t6pcFj8pEsIEcxD9w6ii5uEb8ntu/If4/G3wNSSX8PlxeAjPoLl
         Y70OTFdzwPJWtjOi0ZgCMj7vtvYGWmHZKJI+E8v5fHRHePxB+ejIrP/J4sUbjH3ARxso
         QVEr+Qqzz+NUunbEb3WOSQD3NRoa5A+Klp5DVbzEmZVseWHkKFQ4zLZtbsNLIwbZyN0u
         PutrhaEXb+e769lEFkuhDhaLWCa095YaCOtEOVteFEvjwsqfEV+JWJ7Q7ewMRs5wqmwV
         DRlg==
X-Forwarded-Encrypted: i=2; AJvYcCV3KtnV5eD4ch1vvEApk4IWC7OdCYIOQ5XbnpQAp5q5XnFnttax0ZrgM/CHNxqFIb4Ljxs1hQ==@lfdr.de
X-Gm-Message-State: AOJu0YzSmmJ9OovaHbMPJujE6C63Bo9SW/qouAEG36DJCLVFhZXUdZEK
	IA3kE5jGOsd56CPbhask/zA8BdA6frcq6q8/3iJq/BrxLd6xHw/X
X-Google-Smtp-Source: AGHT+IEEYXTFU9fliFEN8BgCBCLEuhgxf8bDJ3cUWlYw2BovSvllqjEQdFmaIpH0hQSN8V7Zbq6UCQ==
X-Received: by 2002:a05:6214:568b:b0:6cc:1f0:d38a with SMTP id 6a1803df08f44-6cc01f0d4c7mr185466546d6.14.1729110514937;
        Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aef:0:b0:6bd:9552:bc87 with SMTP id 6a1803df08f44-6cc371dbaa5ls4872076d6.2.-pod-prod-04-us;
 Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqOTqaa3ThSLFeoZl/TaWGCRmClqCe/zd9AvYaC3+KaFJ+Y6CJCqty4D6vTMK4+fK85unzS3eKoOc=@googlegroups.com
X-Received: by 2002:a05:6214:568b:b0:6cb:e770:f50b with SMTP id 6a1803df08f44-6cbf9e76302mr224616856d6.33.1729110514403;
        Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110514; cv=none;
        d=google.com; s=arc-20240605;
        b=hgPDI/sjt5MpbMolEBSlKBFqeKB1Q+cISQNPE05gbI7bx+u4ZRZ+zmSlWF0gaCrydO
         JtqhI30MkuJmrliMLIQwPvcnf9Bz9oJFnbtl85KP9OQX3Ovs/D2/jWOrKFaAl6kPrC+b
         Ge+Hd3oU5/qrcSACPTryUOEz+V7tOaWfqj1//pG3SSj8dNNK3N3NjR0IaEX6GPowIUkb
         2qlMR0Lj/rQUu5gpR6xHhA+u9dhk4ZoNsyDw8O+8dTFbLFIaUWrT+xRfvJC20lHSv1uz
         rMwA5cDBNqDvgWAOTNWrrIidV2gcIdhmqx5/8Kgtcs3JeXoHaOBNc6BP3HlTsxg4Wjvd
         5Q0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=N8qp+tseh4bMUHTaD+Myf/jjkdJffKFnGUeOTquYIl8=;
        fh=7JYe+beJfpKU5M2mhDaelcnMOCxoWUvDPm8XcCYqKlY=;
        b=J/7+Ab3YOyi1o2qucKfQEcX0v9lzWKYN39dpY4GflJ8DGhgJCBQJrBkvb9bul5zVW7
         VDrmKTxOJsPwzWWz2lI6n1wVzOezVF1TPwugP2VjxepO7AKIWPf5t2HofAzEQc9QJJq9
         LKMfRrhNxSqvMABlLjg7ogedVjSkSDo9tSb1+VGwiVIcgOkGoSJUDyvpXH2RvxnOH4bb
         JF4oKSMyOUwN1fXHAN7GcFPP/MNp5ITFai2lGreRSHbnCeEo8go9gDohDiEaOLoW4Zhi
         /brvid/dgLYXx0l/Xk0le+21YLLiRD92ruuKIyxgNoMaWNatkbYJcVLMTKzlicOe0Azv
         u5ZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=KY5tGq+V;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cc229e4b18si1913746d6.3.2024.10.16.13.28.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-7db908c9c83so145207a12.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXwkD4wBFKKsu0ytQ4lwwDhedQCYzBE6PkcvCyk/RdU9pgQ7MdU6i3xtRgmHk5noRHsz8dUwKK7J1w=@googlegroups.com
X-Received: by 2002:a17:90b:617:b0:2e2:991c:d7a6 with SMTP id 98e67ed59e1d1-2e3152eb736mr19638942a91.19.1729110513399;
        Wed, 16 Oct 2024 13:28:33 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:32 -0700 (PDT)
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
Subject: [PATCH v5 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
Date: Wed, 16 Oct 2024 13:27:50 -0700
Message-ID: <20241016202814.4061541-10-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=KY5tGq+V;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

The guest configures Smnpm through the SBI Firmware Features extension,
which KVM does not yet implement, so currently the ISA extension has no
visible effect on the guest, and thus it cannot be disabled. Ssnpm is
configured using the senvcfg CSR within the guest, so that extension
cannot be hidden from the guest without intercepting writes to the CSR.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v5:
 - Do not allow Smnpm to be disabled, as suggested by Anup

Changes in v2:
 - New patch for v2

 arch/riscv/include/uapi/asm/kvm.h | 2 ++
 arch/riscv/kvm/vcpu_onereg.c      | 4 ++++
 2 files changed, 6 insertions(+)

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
index b319c4c13c54..5b68490ad9b7 100644
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
@@ -127,8 +129,10 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(unsigned long ext)
 	case KVM_RISCV_ISA_EXT_C:
 	case KVM_RISCV_ISA_EXT_I:
 	case KVM_RISCV_ISA_EXT_M:
+	case KVM_RISCV_ISA_EXT_SMNPM:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-10-samuel.holland%40sifive.com.
