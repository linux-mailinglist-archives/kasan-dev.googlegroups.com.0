Return-Path: <kasan-dev+bncBCMIFTP47IJBBI7E5SZQMGQENOMBD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98AD49172FD
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:57 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-706791ae948sf4520568b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349796; cv=pass;
        d=google.com; s=arc-20160816;
        b=YrOWJVjGwKzaXNKtbYS/T9YtN+C2+1xkLBRGRWrNmwlJhKP/8I/ORMr6eBBkkJ4GLF
         lMkz49iAQworbZpEFRnhno3gdw36O0eXHhwYl9mPV5jsRAC9FW0Sx6RL0EJwN94lZhdP
         F8FZMjBYl3Lc0BBUT72nrZXWthinOXpozs9Onx8l9el8zlT+nK9cLGFSpIRfDqg5h+2p
         gmHLHXXer0T8BDEW+/0YAS7/wn5Kmt4U4MFgNGArgFBjadpgUIjbhbzWZoUgT31bMH7e
         zV0RC4JiYc3foS2VAl7hAKzE52rxoex7psV5FQhVYMKdQOFoxInv8KZdunDKPlVVv9Yt
         zYDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=9IjHD36NgnhJSdaZnMqNu1XC0xnDLSrMab4Ws6KXZ1E=;
        fh=B91H6Ph7IR1WPlus6ITCEvcPE4WXIvxQipOntLJtvrU=;
        b=L6fLKIRjSD6NX8tA1v7Ipc/pPj8ToU7FLZ5nZoR6hu2xiMUL86A1tIy5TI2a+KDbnU
         cnHesyHcc+BZePJFM4c7tBlRzX3gwgFStWWy2kPuLvB+MxkPZbaRmxD7WjhMxsi1UEYU
         xnaAnhmKcRFLS1M3JWnjW9XQhOBLuofyL1HiBisWFSwI2Z3TPoJUhNxfI2Vae5/M3pE2
         Sw1cE/huC1746uDwDGuBREhZtsTAWMK/yvdhXMSFImaTtltX6W5ut283VHgsbhzAqZy/
         OIuM4tKWyTEkXHJKfa1XYIOFbnUyMXMnlZdMCad4C/Fzkdy92K1d6WsDxOR98gb5+dtW
         XBXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=jIqKldCc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349796; x=1719954596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9IjHD36NgnhJSdaZnMqNu1XC0xnDLSrMab4Ws6KXZ1E=;
        b=rcU7CHw0wFbC9ZFI2HS1TXQl/76/X0xFAk3XWtTyvfUQ6+JGp0kCUmb/RxAv93GEtS
         fBiS9Jtbi89EhhOy7VhHFAQqC9Ig1bRwKkQpqXKuF+YZaEF5NKpQKCkGiCamFPhJ0twV
         A6mDjI20kKQdDTLN0WxSCjham7e4U8j1DQUr4IJ0nnSyoYKENDMALCXSkgz2w0KgpdOT
         GSpiF72XBm6CzmP9eN5xmFo2oX9vXdA7eYG+G8OO4IECJYZt3ODKXmtQ3EpQWxzRwxC5
         58KOyAdGNsGdxp6CD8FnuxcZJTBDufS1FRehnnlwvrwEsEA6sYJGJMkzTjWdPKoxPmSi
         xhfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349796; x=1719954596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9IjHD36NgnhJSdaZnMqNu1XC0xnDLSrMab4Ws6KXZ1E=;
        b=U/Gsm5eSUbBt8fy5UHmMFT2PClImNsDkSXS7pF/YKN92BQTTQ9J7GoIMO0gjSbSxBw
         aNYl/jc6hOdGaU2rsNG5ZSWRSGi+lzdhkLfgyPkPQF27DeATSo1mUMUHCQVWL3XGLxbi
         CPrNFDkzIx6TK/X699WXAy40bNU4q24FS2ZGOGB96lPzmf0Duih3wmXaYH+RXBYHcTrX
         6mwsSRoh6SQ2F3cAbaL3B7d01hM5Mpe3JnZKX9g/CJmp4gip9bO9HlVaWFAjX2T0sgDQ
         IbwDol5lurK9BQG9p6Uk2wc08S4JIE1D1djJ1i7sc6e7gMksvJzdI9YgPIcyL0wJVz1C
         yYZA==
X-Forwarded-Encrypted: i=2; AJvYcCWEMV3WwjkqR5ZNksp/wBLLSoIT0xK7/+jRzEtuTEuuNKKqA5dj1R8ib/lmriA0wuSUY7pv95C/l46LGFw1qgmjrwkU6vDMpQ==
X-Gm-Message-State: AOJu0Yw3FdHrLMWwTswRPKws/wT+uVQrm9sIgS4zthI/TNf4a22UXTmo
	AWvkavaRFTvzmKt/RR/b7no5Byg6qzycJM3M5GqkIUMlObXGU2V4
X-Google-Smtp-Source: AGHT+IGVA3dZFFqlH0WOtkIXgjJlylhPvmXw/SqrLWXj5dkkBLH6RX7Fq2cpnOQ4BDbUsBXUQm7Y2g==
X-Received: by 2002:a05:6a20:c51c:b0:1bd:272a:84ed with SMTP id adf61e73a8af0-1bd272a8623mr1520480637.61.1719349795772;
        Tue, 25 Jun 2024 14:09:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4007:b0:706:5fb2:54b1 with SMTP id
 d2e1a72fcca58-7065fb2572als2502314b3a.2.-pod-prod-05-us; Tue, 25 Jun 2024
 14:09:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4pav2pwXGlRUtWYukONzuVbngjzmzp3WyFEdQmjVD+xmI/cKGY4czzNMRkJxahcqdW3Zn1sJv2ch7vDXFWw1O31VZiHzXMRppHA==
X-Received: by 2002:a05:6a20:1e64:b0:1b1:d31d:c0c5 with SMTP id adf61e73a8af0-1bcf7ee701dmr6745298637.37.1719349793629;
        Tue, 25 Jun 2024 14:09:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349793; cv=none;
        d=google.com; s=arc-20160816;
        b=N4QkyrPcLocjbrFfmsagjyzAKCZAm/ItikeF0TZuMFsOJ9q3GdfJt2VN0QnRMCd1UY
         o8yc4ChJzBAeDIt2hqhpxRqfJ0r/ec3TiBLbclF5xl86/CfA+LWCXcAHHn4auxPpA10b
         +GtHMXK3ZMWrmNIaz2OOZhWOduGUQt99Q5osVk15E26BNfqgEfrFxjnEmZ7UTpS+Wfx2
         JwEu9lK3fSYDVc0DQQX0scHoczEG5nWOSC0IPF6dfiUfv+zxzjz2xzhkOOTP05F64VeJ
         1j6LypspGciPf6ldY/mCLmhcL/ncySU1awf1BLEbZLBT8iF1VE7FBdmd1hfyeCa+uch0
         B7LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZsHcmVVCPLrcBxzvj/XWrk8rIm5ozAhc40jGfT9csjA=;
        fh=YF8XyWa4sFviSqAEWZFDug5YoS3CdL5WaQpZwlVDfkU=;
        b=CbISqerhj9tqx65dtwt5t6Jzhyrhcj32bYtmivUQD43jidXFcN8Vor0su98srGLJjO
         m8HEudGgoV3KIdJUV1dUD1k/2XPHDoHSld1daPe8vAxakJIyuJUQe/xHPvFWiHxspv9+
         lOG411Yy/h4mLl+Cb/h01kAisCInpB3Q+xINku2hErp6wGbo++Qi49Pm8G5nHcNzUHIx
         7XwQD1oiqKtYODYiTNAv4VVqjWzZTHXwpzr6mO0Z4sSz8pV3dPrLLmBcLJPTGvcSoGyL
         ETarFsbtnuQe9SICpk/+ytN7bmokgLzFU53fjAsvGQhBxDuAx0BWNMu+hKiraVEk0Ihu
         kb3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=jIqKldCc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c8b836c085si120168a91.1.2024.06.25.14.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1f6fabe9da3so48848625ad.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUn3/GI4GKvzwGurTlT6EXtC1osopvlSEduOEADxUYJX/BxgaLaE8EhW5F7U8qEt4glS9CwVfXAC4zAY8TnKpUrh5buxlCEC4/Ulg==
X-Received: by 2002:a17:902:e5c1:b0:1f9:c6df:a84e with SMTP id d9443c01a7336-1fa23f3638fmr104356595ad.64.1719349793095;
        Tue, 25 Jun 2024 14:09:53 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
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
Subject: [PATCH v2 10/10] KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test
Date: Tue, 25 Jun 2024 14:09:21 -0700
Message-ID: <20240625210933.1620802-11-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=jIqKldCc;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Changes in v2:
 - New patch for v2

 tools/testing/selftests/kvm/riscv/get-reg-list.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/tools/testing/selftests/kvm/riscv/get-reg-list.c b/tools/testing/selftests/kvm/riscv/get-reg-list.c
index 222198dd6d04..301761a5364d 100644
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
@@ -407,9 +409,11 @@ static const char *isa_ext_single_id_to_str(__u64 reg_off)
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
@@ -932,8 +936,10 @@ KVM_ISA_EXT_SUBLIST_CONFIG(aia, AIA);
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
@@ -988,8 +994,10 @@ struct vcpu_reg_list *vcpu_configs[] = {
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
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-11-samuel.holland%40sifive.com.
