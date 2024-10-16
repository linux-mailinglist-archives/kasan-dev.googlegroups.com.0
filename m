Return-Path: <kasan-dev+bncBCMIFTP47IJBB5GDYC4AMGQEOTLTQBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C8ED59A13D1
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:37 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6cbe4fc0aa7sf4214036d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110517; cv=pass;
        d=google.com; s=arc-20240605;
        b=lJYUl2lgV0KNT8N+/0A7mVLHtZmGFOmN1E4qXQ+ix0/6v/FPr3fHC7A+2+Ixe4+DMT
         iPEi0VqSIwH7HlU7yEBQNbdoxXnGmzqe1CUEKzViuQxyiWyxOxg1SkGR+RyYwLfDTxVA
         CnVMZnVcqgMTHC1LEOJvHSXli/55vvSjm9jc88NkbQB3mOeg3zmV9oU/NhVOnsGrqsVr
         3G0roYBqXx143dmmEG5PmMg3nCB11tJ+VNAVCzTOvsnIhXbsBTFZT8JW6ggujNngUJX9
         j6g1vx5iDsAIhdTD/ta/W8/B3LpHs2bC3y82sDgfvLwX+J31zduhwk+xuq00gLChh6W2
         muaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z+bx6eesWTcn/AnnslyXAMyqwevDYjO2oWgK0MApVBI=;
        fh=py0n6rL5oaB/Hg2fTcO7BPI8CoTCYjwJOdwEClwbSIM=;
        b=O2dIOX6vxwfd+RPC0Tgjkk62VahAPY9lMVs9DgtGN3XPjHIBMFA667cZcbGK7GI51n
         M8McB/z9ZuR1ywm9GjL8D3/Zphop1/hvxd5PuEmokSqgXgdXLCixZGTXDv1+rZo0t1PE
         nE7x9ky3eTI2+D1J41E9z6QXDO/Xslk39sjNTyajr6wdUWSB7Zi4ewbGZxi+iEa+rdvk
         nD8viLzd2sndTzy/qHAJtTYDdaNTjxyY/7jNRiJSbk0PfGVJLzIBqHtYUUuM9rYrRhgL
         CL9ofh1XW74WYhnmGiJu7W53AhhoaXEfbExAWGhYHBAjg/BN2sJ1+1NPriu0LQ1DCSz5
         e9jg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gEh3ILgA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110517; x=1729715317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Z+bx6eesWTcn/AnnslyXAMyqwevDYjO2oWgK0MApVBI=;
        b=ROSu31X5VQeUesPmOnhjZ3S5QNC3ihg0+e3XKRWMrw0zZSGw84F4Pei2+01nLCNFYd
         LpfIMA2nMavMpe4xsjHWLOIsFHg93uBnuEUCku8vDX5kTwDYtOkatHJwVK03JU7EoTfz
         2UL9rWefqFeZcPoa/qZcPSUCI8KNEsrxSsFFpOQ004gOyWdMAdJ+zvwZqODlHxDqFf+E
         B5BaSfoV9uqOnKnMQWC/8zFUF7WRFdfx4HvkhYfw4Sxn3f2VafYT09+4mx9eYGtkoopz
         C6hiQzcmswShKiU3i5sACKwz+8F3shEwYavieeJyYxYdLJ3FYhAES/YzzeZpajwBwGvD
         glgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110517; x=1729715317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z+bx6eesWTcn/AnnslyXAMyqwevDYjO2oWgK0MApVBI=;
        b=OYYeVReKd6Rh+VqTBPJz8ImiCjWSMaUqQGw0H/29Y9Gnh7YeBlx6YnQR9YXZmTxkae
         pIgq7x0eeK8KCe7teAl2NVKICc7bgZamniwRpqoc+NrrKni2B8fuTKJgKi10SKzR3xc7
         80m7ivvy5tJOpvogSgEuHkQFG5B4D7Skoqq4gYmH778wKpQlBcJLBJQqTmGTpyf3XQOY
         N749czLQZjbs73vzPuM+3iq+JPErPPe1TIBTt1iv303jeJKV1y8cMigL074l+dJRxdRO
         +8phh47ZULmrIhIwf73jjupfwXhK5V8s9t/Euhbk8YPfKxW6fdlmRbJdkActaDGERoW2
         liiA==
X-Forwarded-Encrypted: i=2; AJvYcCXRithWMjqyb4iDRn3Wx2oZTNysp7xWv3opY9VzTcBetnuMlZg6600eYGJMSDBxaPcpNfULgg==@lfdr.de
X-Gm-Message-State: AOJu0YyEOcCxN78MGVLF8w7i8xmBVBYnYvjIVVhliVJt9QqQ3WdVkli3
	hp5IElZtQV3ZTyP+lnr5W0MkQmSmECi2MJQjvS/SWg0+uyArQQRg
X-Google-Smtp-Source: AGHT+IEa9XokrgmrfMfHMPdZ1uMzp8uiRccN3eTb3BQpfmPlK9h5b0KdBAkXddDTF1sQW7Tx0iSK3Q==
X-Received: by 2002:a05:6214:5542:b0:6cb:826a:f20a with SMTP id 6a1803df08f44-6cbf9bde0a8mr275269516d6.0.1729110516637;
        Wed, 16 Oct 2024 13:28:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2628:b0:6cb:fae8:5fd8 with SMTP id
 6a1803df08f44-6cc36d8fc9fls4579606d6.0.-pod-prod-04-us; Wed, 16 Oct 2024
 13:28:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnTmcEd0614WvS3gTjlRFxDUXfbbNXCXgPb1GnK+ThK3L38vvAixE4kvfQOZcmLdYA2b9pvb1Zwps=@googlegroups.com
X-Received: by 2002:a05:6214:4283:b0:6cc:2c33:b974 with SMTP id 6a1803df08f44-6cc2c33beaamr85394476d6.47.1729110516082;
        Wed, 16 Oct 2024 13:28:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110516; cv=none;
        d=google.com; s=arc-20240605;
        b=WI0DE6MvfBGiBk0OYS4n89khZvqu48qqv7w+Zub2rWiiZSUkmXc/QJ3R2Jp4wmpPa9
         KwEUrmyU09f792/Gtxi+b3JDGICvb5EMgkn1c9CFWdfcMSBsOgsGaBTNKVTc9Q+aZ3wC
         T1tJC2P2KTPIAOAx+r5JG1DwX4rQf0EdeTaOQpQ0YgWHb0SKUcb8GxmQ1Vda5tgUwQj/
         bYxLCjxP2TDaSbMyGTfJLWwDjoXdU9t67aPZclAjIkY4Q5An7Hy2fr8tf9bYsPl52Ofy
         JXkt009wYIyfkiySuoXPES3VT+wgrezfn47Q+EqI67Rh6JTirP1sMhwo9T00ra164SHx
         yBuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5WI0PfAqEvWugCZ5STUUK7Rk7SGo8azDpX4lf/J5+9s=;
        fh=eQvztDynsqjdspFnTJEbcquCfU/iBPqGAE6SAPMXZV0=;
        b=GvxoWzP5RT5h2i0yAqIH0eAZM99wsUpZaZfcRUlJP0SjGzMCtACxurx9K7THECu7NH
         6p8y9mqybc5QxN8KSTUb1OvZ2uRUVNLQXtnz0gucN26KirM9bI4vRTXnvJSPO0I6NGQd
         7DcYgs3qxPMIwyWztLaQ0YZ+b2nWlwpjTJWdoiXxM6qm2Fx/6I59Bo1FAUhGLIOTWXrU
         tBLwutKxtS7wSxQ9tIjsVB++khleab2z0Nov1BOiTa7U6mXSDgIDzDYtrFLcGnRRY0eA
         00W6mNqyH2gRxA7Z+5BGAQC+GwzXrDyyWdFBDf4PlzkWPbLpUX00Cw1tIuMPkQgIWVEJ
         C8RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gEh3ILgA;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cc22a06f51si1804296d6.8.2024.10.16.13.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-7ea6a4f287bso153132a12.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVftXtJ0H5996adDnBTTwJocQ648MZ2TdBHa62EVqoqjOLPj1B7RvWkWEddtg8BCSEbTWknzRrPeqI=@googlegroups.com
X-Received: by 2002:a17:90b:802:b0:2e1:ce7b:6069 with SMTP id 98e67ed59e1d1-2e31538f1camr20096845a91.33.1729110515177;
        Wed, 16 Oct 2024 13:28:35 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
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
Subject: [PATCH v5 10/10] KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test
Date: Wed, 16 Oct 2024 13:27:51 -0700
Message-ID: <20241016202814.4061541-11-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=gEh3ILgA;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Reviewed-by: Anup Patel <anup@brainfault.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-11-samuel.holland%40sifive.com.
