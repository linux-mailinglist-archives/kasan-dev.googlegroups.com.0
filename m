Return-Path: <kasan-dev+bncBCMIFTP47IJBBIHE5SZQMGQECMOHZUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 833179172FB
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:55 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-3d2495664b4sf8463414b6e.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349794; cv=pass;
        d=google.com; s=arc-20160816;
        b=L48xFS7L5Kk5D4xmXBgDKcLMoFYwsfwIKi/xD/KdbxrOd6Ba4KizkxSofelUqUVnvM
         Clkj89YH8p3ATHTvvHbrQOTvZOZ0oi3PtE7WdnvR+d+kLjuvctg39prhcKcLVJcvJOxM
         DDDn9k6GOmGBXW2JEEhJvBSSAMcKJw32SLMeHmB9I0LMXUMB2wjFUknwQ4STgN90y25w
         3SGOsw+1GTrE/9tLzZW4GanBTo3Fo/sfhK9z1o3Ej0LmyqJlPJFfSG+6ad7fvwVlV2dL
         NzT9QGg0UmkSa8WiUaAirI/jd8YRNMS2vEFaCk0y4zNT92MQRTbpYypVJdmEUvohPhnq
         m25Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mnkozh6YiuPYPsk8WXTw8nN/2tFCVuJrGjz+ajUyG3M=;
        fh=PsI+1cdv8/kqEGzjhpx0WktK5rI98DFTZBEeFaeKRY0=;
        b=DW53Sz22sNoK/6Sp+KgVKj8dPTkz8gSCNr3S0URMOoTh4gUzUhl5f4Rmr/wyZuC2Mt
         MAmuA+qWD0mBL6TTb6B1dg7E/5hyY7qy40hiK+dBTUgowBkVU7XdjRQXclp/lZKUGuIQ
         8FEI/j6A5GrPsl5QBoKGRFQVXDjYK/WHe/2xrubx2htdGdNM1QzWWNXFpL8ZeBeMSG+B
         QDPxPoDUTzxUYtjKhGeQ5Giuiaz8D1x5Bdsd+JupZUky7LMs+SCoNIu1n7V2G83W54QG
         y7C9RQRvou+XaYWzTLWeTodl9D9RuKN4U2DszeKu/d0Zus8WWzleLu5fJ+RcX0zw/Ler
         V8AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=l5MqXp5P;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349794; x=1719954594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Mnkozh6YiuPYPsk8WXTw8nN/2tFCVuJrGjz+ajUyG3M=;
        b=PppZMcXBTjwUdpFbBxnUOo6fZbz5tHqUgcChGP1T+nEh1T6wMHxdSjZxFJceHK808p
         I/B0vrki13sTCZCJmYkqS+AnllDDl1Go6lVmH4d6ChvVDp/ghCbxiQN5N7Pif4lrvGDW
         TUxr3jtJdOKWpwdxTQAOnc4Tp8mJtVQ5bM0XAE05nM0Isr2LQBT9vzNcpoXFxLv1+7AA
         j/63hZYRFpKANk/o/kNsYw69y3fgRMhoA7BgLZ5AlNCmnJGMcxlGTKKjqe015Hfh/w36
         uszhNsvpOa8ghhbDcyD1sGcGKbecKNNNMtLxxeaF7f+2lwHc2TxD7BYHG8zy1THLIYjo
         q1+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349794; x=1719954594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mnkozh6YiuPYPsk8WXTw8nN/2tFCVuJrGjz+ajUyG3M=;
        b=ipwgbtx19yH7YtujapDb5k/zuRfEjljPPVg+2RvOyoo152yNTaKsJfKACmtwvOKG14
         L5TUz/cpOE1A2mSQUDMZrvRgiB7mWQzIIoPSKJMw6EVL60C37JA0w4j4wwvlT//9xTBQ
         4lX5MpYJuKSzVxo584zamXItm1OSK0Njh2l0UOzFi/+12dxsgk42QQ1rx61Ej8gROCl/
         UrvU1UawOREarGeJ/lokT5gkMbTJzpm7qSqI66K59hQ6IipO1TqVRKWL2JkukZA4Ln36
         0bmoQ32+7/j7euK8Uua6w2s++Xh2exg3A+RlCeuWVrhALKSO+GiKPs1pFpqOTF0+IMQF
         iX7Q==
X-Forwarded-Encrypted: i=2; AJvYcCWt4PibEQM8+PuAAwVhVuC7I+78uZI9qzTUrIE4TzM2qnRLQUe2QM15XHBKy/D7Q8AUhi6t+Ve5QaV9iL7Z4IcumvmSKoEhCA==
X-Gm-Message-State: AOJu0YxgxdtI/hUY31eQ/7OWKyjZmJylVqkfeNGitOu14Y1Cvm9fM5vz
	j5q1+WQZzg5XNE7hnqbrb5E5ok/fNYX+omTnzxPI4U8YfLg2/YAb
X-Google-Smtp-Source: AGHT+IEp0Mcf8r61dKrHs1D7BSoPLvctVtBfl1scuH4RlKTjhoQGh2oGXyDapTEY33KkoBb0T3jGug==
X-Received: by 2002:a05:6808:1493:b0:3d2:2414:85e with SMTP id 5614622812f47-3d545963798mr8822126b6e.9.1719349792841;
        Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5dd1:0:b0:440:a6ed:f91e with SMTP id d75a77b69052e-444b4c19342ls87939141cf.1.-pod-prod-04-us;
 Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcHbKb2hcIc2sKOD4rXgjV26GwTUqUGPl9l+0pL8vNkXATME4g61hW5l9LcNzs1jm/9qK5uyhz8tEe56SqOBzxZnjQc035dRob6A==
X-Received: by 2002:a05:620a:31a7:b0:79c:10dc:67c5 with SMTP id af79cd13be357-79c10dc6d39mr113281885a.64.1719349792194;
        Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349792; cv=none;
        d=google.com; s=arc-20160816;
        b=TLPXGF+GntrHj8JIoe1L5pvb6td8XWSOIrTpnT6yPfsCb8yfSH+3yS1dy3KnVICnUZ
         TgVqWprvBCyWayv968CXsB4yUofoElCY/PH8HVG7P+Y7eng3TMfHsWQpxyzrzXvFXP3I
         mpEDTk7FdbVStmRnLodPtlo3Qt1ea1C7EU3gah+U5lX2C0GDRnXnR+LJLxDsC+rbt5pw
         wXRUWRNhX5q2vfmUyniB48FSQmy5/a8ftk/LlFC9d0zrei9dGdEovK2pVlz6aF4oYZvH
         7z0AfBnlZZ3gissLETmGGx6paZNYZN7JvshAUN6HUMcHAgoVyTFwrZ4APcG3Zss7QZWK
         p5aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WmS6vWk00EfafKWbKkl85gc2oDZFAwwt7tuzVTWTGwo=;
        fh=jbFuq2GU6CH/lK8afJNtC4ZK6NTJiTLGZeW8LSH6X/E=;
        b=BjM7VNs33X+pUunL2t/yGWJj0QQs4Nc3i7lMqPmQUjak06SGcisRoq6DtYF8R1pjpI
         VCZKPXHf0VBOYytFuP/hkJ6ONOl80tmc2aPF6G5vb67O9+QPNztWkiaQZToYUQcY0naF
         MntI3D+PbrJaKHBfKYxiWCsg/noVa6uO2aGcQEO8c7+UlMZ4A/BKcU/J17fssUCItZ70
         WkR/CQCOf30a5InHTb6MhZiZ/bIK3TRID917rZTP/NX/AbUNtbUlgWlSh2kyLtTwEJQr
         AB25vF7DY6Xg6DEPiUKVzNFU4I9FL4IPtj0VRLtHZioek+9dVkKh8g/k0NZdZyGsvKiZ
         tW6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=l5MqXp5P;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce4d0851si40271085a.0.2024.06.25.14.09.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1fa75f53f42so6809415ad.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZWrKmnIg+bpcGh1mPm/DAUFX34iwe0943xH31Ztyvw+RkmNLOJyMwjwwE1o2c7s0SBWW130teGwTcINys1/nQZ52SoAbnaOixeQ==
X-Received: by 2002:a17:903:32ce:b0:1f9:e95b:5810 with SMTP id d9443c01a7336-1fa24082313mr90605365ad.53.1719349791487;
        Tue, 25 Jun 2024 14:09:51 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:51 -0700 (PDT)
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
Subject: [PATCH v2 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
Date: Tue, 25 Jun 2024 14:09:20 -0700
Message-ID: <20240625210933.1620802-10-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=l5MqXp5P;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

The interface for controlling pointer masking in VS-mode is henvcfg.PMM,
which is part of the Ssnpm extension, even though pointer masking in
HS-mode is provided by the Smnpm extension. As a result, emulating Smnpm
in the guest requires (only) Ssnpm on the host.

Since the guest configures Smnpm through the SBI Firmware Features
interface, the extension can be disabled by failing the SBI call. Ssnpm
cannot be disabled without intercepting writes to the senvcfg CSR.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - New patch for v2

 arch/riscv/include/uapi/asm/kvm.h | 2 ++
 arch/riscv/kvm/vcpu_onereg.c      | 3 +++
 2 files changed, 5 insertions(+)

diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/uapi/asm/kvm.h
index e878e7cc3978..eda2a54c93e3 100644
--- a/arch/riscv/include/uapi/asm/kvm.h
+++ b/arch/riscv/include/uapi/asm/kvm.h
@@ -168,6 +168,8 @@ enum KVM_RISCV_ISA_EXT_ID {
 	KVM_RISCV_ISA_EXT_ZTSO,
 	KVM_RISCV_ISA_EXT_ZACAS,
 	KVM_RISCV_ISA_EXT_SSCOFPMF,
+	KVM_RISCV_ISA_EXT_SMNPM,
+	KVM_RISCV_ISA_EXT_SSNPM,
 	KVM_RISCV_ISA_EXT_MAX,
 };
 
diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_onereg.c
index c676275ea0a0..71c6541d7070 100644
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
@@ -122,6 +124,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(unsigned long ext)
 	case KVM_RISCV_ISA_EXT_M:
 	/* There is not architectural config bit to disable sscofpmf completely */
 	case KVM_RISCV_ISA_EXT_SSCOFPMF:
+	case KVM_RISCV_ISA_EXT_SSNPM:
 	case KVM_RISCV_ISA_EXT_SSTC:
 	case KVM_RISCV_ISA_EXT_SVINVAL:
 	case KVM_RISCV_ISA_EXT_SVNAPOT:
-- 
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-10-samuel.holland%40sifive.com.
