Return-Path: <kasan-dev+bncBCMIFTP47IJBB76O6G2QMGQEQ7BD7UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CE3F951650
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:57 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-39ad7e6b4desf81440005ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623296; cv=pass;
        d=google.com; s=arc-20160816;
        b=FlWVZ8BGVPx/s5ff4akIXt3f3pq8YRKmGMEnaoVPPlp3Wrp6qQ7qakq8sRsDdu8jsn
         4oUnXKSDG77wrNWajCNNQU7Kw4FS+KQHMRUmuxrKdvL4dEgghUAjZh6qY72XhoolQuMb
         maGLIfX8Mo2QQvhSt8GWODWvoGkz5unrwSw6okapdaLaPwTsUp3BoCLr5+Yh5vXeIvPQ
         gvdrobN+cyTEUxiPrNklz34lLC6icKe0I9u6MtjQVeYD5wV7OzXr4HX2F6Bel04vz9i0
         vytrDbURMS+XRgFAyfggXDoPeUCAG9a8VolZkPZYesV/tpU3d3ucGNgIHWeO/iz1+opm
         +wFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=g1NSadtp79SFHzbmBKUOEKhA+sXUU2Wg6gzhDP8Za8E=;
        fh=uLknu8wEq/IqAHpqIjrEj5XzSFWNF/Dk6iSlh4hLjM8=;
        b=Jhx2gFrB01oo1KbvLiiKAg2H7RmTYg7hXaWGxeojM0OAuCkjro0T3TjTpehVk6CBZX
         TT0O9PCoXG3HNgKEfm1jIfP2V6+HHwO+mSOgZ4RPhoPmPqQliK9cTI3F4NyeXeRbCoN/
         JJcfBpis9FssYbeb2YtlHlofX0a9358zs65f8JHZcldaxC66lECJXXbd2dENUJ6lyPuR
         V1jeEn2SaXQVdd6xpOLVmeqORuv0kDz01nU2KiRgXBEUw5qOxnB0kqGYr0lTuuIn/7qP
         DFtEXs1zqRNO+ktH2H34Y8lwVlfU/r4PmrYs1tYKUIUI73MGcI2SW3NRoYBLnLg0u2jR
         w8Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=lM1NXg+Q;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623296; x=1724228096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=g1NSadtp79SFHzbmBKUOEKhA+sXUU2Wg6gzhDP8Za8E=;
        b=xeE5Oaf7C/+o2uQkrUuq7UMFRtbuCymxZKDz+jktHOQX4dX4PH7X2vHFHeRA+aYAu3
         f0wzQat/b4SC9L2+5bIoTGkJhLVtz30m683LY4q2o7+tiI4OBrW27MiIkfJuEivNGseu
         KVY7De+kUA9W8eBXGz8CJIGR9FCGdnVqggTuZAYXMYcIY4v55cJxjpKg31GEZU/1ppxq
         4apMuQEBpuzRhF6BXVus9eoYFzilSrfsNjqzh6mhKR1Vn2lN4/m14Oyf7rXyVWMtVdD1
         zEe8zHzvrLPJbJHVxBYLf3AhHHb0SyWOIMu9HZIRZmdOv1F7T+DpNKgXYvHqolPxXD/H
         WrLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623296; x=1724228096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g1NSadtp79SFHzbmBKUOEKhA+sXUU2Wg6gzhDP8Za8E=;
        b=uEuD/yB5uQypSBcTq05lfFGnFn3sFp/TTukiCn29Mjtnc+AiN43itfkcvfDPV2Jg60
         iVdMwe85Scn65o2XLXAimpU7a3mR/t0jvmvre2f3yH7T4TzdLrNxbHDxAU4rnY8DqgwR
         qyHHykNDQEaW6ugZLPNSFbCtDWs+km8wo8SWDlAP2ljWkraNXyjfrqjVvIhApg9bxtuV
         MkKv/5MjY8yr0+XpNdO2AjyRsA/qZJWkAu8q1yXBFLI1+A3jHIq/cQOH++0t4U38PcN0
         wJLl8nsJXdmksyngQBAFfxu+SAumErCp6CEBX1e7FKX5mad+iHDg7JNZzjXuAxo1Wd27
         84Rw==
X-Forwarded-Encrypted: i=2; AJvYcCU8YOJPM7n/1DGMRj/tr1wSF7jPe4FOF+dxKDRCfBXNIe4sUXwZ4SMMU9ULI9npu454keXEYA==@lfdr.de
X-Gm-Message-State: AOJu0YyIVpiC7qH8zNxA8Hhqm1ipxQIsF0B9feh0pNN7TwKnDVAT0k/d
	n/QYO8GurbGbCi3cnhay5gyA2IE/76Rq7lyIDg2eNM+lLCliHhmg
X-Google-Smtp-Source: AGHT+IGGBrYmTm40l68kCGrd3HlpXeP3GIfkz5pe0sGhJOavCY7N82DDxvPyiDmLq1VcubRiLzC9Bg==
X-Received: by 2002:a92:c542:0:b0:39b:3380:e5b2 with SMTP id e9e14a558f8ab-39d12445bf3mr26585365ab.2.1723623296011;
        Wed, 14 Aug 2024 01:14:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e13:b0:375:a4ed:3509 with SMTP id
 e9e14a558f8ab-39b5c992e07ls1310275ab.2.-pod-prod-03-us; Wed, 14 Aug 2024
 01:14:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmp8yqCCrQLpREt0H+1mgLLUVuhMkhBIj0DEVotC65hx7wdv/qwmQTXvZzhT8GuMfSLsSS3T8H1Pk=@googlegroups.com
X-Received: by 2002:a05:6e02:1c0e:b0:398:81e9:3f9e with SMTP id e9e14a558f8ab-39d1245c2d6mr28789925ab.12.1723623294992;
        Wed, 14 Aug 2024 01:14:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623294; cv=none;
        d=google.com; s=arc-20160816;
        b=b7ZL5E5z3LuzUqm7GlVzj7q4GnTGwNd6Rw/1Y9nv9pFOL9NiIivNimm8bkYmcBEl0J
         EXcE2ErI+7V/TJl/KHi+6BmfB26iLZpPWEcYzbwTuYZdN5B85aG0+bj2r7Hnv8QdG5TK
         jbSC4VNFejmOTXJx5u8f1YCR1pTsAK08PeyONVSj78G/6FCdJwEkT6659WD3exJLo4Hl
         YzW6UdMk3CSCdmS+am4xMiSDNFQqE9R8d5nO63l6ntvXsyUWdtHe0vRFRlMTqJZOqrjw
         6psKO5JLHi0XDSLuST4DhRGORSaCEx2XD93Pq3des00tbWY2St9V3VzEw6zsrH1Bkgon
         VcRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UVeUN5Mn4knmfhlWREJV6zJkPuiqFserRZxouOs1BJI=;
        fh=w8WImQgpj2ORr72gD3R4HTZgpR9cPQtLyK077a4T640=;
        b=Shg03hZp674XmtJk+kafTVQ87Isobrlr/rtskuGsTKKBfP02afhfqb1pBF8FcJW0O8
         2ugY6CKZU8qd+VYS2G+a03gA083Oo+I+xXE5ul2OyYKEDUoiNW4BYY8JGioMAj+oP40X
         /vUpteQ3fTl9LrUtYezdyqhmwtFqdznpsRKVVep8mZfEz4qAX7j/4ClUMneaU+hGXENz
         RGufloRqWHBEz4lTWzFyKBJwwFaBjTcWhH8mQEn+HM0ouPOmmLmbE1r5oqEr+KwvyLxP
         NgXhjkKZCSOokNS4A/pGN6PWyA8IbjMjSDVGfHr0LKDaX0G7jTmYUJuywNSJVei+EbTA
         fWxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=lM1NXg+Q;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-39c30a9b0b0si3136825ab.2.2024.08.14.01.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1fc569440e1so58411885ad.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfZJYKOVeqGUIEx/XZbToq+mAZ5IJM1wuWD2SJ5suWxEr3F0THTsMstn0zaVstF61Gk3UXw3nFPvU=@googlegroups.com
X-Received: by 2002:a17:903:22c4:b0:1fc:6c23:8a3b with SMTP id d9443c01a7336-201d63abd21mr31984405ad.17.1723623294220;
        Wed, 14 Aug 2024 01:14:54 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:53 -0700 (PDT)
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
Subject: [PATCH v3 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
Date: Wed, 14 Aug 2024 01:13:36 -0700
Message-ID: <20240814081437.956855-10-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=lM1NXg+Q;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-10-samuel.holland%40sifive.com.
