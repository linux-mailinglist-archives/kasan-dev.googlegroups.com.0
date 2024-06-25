Return-Path: <kasan-dev+bncBCMIFTP47IJBBH7E5SZQMGQEPVPFKMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BA2A49172FA
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:52 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-377165d910esf6585985ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349791; cv=pass;
        d=google.com; s=arc-20160816;
        b=ii5li2fNbUP8Xk7jzepdzwf3y/+RGJokbk+5LxXmiY/U3INWd+NU1HLSYCtGm7Ioql
         dqCv0CwxkKFhsOCZA6LZXXPSl7NXHhGZuFKce4KhWS547GB4s8JPaU8X95JFANLdUcDL
         98aRpypluMTRgl8qV8ZjM5cESV4xcF3W+QGq8r64bQ9q0L7tiEdZQL5zyOIBQz6iHeUR
         kAdBylZVeH9E6BpYa7lgs6020R6aoW8gU7mf8CVARJG08aMIJlD5iD6t4z8KlwLDkS/W
         YONw/nTQNj1DdCB64Qp5zBd339yt8se1YkdM6gv8ozSH8Nalk8iJ8SVRE3Vgl3PYr0g0
         F4Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=H0elFjwZo4Z4WtqoI6FzT/QiqG0XiKZrYIl1l/4Wcvc=;
        fh=Ggnt1VF1wLGimEwVbz3xJushoYwtqKGgpcl2xDz6DTo=;
        b=jbKN9R27/opFu7IwHYXfcw8QbBVtflNiP0roDWKNh9jlNCQ86i/V4RugEVBV6XRShN
         zaJdKt8q6hng3Yu7iHYnVb4HSqY0xMOl5515VAhGn7jgNsyjYEPpsp2xNXUWQ9ModHe6
         nB1Yo6wypXQxFvYHtmALTpk0WgWZFXZXhFcjZsxwNdLEssWSxzU/B5TO30q3y3C549eZ
         eG2SNWZRizylHlkTe60KX7h+PYHEd++heG51Rfz4d/IcAyWuK0KdmbYDJaUROtzw7HeG
         yCnla/C69U+Yqm8UU3lfLTdVq49AX0wpj8L026tulE4JSCbuzLbxqtWpXn7tOgrI6sIP
         5MRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gWNKvKOl;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349791; x=1719954591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=H0elFjwZo4Z4WtqoI6FzT/QiqG0XiKZrYIl1l/4Wcvc=;
        b=U4wO80xmoImwelj2kSWhxePa80mVu5NZZvLATc8eCuYnBhp4hO5Ybk1QGeblpwv7qa
         9Pu4+jgg3ue2RE+hh4MWB6Sx+3X5PCzlgJzOhF93SFXPJytMm6OB5d3USJK1YTEUKFxS
         Rw6S7yqu4Rr/KXTuBJ/Q2R706HGjtFTHUO68C9EytpF8eWvcBv20Mbt9UPhOYED457+l
         0r1RLhvPaOTWINMmGKSQHcFX0GCxoTOmQXgr1HUyDzYjl1DqddXuQHsIPRhzrJ92NhNQ
         EOjvx8jnrqCEg0uri5h1kJSsstke79xkV3vxT+xxE8zRxxGWyi0la0ecaS8Os/x48Snq
         FFbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349791; x=1719954591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H0elFjwZo4Z4WtqoI6FzT/QiqG0XiKZrYIl1l/4Wcvc=;
        b=dIszKuQkUTDsEmnloLDzDh3MCKU5mdvlAX8/alL0zFmKR4L18fsaEMmoe2wMknJidp
         R0sypu0nPzysKa/YrSFgEceVlLM+FtC65kQQBua0koFx+vWmRgbnImRlRC9Pcy5E/eA3
         pSpmsVzH5a//BTPJW2BY4i6HHKkaWVJqCXEF2Ow+/b7D00WPaRFt4qND+bUwIl5yZYxt
         RmSWHX1VCsMm8fwZeG0G447GvlGEvJw7b/v9LxozVsk7tGBmYG4VpScHqRO5SCls4UZl
         3BWgHePJ9iQRAk0IPj0/iVilY+KPlDyaQXXQTB0h/lwVRujOs0GPCNNtaLHwmEUt7oiw
         657w==
X-Forwarded-Encrypted: i=2; AJvYcCVZ7CJ3wF6eBJeoMjxLuxgqIYH42Pb2v35qVP9qARclehYbO5Kk5+ioyRStCtlDG3pUV1EELQ11EKgH/FnqbdD2V9urK3lTbA==
X-Gm-Message-State: AOJu0Yz4/Fq4cVGx286T6T/+St6FGJ2AKP2icaOovqC/BTRAReyt44DB
	K04RF8beeTu2hl1TQW5QJ/ER4ycFxws0uBcEAWFjIkOEUX92VOnY
X-Google-Smtp-Source: AGHT+IGEwh+sJR8BjSkUJb5+7OBt4v/TXcgupr0IfArYcM9yfaKWTgcE6xkNK+ZAncWwW62j/0L26Q==
X-Received: by 2002:a05:6e02:12c2:b0:375:8a71:4cbe with SMTP id e9e14a558f8ab-3763f695927mr103466425ab.21.1719349791502;
        Tue, 25 Jun 2024 14:09:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a03:b0:375:ae19:e63e with SMTP id
 e9e14a558f8ab-37626b1e54dls49817175ab.1.-pod-prod-06-us; Tue, 25 Jun 2024
 14:09:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYkQ46gNoQHDVscsY8/Qo1TdQ3i7i/ARX75R8rFjzq7I4imXOe5raeTCpW2FOjjEExC3Loh8nK6qfc9IYJMsr60DzY9GvleBFKJg==
X-Received: by 2002:a05:6e02:188c:b0:376:40f2:9b26 with SMTP id e9e14a558f8ab-37640f29f72mr104060925ab.14.1719349790678;
        Tue, 25 Jun 2024 14:09:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349790; cv=none;
        d=google.com; s=arc-20160816;
        b=bEsIScl/DyVAYhHHL55YejYdrmxI7xwrp1iBCb+hl2HrzEOmnXp6yuq2YJsaiUypuE
         7ol9MvwWLYadNH0SS/5ZmJth0jtloicFMWKou3APAZiYAGJDb5Xj0ijWsU01TuVxkzdo
         4+dTeAW1gGZ16QhSNFGCIxCk/DXLiWSp+pCUv8EIk7+Fo7crH4MW/4Uq1xT805D83NBm
         Ijk7OJqp8+W+R4wEb6j8uf7rhorFjtZ61wNfshQjmPgD/zwxXjbMBKX81f2DOB8CHtev
         j7qJmhn77Ja//qVAOx0Rw2j9lk40aB16DGIAoyuE+wcrGDWrGT7CK187Ik/MJzK5TcO3
         YBfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XfPM04Pyb/lGY9Q7saAL52HDlLyxzOizf7aq1c4K5eE=;
        fh=hpmgi6asv/o6qyvHMIlOk9tIpada+1+7WgmLGAOcJNc=;
        b=HRg8ABg/QWH4iEuScyPQ47WFTpzoA/bCE5BC1e18meYFpUtF+kaAc+GW11qbqQmIhO
         L/JNcdZL08fZA+roUTHYsYjI4kqWx9B2jIzElKd39rnrGc+++JRbOq8uaPZZyCUcTtp7
         m8KrgMEfjG75JQW2ljucBSOZi/cTQPuNYCF9X15WITiq7/xl7856EvLe7MaTFTDIPiDY
         oEyVhhC0JAuoTVz1PBOu6NcffbeIXgbAp5msKFhw9q2RYMGuWkKTUP1k1kp7HtHMfvx5
         gAsU1vcT5tuutTdfkJjwwY1rJmGGgxfqQ28XoL2lwuVYfEIDSdpndEpoyCDxAL36GcdS
         0SQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gWNKvKOl;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3762f3d60a9si4456335ab.5.2024.06.25.14.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1f4c7b022f8so51410295ad.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWGTaKTpVaUgtk0CpWvvDo7szeYS0ECRf8kAO6SSjb/3nbkc0xTFkkdzM1/7OPD5E/kV72uqvAap8XfjTypj31qtFyHXzut9YFcSA==
X-Received: by 2002:a17:902:e5d2:b0:1f9:c8cc:9df4 with SMTP id d9443c01a7336-1fa23ef7f7emr98497255ad.45.1719349789879;
        Tue, 25 Jun 2024 14:09:49 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:49 -0700 (PDT)
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
Subject: [PATCH v2 08/10] riscv: hwprobe: Export the Supm ISA extension
Date: Tue, 25 Jun 2024 14:09:19 -0700
Message-ID: <20240625210933.1620802-9-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=gWNKvKOl;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Supm is a virtual ISA extension defined in the RISC-V Pointer Masking
specification, which indicates that pointer masking is available in
U-mode. It can be provided by either Smnpm or Ssnpm, depending on which
mode the kernel runs in. Userspace should not care about this
distinction, so export Supm instead of either underlying extension.

Hide the extension if the kernel was compiled without support for
pointer masking.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - New patch for v2

 Documentation/arch/riscv/hwprobe.rst  | 3 +++
 arch/riscv/include/uapi/asm/hwprobe.h | 1 +
 arch/riscv/kernel/sys_hwprobe.c       | 3 +++
 3 files changed, 7 insertions(+)

diff --git a/Documentation/arch/riscv/hwprobe.rst b/Documentation/arch/riscv/hwprobe.rst
index fc015b452ebf..75fbefa0af26 100644
--- a/Documentation/arch/riscv/hwprobe.rst
+++ b/Documentation/arch/riscv/hwprobe.rst
@@ -207,6 +207,9 @@ The following keys are defined:
   * :c:macro:`RISCV_HWPROBE_EXT_ZVE64D`: The Vector sub-extension Zve64d is
     supported, as defined by version 1.0 of the RISC-V Vector extension manual.
 
+  * :c:macro:`RISCV_HWPROBE_EXT_SUPM`: The Supm extension is supported as
+       defined in version 1.0.0-rc2 of the RISC-V Pointer Masking manual.
+
 * :c:macro:`RISCV_HWPROBE_KEY_CPUPERF_0`: A bitmask that contains performance
   information about the selected set of processors.
 
diff --git a/arch/riscv/include/uapi/asm/hwprobe.h b/arch/riscv/include/uapi/asm/hwprobe.h
index 7b95fadbea2a..abb7725fd71b 100644
--- a/arch/riscv/include/uapi/asm/hwprobe.h
+++ b/arch/riscv/include/uapi/asm/hwprobe.h
@@ -65,6 +65,7 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_EXT_ZVE64X	(1ULL << 39)
 #define		RISCV_HWPROBE_EXT_ZVE64F	(1ULL << 40)
 #define		RISCV_HWPROBE_EXT_ZVE64D	(1ULL << 41)
+#define		RISCV_HWPROBE_EXT_SUPM		(1ULL << 42)
 #define RISCV_HWPROBE_KEY_CPUPERF_0	5
 #define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1 << 0)
diff --git a/arch/riscv/kernel/sys_hwprobe.c b/arch/riscv/kernel/sys_hwprobe.c
index 83fcc939df67..b4f4b6d93c00 100644
--- a/arch/riscv/kernel/sys_hwprobe.c
+++ b/arch/riscv/kernel/sys_hwprobe.c
@@ -142,6 +142,9 @@ static void hwprobe_isa_ext0(struct riscv_hwprobe *pair,
 			EXT_KEY(ZFHMIN);
 			EXT_KEY(ZFA);
 		}
+
+		if (IS_ENABLED(CONFIG_RISCV_ISA_POINTER_MASKING))
+			EXT_KEY(SUPM);
 #undef EXT_KEY
 	}
 
-- 
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-9-samuel.holland%40sifive.com.
