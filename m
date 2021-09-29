Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB2X52GFAMGQEOHW2G7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D479641C793
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:57:46 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id s8-20020ac25c48000000b003faf62e104esf2588517lfp.22
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:57:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927466; cv=pass;
        d=google.com; s=arc-20160816;
        b=c2Vk/8P7W9DISw8DaFnVTsQaXckGGAGEWK87uX+WsTVOLE6/GYgc9KBcyrKRUQmlbR
         jDpHy9L4OGI5f5x9LPLqp5Nf92MOKdSlmWmHI/B1QpH9RYyTJGv+SBGCLIJFA2WKgGls
         F4DE5Bjr9xC0Nvu90VhMEYuA9158yxsuvA0OQb1xkJJFIEGJuTawlYXP+Yn4PoXZNibj
         zIOSVXvs1qqvrQFU0HmcKG6qAsIgcYSSbkjzn5yGGHP1e5tIERNcBzYypNB5qVOtf6NN
         +V/Iox5sexH0JiwdAGa0vnyv88kWW31td8PT3n2kXoCgslygaB4cWGHDPzt/wqnhGRyl
         vH9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=yIcKYhWrSjdGNQN6MmrSktJ8xjGsYMaQYK32b2TgvUM=;
        b=CkVoDdxNaECpuFyCCuxOniZxcP1haXYcBAlZX+desNQohtsW4wuAuM8fX9W7G0Y75t
         73YIfYnE8ybu0qyaK6uFscEKnP0aPPWSf8OLjcwUTZjcgQ+hrzKlz/iqhirZE3NVAM2U
         3FllPUKuwts0x0wZAx+o9AM5/zObwlxGyavFe/jVZTuuLT4IVTzoNM39PM6dwpPlj1bi
         w9UitsWpRSoONWtkSxSadT1udN94sKmuBV9WMQZ8wUKNOOv3vtb5QsZ0x8ylPM9XWfFw
         9b/MFc88RpUs0gzhokRROGz57IH9rl3KS7DjV50pgz7oXDPWevaWik10bVocmEOZuqL6
         P89w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=QXbTcDat;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yIcKYhWrSjdGNQN6MmrSktJ8xjGsYMaQYK32b2TgvUM=;
        b=NsvA9oynhwRXxflX5X88lKTVzxJeHxJBu3hRA18ubLRpQNuN5PKX3zej8qFZexpRe7
         Q5qRH5C9pSArk0UEb+y8g2efzS9eDN6ufYybkKdX0j2/IdgeafOs3C5ZMtPY1o+RhGCv
         zo3iwak8CYV1xQcLx3TrungD4i4pqz48DbOUH5y02fOd6TtzUVZKKOXTbPk0NgQZd7xK
         wXudMXANtvbvJz0D7Col2JXLJCPptXDLdc/PK6lzr9hV0CzpYy2m+hZHREp6kwa4xmoc
         lPY1/VqC3IaTQboXsDMMuOgVfA5xdEtEL56lpwZSksS2limmvQxIbZsyL/43qV6gfAe6
         +2nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yIcKYhWrSjdGNQN6MmrSktJ8xjGsYMaQYK32b2TgvUM=;
        b=XrPG9hv5nqYKm9cH2oIxNA5NoLIo+JGrJSLUJVXVKMPjm27OULc7vMg8MO84OVYvLt
         +vvLGfEifI+qt6PVD+iuY56DGkL4PcUMYbjwydokesAPnpi4TlELADGaLFzZ1ehguV1j
         QGccMcShz0+VTgtMelyrIhIi3bTdOWGbh8UasRrv2HovNh0CtOrietxIptSh5kzbD7dJ
         4dyl7su9lR4beKYx8+EQiMP9L57VrR6616VtcQx/sfH/s5wQOSXHbQa/6ht8IZYcgB3y
         Eg/e4kGD4xayOeWIj2ozEEJk34decdmt4Pi7QjX3AIoa7YLKCb3mf5xVZbNm+7HbXhUU
         jJsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531E9IAY+jSg5pGNB4iYc/GcCOBLZA3RR8gItsMSbAsEqytSRUju
	Qh7AAXCsLow3D+QFf9C2mw8=
X-Google-Smtp-Source: ABdhPJylQBqOa+hvvy29x3cBXL21vysiIyt0VPt1v2YA2NLOnkN0vh6OJJY2ePYDfRt1xCiY26ttnA==
X-Received: by 2002:a05:651c:b1e:: with SMTP id b30mr322137ljr.341.1632927466442;
        Wed, 29 Sep 2021 07:57:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls584337lfu.2.gmail; Wed, 29
 Sep 2021 07:57:45 -0700 (PDT)
X-Received: by 2002:ac2:41c6:: with SMTP id d6mr154997lfi.400.1632927465613;
        Wed, 29 Sep 2021 07:57:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927465; cv=none;
        d=google.com; s=arc-20160816;
        b=gQvgBFMbVRieKaJLTrYeDb3bUyGCWJJvUMIPyr/ycFNw7qemrtzvhKAoOC/G7JamD8
         H8t6t0Y/5M277Ov94okePLdeCRwsxMHIuGGDmioORG9SOKHajvqztVtpXwfnQtg3cC0h
         QtWf+23BPkveGvVS1W5xBaChYgvPPnujWjUKGBNEA6GX54329XVRPcGU6nMOs4OqABg7
         9s6M+D85NRGafabXj3cg9yV8CXZnIlr0/+tKgh/bP60OYj5K1BeWY7mWlkRsL9fE8bc5
         7umonymOCwtC6TyRW0xO6pvXQgTex9wjvBJcsc6OU4hrg5bhF3hHI4RCbtni8ryFgDJi
         uJjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OQKNU2zsWxm9Jo/LuBgWw8xEdpf0SBZ+oU39CLxAstw=;
        b=06V/pPXnsi79/yPHqeugxMmlhmxTaYiAO0BBOnco8AIefILY7T4WRnEUdGUAe13lxQ
         pMcbcWOWo5WwitMt+6UaubWPdjUu3ly0J1z8SFsmLZYA8pteBKT5/eeL7EEh4zPZ1e4z
         b5x2FNcA1S332swtX3mB9vKtNeOf3GheintIr7jD1JXdmFLY1lANTP2pkL+lbZ2WFsFg
         FxAaKxvUWkIrz32Ut8kiP8LNcuL4O8iTDBjDtQU7LL1ALvKIL3ko8/wKvj4/hk47Ljwg
         e759JFbpRelrYgPnM1oMBDgGIpQCHn9zaC8zFPEr/qVKF4rBQ4rVNonJqaOgXXCOpmeV
         YPXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=QXbTcDat;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id o26si5178lfc.4.2021.09.29.07.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:57:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id E3DDC4019D
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:57:42 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id y142-20020a1c7d94000000b0030cdc76dedeso2825327wmc.5
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:57:42 -0700 (PDT)
X-Received: by 2002:adf:a4cf:: with SMTP id h15mr370301wrb.56.1632927462556;
        Wed, 29 Sep 2021 07:57:42 -0700 (PDT)
X-Received: by 2002:adf:a4cf:: with SMTP id h15mr370287wrb.56.1632927462418;
        Wed, 29 Sep 2021 07:57:42 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id a25sm1888009wmj.34.2021.09.29.07.57.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:57:42 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Palmer Dabbelt <palmerdabbelt@google.com>
Subject: [PATCH v2 06/10] riscv: Explicit comment about user virtual address space size
Date: Wed, 29 Sep 2021 16:51:09 +0200
Message-Id: <20210929145113.1935778-7-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=QXbTcDat;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Define precisely the size of the user accessible virtual space size
for sv32/39/48 mmu types and explain why the whole virtual address
space is split into 2 equal chunks between kernel and user space.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Reviewed-by: Anup Patel <anup@brainfault.org>
Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
---
 arch/riscv/include/asm/pgtable.h | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgta=
ble.h
index 2f92d61237b4..fd37cc45ef2a 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -664,6 +664,15 @@ static inline pmd_t pmdp_establish(struct vm_area_stru=
ct *vma,
 /*
  * Task size is 0x4000000000 for RV64 or 0x9fc00000 for RV32.
  * Note that PGDIR_SIZE must evenly divide TASK_SIZE.
+ * Task size is:
+ * -     0x9fc00000 (~2.5GB) for RV32.
+ * -   0x4000000000 ( 256GB) for RV64 using SV39 mmu
+ * - 0x800000000000 ( 128TB) for RV64 using SV48 mmu
+ *
+ * Note that PGDIR_SIZE must evenly divide TASK_SIZE since "RISC-V
+ * Instruction Set Manual Volume II: Privileged Architecture" states that
+ * "load and store effective addresses, which are 64bits, must have bits
+ * 63=E2=80=9348 all equal to bit 47, or else a page-fault exception will =
occur."
  */
 #ifdef CONFIG_64BIT
 #define TASK_SIZE      (PGDIR_SIZE * PTRS_PER_PGD / 2)
--=20
2.30.2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210929145113.1935778-7-alexandre.ghiti%40canonical.com.
