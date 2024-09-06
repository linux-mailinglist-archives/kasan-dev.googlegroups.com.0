Return-Path: <kasan-dev+bncBAABBGHY5K3AMGQECDGYEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B738296EDB7
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Sep 2024 10:23:53 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e1a91576564sf3881618276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Sep 2024 01:23:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725611032; cv=pass;
        d=google.com; s=arc-20240605;
        b=UnI+dZ2BvnECT8KNRh9u8lvqfPR0b8jdp+xSiw95kA41nSiCZ6hpgjXGkkTscdXmf6
         6bA9BQd0uWgy1+tYjMHP+fWsA3yrUVKzKsFATKhSrytosdTvDbTLWRp92trykS7GI/pY
         a7nZxmJWODic2bRAc1T7BSQQSQjWscJBlvfEy/B0aaltJE1hfWwyBaNsHrHwCFY+eIed
         pSrgSrMaX/lZ3QzYNGMeM3/9Khbdu5drki3JfuBRr/BjektcvqRPByoOGV8x7+aUU8/m
         P1w0KlBz+rq9idHLfnNOWx3YL8kWvtlIG3fN2PrSdRL7f0a4ypM9DPlwxwOQUV1zcv6x
         4ysw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=68m7NQ/lY2IaNh7D+pYDan1wqfQPB5BEYsLtChmdo1o=;
        fh=y0X3bRfMPiDXW3c4MDLNDAhlsZPnOdNy3JvcUcUaAoI=;
        b=gMN7yb3w1/HjBVnlUhHoFcwd7MnAa60pwW2/5W6BAYrAQV6iTeNQHzV4eg1OUywx2E
         Uvzlyg9G4c39VNMjzEa6cvN3gLL+CE0GmsJm/4fnUx/QgsuEZb9SfgtamKVYF983gdIA
         Jr4teExE1mEl/7tCz+8hM5Xmqhkt1JA6I6P/kQY+c6RpJ9S53SMbcgWfoeiupjbCzhA8
         Gv3FoZxwVFQQ7ZLI2pFKYDqs9842TKgr3ajqMfN67uP717qt5DZmrHx+BivNdYR0AyGl
         zyIFUBB7yXBdxJYlMSXQO9zkqU6madLpm4d46UCFsoNpXpjxNCZf854TPXD4K+MPoPKS
         O3CQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=nazGTTq5;
       spf=pass (google.com: domain of wangyuli@uniontech.com designates 54.204.34.130 as permitted sender) smtp.mailfrom=wangyuli@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725611032; x=1726215832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=68m7NQ/lY2IaNh7D+pYDan1wqfQPB5BEYsLtChmdo1o=;
        b=njvho/auwI7ZxUX+1VFHlHpspMYhsuQfVAts1R57yVQiYS95gtX60moo8K+wN7B+Qt
         XTO516lQ09vqWWr2QpkTJDgSSKmYgTivFCIt0P742b/+HV0h3GgQjIgV1eW8LI5/m5l7
         rAEIe+hXmifNQ6P0FXFNImj6V8AaqbjuxCcnPAx3Lkfrosx++fPCRmJBwn0olAmYhkn9
         P5pgHk74kPGtVvxslGPMsyG3I5dJOKrlSGl3r0rd1alvv3puox9yYXBCwyagEL9+s5IK
         pzFTNJnlRXrTIVp2lHYqsgCiDOMEfywSag9U/ogEydYiKiicaznsA6Nk9UJri5nomaRw
         JSEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725611032; x=1726215832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=68m7NQ/lY2IaNh7D+pYDan1wqfQPB5BEYsLtChmdo1o=;
        b=Opt4BLf/VMYuIsLDCdXcT7Egf1rWSbk0EPqesminYndGQs/95qfkgAA4dsKJq+XTvX
         beVQozG3s6K3zfv/MEgBfGe9A1Ge0+h0ovdYR6ZKFso9L+UdPks1ytT9/CMiiMTOp1lq
         oRLG2+lzD0zht+A0K3dwaAVHHo+5ox3Fs9f2CBMUt36ytweizF5cxHoVqAbllGREaPVc
         W1l/4bqCDvnWE4Ot1/IiNy9LVdo3uxGO9QRxRXK1tVNw8eCSDz2fvEFfUlLBElDQvvxh
         9v+tBWmksrMD9aMPaK5CHiRkbPvYoqrAgder7jfEoKX8QmQw2eopTeTs9zU0Bk0yxAiR
         rpgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTmMW6aFnacUrkwnhawLKpD28/RokZdEafdOx7SGyEDBZEkj7/q8an2DrhtOLu76kV/ep9bQ==@lfdr.de
X-Gm-Message-State: AOJu0YwwwOrNRRpLhCY+wwyHjMMslYX2ABSJnnnBSJt8P/lRHC2hMoOj
	U0VOl+spkF/+x9z62qz3fC/Gh0CWmGnywjg8EPbSqNd2CJiPIX7Q
X-Google-Smtp-Source: AGHT+IH1Is4RiFbP0IlHMXdSODv9SDChyivSpt1d4hWmVCtNPAfBXGzLf7b4AkPfwAbE78UMONTCKQ==
X-Received: by 2002:a5b:8c7:0:b0:e1c:f184:259d with SMTP id 3f1490d57ef6-e1d34a4e42cmr1946254276.54.1725611032497;
        Fri, 06 Sep 2024 01:23:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:701:b0:e03:514d:f716 with SMTP id
 3f1490d57ef6-e1d33da4a7cls490020276.2.-pod-prod-07-us; Fri, 06 Sep 2024
 01:23:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUULy7AWmkKg+x0DpwOe3wYBB4zYsB8bKIsGlCi/aNlbBBwLFAfH381BXcx5R0NKRnNTHF2lcAmi8I=@googlegroups.com
X-Received: by 2002:a05:6902:1189:b0:e1a:8e31:e44d with SMTP id 3f1490d57ef6-e1d348b97e3mr2248832276.14.1725611031891;
        Fri, 06 Sep 2024 01:23:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725611031; cv=none;
        d=google.com; s=arc-20160816;
        b=mT2M9djBr7IqLvPMRTh9dv0MROEzC7u52lFcl7eA5/8IHIMGaqdZe3i0FYDIVa0R2o
         5uwEiuzsfRVWgaudn70Q3z6N0uDv4a+GLZJ5vsKSQ6TuEIPPxweiPEpSUaoD9B6OlEur
         tUe3ggfX2Btdh2OLl/lWcr16T2sUCn+PqxiPXRRT1FlarfuzMI9cPaeRjnqBgXFXdiEk
         SIzo8xnAeeNNboK8/hU/+zVX4DNWy87HBOouGLpTahyqd1HEmjg2gzJoWbfkfKiO4t2R
         0Xc9IoTCB9oN9EWGjW5AjUa+XhTANB7/CP5/K43/Ea7Dux4mam5ozFzT2yGLlb2ZbhDO
         SXYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MO0pi98eViiMaBz/NH3uP9iuQWzc2fwH2Tnw5ppTaJs=;
        fh=gZAG9vHOZ16B4SEK/V8lEUbRtGWfKWOwkMT9Yi15/RE=;
        b=RctHJGveX+ldVAfCqjCnAFgdCnAKrdC4c+H4MZ/z+E+rNQNvGu/DSfsRPrUEyhZPpE
         kYk6HwDPqb/Cs72z8kCyVKjaIuQBrNVreJIEnjT6aQnfda7TQViwXOMtiWOm6rB9fvIN
         aSZFz/0tBJEF5rJtBKqy6uYyvMtiYdykxT8r7SbJfSMmW8cbpQp27lnrsStuAX5S8UZP
         2UAi01tTPP+cBX4IbAkVduG+/v+zyQa/ZP8wEsA/6FTPFkHFKIkmS/2vP8Nd1zamvqOA
         FxQRsfYzfjTWugzvZQ1Nte26EIFNFjsrW062Zcmoviga/ZEEkDiI/n8zLUyaUhqzRH/a
         mrSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=nazGTTq5;
       spf=pass (google.com: domain of wangyuli@uniontech.com designates 54.204.34.130 as permitted sender) smtp.mailfrom=wangyuli@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
Received: from smtpbguseast2.qq.com (smtpbguseast2.qq.com. [54.204.34.130])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1d1142cd54si309354276.1.2024.09.06.01.23.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Sep 2024 01:23:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangyuli@uniontech.com designates 54.204.34.130 as permitted sender) client-ip=54.204.34.130;
X-QQ-mid: bizesmtp82t1725611003tulm6gpk
X-QQ-Originating-IP: WlORxptxdtKcKmsPKXiz0WSiWrD5HCSBdepoR+2Hh7o=
Received: from localhost.localdomain ( [113.57.152.160])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Fri, 06 Sep 2024 16:23:17 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 1
X-BIZMAIL-ID: 18096305791163907771
From: WangYuli <wangyuli@uniontech.com>
To: stable@vger.kernel.org,
	gregkh@linuxfoundation.org,
	sashal@kernel.org,
	alexghiti@rivosinc.com,
	palmer@rivosinc.com,
	wangyuli@uniontech.com
Cc: paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	anup@brainfault.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	rdunlap@infradead.org,
	dvlachos@ics.forth.gr,
	bhe@redhat.com,
	samuel.holland@sifive.com,
	guoren@kernel.org,
	linux@armlinux.org.uk,
	linux-arm-kernel@lists.infradead.org,
	willy@infradead.org,
	akpm@linux-foundation.org,
	fengwei.yin@intel.com,
	prabhakar.mahadev-lad.rj@bp.renesas.com,
	conor.dooley@microchip.com,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	ardb@kernel.org,
	linux-efi@vger.kernel.org,
	atishp@atishpatra.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	qiaozhe@iscas.ac.cn,
	ryan.roberts@arm.com,
	ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	vincenzo.frascino@arm.com,
	namcao@linutronix.de
Subject: [PATCH 6.6 3/4] riscv: mm: Only compile pgtable.c if MMU
Date: Fri,  6 Sep 2024 16:22:38 +0800
Message-ID: <A01B1440514C416E+20240906082254.435410-3-wangyuli@uniontech.com>
X-Mailer: git-send-email 2.43.4
In-Reply-To: <20240906082254.435410-1-wangyuli@uniontech.com>
References: <20240906082254.435410-1-wangyuli@uniontech.com>
MIME-Version: 1.0
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtp:uniontech.com:qybglogicsvrgz:qybglogicsvrgz8a-1
X-Original-Sender: wangyuli@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@uniontech.com header.s=onoh2408 header.b=nazGTTq5;       spf=pass
 (google.com: domain of wangyuli@uniontech.com designates 54.204.34.130 as
 permitted sender) smtp.mailfrom=wangyuli@uniontech.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
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

From: Alexandre Ghiti <alexghiti@rivosinc.com>

[ Upstream commit d6508999d1882ddd0db8b3b4bd7967d83e9909fa ]

All functions defined in there depend on MMU, so no need to compile it
for !MMU configs.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
Link: https://lore.kernel.org/r/20231213203001.179237-4-alexghiti@rivosinc.com
Signed-off-by: Palmer Dabbelt <palmer@rivosinc.com>
Signed-off-by: WangYuli <wangyuli@uniontech.com>
---
 arch/riscv/mm/Makefile | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
index 3a4dfc8babcf..2c869f8026a8 100644
--- a/arch/riscv/mm/Makefile
+++ b/arch/riscv/mm/Makefile
@@ -13,10 +13,9 @@ endif
 KCOV_INSTRUMENT_init.o := n
 
 obj-y += init.o
-obj-$(CONFIG_MMU) += extable.o fault.o pageattr.o
+obj-$(CONFIG_MMU) += extable.o fault.o pageattr.o pgtable.o
 obj-y += cacheflush.o
 obj-y += context.o
-obj-y += pgtable.o
 obj-y += pmem.o
 
 ifeq ($(CONFIG_MMU),y)
-- 
2.43.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/A01B1440514C416E%2B20240906082254.435410-3-wangyuli%40uniontech.com.
