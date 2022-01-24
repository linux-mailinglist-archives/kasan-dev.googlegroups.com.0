Return-Path: <kasan-dev+bncBAABBIOWXOHQMGQETR4RM5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C38CE4987E0
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:08:33 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id w42-20020a0565120b2a00b00432f6a227e0sf9371428lfu.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:08:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047713; cv=pass;
        d=google.com; s=arc-20160816;
        b=aMeXQIEn0REyekjPy77D7E/ih3FZptueGnPQNksn1lZloycSPB2AWSaRThl2mCCR6i
         VGQPX7hJ5J7i/Usx7nHFNu5hRY3StNpJ9z0l4IA8JYPhC817spd4pJCUwAZ8bXhvcpSw
         WcIMULDUQIsclnS5n9N9YgU2XxxiIYXbWNGkEUbN5n1DxNoEQpyCl+jhqgnnMIxGKmiV
         mpT0XNreibU47nJxXq4+JGgjdYZIAQ9i6W5NOhX48yvqDKPMolt6bUOhDKqWU6vS6h28
         UR5xYutCueLOM7xLO5rNe23/wN8+9WH5vysB2x1GjcM/JqXxlOTYiW6ZBhNBLpc1OBp7
         mBXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7Cn37/Pp9cge9G8pxFYdUm/+skYSBFSmko/HIx2ff4c=;
        b=uYaBdMlgakBAJcSXDyN4K1uhXZZP8jHn9zasNA90oceHPgsWtzHMSxw1tBcTOFaVTM
         7Z+LSSX+2zdSdNvqZDuyQRXFdOSRqSPSRG06AbBGx317wLjOxqh/KabAgS4TnuJOn+Jp
         809tTkd2WrFfrINoRO0xdj0azaBra6Nz946trEtJVZsW9N7Bs4YQJSEUobh76Zkz8dml
         aLTO7da564vUrNM7M6/QQyATvK9BL+K7j2h9XEOZQ2TlXP6FO/RP8/j1jDsUMpCJchy/
         kQngbNOdYCg+6XNKzgIsM8Np4iwxZ3TK7NN9mwelP0qbuGbR2SZZw7ya61wYXgeoR6mj
         SxLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wHE5nEfz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Cn37/Pp9cge9G8pxFYdUm/+skYSBFSmko/HIx2ff4c=;
        b=pfxppljemYQJT22sWmAgKwR5hGXcWsiRsQH3kAiXB+DrHmvYNkpHGwpPa6ADURCHl8
         TCUKLe03SvzzJMq4LzWx+ZD9yiNxE8eGtGk9Cmd94VZzS1/3bCOAP/Uz6WbPvYOnV7eR
         RvmRFDU4+oMoVEbgPJ4m5Nd0SozAes0HFiVpe+jyzoQAxKQrNdZeFZSUSx+/nXvKV6jE
         dNZFIqW3DnpfJoS9mKlh2uJplbucszrkMW8+GDlDfHUiF+cJymWxKu2TLv5PpuEU8d9n
         JMxGZWPEaZvfnF/kA2aaQOi+Qd8uaWkhzilNLRTbDuhloQk6Oap0GGPjnOUo1YFvV4np
         LQtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Cn37/Pp9cge9G8pxFYdUm/+skYSBFSmko/HIx2ff4c=;
        b=yJUYqL4Tkw3WS/TiW/dseFqpY1DgmRdferFbPKMSBwMWn4fPgtqrdW1HVHXawHrqgV
         w8iaM6E+SmZ6F60aL4kZVHyAmM7Bgu8NvYQFPGU7Rob8XozZ0Y3s+pUaUrrqDFQzNBlS
         D5jNRzmycwNgz5QlZf2Vz5dFtg15+o7i6sRvPVvJGHRFH62t8je4zo7ge0HdfL3m7pY5
         MGbny93HDGc7KyK+JEa6Ui8PXAzVQ6awnoi/NVb2RQTH/TxUiyhkIVr5m5bQnwpEJJLE
         p5ctvd7PrtM1air/buoI2QJO3/wLYmCY1eyzgk0uQNO5fpvNmiJIWKux4X3q/jnE/Th1
         9o7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hEyux8WUCw+JAouWosSnRCoA1Ksyakul4+Bj5imZqpjCiPK7m
	DEytVgF1TaHi8eoIZkNsQVA=
X-Google-Smtp-Source: ABdhPJzk2FurBe9ATYw9Ik29io6k6S5ptJBqRDdBkQKe6G8kz8FBR8qEQydJDFNEKBj70pba5FFmuQ==
X-Received: by 2002:a05:6512:b90:: with SMTP id b16mr1074472lfv.38.1643047713403;
        Mon, 24 Jan 2022 10:08:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1592:: with SMTP id h18ls2480708ljq.7.gmail; Mon,
 24 Jan 2022 10:08:32 -0800 (PST)
X-Received: by 2002:a05:651c:b2a:: with SMTP id b42mr11651677ljr.168.1643047712572;
        Mon, 24 Jan 2022 10:08:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047712; cv=none;
        d=google.com; s=arc-20160816;
        b=0CBgRZvjTAPucfvCNWRHSOfmxNddTaJ8QBh7rM0sDBZadPCxMfkRltoFm6q4fvGAWH
         vP8Sa2NeZeLYt2CbRJPoBhL8rFHpWYaBQ6jNk7kPHw1eoVi4Fg8dm3d9+xGOYWzLtYDH
         0wA+ctoYQWBANzsNNqYWR8CWd5vx6IaUwZFtfFClqlu596/ozdM8YuEGwB9C3h96ySuF
         FQ4+HQh1/mBH2xQcvuwg5onuuj8KXHOOizG/4AqfWm94w6Dm+LKblUWSlXGWURdD2ubN
         6Q9zYMfGrw0NuNTAYFKEImmjK9i0XICmzq5ZVrcuA7H7iXxeU5h5gswget8AN2lJwoBC
         ovCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iNP88pCjnQrqi/xZg5Z3uUoNwPfihld579YonDiORFw=;
        b=wunZqFyQbtnRhNxjVfAcIBY4hPd3mGsUlJIwJ8/BrEaSj4bqSiVRqfdiuekW6U8dTJ
         nMTuuBTykVuH4FW4JINcBqM4nHR/gsPNiaYMqWU95TJnCqPUXgSRPXn8glUjesaNEnH0
         dvhwBOAOt2iTIrpYekwYMyFv/bQrEElIrnQd+qIteZa85E17ir+GRon9edUSR0dLQ5Ya
         s1AE5dwRUf10uv89ChO3Ik0csDxbQb8gujlEOFARcPV5rwT8oOu7hIXCLulpqw5gbtyb
         rJjHbYZeGvqp4VxU82NG7i8AbJTVESfFdjRlI8PPK07U4PeMUsL8uPw926Gg01LRBWlM
         oL1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wHE5nEfz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id e18si474235lji.4.2022.01.24.10.08.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:08:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 37/39] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
Date: Mon, 24 Jan 2022 19:05:11 +0100
Message-Id: <99d6b3ebf57fc1930ff71f9a4a71eea19881b270.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wHE5nEfz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Generic KASAN already selects KASAN_VMALLOC to allow VMAP_STACK to be
selected unconditionally, see commit acc3042d62cb9 ("arm64: Kconfig:
select KASAN_VMALLOC if KANSAN_GENERIC is enabled").

The same change is needed for SW_TAGS KASAN.

HW_TAGS KASAN does not require enabling KASAN_VMALLOC for VMAP_STACK,
they already work together as is. Still, selecting KASAN_VMALLOC still
makes sense to make vmalloc() always protected. In case any bugs in
KASAN's vmalloc() support are discovered, the command line kasan.vmalloc
flag can be used to disable vmalloc() checking.

Select KASAN_VMALLOC for all KASAN modes for arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v2->v3:
- Update patch description.

Changes v1->v2:
- Split out this patch.
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 6978140edfa4..beefec5c7b90 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -205,7 +205,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
-	select KASAN_VMALLOC if KASAN_GENERIC
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99d6b3ebf57fc1930ff71f9a4a71eea19881b270.1643047180.git.andreyknvl%40google.com.
