Return-Path: <kasan-dev+bncBDXY7I6V6AMRBHPSXCVAMGQEBM533YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DD9A7E7CD5
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Nov 2023 15:07:28 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5091368e043sf2387145e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Nov 2023 06:07:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699625247; cv=pass;
        d=google.com; s=arc-20160816;
        b=KYbsndt8aMWqo0BtBXG8IfCKzpJsVAmUp81nsBw0l/p+Y5/h56XFLjd9bsmEeZo2wf
         BB8KgEy67aBw16DCoYjAfO4AEHKMiNk7OWjkK6u6QMjV5yHTWFhXBWh7WVGeWzm5WysW
         jnFoMqwKfAdu+gLEyEyKVCD32Cju1gwf+1fXmYIpXaf1e2u4C9cl1KbmB3QkLwZF2WK2
         zwF0OLDtgv5G9LidW4O0CQaw5Mzy1iGEiEcje1QHG0drQAO/7vjwA8j+2sfU1ipIoYMY
         6du5e6MHsNcTzdqTo2mcaIMpZsHStXXJ4AIcgwfsGRySqi1gAC4YHaHOOzJ5Miva/CXU
         vmuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=13PI9mz3hSDR1urqw/IhBfFC4YSMnegS+apH2zMJ9+M=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=now1X7A3JzJZRQGwSvdX3G/g5nxh2U91zqEu6HSJo1RAnkf2pro0w8OWCLacss8D+2
         KkoLviLENrHyGk4K3EEEBj2sMSykeOtv3iRrmuFwtkSqt0IL+5BtGZPNcU0TMYNvTXVi
         pOceO1Ryt2IAfiXmr31LcJaWNXhoZSef/QGOMlWI7uaV/3zy55EBd18dIai/8bJhiOaM
         jFCkOG1MRlnICAbCeLxQlyn4cWJrtuqNgPlPY8hTjrlX4ZXYCijBI6E2xWV2yverC8c8
         l6BfbGv+iwBQvEwl1geqg2NybwxTJPRcQlo7I2wsFjBsLRxtxuvGKnKc2lTiDHFgKVcq
         Ookw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=IioXvdER;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699625247; x=1700230047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=13PI9mz3hSDR1urqw/IhBfFC4YSMnegS+apH2zMJ9+M=;
        b=npAWnWsbVF7F/bTxYQ0fHvKEeMJYofyBzIy8/84g9A0s9ZwGIfwyfuVEyjKh1wILy7
         ZSGHV8LQN26JitHPgILlAne0/NVHPMvTLcZyXfj+6bMBa4Z4OhvHQz2UNmUY7wUizvNH
         jSTs8f+jwIWt4J98DthZDMjA9KlKLejc/DvL4Zi4RWGeTSTfHKAU+WgwS4JM+RLqvg+Z
         I4tdDbV+7zP8HCbPgDFXj3lLO6+pjkTIikxWFA8y+vPEB2eaeobMK+JCwkHtrKQLt2Vx
         hG6E5E1L2arsYfjPvajv3seAzpAtCvnRGpkspZojBk9XtkIeGUAX316QyLB4bhvtGBhZ
         wZyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699625247; x=1700230047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=13PI9mz3hSDR1urqw/IhBfFC4YSMnegS+apH2zMJ9+M=;
        b=LFBGySq3GbvZ9+MwkSz/DVP01uFJAQLcP4TNHIppBO4ZZdpEwfiithll+OIxatO0a3
         gytS/Q5baUaKVYQPfrv3dmyuiChABLatfr6tSYKp7D9lKZlbuZrF9Kn1Z1wGIpjUr0z7
         M14D2Ux0oDK1iU3omCugxEuB4h+di9y8ZsnfeaZ4IYWaIyU5y136uG4vBb2AgQ2CLeWt
         AtyrbzatoeBwZlHSkWcOrLenl692BGBooOAFjOPYlgR13+r2ndyPcu9DIQFmiBt5rYMY
         O9F8iv43yhSWI6N/DWK/CB9RlIXZad3khmP6SLsKIAz7TLns/8t1cfQ+IGNENtq1xF9z
         Sg4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxrb6Bx0Ig7NVezOBGczV314zWC7CYt58uVNhxKAUwt8QXhe7zS
	DMlt/3JQQiT4v7zbGvEe23Y=
X-Google-Smtp-Source: AGHT+IE5/Iv3y5kORJwsK3rd9KNgBr3NFQpTJCCLH3Mbzd1DI64xJo7om2kCEKIuiz6dU/LIB+mE6Q==
X-Received: by 2002:ac2:5e83:0:b0:509:4655:d8d5 with SMTP id b3-20020ac25e83000000b005094655d8d5mr4215898lfq.11.1699625246049;
        Fri, 10 Nov 2023 06:07:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b8f:b0:507:999e:6d67 with SMTP id
 b15-20020a0565120b8f00b00507999e6d67ls132059lfv.1.-pod-prod-09-eu; Fri, 10
 Nov 2023 06:07:24 -0800 (PST)
X-Received: by 2002:a05:6512:12cd:b0:509:31da:43fd with SMTP id p13-20020a05651212cd00b0050931da43fdmr5140776lfg.7.1699625244103;
        Fri, 10 Nov 2023 06:07:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699625244; cv=none;
        d=google.com; s=arc-20160816;
        b=o51lKLRLFxZ5l1Tjp9uqE85YQBkHzoA0Px4nd8OTWVDimBauGCFzOt6Rq25EEDsPQ7
         ye7WjxZbn+Zf4EgkMyc9S51qXqjuD4kJcJHCFS8qIvLD8fU+Z49pYFIePedQtqJtKWdO
         mZML+Xa0Y+2y2triNxMIFu3pevOfYjOCGkZEJh3Yhjtss2PUY0++xWVfsKdAqiA2JtQX
         iBjvTcY/gKBiLq3HWA2Gn327EOObakCC0pfTM48SlDx7Pu5oCf0CG9b1gSPZzZHBnRXE
         MejWlUbvxnpaH34KQ1IC0hwLIe1wdUcqo12/U5Jmm/ojyFDM3MPSrlV45b4UhfxD8oAa
         C3Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8Lab8I/AjLwx8QNQ8rr3txbgHn2fsKjkqhEzna/zmzw=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=qxE2WtH8wOsy8sOYOIDgZ1gC57Sh+yx/c4LYd64Ufy3nKtGkmOYn/9Ubdtb0Wikro+
         hA7arNWfMj+7cV3Gygw/A23i8csFrACrfU8xaIt5HRu4wprsPtpOuyrsgjupz+dsHu6Z
         IsG3Lewlu6yYoP3JJgfU6XCL0XHV1VLWPmJadWt0Gj+qiRPsm32CAWscYNmclVyC/17g
         KPW7qQ57B96snkOzXMoTpfLEDHtWnM8h3QYxRwagHJp2j6XA1wIWZyG14SHsq21txkCy
         SyO67ruDRxJeOlnzbS/9ry+DgqjLs7T9Mf8Q/THwAg4Ufw6rEXD5udjJHVYhcSHpRdBv
         PwAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=IioXvdER;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id k12-20020a05651210cc00b005090fd18c05si1213043lfg.11.2023.11.10.06.07.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Nov 2023 06:07:24 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-4084095722aso15507175e9.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Nov 2023 06:07:24 -0800 (PST)
X-Received: by 2002:a05:6000:18a1:b0:32f:bd90:c22 with SMTP id b1-20020a05600018a100b0032fbd900c22mr6532442wri.62.1699625243298;
        Fri, 10 Nov 2023 06:07:23 -0800 (PST)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id l10-20020a5d560a000000b0032f7865a4c7sm1983318wrv.21.2023.11.10.06.07.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Nov 2023 06:07:22 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 0/2] riscv: Enable percpu page first chunk allocator
Date: Fri, 10 Nov 2023 15:07:19 +0100
Message-Id: <20231110140721.114235-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=IioXvdER;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

While working with pcpu variables, I noticed that riscv did not support
first chunk allocation in the vmalloc area which may be needed as a fallback
in case of a sparse NUMA configuration.

patch 1 starts by introducing a new function flush_cache_vmap_early() which
is needed since a new vmalloc mapping is established and directly accessed:
on riscv, this would likely fail in case of a reordered access or if the
uarch caches invalid entries in TLB.

patch 2 simply enables the page percpu first chunk allocator in riscv.

Alexandre Ghiti (2):
  mm: Introduce flush_cache_vmap_early() and its riscv implementation
  riscv: Enable pcpu page first chunk allocator

 arch/riscv/Kconfig                  | 2 ++
 arch/riscv/include/asm/cacheflush.h | 3 ++-
 arch/riscv/include/asm/tlbflush.h   | 2 ++
 arch/riscv/mm/kasan_init.c          | 8 ++++++++
 arch/riscv/mm/tlbflush.c            | 5 +++++
 include/asm-generic/cacheflush.h    | 6 ++++++
 mm/percpu.c                         | 8 +-------
 7 files changed, 26 insertions(+), 8 deletions(-)

-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231110140721.114235-1-alexghiti%40rivosinc.com.
