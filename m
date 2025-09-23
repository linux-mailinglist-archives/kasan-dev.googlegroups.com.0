Return-Path: <kasan-dev+bncBDB3VRFH7QKRBIN3ZPDAMGQE76XXZKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 07519B9717F
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:25 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7e870614b86sf1538397085a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649762; cv=pass;
        d=google.com; s=arc-20240605;
        b=S4DBOYBPVWP0p4qHYwNEzMTYQOKJNvjvRzkRHPumxm5X43lybWBvoAv3tMl1OqZ+ja
         ZiPgjncP03C5MHXatLxuEE+Gp+rcii2lP/boIhmGJ8bTTbSJsbqAygqPoTKvwr4UaFii
         h2pN+kX9kWeHP/JtP2U0dKp8fK9FoD8rWVr3/aP6Zh3RTZtgeIT7uKBfuowporBWL0cR
         DbH2TbwUcrJA9CHmeZvrPzKoJ93t+Dq+F5bmevqP9HDATGneilIVg3tqWaSQqFXOmbnB
         cKQm8rHM9s/bWrYPAKbusqANy/lx6DauMQGrZDAqiNWr2NyUnfljow0+zQ9Z8Jujhkrp
         4bIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QIjEj8Kzh2FB2F5WCoeSXGxplGiIknFSZrXh1V+cIpw=;
        fh=h3rDLyz10rPPlh5v9Q8GTpVT6FWVqoNlGQzuDW8pBMA=;
        b=SUJ8/YVvVVgD1cjkCn1skeJ9PY7PVGDdRl7xhZ4USwCNuGeLTG1wCkNRGpLNWYmkvy
         5JL7A+Qu6bivGhCSR1DBByMbyzjzuqsI7RvlcHRWT7RjS5PjGbAVehqIJJrzHqHsMqA6
         InOPgf/m23Z1/3PBf9LulJndivxB0NLXUaEHMzJ66ec/hSTtrxnv48xp78oNiM8RFDqL
         yWHiX73ATO1fdJwB6qkX+LAwhuiKy59AWUu7q3erTADIBuDBbuX5YPcrHNEmOhymRSls
         4v9hAjcER7cIzD3V2AlWAVr2JyfjcZno1QvFmu1NoJ5pAhk3tJWq3GS4/m2wVLuWdgxI
         FEHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649762; x=1759254562; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QIjEj8Kzh2FB2F5WCoeSXGxplGiIknFSZrXh1V+cIpw=;
        b=DIWe3s390FPj7y681xocMNS/54EjvgtFJwBwN24rMpOVP0G2MyJZRSMXweRu4UtWw1
         dSmOjH7DHBHGcROFieQS13gvzQbhts5UOeC58YvmKg/p37/4SSV4CEvqepl2VSqgMCFS
         5mLJQsGfqOtDcYBrWktxozzLgFzjU816Pywh/dKXi9KZsbKwNFNEehjjSQd7yn2kJmyG
         cYjHTK6n3Qsj6AytGEsa88sGwJfnSioDpzfwEXesk9lWubGNqnM5U20F72Gy6T2uRZr6
         knV7bW40cnrSLnQZ7C8Oio4oHJvcOno2qwrIX/+gR/7FIB1HskAIPIn4UwMcBw/gEeF+
         nLcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649762; x=1759254562;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QIjEj8Kzh2FB2F5WCoeSXGxplGiIknFSZrXh1V+cIpw=;
        b=kEMz5fq+nOeuusBTo16IaSGikN+0U32Z6dXzmMZpriFNvs6wC+/M49iLK8cG3QBz4q
         X63wdvA86mVKobv44iMAJ019UD1yTS7IZFt7yRUxvUxARKgjiDsu0+N9yNzOoTGGgkYG
         GcVQqTKgfKu3rNKzlYjHglGiQ0K4CYA98cxdEQ/vQ75H245Jyxhi35d51kTTzSJdKzwJ
         1empCgt3PGMz2kz8KMRI/q7VGSoMcWUoVhuN+OTBsHe1nwIdOtQ135AhxbcnVARM9vnB
         4Mla4Q3e1qvfLphqJoX/ZHeBfDUCfO9MGiE6XTPyUofYZLm14eJ8Y1oInGNbOm24fSAp
         Sx8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnr4jZzqx8cC/VolFjWfCZm26Kiav3ZjcBqi8wAWMv9Zy3idBpNhiwwVYJ7flyPmC80LXYHQ==@lfdr.de
X-Gm-Message-State: AOJu0YzzTyyTGfE7i40A/GxAVeVZdSFIdjnfszhFcQDx5P3JElxUondn
	0epTtovFLouZ8BQ3ikIZVU3uah97BpYxDi6jp15p5P3LRuXCXdr2u+mI
X-Google-Smtp-Source: AGHT+IFxYTxpVirHiQheGfA3b6uFlKaTWYtgDLlqG4HQ3Uk9pTHELuzoH7bB99hXDnSetbSQOigI/g==
X-Received: by 2002:a05:620a:1712:b0:829:edaa:a0d7 with SMTP id af79cd13be357-851697d3157mr402149585a.1.1758649761557;
        Tue, 23 Sep 2025 10:49:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7JQer94US9CSQ7FgOfxd29S31jXR43nMlty9OoVCU+gg==
Received: by 2002:a05:622a:47ca:b0:4af:19fb:76cc with SMTP id
 d75a77b69052e-4c907dffcd6ls44789051cf.1.-pod-prod-04-us; Tue, 23 Sep 2025
 10:49:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVw8p9QlnmgJ3szGN1wRMcVn1dkHXOGAS3/bm59FPH08hfYAS4nnfRm+BtUcj33oS70DV0nfH1DR9I=@googlegroups.com
X-Received: by 2002:a05:620a:700a:b0:826:bdc9:b803 with SMTP id af79cd13be357-8516ade6a9cmr499275585a.22.1758649760616;
        Tue, 23 Sep 2025 10:49:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649760; cv=none;
        d=google.com; s=arc-20240605;
        b=DUUexqhmf7TbpIqEIqnDxsBSusEkKHMk4KTe+6/4Z+9PWCZdyzguq+Eoyh/6zv6Oy/
         +II5eFRUTg5PyLJN3r1zyFn6kLfm3E9CBuNUhBqZ7R0ilz3cFCULfEZAab2gdxO5Kdfg
         CrHQd+TgBHjIOf5LA7nr4RkHOmcrZ9djTpc0/+OTKkqphGqx0/230zJyeQ6cRLUC+C19
         kBfAukwkwf1ugYZEBN/pmqGRyk+10jVzChPcz/PMMMPIear9aZVGrg3to5oVyb1dWqSu
         OLcjNroiXjmHJBReFsn7IXOpX2RbI2lK8oMFA0svFFiPVxxdGmhPCvYeJjAyAuYwOVwm
         VoTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GErQLmtJrjUdcCTE/nvIg6Ar7HZiUFZBB3t68HP9ib0=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=Lk2x8Yh+3yrMRlnO0etmXOzIiCu6ndHbwrCa2Cfgmh/QoRibZc8SgzpRQ4Spb7zxNc
         5RkjpIGiRG2tyRDbfNHX+XwQ6I4naB+ertGkbvNDiPVyVMibq50SRKIln5tYu704gjbA
         nxWbYIUVqAqe0INfQis+ij/U6aJBrzXK1hUO9UTW9wsA8IRz/Gzjbg5rcDhCJ9z55HQd
         Pny45w5SF/JiTNz+FYADZGXqj8hqlcY9TpRMmV9RoXP/1cENe9UqBnJQCmoZkqbr3ijh
         ZN6Hmuvh8Pve2Bx0v2biWzomuzyJZPcIek2unVWce3JzNAAUdgkD1llpKBD6ncacOouo
         EM6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-8363066c299si30915785a.6.2025.09.23.10.49.20
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DBD86FEC;
	Tue, 23 Sep 2025 10:49:11 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 1734B3F5A1;
	Tue, 23 Sep 2025 10:49:15 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [RFC PATCH 01/16] kasan: mark kasan_(hw_)tags_enabled() __always_inline
Date: Tue, 23 Sep 2025 18:48:48 +0100
Message-ID: <20250923174903.76283-2-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250923174903.76283-1-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

`kasan_hw_tags_enabled()` and `kasan_tags_enabled()` are marked inline,
except `kasan_enabled()` with `CONFIG_KASAN_HW_TAGS`,
which is marked `__always_inline`.

Those functions are called in the arm64 alternative callback
`kasan_hw_tags_enable()`, which requires them to be inlined to avoid
being instrumented and safe for patching.

For consistency between the four declarations and to make the arm64
alternative callback safe, mark them `__always_inline`.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 include/linux/kasan-enabled.h | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0c..d3d5a2327e11 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -13,19 +13,19 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
+static __always_inline bool kasan_hw_tags_enabled(void)
 {
 	return kasan_enabled();
 }
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-static inline bool kasan_enabled(void)
+static __always_inline bool kasan_enabled(void)
 {
 	return IS_ENABLED(CONFIG_KASAN);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
+static __always_inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-2-ada.coupriediaz%40arm.com.
