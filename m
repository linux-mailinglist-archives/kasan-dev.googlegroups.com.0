Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBVPUZ2IAMGQEHYG6BMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 11FF84BDAC4
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 17:14:15 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id q21-20020a2eb4b5000000b002463ddac45bsf1907976ljm.19
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 08:14:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645460054; cv=pass;
        d=google.com; s=arc-20160816;
        b=uJfrXdDiGN26z/Hae7DXkDM2OipKftrEvxUbAq0AhzGrDUkqmpsWYzAfncxYMlaTPx
         /xAcGZgH4LtsaIlP+wnee6H330ShZvbrwuIUOVVYIg3JlGEfOHJcWbmCmjjkL1OEFS8g
         PNp8SXW+7qcnT54V3+wMwkf/7reKQzC9p+Pp+Zy/gRdTDn73eRnHk4T810gh3YPen6/U
         vQjHnvRrRzq68JBGmo0gQv4gMk49wDbv6szNtAY7RonpQrVXUbiPZGd1uV193yCsXkoD
         W+56b5ykDuGb6O5LO7UQprsi5KldZnh9tE8pF/kJ6Exag5Fa2Sy8vPX0fC7QO1oSTmhD
         4Jyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=V99xFYxdnblwyOLaDGWbq/Eel9Aex+FSLtSdBMG4GnI=;
        b=Ez0pOgl/YiLbRxMW7nHaog76l1fLMBxPE0AFQ6w9/9btRAAkiCrH7P+ZBF2oTADoG5
         izdZSEiKpwGiVsgnUgpcAygswIzCMFaem0yOgH5KkhrUTFJXMpTdu7rkum6uBFg2Eoul
         CqCjjURaI2Pz5Oo8DTFL7NyRAg33bmsIxNCDYOlMsw8FPtDomeC7Z92QkfwfAAj7bs9j
         yki5TG0gySXqt0FTGrwPleezEu9U8ELW8zB33lBkSvV6aALDivC4ZNEjahyQKTDK0lYN
         rLTiOVKFwKV6ZWG5uj93SETmDzRHCFY/PvD1oXRhSXDmO0Mm4XDggI76xz9RwBMDDNIY
         f74Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Pw8zIvxw;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V99xFYxdnblwyOLaDGWbq/Eel9Aex+FSLtSdBMG4GnI=;
        b=LJLZrP/F69pIaX79TjfzeHCe1CS7V+G2dIRGWKFVy0fVJAgSi02RctewZIMDX0gane
         4L/4iA4TcOx3jAdFflUgdsdT0JJJS+OLRoB420bOaId+wsm/wSOUpxWz3qyfZtilJAbh
         BdHAtWOKa6XIBNdV5MJfr1XJ7guCUCatwOWK6qTxh3ltwUgEfWpl8CgEp18WdczrV6bN
         1Z7kShasSZmXLBmBWlClST18yZaRuThlColuAVm1tM6XAzcR2bhuPzDH8x05McUcb9Jw
         93C9NOqp7P/9e9363SR/rJLx4qYanXRTtUigtHShpR1jH5RKNVzMXeV0Pi2OZLqPQUTn
         BTjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V99xFYxdnblwyOLaDGWbq/Eel9Aex+FSLtSdBMG4GnI=;
        b=uEb9joc6P3mANPcDt8FElRjV/OGXJTzGeC02Z4w36fdBE7jBUWC72vr/MdB9NlBITD
         OECIwbMPWW5Aghcz7/x1s5P8MxFGU2XRhcwWZMyPJDRgcVQV+bgh5GufLvi+BSzmUD1I
         i4Nt/cjrxTo6kQ9fMYY4bf+B/Ptk/US3QK7fs72+pZ7U0j5Y5dIe6w1N0Cluu4vIGF2V
         vmVGBQxEaiaV5eryI/oZW2+lDUjcxKbDnwHRnoWyMF/fZRvvgnme+fYSjI9uhKoGxpem
         XdN6MMdRctsiQdWYaGsxlkxedMdsG/avbXslPa0tjfpTRCUS7EPB9wirkVfbd3cpyJbo
         k7Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532A49PG+8yG11o1axXnHXPxk8xcPzSTvi05wJPvAAlmd0iiCrrh
	KR+qvju9nAQfnCpWNwNLTmw=
X-Google-Smtp-Source: ABdhPJyJxY4UbWzry9PtsZpR5Cj6ZY3xUDjsggtWVan8z8wr88AziPwnMMd+Geyfaw60gn5RHlsqEQ==
X-Received: by 2002:a2e:a7c1:0:b0:246:f13:1ea7 with SMTP id x1-20020a2ea7c1000000b002460f131ea7mr14915989ljp.276.1645460054022;
        Mon, 21 Feb 2022 08:14:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:0:b0:246:3e9a:df6e with SMTP id x4-20020a2ea7c4000000b002463e9adf6els594224ljp.6.gmail;
 Mon, 21 Feb 2022 08:14:11 -0800 (PST)
X-Received: by 2002:a05:651c:b09:b0:246:46ee:370c with SMTP id b9-20020a05651c0b0900b0024646ee370cmr1394995ljr.374.1645460051547;
        Mon, 21 Feb 2022 08:14:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645460051; cv=none;
        d=google.com; s=arc-20160816;
        b=G/7ANyljBZdEqcb4D5RPve7iearD5U0b5wpPQVipUSY0j+sF4Db7vevgNHylx5aw+1
         114DhTihFRmtdO7hxMGsWDca40Ix8WMeaoUEuCa66AL9G3bzg9Tr8Z3JahAj5Y4CPb66
         oIGH/kjAiTXDQKwj0sWNqn/Dk6iL2oRR/arsZl7vSVmYce4uIJaQhBRFQlErdR2kLnPT
         Jo/hfwc9ZbEWYZx0ASFOf4KfwYFSuBY/mqT2gwfk1xu7pjMsnizK3Df31mIzZfmDRExd
         6YfTQyO9BIDkqvDp1rv0lasFGCXUausrnXIPPEL6AHsdX8Uxo7gB0ZNbnn95BUh8zu4q
         6Zxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=PQyFtNV3tW1qRmwZ8HqaxvUDcyO7BHPqZZLC0geQ1k0=;
        b=gm12DpiDqni2iDW3wul7EmbyJVpjsXJtqPK4AY5lHD2s//8PjHWoqzq7Lu5q+teXa4
         I6IAhgaT4ZoFUlKng0exdEsOldP6vwZnChBT75wlXoNAMIDIJcERGDVoOTA65QXml6eO
         f0sobrMO7LYB/zLa1sd6mYsEjgErOAj0fCn/Snc3slCCNARdr6eO2ZsbI884KE6zaVUy
         hnHv/3jhRJgM25UZnDtZoiZYPreb8roZvgtZBOTHChLYw/N9dK5JN9tDsi4UPfLSiogI
         qFgiBDhJ8SoxTm4WmBhywTPL9zXuTx/z4mJ5Q0yv+UhxE5WtPcoI7WjdM6jhXWxV3ozn
         WeLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Pw8zIvxw;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id d35si401081lfv.5.2022.02.21.08.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:14:11 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com [209.85.128.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 668B740017
	for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 16:14:08 +0000 (UTC)
Received: by mail-wm1-f72.google.com with SMTP id p24-20020a05600c1d9800b0037be98d03a1so8238815wms.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 08:14:08 -0800 (PST)
X-Received: by 2002:a5d:59ae:0:b0:1dd:66c3:c67b with SMTP id p14-20020a5d59ae000000b001dd66c3c67bmr15950150wrr.400.1645460048041;
        Mon, 21 Feb 2022 08:14:08 -0800 (PST)
X-Received: by 2002:a5d:59ae:0:b0:1dd:66c3:c67b with SMTP id p14-20020a5d59ae000000b001dd66c3c67bmr15950135wrr.400.1645460047868;
        Mon, 21 Feb 2022 08:14:07 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id o4sm32504065wrc.52.2022.02.21.08.14.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:14:07 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v2 1/4] riscv: Fix is_linear_mapping with recent move of KASAN region
Date: Mon, 21 Feb 2022 17:12:29 +0100
Message-Id: <20220221161232.2168364-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=Pw8zIvxw;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

KASAN region was recently moved between the linear mapping and the
kernel mapping, is_linear_mapping used to check the validity of an
address by using the start of the kernel mapping, which is now wrong.

Fix this by using the maximum size of the physical memory.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/include/asm/page.h    | 2 +-
 arch/riscv/include/asm/pgtable.h | 1 +
 2 files changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 160e3a1e8f8b..004372f8da54 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -119,7 +119,7 @@ extern phys_addr_t phys_ram_base;
 	((x) >= kernel_map.virt_addr && (x) < (kernel_map.virt_addr + kernel_map.size))
 
 #define is_linear_mapping(x)	\
-	((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < kernel_map.virt_addr))
+	((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < PAGE_OFFSET + KERN_VIRT_SIZE))
 
 #define linear_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + kernel_map.va_pa_offset))
 #define kernel_mapping_pa_to_va(y)	({						\
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 7e949f25c933..e3549e50de95 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -13,6 +13,7 @@
 
 #ifndef CONFIG_MMU
 #define KERNEL_LINK_ADDR	PAGE_OFFSET
+#define KERN_VIRT_SIZE		(UL(-1))
 #else
 
 #define ADDRESS_SPACE_END	(UL(-1))
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221161232.2168364-2-alexandre.ghiti%40canonical.com.
