Return-Path: <kasan-dev+bncBCH67JWTV4DBBH5AUDUAKGQEUWH46YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BEFC494D0
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:11:45 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id e16sf8585127pga.4
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809504; cv=pass;
        d=google.com; s=arc-20160816;
        b=wN8usjPqy3nhSNN+lRG1pRtVMT+n9CIBSpzhkimaC+R0R1xDv0kgHY1SJuCtbbUhak
         GGilUWWS92pnJY1yn7z1RBO+yaH1ps8lCSaLIRkaP31vVkxpNZBwTr+HwAQPJlhlYhWO
         zVKTfLB/C8jC8iIbax1qddrzS6VCKFIysv/SmJAxsJx64f6w8my00Y8sXslikg86RwSg
         u9x0yYc2MYzBgEAy0PRzzf8EgNgF+1/aSF+jd6EtTiUpcavqdrYWkaMaxlzGYPvz2UrM
         KjLam8FheTG6DxWDXsDp3HW/IhvU5fUNjOshDdZpK1dE4e2m/ErEBaV9TG+UDQwulEWr
         ID+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MxjNTUGT07Dt27ttmmFLbFX/tabQI6y3cvuXTa1pDxQ=;
        b=r+yUMv1BooGVUI/qeJgghvhqigJPRxx23XaM9DHejcPKv6L/yDT+IICm4H963pjL9I
         mxqNbdduveo10Y+D3ARMsI0AVISunbNmFcBJR3aCv9mb0Tk341rElSkpZ4hwkVJJNwVp
         Ys+nvm+AypXHE4xMNdmj7nIOEc52FeWOqmSDXp+x/I9ByM/gregh8rKaTrSN8yL+jLT3
         WFVHp04aaYiwpLB83CZL/M93qmcnykEcOU0VjDYkQatV/p7xaQ9LtHtO2+xO4SN3+lsO
         zQZfU7sgnqwU11+Wf0NzkvxM5MRhQ8gZ6HxPEJ6UlXgSnWEtxpLwYz/uCbxpoq0UTy22
         Zexw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iXevDhzZ;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MxjNTUGT07Dt27ttmmFLbFX/tabQI6y3cvuXTa1pDxQ=;
        b=qW1qCkDQbcgdnhu3wkv+6ZTUILdv6scZREyGNvr5uuR/nj5Xqu0Gm5bjUXcnFo+6Ey
         yaTnbfERz/G+GPce6PQDJ4Z4w0E6jxDDSL9DWpSoMkhnWO+9cEMkFIsaWvg3pNNiNZYk
         t6yjmNJKf0wEHSOUjDzkLyE5fZ4dri6aKABnImD1BK7AdN54Mc+LoQdq8g4AnZvlG2dE
         qKydkyQlw5tyKBtRwKs/DbhUxVA3QBXmlYRrYo8hSzBQlH1yhrDmuIKYBcE+5SqWYKDQ
         bAJgr62v8a1KauvvLLHnkJAyXKJk7ARAesw/urtXTwBrqlZ4Nf8OdNA2w/ntCGk6ae7X
         4PzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MxjNTUGT07Dt27ttmmFLbFX/tabQI6y3cvuXTa1pDxQ=;
        b=Qgji9Hd14e3vLHHwJjHYeQ5mKRDK0CtRybUKg1xAL+Ja25LYHnQNtkiohqze+8vB9U
         9Q+lU8xLAlnCze9g341R9GGmOa2q887k8IcS1ZpWbb/nczpzH4xLOvlE1etblU5gAsGJ
         GDddNFDIP919seaE1QaO6aPbET0wS1kaiUW5t8KuxWhNH1gZeiq/azk04/89IQwOJnMh
         kwDl9a21xizgNCiIQlPrUIce2vXTTBptAuMdy9KXZk5Wah8ipUse3JB29ZoLr8Ld359L
         vIYSTKTeNYOMLcxvPBYAdFWI2iWPzEYpnuVRIo+8lEsXXC440VS7UKzdubo0O6gakTOp
         eMJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MxjNTUGT07Dt27ttmmFLbFX/tabQI6y3cvuXTa1pDxQ=;
        b=MN0Q7ya//yQl80VbnbJ0NtSrI8xvBmiYN9GNv+w3VyZFO2FS2HPYqdswek6RiWpsSd
         SnwBFxPHVemozMyeNcTItgPA8pLJ6s9i6Ng3bdB9pp6l/2c33u9XKiSyhujs8ZjSBQPq
         BOI0w+LbpX74BX9Pyk8fOfWww3TLPhjCJ5I6JktxAibhNYDhx5dqOzPmtVjgOv9oJ3rI
         eMsos8NHU42K9lmWCuXPQXnIJoELiR4s2oebKeNXCbGrRe7vFNjyteupazaW/1hPmXr2
         l0DaUvsxi0+CUSmW7rIQBLMH3sMret5TR3HJaQzNkftCsWuo+KbEyLi661dnG3M2dtHV
         cFwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUZYxqDjs2NzQHqyuYZJGyWWQWQT+IQutWGQtNdu9pOunEnuyvr
	ySachHe9aJOsvBIquaqjlzo=
X-Google-Smtp-Source: APXvYqzCtYaZzILGg2Es3E3lNc93ekNauWY+9/plLX9RcHv7LLFq50mJfBn6dkhFii8QqSeKZOy7Qg==
X-Received: by 2002:a17:902:7297:: with SMTP id d23mr97070673pll.254.1560809504103;
        Mon, 17 Jun 2019 15:11:44 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:32d:: with SMTP id 42ls4305903pld.11.gmail; Mon, 17
 Jun 2019 15:11:43 -0700 (PDT)
X-Received: by 2002:a17:90a:bb94:: with SMTP id v20mr1436626pjr.88.1560809503612;
        Mon, 17 Jun 2019 15:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809503; cv=none;
        d=google.com; s=arc-20160816;
        b=Y5WrdVfNiMzjSMLqro3J2gs3/kHjJu4j/oG0Ju2zNJZNTEZirQmrZgDkAbrt2+dJd/
         zN5zFalOsyFGRsgV2n+M1yCo1ekZDiqQn5lLqSKFfqt28IEvA/V8g2OtiOoXDW8i2U1C
         S1eqQoVpsV3gFz6b0jYQraU+s1WqNwoRExEmbVx9EL1+ML/ZUm/kQBVpH4nV7brVNq2h
         yHU8S5O2dDf2FPC5rTXZg8tpN/VqXfdZc9dOztLfk+KGJ6rmbQFcHywAhu8PC9rEJMZn
         OFWTzXW/LCU4BTVxJPaqf3KFnjjH92o3O3E/GYH/S6o5Zav0NvmhH1kktyFmoNeMLsil
         MA7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=470HXzuWWndUIvDjd8YDkOfADh+SPCvxxBbRCAgfY5o=;
        b=wIrkiaCLmGC9vl/qzzYH6KjrbgUB94JdtKJAkKiOJq9GhySOKiW/k6ggLQ+reb/pgV
         MpWx7yLvICmuT9faNAOHs96FT8UDwD7CcB08AtmNp+5xdh4M2gJ3hRwHM6zFX3iVrbmD
         MZeUC8qZx9Gt28ZNNbjFdwxMTy4EQWI61bn1LX6Md7SFRJOCzAtXQk4SddaB1AR3v97W
         6ddxuNa3q+LwTknizv1DD5UKjI5d2MEMBtuSH7Ur27aiKfC6IwXIMLPiwl91c2Rnf3Ce
         +AlbPucvRjcXp8ge9zwmTxrV7t7I2qoASATY4yR4JnHNBQSs8oX6ZNjbEkS227kj2gg6
         EJ/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iXevDhzZ;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id d128si461392pgc.5.2019.06.17.15.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id f97so4758755plb.5
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:11:43 -0700 (PDT)
X-Received: by 2002:a17:902:7249:: with SMTP id c9mr3904755pll.25.1560809503214;
        Mon, 17 Jun 2019 15:11:43 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.40
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:42 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Abbott Liu <liuwenliang@huawei.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	glider@google.com,
	dvyukov@google.com,
	corbet@lwn.net,
	linux@armlinux.org.uk,
	christoffer.dall@arm.com,
	marc.zyngier@arm.com,
	arnd@arndb.de,
	nico@fluxnic.net,
	vladimir.murzin@arm.com,
	keescook@chromium.org,
	jinb.park7@gmail.com,
	alexandre.belloni@bootlin.com,
	ard.biesheuvel@linaro.org,
	daniel.lezcano@linaro.org,
	pombredanne@nexb.com,
	rob@landley.net,
	gregkh@linuxfoundation.org,
	akpm@linux-foundation.org,
	mark.rutland@arm.com,
	catalin.marinas@arm.com,
	yamada.masahiro@socionext.com,
	tglx@linutronix.de,
	thgarnie@google.com,
	dhowells@redhat.com,
	geert@linux-m68k.org,
	andre.przywara@arm.com,
	julien.thierry@arm.com,
	drjones@redhat.com,
	philip@cog.systems,
	mhocko@suse.com,
	kirill.shutemov@linux.intel.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.cs.columbia.edu,
	ryabinin.a.a@gmail.com
Subject: [PATCH v6 1/6] ARM: Add TTBR operator for kasan_init
Date: Mon, 17 Jun 2019 15:11:29 -0700
Message-Id: <20190617221134.9930-2-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=iXevDhzZ;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Abbott Liu <liuwenliang@huawei.com>

The purpose of this patch is to provide set_ttbr0/get_ttbr0 to
kasan_init function. The definitions of cp15 registers should be in
arch/arm/include/asm/cp15.h rather than arch/arm/include/asm/kvm_hyp.h,
so move them.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/cp15.h    | 106 +++++++++++++++++++++++++++++++++
 arch/arm/include/asm/kvm_hyp.h |  54 -----------------
 arch/arm/kvm/hyp/cp15-sr.c     |  12 ++--
 arch/arm/kvm/hyp/switch.c      |   6 +-
 4 files changed, 115 insertions(+), 63 deletions(-)

diff --git a/arch/arm/include/asm/cp15.h b/arch/arm/include/asm/cp15.h
index d2453e2d3f1f..0b0ac5170ee7 100644
--- a/arch/arm/include/asm/cp15.h
+++ b/arch/arm/include/asm/cp15.h
@@ -3,6 +3,7 @@
 #define __ASM_ARM_CP15_H
 
 #include <asm/barrier.h>
+#include <linux/stringify.h>
 
 /*
  * CR1 bits (CP#15 CR1)
@@ -70,8 +71,113 @@
 
 #define CNTVCT				__ACCESS_CP15_64(1, c14)
 
+#define TTBR0_32	__ACCESS_CP15(c2, 0, c0, 0)
+#define TTBR1_32	__ACCESS_CP15(c2, 0, c0, 1)
+#define PAR_32		__ACCESS_CP15(c7, 0, c4, 0)
+#define TTBR0_64	__ACCESS_CP15_64(0, c2)
+#define TTBR1_64	__ACCESS_CP15_64(1, c2)
+#define PAR_64		__ACCESS_CP15_64(0, c7)
+#define VTTBR		__ACCESS_CP15_64(6, c2)
+#define CNTP_CVAL      __ACCESS_CP15_64(2, c14)
+#define CNTV_CVAL	__ACCESS_CP15_64(3, c14)
+#define CNTVOFF		__ACCESS_CP15_64(4, c14)
+
+#define MIDR		__ACCESS_CP15(c0, 0, c0, 0)
+#define CSSELR		__ACCESS_CP15(c0, 2, c0, 0)
+#define VPIDR		__ACCESS_CP15(c0, 4, c0, 0)
+#define VMPIDR		__ACCESS_CP15(c0, 4, c0, 5)
+#define SCTLR		__ACCESS_CP15(c1, 0, c0, 0)
+#define CPACR		__ACCESS_CP15(c1, 0, c0, 2)
+#define HCR		__ACCESS_CP15(c1, 4, c1, 0)
+#define HDCR		__ACCESS_CP15(c1, 4, c1, 1)
+#define HCPTR		__ACCESS_CP15(c1, 4, c1, 2)
+#define HSTR		__ACCESS_CP15(c1, 4, c1, 3)
+#define TTBCR		__ACCESS_CP15(c2, 0, c0, 2)
+#define HTCR		__ACCESS_CP15(c2, 4, c0, 2)
+#define VTCR		__ACCESS_CP15(c2, 4, c1, 2)
+#define DACR		__ACCESS_CP15(c3, 0, c0, 0)
+#define DFSR		__ACCESS_CP15(c5, 0, c0, 0)
+#define IFSR		__ACCESS_CP15(c5, 0, c0, 1)
+#define ADFSR		__ACCESS_CP15(c5, 0, c1, 0)
+#define AIFSR		__ACCESS_CP15(c5, 0, c1, 1)
+#define HSR		__ACCESS_CP15(c5, 4, c2, 0)
+#define DFAR		__ACCESS_CP15(c6, 0, c0, 0)
+#define IFAR		__ACCESS_CP15(c6, 0, c0, 2)
+#define HDFAR		__ACCESS_CP15(c6, 4, c0, 0)
+#define HIFAR		__ACCESS_CP15(c6, 4, c0, 2)
+#define HPFAR		__ACCESS_CP15(c6, 4, c0, 4)
+#define ICIALLUIS	__ACCESS_CP15(c7, 0, c1, 0)
+#define BPIALLIS	__ACCESS_CP15(c7, 0, c1, 6)
+#define ICIMVAU		__ACCESS_CP15(c7, 0, c5, 1)
+#define ATS1CPR		__ACCESS_CP15(c7, 0, c8, 0)
+#define TLBIALLIS	__ACCESS_CP15(c8, 0, c3, 0)
+#define TLBIALL		__ACCESS_CP15(c8, 0, c7, 0)
+#define TLBIALLNSNHIS	__ACCESS_CP15(c8, 4, c3, 4)
+#define PRRR		__ACCESS_CP15(c10, 0, c2, 0)
+#define NMRR		__ACCESS_CP15(c10, 0, c2, 1)
+#define AMAIR0		__ACCESS_CP15(c10, 0, c3, 0)
+#define AMAIR1		__ACCESS_CP15(c10, 0, c3, 1)
+#define VBAR		__ACCESS_CP15(c12, 0, c0, 0)
+#define CID		__ACCESS_CP15(c13, 0, c0, 1)
+#define TID_URW		__ACCESS_CP15(c13, 0, c0, 2)
+#define TID_URO		__ACCESS_CP15(c13, 0, c0, 3)
+#define TID_PRIV	__ACCESS_CP15(c13, 0, c0, 4)
+#define HTPIDR		__ACCESS_CP15(c13, 4, c0, 2)
+#define CNTKCTL		__ACCESS_CP15(c14, 0, c1, 0)
+#define CNTP_CTL	__ACCESS_CP15(c14, 0, c2, 1)
+#define CNTV_CTL	__ACCESS_CP15(c14, 0, c3, 1)
+#define CNTHCTL		__ACCESS_CP15(c14, 4, c1, 0)
+
 extern unsigned long cr_alignment;	/* defined in entry-armv.S */
 
+static inline void set_par(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, PAR_64);
+	else
+		write_sysreg(val, PAR_32);
+}
+
+static inline u64 get_par(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(PAR_64);
+	else
+		return read_sysreg(PAR_32);
+}
+
+static inline void set_ttbr0(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, TTBR0_64);
+	else
+		write_sysreg(val, TTBR0_32);
+}
+
+static inline u64 get_ttbr0(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(TTBR0_64);
+	else
+		return read_sysreg(TTBR0_32);
+}
+
+static inline void set_ttbr1(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, TTBR1_64);
+	else
+		write_sysreg(val, TTBR1_32);
+}
+
+static inline u64 get_ttbr1(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(TTBR1_64);
+	else
+		return read_sysreg(TTBR1_32);
+}
+
 static inline unsigned long get_cr(void)
 {
 	unsigned long val;
diff --git a/arch/arm/include/asm/kvm_hyp.h b/arch/arm/include/asm/kvm_hyp.h
index 87bcd18df8d5..484d35e5bb36 100644
--- a/arch/arm/include/asm/kvm_hyp.h
+++ b/arch/arm/include/asm/kvm_hyp.h
@@ -36,60 +36,6 @@
 	__val;							\
 })
 
-#define TTBR0		__ACCESS_CP15_64(0, c2)
-#define TTBR1		__ACCESS_CP15_64(1, c2)
-#define VTTBR		__ACCESS_CP15_64(6, c2)
-#define PAR		__ACCESS_CP15_64(0, c7)
-#define CNTP_CVAL	__ACCESS_CP15_64(2, c14)
-#define CNTV_CVAL	__ACCESS_CP15_64(3, c14)
-#define CNTVOFF		__ACCESS_CP15_64(4, c14)
-
-#define MIDR		__ACCESS_CP15(c0, 0, c0, 0)
-#define CSSELR		__ACCESS_CP15(c0, 2, c0, 0)
-#define VPIDR		__ACCESS_CP15(c0, 4, c0, 0)
-#define VMPIDR		__ACCESS_CP15(c0, 4, c0, 5)
-#define SCTLR		__ACCESS_CP15(c1, 0, c0, 0)
-#define CPACR		__ACCESS_CP15(c1, 0, c0, 2)
-#define HCR		__ACCESS_CP15(c1, 4, c1, 0)
-#define HDCR		__ACCESS_CP15(c1, 4, c1, 1)
-#define HCPTR		__ACCESS_CP15(c1, 4, c1, 2)
-#define HSTR		__ACCESS_CP15(c1, 4, c1, 3)
-#define TTBCR		__ACCESS_CP15(c2, 0, c0, 2)
-#define HTCR		__ACCESS_CP15(c2, 4, c0, 2)
-#define VTCR		__ACCESS_CP15(c2, 4, c1, 2)
-#define DACR		__ACCESS_CP15(c3, 0, c0, 0)
-#define DFSR		__ACCESS_CP15(c5, 0, c0, 0)
-#define IFSR		__ACCESS_CP15(c5, 0, c0, 1)
-#define ADFSR		__ACCESS_CP15(c5, 0, c1, 0)
-#define AIFSR		__ACCESS_CP15(c5, 0, c1, 1)
-#define HSR		__ACCESS_CP15(c5, 4, c2, 0)
-#define DFAR		__ACCESS_CP15(c6, 0, c0, 0)
-#define IFAR		__ACCESS_CP15(c6, 0, c0, 2)
-#define HDFAR		__ACCESS_CP15(c6, 4, c0, 0)
-#define HIFAR		__ACCESS_CP15(c6, 4, c0, 2)
-#define HPFAR		__ACCESS_CP15(c6, 4, c0, 4)
-#define ICIALLUIS	__ACCESS_CP15(c7, 0, c1, 0)
-#define BPIALLIS	__ACCESS_CP15(c7, 0, c1, 6)
-#define ICIMVAU		__ACCESS_CP15(c7, 0, c5, 1)
-#define ATS1CPR		__ACCESS_CP15(c7, 0, c8, 0)
-#define TLBIALLIS	__ACCESS_CP15(c8, 0, c3, 0)
-#define TLBIALL		__ACCESS_CP15(c8, 0, c7, 0)
-#define TLBIALLNSNHIS	__ACCESS_CP15(c8, 4, c3, 4)
-#define PRRR		__ACCESS_CP15(c10, 0, c2, 0)
-#define NMRR		__ACCESS_CP15(c10, 0, c2, 1)
-#define AMAIR0		__ACCESS_CP15(c10, 0, c3, 0)
-#define AMAIR1		__ACCESS_CP15(c10, 0, c3, 1)
-#define VBAR		__ACCESS_CP15(c12, 0, c0, 0)
-#define CID		__ACCESS_CP15(c13, 0, c0, 1)
-#define TID_URW		__ACCESS_CP15(c13, 0, c0, 2)
-#define TID_URO		__ACCESS_CP15(c13, 0, c0, 3)
-#define TID_PRIV	__ACCESS_CP15(c13, 0, c0, 4)
-#define HTPIDR		__ACCESS_CP15(c13, 4, c0, 2)
-#define CNTKCTL		__ACCESS_CP15(c14, 0, c1, 0)
-#define CNTP_CTL	__ACCESS_CP15(c14, 0, c2, 1)
-#define CNTV_CTL	__ACCESS_CP15(c14, 0, c3, 1)
-#define CNTHCTL		__ACCESS_CP15(c14, 4, c1, 0)
-
 #define VFP_FPEXC	__ACCESS_VFP(FPEXC)
 
 /* AArch64 compatibility macros, only for the timer so far */
diff --git a/arch/arm/kvm/hyp/cp15-sr.c b/arch/arm/kvm/hyp/cp15-sr.c
index 8bf895ec6e04..efbbd2e8927f 100644
--- a/arch/arm/kvm/hyp/cp15-sr.c
+++ b/arch/arm/kvm/hyp/cp15-sr.c
@@ -30,8 +30,8 @@ void __hyp_text __sysreg_save_state(struct kvm_cpu_context *ctxt)
 	ctxt->cp15[c0_CSSELR]		= read_sysreg(CSSELR);
 	ctxt->cp15[c1_SCTLR]		= read_sysreg(SCTLR);
 	ctxt->cp15[c1_CPACR]		= read_sysreg(CPACR);
-	*cp15_64(ctxt, c2_TTBR0)	= read_sysreg(TTBR0);
-	*cp15_64(ctxt, c2_TTBR1)	= read_sysreg(TTBR1);
+	*cp15_64(ctxt, c2_TTBR0)	= read_sysreg(TTBR0_64);
+	*cp15_64(ctxt, c2_TTBR1)	= read_sysreg(TTBR1_64);
 	ctxt->cp15[c2_TTBCR]		= read_sysreg(TTBCR);
 	ctxt->cp15[c3_DACR]		= read_sysreg(DACR);
 	ctxt->cp15[c5_DFSR]		= read_sysreg(DFSR);
@@ -40,7 +40,7 @@ void __hyp_text __sysreg_save_state(struct kvm_cpu_context *ctxt)
 	ctxt->cp15[c5_AIFSR]		= read_sysreg(AIFSR);
 	ctxt->cp15[c6_DFAR]		= read_sysreg(DFAR);
 	ctxt->cp15[c6_IFAR]		= read_sysreg(IFAR);
-	*cp15_64(ctxt, c7_PAR)		= read_sysreg(PAR);
+	*cp15_64(ctxt, c7_PAR)		= read_sysreg(PAR_64);
 	ctxt->cp15[c10_PRRR]		= read_sysreg(PRRR);
 	ctxt->cp15[c10_NMRR]		= read_sysreg(NMRR);
 	ctxt->cp15[c10_AMAIR0]		= read_sysreg(AMAIR0);
@@ -59,8 +59,8 @@ void __hyp_text __sysreg_restore_state(struct kvm_cpu_context *ctxt)
 	write_sysreg(ctxt->cp15[c0_CSSELR],	CSSELR);
 	write_sysreg(ctxt->cp15[c1_SCTLR],	SCTLR);
 	write_sysreg(ctxt->cp15[c1_CPACR],	CPACR);
-	write_sysreg(*cp15_64(ctxt, c2_TTBR0),	TTBR0);
-	write_sysreg(*cp15_64(ctxt, c2_TTBR1),	TTBR1);
+	write_sysreg(*cp15_64(ctxt, c2_TTBR0),	TTBR0_64);
+	write_sysreg(*cp15_64(ctxt, c2_TTBR1),	TTBR1_64);
 	write_sysreg(ctxt->cp15[c2_TTBCR],	TTBCR);
 	write_sysreg(ctxt->cp15[c3_DACR],	DACR);
 	write_sysreg(ctxt->cp15[c5_DFSR],	DFSR);
@@ -69,7 +69,7 @@ void __hyp_text __sysreg_restore_state(struct kvm_cpu_context *ctxt)
 	write_sysreg(ctxt->cp15[c5_AIFSR],	AIFSR);
 	write_sysreg(ctxt->cp15[c6_DFAR],	DFAR);
 	write_sysreg(ctxt->cp15[c6_IFAR],	IFAR);
-	write_sysreg(*cp15_64(ctxt, c7_PAR),	PAR);
+	write_sysreg(*cp15_64(ctxt, c7_PAR),	PAR_64);
 	write_sysreg(ctxt->cp15[c10_PRRR],	PRRR);
 	write_sysreg(ctxt->cp15[c10_NMRR],	NMRR);
 	write_sysreg(ctxt->cp15[c10_AMAIR0],	AMAIR0);
diff --git a/arch/arm/kvm/hyp/switch.c b/arch/arm/kvm/hyp/switch.c
index 3b058a5d7c5f..be8c8ba0e4b7 100644
--- a/arch/arm/kvm/hyp/switch.c
+++ b/arch/arm/kvm/hyp/switch.c
@@ -134,12 +134,12 @@ static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu)
 	if (!(hsr & HSR_DABT_S1PTW) && (hsr & HSR_FSC_TYPE) == FSC_PERM) {
 		u64 par, tmp;
 
-		par = read_sysreg(PAR);
+		par = read_sysreg(PAR_64);
 		write_sysreg(far, ATS1CPR);
 		isb();
 
-		tmp = read_sysreg(PAR);
-		write_sysreg(par, PAR);
+		tmp = read_sysreg(PAR_64);
+		write_sysreg(par, PAR_64);
 
 		if (unlikely(tmp & 1))
 			return false; /* Translation failed, back to guest */
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-2-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
