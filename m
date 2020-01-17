Return-Path: <kasan-dev+bncBCH67JWTV4DBB7HURDYQKGQE5O2ENEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A398141454
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:51:40 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id w3sf17473745edt.23
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:51:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301500; cv=pass;
        d=google.com; s=arc-20160816;
        b=NbsjE6wY5sMYb1A6BbZZBbXXRxeO72l9q0hZzbRN9pcV/jMJDND0238WLktQCdEyct
         ViLsu7H4KBVU6dQ2YXS8e7ikbIoPz826oQMsaoy8BYrDEQAjZ4PSf8k8nwoIXHr1eSCn
         3Th7xh9ja8HihFYRzU6osXfhoYL9LzWMM0bx1wCPZq43D0uh8Iz8T6iIxYgHjN/QadkY
         PubQ/v8bIdMqaeB9ZohQG0r1n1d4iLxo9WYep7B+cvWfRLtc4j6ZXZmX1aKERgeDVsGG
         zWZxMlzIvXIo3phkV8LJwwwjoNpGAONmPt9Wgm5pc2thI+wUac4vpk0crQXuVvhR5jxE
         Zoxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Anj+GWJx2D8raWQphe7wWRlY+NaRE7nwdjXj4A+rhtA=;
        b=i5uZdARJuucrvzhWoDmJVz4VSB6uMP/CpNXAWGrTJ02MQx9D+aueNRyuOGLYhwp0hi
         i6z6QsGg4z2/4B9zO0XsmtZRya0NWi0R3+XoxZUXP7aQNzFlMPNmO0Yg0z2Qjq9iUllh
         gaXRIFisO+1nYzaMmhAqf1pgxwDI/DMp7UwmsDjBXv8n2lJyJruYxBfHRocTky/ZgyiJ
         jRQd5sz/EysN0umJm3GkMVO8Kz6pxuQ5U7VPJvW63rnIB/b5mNU8zodk49cXd9Hpdl9j
         1Xe2X3z4wEVLDKCFPyQ+Olj4pY7n9CJZfA8InNOtTDxriAN+7iVlWQ1bVp+qYkFa0XO4
         HUTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mrCFH1Gw;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Anj+GWJx2D8raWQphe7wWRlY+NaRE7nwdjXj4A+rhtA=;
        b=LmrR6a5YAVgIntc2oKpsEFJH+GP/HO7uT00YAjcY37wKsQf8+xgtCs7wpkTUwSkW/p
         ZUZcPgoQDOr0c90M17Qg5c89rXFfit2/cVh1wc2hXEtsqQp0nW737fOxDW9WYJGZ7A8I
         5t5YGaiAKLY5CKD2NLF0mD3SpuE6qSeLYwmskF+y3BcPY4SBy9+/mBU4YC0atN8aCk6e
         a/45ScJfM9PHs8Bp00YOgUfRCYIzGIplGI6Cknn8caL2KjL8GD9plD25+Nx9SxWzaqrY
         vt5ciAQHkFk+3Gvo54aVVeL3acKAfc8VA7l3TMTEzl02BpT6eA1pXugrRRWQeG+jncIs
         DuGw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Anj+GWJx2D8raWQphe7wWRlY+NaRE7nwdjXj4A+rhtA=;
        b=GjtqKZuEvfITd4lhDnKOa9DKzPNxfnCBB0fqfSyqNy9huVGYLvfETIaVvm31SMiFse
         y7XxC9baDcvvcMQ1It4WrlkFCTHi6ZDhiJlAmileVCIWGAdks/qb8LYQk94n7xLKuL9K
         k1CDhlpgnuipxXxyvFTKfzMhPAhW7JmITJ7JmI7nYWWTE5fPtkniNyR+9eRs7wQL85nW
         T+giMXe0EPz4UkqDYy/q5IR/Tv6qwvV19VC5aoBFitPZTrXP6nnm7CeRE8ysE7eTkY9R
         BVP5d3CGPcxWUTAzzwwdX5ibFLJX10U2rMUo0lpmfdO+6JqJktTKsGJggW4EKeV3RbxJ
         1EhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Anj+GWJx2D8raWQphe7wWRlY+NaRE7nwdjXj4A+rhtA=;
        b=elLodJ1I8l4kgBdA+44zI0lp1pZBVf8YPdihvOndwY84hYMVPVDzAFaQi8x8EGFmvy
         jU+WRI0ESqFHJDn/vS3Ig27ECuuLxEryFbbVXbN9HXw4UEoHtKiYxhVMMpEmMJYzstTp
         x9wo76+01BORCYR5VStNrRyzR0O+N5K+ECK0ta99K1Q5egNZhlgx9c5RCPxmRM15qX3p
         RKbtfVPU/PJ26S9O6x/DPdK0elEFdi46a3CqIlln9MV8CdO/Rw3dYcx6vGGbeDRfWAYu
         O121uMhxD/qXa+OKYakKcdcWz1zIBO5ShOzSRZ6qP1cF2aaUI0/eJyf+qnvdQ2qOYUKR
         yexw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVme9g/kRhvq96+upaym8lO/jPZsGhNdDMWdo4hy/tA+DSk1S8g
	mmC4ttBByQf+kbkyBBN1cKQ=
X-Google-Smtp-Source: APXvYqzqqZ23Tf4LqIvugsg5Y5FdLZ2+JLsIFNw2QumVCcAW7tRjrIqHgQqYU9u+UWJ3pbSJfyv/ow==
X-Received: by 2002:a17:906:4947:: with SMTP id f7mr9805938ejt.172.1579301500143;
        Fri, 17 Jan 2020 14:51:40 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd15:: with SMTP id i21ls6538459eds.9.gmail; Fri, 17 Jan
 2020 14:51:39 -0800 (PST)
X-Received: by 2002:a50:fd93:: with SMTP id o19mr6441668edt.28.1579301499518;
        Fri, 17 Jan 2020 14:51:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301499; cv=none;
        d=google.com; s=arc-20160816;
        b=oYRAn2N868Zvm2JeXc8JqQpVq2PLoP0T15RScLLAh8HlhdqXHngLR8em+iWi9zMqZ/
         8ypzmtSCjdQc02lWL0WWRhUL9w67n6jZn6TL7WPjX9bMIFrpkTIxa37U+5nXUNwzr/B/
         Wo4HeY5Y260skgltOCNC8akhLl44LQwQX5e6BlNXiCjULu8ww3lZWTAjuJvVrP5JCMIs
         Hp8u49ANcTH719SfMGpwXG6LPDgJ/hJFf2Jv6M+8EP11eNCOkdbxv96h59lGyQfe3q34
         ai0m/Bwg0wes2t1WmPcH/IfpkRSRxlJ4s7u97kXVWgZnAG/mq8gMb5izGZEKTRmI/GX4
         lmvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=a2nRYyxjPyQF3IQbPCKoaUguo6CO4aiwXRtlS8UQpy4=;
        b=a90RmenWHMLor69gdnvTnXV2Huebvey1vgU0qR7p4AHUBRFp2aZmq4iG7HFXJRsgxq
         HD38W38kPnHGNUn0W3INKm1EeB7R9UF7uPakg5xPV+SdI6lo6Vxp/L9h2CyTeijEguUN
         LxxKIkXEI3qFReiMELYp4j73bM7EIOM6Nmr1HRAZIVN6emBeln2QNfiSvP3hX2+VveXf
         6YYoonWxx/vV74SeTjyx2HWSc/Pr6/jSNnALXs49PlU+Wjmz1B4dGOKoJYnFLGD/ThQH
         DesjMpZH2AcIcr+kkR9NYypeeTL4ILE65hLx3feJlARGDQVc3pLhAcNsfELD0u7nyKc1
         ByCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mrCFH1Gw;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id cc24si1224999edb.5.2020.01.17.14.51.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:51:39 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id f129so9153022wmf.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:51:39 -0800 (PST)
X-Received: by 2002:a1c:3c89:: with SMTP id j131mr6975350wma.34.1579301499190;
        Fri, 17 Jan 2020 14:51:39 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.51.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:51:38 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Florian Fainelli <f.fainelli@gmail.com>,
	bcm-kernel-feedback-list@broadcom.com,
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
	liuwenliang@huawei.com,
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
Subject: [PATCH v7 1/7] ARM: Moved CP15 definitions from kvm_hyp.h to cp15.h
Date: Fri, 17 Jan 2020 14:48:33 -0800
Message-Id: <20200117224839.23531-2-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117224839.23531-1-f.fainelli@gmail.com>
References: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=mrCFH1Gw;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342
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

We are going to add specific accessor functions for TTBR which are
32-bit/64-bit appropriate, move all CP15 register definitions into
cp15.h where they belong.

Suggested-by: Linus Walleij <linus.walleij@linaro.org>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/cp15.h    | 57 ++++++++++++++++++++++++++++++++++
 arch/arm/include/asm/kvm_hyp.h | 54 --------------------------------
 2 files changed, 57 insertions(+), 54 deletions(-)

diff --git a/arch/arm/include/asm/cp15.h b/arch/arm/include/asm/cp15.h
index d2453e2d3f1f..89b6663f2863 100644
--- a/arch/arm/include/asm/cp15.h
+++ b/arch/arm/include/asm/cp15.h
@@ -70,6 +70,63 @@
 
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
 
 static inline unsigned long get_cr(void)
diff --git a/arch/arm/include/asm/kvm_hyp.h b/arch/arm/include/asm/kvm_hyp.h
index 40e9034db601..f6635bd63ff0 100644
--- a/arch/arm/include/asm/kvm_hyp.h
+++ b/arch/arm/include/asm/kvm_hyp.h
@@ -25,60 +25,6 @@
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
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-2-f.fainelli%40gmail.com.
