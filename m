Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLMXSWAQMGQE7K6KNUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E888318E06
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:22:25 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id s12sf6268543ilh.20
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:22:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613056943; cv=pass;
        d=google.com; s=arc-20160816;
        b=j+zwB+2gRFqQw6A98f0rkyA9rtYkQmqxp2DQWF1YNwO0Cw5EQjB96zD68SXjllTAYn
         CfBRhssvALZ2eyvbSdYX4ncSt0TfoAyVE9PmZhV+2uylDVUFlQ8/24CP3NxNnjksqP/y
         N4RKDnIpoMp+UW/2ePWxgQIlzE9dJo+FEEugt1j2NR6VA1vJ+JBwQgMH9vMmhYukN+Zt
         27Gi3pUVi1GJ78jKNm0aKoAPX/+Qri5+LLeecECuJr5Z7SUXEmH+WsYnBi8tJ45MMy1w
         K411xmuY9xa7DMCoTUSTcLCEUdBeOgwYK0pQkdH2WBNB+OWP7zSg9ySs/cumqVsii2f4
         T4qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=Ja7bcXV4hGF9vJd2BFOHuphwJU3FxoS+m0ZEIud2wEU=;
        b=wNpWz7pYV2feLj8Xs18P2xIPxrTH16MQZFrnRL8Y3uzNWQrgWwKYn9JETzQm8msipE
         wfltgpBmJLmgMP5iExvHkBcTLKLRujpjPSFcbTtOHxAOuPHkJwNFysAb2xjHlSZHRCYi
         AbDs47KkGT/bXTI8kgK6zTT/j5Vyi7QwhgMG/3nB35wgTgcUoOnMlbPZ7RynXMAKk9ZA
         xu2xx7d0ovMxA7nKOUAYeOJxr4TkodgI5GZXzlLzNGucQp9qGHvkjjFLrJ2724AlsjO1
         XyzfcRrkhi3osbPT1T43NqxHzaafsYgBbtbYOJIMtoMIA0KBToYC1VvxDc//7ILObrax
         KV3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ja7bcXV4hGF9vJd2BFOHuphwJU3FxoS+m0ZEIud2wEU=;
        b=S/3xAzpcgSj0nyn8Ac6uskrVHPY0zgJumqesefwT7LMcuy5F4hyaWY9p95WrUDj0qO
         gMcRKqqd8b1EcsrytIXu1UWSw8Ut750lQGkk+wjgy0HrOOoGq+H9i81EwsFs6G9o6k8D
         QMtqh/fpMIzMljnGvFPOSz03ROMtxB9bk1D13i07mDZGrIe/3WzpDh+6i71azSbZH0Fl
         cJTPuKODg5Ez0adg/nEPbAv+91cZ92zL5+U2/n1fJxdzXEpBDoEA1cPWuBMPodoBPzqb
         z28MIJvcG8o1NpkGIEcM3J8F6byb6ORlhqvH1SK4AcOCt6h52xwmEPmNOexQr95OqLir
         TKNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ja7bcXV4hGF9vJd2BFOHuphwJU3FxoS+m0ZEIud2wEU=;
        b=jAc17RjHsDCLCWYRU5R4Yt3/QFnOAK8yXbk7ZzDh4ZCBKiece1271sxR+s4Pgk6bep
         ZnGSMmPHyrKme4mmtQESCNcQz80IoRiDw8VA27BdQ3t/17XfQIPx1u6aZYK2rbDNv1gS
         yb3ugqpx+4tQnBswgZr0w56C6Ekdl+UIhgADLQg4lyCSV2wUj10paspeufZv/levbjhU
         cKQFHw3xU2ib2CtPKIXfDRTIh02OoF91ltozoEx3V/+kHO+DMtPFylhQ8gfmcecD6t4Y
         G8fOqVFgMdjoSXiveym0MqFytrM3OC2HvAn5LL69OT6Uov7wnVMCl+dPQTXnJ/cmHo9z
         tX1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530D7RZslPHrMrcihH3ATbWPxjUo/aA/dyoQjOLeb0gy0IygZ8FM
	mWtZGnbxpceHAitHrsai3ig=
X-Google-Smtp-Source: ABdhPJw+WVhuD5BK1JQn5dujTa7VNsuRzrG8GbZibfXVIU3Ilsj6hg33LYCUjvn0d7vtRoiSafgkSg==
X-Received: by 2002:a92:4b06:: with SMTP id m6mr6214312ilg.177.1613056941909;
        Thu, 11 Feb 2021 07:22:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f0f:: with SMTP id a15ls1590265ild.8.gmail; Thu, 11 Feb
 2021 07:22:21 -0800 (PST)
X-Received: by 2002:a05:6e02:1806:: with SMTP id a6mr6188426ilv.8.1613056941380;
        Thu, 11 Feb 2021 07:22:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613056941; cv=none;
        d=google.com; s=arc-20160816;
        b=OCJEGgAm+DDH9zXKjDzReTrS3qQcMQ2EJ3xsMzSNaexmBr1k0IQe5L0D1ercE/9nxR
         F+0l2oiSOdimbBi8P5IcL73aD/pwo9LQPkRKonPdeJFXMb5PvqGNDBFfHx5T7JJZuQT0
         aKpVDyuyYVbNlRil/khExkUv3YNwsx7sfdpGqT08L3Rw4kH9gOfuqn9HQRjiKQsdotVu
         hXNzgtg4RpBNGhINwSK6GB0UPFTwiPQjz3HAEtV+Ys2Hvo5NJBC/vZ81y6aCS174NA3W
         oxciGLu1c+Gk6anxrHe7If8XxZ1rJHOSIaFvm6syGixxXuyRvbAp2tWQewxksestxlzc
         5bww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=eu11S9hkvYPmcCBBOM7A6eZ0irh4MPt8+m1SW3vufMs=;
        b=cpcfbmsd2+8PBXaxTFZzMol/1q5g7YcBKKPUmjsP2d/KbR8Mv9aJ03LeJttT2Zwdkn
         aCg3tzh+NbBbzTxb7UWDqGciYZ4XUuZwxq8H71aKIw3pQ7WwxYQ5sJ+vGOaEYif+FpNY
         ifWRo+GAjqlF1FJmm1hHuM2dCeMgup3wXpCB3vLqJ7WnKJnzdQ41faFf2sCIY0r4jXXa
         Xx+0lfWHm79jhO9Iah+DabD0b6nNXT4YjXwZjPP2cnLBnm5a//zcrzd6LmqUHVEeSwB4
         94URO996PM8f+/ZsOC1CJY4y/PWwqceDPoVmKkq1G7zew1NIO24B73eCnQamiM9wCmhd
         uvBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si317572ila.5.2021.02.11.07.22.21
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:22:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 776AE113E;
	Thu, 11 Feb 2021 07:22:20 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5A94C3F73D;
	Thu, 11 Feb 2021 07:22:19 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v2] arm64: Fix warning in mte_get_random_tag()
Date: Thu, 11 Feb 2021 15:22:08 +0000
Message-Id: <20210211152208.23811-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

The simplification of mte_get_random_tag() caused the introduction of the
warning below:

In file included from arch/arm64/include/asm/kasan.h:9,
                 from include/linux/kasan.h:16,
                 from mm/kasan/common.c:14:
mm/kasan/common.c: In function =E2=80=98mte_get_random_tag=E2=80=99:
arch/arm64/include/asm/mte-kasan.h:45:9: warning: =E2=80=98addr=E2=80=99 is=
 used
                                         uninitialized [-Wuninitialized]
   45 |         asm(__MTE_PREAMBLE "irg %0, %0"
      |

Fix the warning using "=3Dr" for the address in the asm inline.

Fixes: c8f8de4c0887 ("arm64: kasan: simplify and inline MTE functions")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---

This patch is based on linux-next/akpm

 arch/arm64/include/asm/mte-kasan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mt=
e-kasan.h
index 3d58489228c0..7ab500e2ad17 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -43,7 +43,7 @@ static inline u8 mte_get_random_tag(void)
 	void *addr;
=20
 	asm(__MTE_PREAMBLE "irg %0, %0"
-		: "+r" (addr));
+		: "=3Dr" (addr));
=20
 	return mte_get_ptr_tag(addr);
 }
--=20
2.30.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210211152208.23811-1-vincenzo.frascino%40arm.com.
