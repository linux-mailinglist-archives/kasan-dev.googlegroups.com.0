Return-Path: <kasan-dev+bncBDB3VRFH7QKRBJN3ZPDAMGQEMFA6NLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A217B9718C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:27 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-767e5b2a74fsf1682016d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649766; cv=pass;
        d=google.com; s=arc-20240605;
        b=L3A7OnOo3h+f5fPfl7GMFRR6UQ1W3gVsZJAj++EAl/HdnA6f5bKWJmCjcowWbxiGAP
         VWjHY2pt2dVh/jDOTg0gTLEHvX6Hz3CTMvuDZh4L6w6UwPXqvT2CSgre0WPJf6XW2k/u
         qf06cW+uK77OlUABBRUCJhAYxJXsSuer1qutR5sV2KBHw6Ah7bnVuYRcTJA+vWSVT/0Z
         BF5+zfh+mMEH0op3uW6HO/QcmRih9HFX+YRsdkooV8kc+hElLrd59A105cyK9Rz7HlMr
         +5zSrhext+Lgj8Lvf/tq2wxWaB0ujeZqOJ8gUwOMHSdZdEKFbKytJYDqRgN6aXnY3VoO
         LfZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4uaRR8Opf3GGJfbwv7znnL1c/n12WdsJ8UlnL1R74dY=;
        fh=OxyRgD1pEKOKgvFZDznpQyvUVy7e8w5jtCTwEHRWEKM=;
        b=DTOKgLnIZOmv6EiLOpjATOeyt1GGtdh2vK90wNgirE7D2oW/kodh1R7AmaEHJFswhP
         eBmExpXf2HcAckyV+POwi3/T1jkKTO7bJbwkJm1iff10boD/SpIlMIU6SmIGWsF6tzdy
         UrQ0ddqDO/p+6wylkOaE2BPVC7t+TD42te6mrOCCtCm9mwcJAONUUZEemICFc+JJPUXP
         F0zE2mYdFwTEClvcAUjLa0ej96DbPiMsVK8BjYMHENtfmYeNYAChm+VgDdjAboM+CHUs
         TRFW9hCNWLGkuzQFq/wjKFel8nl28vUDDrHH1283L8kfD26rsair0/612OpL19QyCor/
         S2MQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649766; x=1759254566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4uaRR8Opf3GGJfbwv7znnL1c/n12WdsJ8UlnL1R74dY=;
        b=jwBH87Ju73O16tCq9BTGtedYzCbfq0H/wIE6iTwYslDRJd9EmD7KenvUCtiVrFn/GY
         N3XxnD7w/HZEPuZ+90Qd4YFTydwZhVNa6l9KtzD69mMoT1jTNPSGUDdDnMtaJ6piQogj
         4xAsF5JE79QZHrCZQF5syihXnbrw+DK1xzsC22opV+AMWIluFmvro0r9RhZvp30UDQSa
         kKsG6d5xLaeEtSWXDohGdx+Igp6xazfB2HqYLJDHgnww00wrQoIwaDObXlZ7fNdjLphJ
         MCcVY+8EU1uGY1bbAZV3SXpJPDscHukWMaf3zg62ro/0wGoHWMhjoOPLQ+PTGuF8Bd0K
         GS6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649766; x=1759254566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4uaRR8Opf3GGJfbwv7znnL1c/n12WdsJ8UlnL1R74dY=;
        b=H5YAodrZCWKKRjPgqWw3mJjUZHrhzllV6g5vTF4/mkxhvhyR5pV6xcfZw2S81USoHt
         YacmPllgJTLKviBS6EPhL0eX07c5Ef3M1mvsxoHJqGVWYU5kVHHGAniBvuVSjtygBGEu
         AHQy8oDJYSH+h6kls2/sWy3L2nS4pTNCxVvDCbfHoRf4am1de5O2VwZ9yKGcS1v3RkGk
         FPb5HE3Gz4hCNp0KDKJkMt3tIg7EmnZT9hIumBhTph1EGD0jyR7//eMVRAf5Gtj0S297
         ocZKJLaxQTi2o/8Em2YYK1SCHoeQ9M/7Mlz0U24i4P6mKsE9qBAF5VoJNGa4FtPYsypV
         sT2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWON4a/zXJRGKG1agynn2/8+NY+i4uEN0aUW3r9zMLKYYIpNC4b0B0eG9iHb1YuEctY/lNalQ==@lfdr.de
X-Gm-Message-State: AOJu0YyVrj542ngEQ13/7QOKlyr/AzLALId4DkY0Hw0ALb+WzWLHzOJM
	KUs8LV3fsE7kw1OXrbWB4tuTyz2aCpYNOJHzCCuuzH7tTx2ObTOnvN+j
X-Google-Smtp-Source: AGHT+IFCfxlkYHM1GeYEKUE/iIhRdxm+7zXl2gqPMp+BRRMvqQP6yFJaq2VPr70HGq/ZulVYC2CgHw==
X-Received: by 2002:a05:6214:1c4e:b0:79c:4d80:7357 with SMTP id 6a1803df08f44-7e7a01564c5mr42652636d6.4.1758649765844;
        Tue, 23 Sep 2025 10:49:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7dKndeZrRORknTP9/1jyAyCIHLdbBmnlgRAhSeZxhnGA==
Received: by 2002:ad4:40cc:0:b0:6fa:bd03:fbf2 with SMTP id 6a1803df08f44-7efe9c7b521ls743776d6.0.-pod-prod-00-us;
 Tue, 23 Sep 2025 10:49:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhtM0hnU9WQheXzZovs+2yPUoIEaoAyFjtyMtWeRl2sFJB7Cnx9qEJELsmaYAzGjQX0kdsCcAsxYU=@googlegroups.com
X-Received: by 2002:a05:6214:258c:b0:78e:5985:92f1 with SMTP id 6a1803df08f44-7e7a3c99478mr40322636d6.11.1758649764834;
        Tue, 23 Sep 2025 10:49:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649764; cv=none;
        d=google.com; s=arc-20240605;
        b=K9HhBy4ucS0uqOMBYyov6+pNmklcdVlcBFp7ovP0uyvsiunPxssoYPWkAQOw2AHq5m
         D8V8gLb7vxPxcJlisDDZDRbD6Yr7RN1mLycGiq8wqvk0IoDDw3/5SY/4+zpBmctjNBRT
         OM1GGByNcFJAgPLcSAWfqYGM8sTvw02h+zBS4cTI9f3yoP9x1PosLRvWjKQpu2OBBj6k
         pq4gkaV60zIukSqUsfn/IRLIhRh30hzva7hBKASvkV4fS7TODpLfI5O6ekhM+2/CG89T
         tdsdpo1+TzicheATGBWJSS8s3yYI5QU9Nnyfdgfs6ziVGZEr6x1Mx/mrPFe+LTkByD4Z
         XCeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8BNGHKYTksCgXacuIfzUjXtJP9J31ATouaI+NCug5mc=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=MNVEFiwNHOZ5VMea2k7n2gcwInL8urEljm4fKJLRXwJYKliPtQv+RtfP4U7Gfyr+e2
         KPBx0cY31OkHcErVZCBYxJ+gxEDvh2CJ7BwI9YqRgmyDRnx+nLx3e9IWtgwM3e7JQBEG
         RGKQt/+n46+CRC1gSCgcXnmr7xbGw9mxsbDZ0Qdfbujo8WHh39puf6aiiXlqZ5o0nZ70
         GGPuyx3hFGI3UsU4Qg4k+bubXRg2gG3lAgowNLgaaTL5ygmbb0wmxreBzuh12oFdL76o
         2tzjRe68gDFhF/xyi4dlG7YQEZ0Gg1ZVLbzSUdz/HfYmd7ROvZ92GCX0sJb48DjJcIda
         UpyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-79341b6ce38si6087546d6.2.2025.09.23.10.49.24
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EEBD7267F;
	Tue, 23 Sep 2025 10:49:15 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 67B913F5A1;
	Tue, 23 Sep 2025 10:49:20 -0700 (PDT)
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
Subject: [RFC PATCH 02/16] arm64: kasan: make kasan_hw_tags_enable() callback safe
Date: Tue, 23 Sep 2025 18:48:49 +0100
Message-ID: <20250923174903.76283-3-ada.coupriediaz@arm.com>
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

Alternative callback functions are regular functions, which means they
or any function they call could get patched or instrumented
by alternatives or other parts of the kernel.
Given that applying alternatives does not guarantee a consistent state
while patching, only once done, and handles cache maintenance manually,
it could lead to nasty corruptions and execution of bogus code.

Make `kasan_hw_tags_enable()` safe by preventing its instrumentation.
This is possible thanks to a previous commit making
`kasan_hw_tags_enabled()` always inlined, preventing any instrumentation
in the callback.

As `kasan_hw_tags_enable()` is already marked as `__init`,
which has its own text section conflicting with the `noinstr` one,
use `__no_instr_section(".noinstr.text")` to add
all the function attributes added by `noinstr`, without the section
conflict.
This can be an issue, as kprobes seems to only block the text sections,
not based on function attributes.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/kernel/mte.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e773844889..a525c1d0c26d 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -239,6 +239,7 @@ static void mte_update_gcr_excl(struct task_struct *task)
 void __init kasan_hw_tags_enable(struct alt_instr *alt, __le32 *origptr,
 				 __le32 *updptr, int nr_inst);
 
+__noinstr_section(".init.text")
 void __init kasan_hw_tags_enable(struct alt_instr *alt, __le32 *origptr,
 				 __le32 *updptr, int nr_inst)
 {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-3-ada.coupriediaz%40arm.com.
