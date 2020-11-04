Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5PNRT6QKGQE6D7HO6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 785FA2A7113
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:17 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id e9sf53358ejb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531957; cv=pass;
        d=google.com; s=arc-20160816;
        b=pPJTM5MqCbGKikHNbcQNoxWFCMWcMWp3IWeY8HhnZVErwI4ctce6RZikGXkJP8GFbQ
         aUczKdwHm/aE7iC4KWzZWoS3aeWL8Nr1RYjsWmNRPTzkpn0abA0zuCD9kXb1tLPAATUt
         OPfMLjW+dKx8MXGKCTCxVCb+yYZniIwCaSxrUCiEiJIyUse1Ayqcl/4buzbk6uygkyeY
         Z3GuF3r5xFpnZWzb4rg/wUT2Shqs8X11YjpSC1YJ3YUd8U1O0pXxOlp4VbZ+PXDv3Gm1
         YVCHmYBTPTlILqoPwwVKc4h6wApvskpL2EQWwI+KmWOanTP+RodIY+grXGA21H7TnVU7
         WqPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=x98oZdLl3K6FSbD89ZcqwxWG/Mp1qx5N1DWObQy16mo=;
        b=cOF2iaNvuJGh/kQFkn7FzU9l4KVSgIYww9D2RFJcpJzYt9ZuNNd6PMcjCQNbLaDYt8
         yfNSdAvnajgteOP66WhJRSsOBiN3ApSoTzI0gUwoFHj1+4pzmYMah7ifgqMsYVPhSFdM
         tlskivDJPzdhV4sac6JPrS45iOhggzDyX4U21scvv30T+bXKChNknwW5gTLInPMGSl+K
         hZP6bAidaQuCKSuQ68tB+ijXBhtb7KZ4XEtJ4ymyF+byN1Mxhs39bqUM+cTtodjmpQGv
         tUXJQKHWsbG52q99BJBXxu9rWrqMnQBvsr8+lc1fS4ARH8Df+Oec1YMFkd0wdTVKM1z+
         iyDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XQOwaLsj;
       spf=pass (google.com: domain of 39dajxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39DajXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x98oZdLl3K6FSbD89ZcqwxWG/Mp1qx5N1DWObQy16mo=;
        b=md8IIUVXZRP27hU5iDzjR626WCD4fB4wzawJGjxjWRW76XLi+cE4EYiht17FypIEHa
         KZb0B3nvT+k76iwBVT3O09esErKPdUiXptZpmoZwdb1Ohs19FNiHZov/jBHSVsrUZGb1
         8R1mvQFr+ynR3EJrHCME+VbFIA1ctT79RDore3fMKWQCiBFTZvRbfqSfw2VHhn4W4SSD
         SwZ/rJgcM9KARAzuTlMG7VkkklPmjobm6r5T3MxqeRgKw/K12uMmOCL6dwc796+M54gV
         Z8+7Ttski5M4Xf4y2sRSsBQdTBQpou/Q6CVvX45Qz6o33HoTPtwxFDYakmvqycT8KQ9t
         mQHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x98oZdLl3K6FSbD89ZcqwxWG/Mp1qx5N1DWObQy16mo=;
        b=mepK1YTPlTKhDwYz6bO8dUq/8E5Rf14Z38K0BnnHpfaCBBchV9asW7Jx4kHfJyyKGO
         Sc6grlCpi0rw9Du6JCtcrSTFip3nE8UnCBeP9vX4sIYkpzaxlfr5KEJWpuc9YPgs7teu
         4GXWx58oDMchulTUoWNd74w8nmrLDiRkTo3pHslPxDV3ZDk0N3dZPCgYy6IOh9PriItc
         2UedABjLfPxsErs2MBMlwNUpsZnz/Iza5Fb0nDiRQJ5uzYrFjxMsHEyjUCaFRY7z0MeG
         SasbbCMxxf2Dya97ZP1U3xw2rMvQAXFIGUWYXfU1UCtPIedXYXdXNW44UyWC8XqmlcuG
         D5gg==
X-Gm-Message-State: AOAM531AGriBeGUT+oi871XYaCeJCWa9+iI7FSCfGhDIub3WooDXsSzl
	zpEc+ytfLDrAwP48DyjZiLk=
X-Google-Smtp-Source: ABdhPJyVipn6KflOwSEvu5KVOxlMQff2Ir71Q7Zpr6jZkwnfebdeHaLsuGfhmSJ5yx4qGq3wAREomQ==
X-Received: by 2002:a50:8b65:: with SMTP id l92mr204937edl.132.1604531957274;
        Wed, 04 Nov 2020 15:19:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4c3:: with SMTP id t3ls4128321edr.0.gmail; Wed, 04 Nov
 2020 15:19:16 -0800 (PST)
X-Received: by 2002:a50:eb87:: with SMTP id y7mr165916edr.187.1604531956425;
        Wed, 04 Nov 2020 15:19:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531956; cv=none;
        d=google.com; s=arc-20160816;
        b=OAZhad05FQH5e9Sl+xLdYZp3QAuPFMfYHAwL7+FKtylTHRZfKWY1Zx8r7YXD1QPc9u
         RX0cl4XGg5LgkDmjSKdn8POQxdLw60Bof86YFaZ531hnATs5O1iwMY27RaTw5Dii7zS+
         BxayIqrUTn2CpQaujMTFQSRNSbggpVxY+G1v+glOTRszTrFFkvTz+x+bTkBmxbZQusX8
         xx5wAFHTIoKxvxy7GzndoLRb3/ASwBL5h2I/oUmF0NEqEZ7nl6Be6zIyMLyhRILh+G6x
         7JGcl+kPFXQ30XZV6rK0dPZGUMgXha53pwpEAjG84LRgF2zLlUAjco1MPgV6lR4b6f2f
         y+RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Z3coWAI2tcKTBrlblI3/IYJAWnH07Z1QBuIRVdtXJnY=;
        b=lsYA+uWSUOneWoSxWqP5xGX9ClYd9U+jd7c6Y0wwuvpt5BLF8RFAa/hNX1ek8NF5yS
         MpuEbLLeVlteaZByZ/UortVxHnFBgG6l8Po+uq6hF3Jwx4gVp+g+kdEhuBS0SwDmgg6v
         T8+N+J1kfPQR8zcY0klDUhEGInWu8gjjGxnZeYgT2y0T7hWObBY+71QKYwBfwewZblBE
         EiVrUUpKx1F4wWk53kvSLE+sIgN4OX19SJQ9zwI5NBfomTS4DQxqNnyCrTJX4y2CMdUm
         M7lZl1r2lDfRBovWp6Zy+C20rYA5LDApZKjJmQuDuUbEa7ywQCdPpRvRUy/jL7PeYOBq
         9nfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XQOwaLsj;
       spf=pass (google.com: domain of 39dajxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39DajXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v21si89092edd.4.2020.11.04.15.19.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 39dajxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u9so10560wmb.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:16 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a752:: with SMTP id
 q79mr97594wme.24.1604531956154; Wed, 04 Nov 2020 15:19:16 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:19 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <f105f0703bd0c80a538f0f1f78a8edd342b81a1a.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 04/43] s390/kasan: include asm/page.h from asm/kasan.h
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XQOwaLsj;       spf=pass
 (google.com: domain of 39dajxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39DajXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

asm/kasan.h relies on pgd_t and _REGION1_SHIFT definitions and therefore
requires asm/pgtable.h include. Include asm/pgtable.h from asm/kasan.h.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
---
Change-Id: I369a8f9beb442b9d05733892232345c3f4120e0a
---
 arch/s390/include/asm/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/kasan.h b/arch/s390/include/asm/kasan.h
index e9bf486de136..4753ad0c3cba 100644
--- a/arch/s390/include/asm/kasan.h
+++ b/arch/s390/include/asm/kasan.h
@@ -2,6 +2,8 @@
 #ifndef __ASM_KASAN_H
 #define __ASM_KASAN_H
 
+#include <asm/pgtable.h>
+
 #ifdef CONFIG_KASAN
 
 #define KASAN_SHADOW_SCALE_SHIFT 3
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f105f0703bd0c80a538f0f1f78a8edd342b81a1a.1604531793.git.andreyknvl%40google.com.
