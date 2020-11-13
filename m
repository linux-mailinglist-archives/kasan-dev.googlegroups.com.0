Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZMLXT6QKGQEISJRQFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 54DA42B2818
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:10 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id o14sf3193290ljc.5
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305830; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0xMUHzRQ8PuskhyY4UlDBYtuqaSMWPTqU3+X8Z/EAyEbVyauSqUeL+vOgllvcOMDY
         MuBvS4pWF8s9EZtXxHq4dBUJMOfB5B0H04MzwkNX0iQkAf23oBTy3KXxGn+J551O5xq+
         sauYRgMXW7GcjdtPlEWcu2yk6Vo3lpml5u/CF1i7c8/OcaZzXyf5bqD9o2jq0giM5X7Y
         Nu9iQK+2fnWiLpreJWdhVanXzEFJ/BgIWpciaIQdmH7Z3yrtB04ar+WOQpLPblurH8V7
         +Ch/2bTfF/bIfFvJWv9gyApPdEwFDn06KaX4sgzEUlMG9QBdgsJnFaznrBk4R78cYIrn
         ABTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OOCxEDtQJ24t95r1eDNDRLZcbDxeSvwHtg2+THTRKmg=;
        b=pf2mlJsDHOQAijeZ91HD2u1HuLDFo0SB3dDy0G9X449tFZJBeDpVcikNDLWdqRGvVv
         9SiDcDjWazWbqnW7NtIsipGkfl0i1qbjZCB31M76mAEbaZmw3VDTMhfVS32NApFojlj7
         QtWDrItJEXTiIUCs1IHqmgWlnA8lv30ziG7h4b4812Z98QKMTqC5phrwYNmfh5JxyAVg
         EyYboO3sexNv0UwBVJkadTVZsyspApRG1/N+oPOhrTx1EyF3rs8WT+0iDzNtMlTYvNaf
         QqMxocH4skJFJ+evInT/PYELDH9reZvYil3uw+nmQ0D0oD/x5JDSEQf1RFNXClr9IPRB
         ZvXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MjJCBEnc;
       spf=pass (google.com: domain of 35awvxwokca8pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=35AWvXwoKCa8PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OOCxEDtQJ24t95r1eDNDRLZcbDxeSvwHtg2+THTRKmg=;
        b=Q/AW8L0WG4tKh/XuUFwLYhiGqx5Pc9IXaog1ILXmyjCcBFAdE99X30hCsDjlQWXnlo
         t18Zfh1M57sXmV5wIVqzC3d/Ci7/Llc0UbVJLJFHX/QXGJkFHxeMHWcfKit3Xn4NgXJD
         Dh9VYWbfJixhdiXV8t1iwoNsS4TV3K0+YJdzaIN+rfxhIA6ZciFjZVVgescoiuu/LzDl
         EBnpbfPobgOdDZB4BmjrupKHHGaQv9/vfa2WypAUAGVi+dQdKjlqc7AbeSc4NuRFRmZU
         Gd6w+fA5SWPX21jfFe0+CACiaNWjI5cp0CtgtkyBib87Gke106UIO3IeJeioh1wCibgo
         FVZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OOCxEDtQJ24t95r1eDNDRLZcbDxeSvwHtg2+THTRKmg=;
        b=jaUGMzb1yY6dDzaamkR+Mh+oF1BX7yYtY2Tby/ljb3+XAxrw+HlqH3QDkyEuH/WA/A
         Jxa/cnBTR+yotp2NNp/RgO+KDpUVdfpz3tK0FzlNMV7qOIdfGkeHC7Pm7L5gfQeiPnMk
         1Tce4/8tCFgJ8e7qqD3/dpZyPsHd9ShIUmvrWFAGbSC/QubM/GVtaTA2E5d3E+UrVuWq
         vnTxsW78CmKibof7i7uuuBx6h4bf/wwt38uOOJx+jIyhVzTGehkrJTlwWLzVR+Rwdgcq
         l9yTDo9Iq9J/1raOpdEZ7JNC85AfWdGm8UNq/DHVTSbvr1+Awsx0CLHdsTTlFRGQz8qz
         CRbQ==
X-Gm-Message-State: AOAM530efChQpINJjhg053Hk0dqWY0kf7aXnyd1SmCIctr9oI5U/gcBU
	bAQJxBZrr9RE98Pr0nTSnDA=
X-Google-Smtp-Source: ABdhPJy5Pz/HsyjEVubjQa7IBYdf4cz7SHi1pNo+69WAG2NjKcTF++LGXlyJc5Uj/9ZXz0sdrjMasA==
X-Received: by 2002:a05:6512:481:: with SMTP id v1mr2002540lfq.132.1605305829936;
        Fri, 13 Nov 2020 14:17:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls5537679lfg.3.gmail; Fri, 13
 Nov 2020 14:17:08 -0800 (PST)
X-Received: by 2002:a19:c207:: with SMTP id l7mr1522728lfc.497.1605305828907;
        Fri, 13 Nov 2020 14:17:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305828; cv=none;
        d=google.com; s=arc-20160816;
        b=j6Ot6wFQAJyTKvQypnZ1p05YZZP64xyfl0rn9T7/9yyOEq9eJyYnKS0WuuTwSvV8/G
         GCggywiP5csQvYUwkUMEdzZPtEjb1ieK4ZBAuypt7RwZIPrXxd6xBhShxOcfvwsWFWk+
         SGePFAUdrvIf4fZriEg+iauAw1NS4X6lvvEyOM4lL7Da6TI1ztc5oT0Ig/WQ0xH55rO3
         xiUnP52FNggECdXqZHf5amGSg1ia7+n1jWy0ApAymgHqBD4bDE8+sl2hey3Jg2HidXvt
         NbZQAIsqG6W5q7bZ+j2cmLh00wfynoaNdXQM4rebRp2/qc+f1hblLsVIRgtmqJF61glh
         a4rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ieTC1eIMY6CyRmTdTXieBU5zsmVSQCTeilNuNPVSDIY=;
        b=YubHGc/75NEVranXuZ8qc5za/60AKPNe1vxlPymbuLcvT5oS5Xwy4nslXap/q04jP0
         5FUFjIps3ebAPA07YkgAWIWmHrWQSoZIzlRNmr4srSTIyN0DWPqf0PGdlRO8XgUDiUSR
         Spmgc6d5Q8XEfrlQ5unSBKB4OVjKf17o8a+rqIYQvcH6a2vfW4PwCyJbx1Chn6SUmOih
         H6tTgr8yp5NBv7Abp44VPk9HK2QEZPEH/HC/nfdN+lXqXgHA8Qi2Bvww8wytZfsDPauk
         /xyT/9eERlJfVm2JzSJL4LzudNds5rMlGxDbTR8jR7XroZYX0XAK+LnVjWQv9J6MoSc+
         EVuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MjJCBEnc;
       spf=pass (google.com: domain of 35awvxwokca8pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=35AWvXwoKCa8PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 26si365834lfr.13.2020.11.13.14.17.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 35awvxwokca8pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id g5so3269696wrp.5
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:212:: with SMTP id
 18mr4736487wmi.175.1605305828107; Fri, 13 Nov 2020 14:17:08 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:50 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <c11b96789e1717583a63e10acde14d44260acdff.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 22/42] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MjJCBEnc;       spf=pass
 (google.com: domain of 35awvxwokca8pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=35AWvXwoKCa8PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 2f0dd5bde83b..c999da4f2bdd 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,7 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c11b96789e1717583a63e10acde14d44260acdff.1605305705.git.andreyknvl%40google.com.
