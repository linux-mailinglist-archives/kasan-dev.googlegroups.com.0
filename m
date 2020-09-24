Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6GFWT5QKGQEU6MASJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id C858A277BDB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:36 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id s13sf313710ljc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987896; cv=pass;
        d=google.com; s=arc-20160816;
        b=ona6pUdk2bZ4GjHrE5yt3Da4VbDyZfTiPqFs/DYy09peS9eJhGQfla3JVKRdOJcK2U
         3QosRoAYn48BxaNlMPiC2Z1Fh/szO0ck6qkC0fK8HyFSIRTbk5llxuNqMl1PWcSKVDe9
         uilayPIu/YDCwFBp+r0LSdPI7h3Bu8KvBBJOizVdUi84ut1i4eW8lNXekbN0HnBbES1E
         W/yPXL+Ru3mv4t734CUl8VPg6lOu80kX5Q9Q2dkD2LzL8oZUFDjoZ/mJf8dJpm/31igT
         dg0YMNsOE3ZJhVlmDF6dh98/Dy9BHPIP8XAjDqrQr0JzKzk4zkrVH0Q4jNiO7FM4I3xv
         ajNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hSTYqGsrtxKWSC6naLPi8cyNniYlIK2jTL957KXFEEQ=;
        b=Hb4AWof4W/zZ+uYQSL1PzanMxLBdUGU0Gb3SMtjjvnWhrPAyyGm6sCpfbKkvnY1lZ+
         MPU/SLNhYNwt6uwOOyLPde9c6BaTX+T0bnTnE4pnmErr1/V4r1VZjjfqW7JTHsptSpx7
         LdEaVnR7u3XRkUuHv1fxZPM56PInS3goBLVauZaivs2UH1PPljeblSWJGKln43hkMk4W
         iqZgRsxXdA/7k1I8qMvAG1opUnVZ+9qrWeakF8cUWrIZT0xdpNXRKfWu1NSlQeNsWOQB
         8Q9Vm+p44qvPPyMznc51AtlecGY/HlMD9bn7/NmpHSfMt5cl5vteSVQYMBXv4Bm/sFlA
         b/Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j8tE91Tv;
       spf=pass (google.com: domain of 39ijtxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39iJtXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hSTYqGsrtxKWSC6naLPi8cyNniYlIK2jTL957KXFEEQ=;
        b=ZthBgNl0/AxZerY3FBDhe2Zm1xZccn6K1XC1GNhMnwxtHpPtbpyTn0Mwbh+6Jk56Nw
         zCEXlYs/wriX4FkiwYNojGtH1XFNKf63QKbdLoB78pJfUlgsIG9aShVB8Xo9v9Ys55pg
         Yycmy/2Ui/g1GHe/janPQtylr1zI2oGRxH5Z8VRDyrcdu3ALqOjrpz/ujn6+BIHJAEQ1
         ZqYpD8i3lwdDCgYOJZr8vVbEFXzTsvwDar7OEYDHmu3s15+AVGK3kZlxGgNFUTuk/SPO
         zuRqlFykD7ONx75XOATcpCALiVLbRKdNAQ4H4LxuC7TslrTxFgF52SM1DI0mhrhNFvZe
         EaIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hSTYqGsrtxKWSC6naLPi8cyNniYlIK2jTL957KXFEEQ=;
        b=iEWwsFF486rC6GuTZ7xGSQeLFM5auc3DrFvdZmma2JZ+DDyJRDxSP7/BFG6TiF2s9D
         OPSg59gjgB+/mw/BvQhseHbOkF8dHC3wNMFTWd/utsiAbrrqtvbtzAOq1hOiDTU5S9cn
         yin1n5novZQD5tMKYi5L5OtQMmPvRpWJCIfCU8PuGhZmX4RL1/dnTnpLVLcMr6VSWpzh
         enn4LMe4wL5lgRDKlyCcZ/vOLnI1PoFr7yOtRT3CHmKgvs55H1QI/mefzZW8SFtX3xOO
         Ldhhc7xDpufsi5qkrerLGi+7AWZ4bqHE96LoASph3gQ0sPUL+cWq7URDpRClq4pEVQIs
         fezQ==
X-Gm-Message-State: AOAM532V6Fg6oczJsLK/LjHEgmgU3tKVATWAnj8JCe+8gy1nBxp2VKoK
	4ni+ofVFAdIPdmPtIBGoPC0=
X-Google-Smtp-Source: ABdhPJwX0f4+JRErlX95j0VhPrOP0AHM9rDrDoqjrjbdTe0Sg16vtMnQzgsO7kt+KgWdUSYUNu1EfA==
X-Received: by 2002:a05:6512:32b6:: with SMTP id q22mr387759lfe.160.1600987896398;
        Thu, 24 Sep 2020 15:51:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls248934lfp.3.gmail; Thu, 24 Sep
 2020 15:51:35 -0700 (PDT)
X-Received: by 2002:ac2:43c2:: with SMTP id u2mr312283lfl.573.1600987895520;
        Thu, 24 Sep 2020 15:51:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987895; cv=none;
        d=google.com; s=arc-20160816;
        b=Zek6HAZ+QtyxMnKgYb1wmZBz18Ax61hRCRWOyzOyMrj2O8/RHCXGLPvIGbaemq8O0z
         7EExogamYCdF06XnAgCv/jBsobFmbzx0APXx1xt99trqgYOnUQ6QNircAxgx+euIt+3F
         MYF5oE0DfldfJvjlMx2WbXG4+DO2pmWMPf9nsoZhTIgthWgU/jPt+eBy+zqy+cbpIreH
         MPUtLeyQus2WUU9jUsmhH2maa9Jfzv8m5zBxxn9ogeMIu56iD5Nq7iJdPR5bsoworxrD
         ymXe0vcwnLue6PCAFOoaRSi/M44Xy67hUjMPsrOZUhwmjE+bGepdssfOPn2kJQNu2YKV
         pnBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zaZ7iYa2nX/LEWBkDi8yCOPbi1dUYelfO4W8YWr1Gms=;
        b=Z1ANDfbpxtryu8+idq+jFm08ZPTk1LS6XjbyTCrkV4k8leGXI0Xd8ueaZ2+5JCZY/u
         YA2str1LW7/YP8fOW6BHoH4m5ZunbJbpe/O9oGv/RahR2K1j7x72gPu/PPTBBU9AmV48
         4LvHl9EjxeysLKv+JeHFazSDzJLGhfdemMwxuOWEJCASl/aCApa91NVPKVlutY1+jilr
         Bm43huaDvEX1wWNM20An2WaaA+yau0gB4XMBf9FJ4wdFjZXuw7RizEaJTnfgCYRnTOPV
         KrTjlRR5KKuZHIqJsRIwfM1MdD0oatcV7bmQ9QqdZ6yTO3ErQiRK3ODOGDD7OttB8wWp
         qZRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j8tE91Tv;
       spf=pass (google.com: domain of 39ijtxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39iJtXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d1si18117lfa.11.2020.09.24.15.51.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ijtxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id b14so275831wmj.3
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:35 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:d4c1:: with SMTP id
 w1mr1209062wrk.108.1600987894827; Thu, 24 Sep 2020 15:51:34 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:25 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <ff0f9a3bab9d2b99580f436121812d1eee560b44.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 18/39] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j8tE91Tv;       spf=pass
 (google.com: domain of 39ijtxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39iJtXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 9e4d539d62f4..67aa30b45805 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -371,7 +371,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff0f9a3bab9d2b99580f436121812d1eee560b44.1600987622.git.andreyknvl%40google.com.
