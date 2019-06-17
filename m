Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBTEJUDUAKGQEZZXVGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id EF691492AC
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 23:23:25 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id a8sf2345091otf.23
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 14:23:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560806604; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q9GPGQYif6SIlyCJdOVLOf47jLjP0E4wfX75DuT1A9ziTocFxDM3zZG+vXDnPRJooi
         Lag/fGQ4pioqKMl3ddHGK3ODzlqoPtgSiDMLh//C8dCPvMVdR3qC8jrnWVV5uIccP2Py
         ljYSgXvp9SNtIZ/AVGiEnBuJSvr8VAw+Gakn4bvjjPEkivIZd3WCOxF0twIMzSoav18H
         cNXs4OtRtsd/cEpxgH4GxHszJPH2IHzjrqKVaySnUtx9YiEKExkbZRimto2ywwO05iN/
         LtF8ElF3NNQ2uLaNtf8I1Tgd/G091Sr0bCRFD+/T/AZhZ4z3vBYZstVamDPRlgdAMP5b
         Cggw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=niY7x5NC2dc4PZBtmTzseKH7Z19YOECSRNgJf/6hCxg=;
        b=U0hogJtZ1PIgrM3nYPn2Taf6SdjIADW83pc+wxFGE1RFT3B1eOXv6Hp7ViOyENNNpV
         1wWeQrrWCoyA0ZAl+pTlxZTNVa5UxM7nP/AInTBOA8bmqozBjDcL/XMs/6/N8EF1QCOx
         +ANh9teGO4sFv5eyfv1oIxubjtPDlaA6GWi8Wc/y6ltq7OdZhFp6Y/rk4TDePmW1xrGh
         rn2CK2gv/pzzg0EkS/7lm7zqXhOOUSA52g1wtuBCW75nemrOQfRP3xqiRCs1nQ+L6nFv
         hADw5lUIkmLEHI3jhEZHB4ChGJ13QaKdkT+wHMhiLtUXrVm+wCbGC8eaG/j6wCJbF1+F
         OI3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=SjsiOC0C;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=niY7x5NC2dc4PZBtmTzseKH7Z19YOECSRNgJf/6hCxg=;
        b=dexdJMqxRuzTqCGpJyWICUOv06PUqcGzTNdkDgk+PXy84jot4eu8jwjgQ2AhFsvaFv
         RtkAZzPlV1DKNN9P+sr0cspmYJc5PoHcfh7PVdffV4V8sO7C07bQydFmU9Wz95DyI4eD
         8M8OXgBQXf5IIo/uJf/V2/MrMkOcEvYZTRYF3HHOK1EyrlaJhzKoJ7Wc65Iw5E5WtQK6
         FnIF+zJssuL+cUtRz2M4e1bcXRnxlLYQXPYbiP4lWHsVUGLckJT52lA2N+RTIe9pYfKG
         /bUU/B2kpy4fAqMEMwb6mLIcKN9wG+E+bpirotIzPeQVP6IbAGUxaiamHQP4gnHZK/nx
         1LNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=niY7x5NC2dc4PZBtmTzseKH7Z19YOECSRNgJf/6hCxg=;
        b=lCxhU119ZTRNZES7o50o1Y34xLr8ZXExAU0pdPBk9gnwHhiPsMNP2ok1r4M6hliuP+
         cqADMBszPVqPbybLE4c406KO84b+BaWZahlqRud4AF3bkyqA6qbYO/jbSDf4p240cM3p
         YvBcEMCJXEhMipMkH3qmQ8HOmbBGrvyaYv4ctEgahxCJxigFBuXoMSXPo/cE4ALrzh6r
         1chC8eCCNDSHOU9CeKqsYFrbsmLaG45eYkUvhlxS7HyJe7hyVECj87B6MWbVcheWwFjs
         jH240XbuD6M+Ty9R+GdI2PtvLBfrZ2NkVBCffxfawyJzlKvV59n0QaibjXEnEW/UJxVf
         90SA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWuEn0SckbUpI51suplG0gDdha+pOvU/FLYiUYmxMwyg7Ohryp6
	elHjR6US2BCS4XDhw39smIo=
X-Google-Smtp-Source: APXvYqwTSY4La/kWkHJWIt3THKROXbYtrvEfWSdeWJTkwcbV8WhjHamv7rhYUVHQwLfqZDGDRtq9qw==
X-Received: by 2002:a9d:7d92:: with SMTP id j18mr38999015otn.339.1560806604698;
        Mon, 17 Jun 2019 14:23:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:47d2:: with SMTP id u201ls2447448oia.2.gmail; Mon, 17
 Jun 2019 14:23:24 -0700 (PDT)
X-Received: by 2002:aca:b788:: with SMTP id h130mr31934oif.85.1560806604282;
        Mon, 17 Jun 2019 14:23:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560806604; cv=none;
        d=google.com; s=arc-20160816;
        b=X0Qb1Qr57AndeXcIjIKX8AXmwk9A/WCZM/L/5iIL+fgkhMRFxtdNN0YbieNB8D1GOX
         6L1v2P/6m1jN53ucZCFyTzDY23aYSzU5gLwOqDo48S2YBsYpJj5v1L9wTbpmc71FuRed
         MhOQVMBTBjCLCH7EQs/xAZvJFXbYxSbDiiQ8P2ykX3ecLww3kPSo5KuAOZgX5Ofg3ot9
         KWwcisrqd+sEyNr7ygGKSFz0Osm+iGtbHBP0nMPB7jlQegYsbxABI60UMzqrIipEYBHu
         ZIat1SyqP/DS1GTCt1ua8vsfGROBrPWgzceSDOPSylae2vWXVs6TGQ7q5AVw/hyFqKTJ
         WzYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2oANRJLDUUs2TOBdqP5hJFxzvExhz+2VjqCZlzAtFw0=;
        b=F+MvwD2vwXSb/b0Qnibd7WrQl59dVxga4gI9ZhM0oIxCsc017XKe0Ea2mOBwCc/wKx
         SuXea57O1fMfyWgsb4+p0MwfmEU3AlLtABwMBA+M8CLK0t2kEH2++k9RwF2wYZzifhmt
         IBSFcrpEtRvvCMq48W2vwf0tZIho1gn860BPAIlYXq3YjUxTp/G5XWM7xItvoGr77gYM
         y0e2BgUrFDoQCSld8Qck7LQcVdX6ciXhLKTczVXnx54l+98DeYuIXbR81/KDFx3Kwuu+
         BOph+70NkD44cJFUU8rThl36ess/CdzsqwYZeAl04cunB1pF9ox78Jf3zhy1zUPgZpA0
         rrUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=SjsiOC0C;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m81si618483oig.0.2019.06.17.14.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 14:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-89-107.cable.dynamic.v4.ziggo.nl [83.86.89.107])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DD657206B7;
	Mon, 17 Jun 2019 21:23:22 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	stable@vger.kernel.org,
	"Kirill A. Shutemov" <kirill@shutemov.name>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH 5.1 109/115] x86/kasan: Fix boot with 5-level paging and KASAN
Date: Mon, 17 Jun 2019 23:10:09 +0200
Message-Id: <20190617210805.492186083@linuxfoundation.org>
X-Mailer: git-send-email 2.22.0
In-Reply-To: <20190617210759.929316339@linuxfoundation.org>
References: <20190617210759.929316339@linuxfoundation.org>
User-Agent: quilt/0.66
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=SjsiOC0C;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

commit f3176ec9420de0c385023afa3e4970129444ac2f upstream.

Since commit d52888aa2753 ("x86/mm: Move LDT remap out of KASLR region on
5-level paging") kernel doesn't boot with KASAN on 5-level paging machines.
The bug is actually in early_p4d_offset() and introduced by commit
12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")

early_p4d_offset() tries to convert pgd_val(*pgd) value to a physical
address. This doesn't make sense because pgd_val() already contains the
physical address.

It did work prior to commit d52888aa2753 because the result of
"__pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK" was the same as "pgd_val(*pgd)
& PTE_PFN_MASK". __pa_nodebug() just set some high bits which were masked
out by applying PTE_PFN_MASK.

After the change of the PAGE_OFFSET offset in commit d52888aa2753
__pa_nodebug(pgd_val(*pgd)) started to return a value with more high bits
set and PTE_PFN_MASK wasn't enough to mask out all of them. So it returns a
wrong not even canonical address and crashes on the attempt to dereference
it.

Switch back to pgd_val() & PTE_PFN_MASK to cure the issue.

Fixes: 12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")
Reported-by: Kirill A. Shutemov <kirill@shutemov.name>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
Cc: Borislav Petkov <bp@alien8.de>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: stable@vger.kernel.org
Cc: <stable@vger.kernel.org>
Link: https://lkml.kernel.org/r/20190614143149.2227-1-aryabinin@virtuozzo.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

---
 arch/x86/mm/kasan_init_64.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -199,7 +199,7 @@ static inline p4d_t *early_p4d_offset(pg
 	if (!pgtable_l5_enabled())
 		return (p4d_t *)pgd;
 
-	p4d = __pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK;
+	p4d = pgd_val(*pgd) & PTE_PFN_MASK;
 	p4d += __START_KERNEL_map - phys_base;
 	return (p4d_t *)p4d + p4d_index(addr);
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617210805.492186083%40linuxfoundation.org.
For more options, visit https://groups.google.com/d/optout.
