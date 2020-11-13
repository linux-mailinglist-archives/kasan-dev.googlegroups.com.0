Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRUNXT6QKGQEP4BYPJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 153CA2B284F
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:56 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id r4sf7202013pgl.20
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306055; cv=pass;
        d=google.com; s=arc-20160816;
        b=aILnT87QiNaKeGzEVPjXY7vBx0jBSIar3DLEdOKDcZMedItaVLUlkbEtRfMikyOn9c
         egx8qJzSPSHTYZvgh7N8VWFeCDe7MPjv1phBkthF8z49cgLDpaiyR4neTdOEhNNLiFUr
         Y6TlKRBcLaI81hzWl18o781f0RLVRNl5cqLICN01o0VvAvqgtstOnlTOkF6StAns+ZMA
         DzwQBRDu9/Vjoev9iSrq+T0DjQzMn8X7MFj0M4rB7nYqvu7Aa1XahW2JF84ya7MeTO+A
         zgcopRvQBMLPcq/lx4HgSbM7nYQNXxel5whikl2+WA1kF/carEgsIj6cbLwvA2wXzIK9
         QaAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=acbHoS/U+LoVzkl4LQPGG4rTNVnFz10bSYh/Ct8+rN8=;
        b=Mk99mGGhc/sIJ4BmZ/9wFpGsQJTrRaeZlKXjFn8jtVH2VF6MYHqzOvRscOMIQu9430
         KxxPgAMvzgF9C0kqylnahGZvfKqASjhwwKsH8WZzGgxNu/s0BvcjEFjIPCRl5DuYh55a
         PJ/DIDOPnBtehUNEjMaKrapLusdaKAdjAUhNbWFbelKzq4arcaZ4DFhMK7TvsJa6/iqz
         XDfvg9fNDz3E84ns+xaWaPF39W+lWrF1ucodoypbej4/k+cVDJ2VlgNCTFf3/8Pb51eP
         eP6RJZQMjHNaAamY7c6uK2HqO/8vmzifM7S1gEkLFOv54mW1ECfNNcOkEmMJoELVrBuU
         AS0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JaBlZxu7;
       spf=pass (google.com: domain of 3xqavxwokcziw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xQavXwoKCZIw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=acbHoS/U+LoVzkl4LQPGG4rTNVnFz10bSYh/Ct8+rN8=;
        b=k0BrDDnor/Ww0LfNW8af4V9QDhDqUXi89iFkkmegbnGnW+CfyfCLGbdtRIkAnzF7w8
         grKIlLQQ4inJnw9NRviSxDqPQV1k6to/OG+sbMbU0Xyn9u7kWt9+4/5CCb7CpfycJHON
         xl6Y218qEEjY3FgAcWV2ZoUnPdEJI1745mufFYL3SnQpxLa3rCaOQxyrOhEUHyiGzM8j
         zNqtug8oXSeyPPFNbcNxr4jKTSaU4uwbg4vd6oZBnnMc1VAzofVVr1eMeIUWyg91asKh
         DJzeEaPoJSSkS/5zW8EzXyfrxp4bHR95deiU/8cmenLdBiw4rtKHvBl73RX/Co//X2fC
         +g1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=acbHoS/U+LoVzkl4LQPGG4rTNVnFz10bSYh/Ct8+rN8=;
        b=L6GLU4g4OkclWax7QKq/Q0PEAyIKjSm5NOdSNN1N4ZBboPOyHBYLsIGi4qF+XOfPjm
         GYdHJmwaA+mKdMiqjbSLDMSAGPxIzhvXPgzeg0Vw1JmLGjmKdOINLT+zWTEv2x0mOBcP
         1iEhaBkvm5omRV8alPptEnmEMPWU4v9T8kmEL16/17OV18+hz3sblGdl2c2vjSQlAvK4
         MrrsgNIq845j1XF0IKqgW+3rFRLxdd4l/n2NsMQEqaEjdZdd0VgEuitJUOv1Z+EZWK1b
         YzVvisWgxzN+dfu+p5TI7siyNlvKK3B2BBgPow9Fg5gdh3bZ/Xo+XurUOqfLE6YM/5BT
         YX2w==
X-Gm-Message-State: AOAM5303hR1mQJNn+fmAtNKDCr4NJtt+OZExv9nCWBs45CO7a96OrJLs
	ASlRkyhRXsvGkHXrQA5PzdQ=
X-Google-Smtp-Source: ABdhPJyD7Sn8Nqy2nS92bkz0VRoHXvh2+1wPrn4fvdsdOCxgBfEgLniTH3ijxaZp3hcUxiWtjd9jCA==
X-Received: by 2002:a17:90a:df0b:: with SMTP id gp11mr5038628pjb.139.1605306054868;
        Fri, 13 Nov 2020 14:20:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7488:: with SMTP id h8ls3636084pll.11.gmail; Fri, 13
 Nov 2020 14:20:54 -0800 (PST)
X-Received: by 2002:a17:902:74c2:b029:d7:cce5:1813 with SMTP id f2-20020a17090274c2b02900d7cce51813mr3587680plt.50.1605306054335;
        Fri, 13 Nov 2020 14:20:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306054; cv=none;
        d=google.com; s=arc-20160816;
        b=hk63WaQn2WmBSSvNMtzyKkzbQN8nAMkayYXO/BTbnQawCl4thY+Dntd7pUdQ8MMN7B
         TqB6NN8g+fkiAp5uHnzZzbhEKSbw8ORaKaYqg8IwgEt0Urap6tZ0WakD+VwsqSaaDmis
         aN78jYEiz2Ww4R5yCF6yKpMPnSOIggX1q+TTur40C3BxAJ+VuddBXbrM1pzB0lBE/7Tm
         V0WrBe5iTrKflFwC1UzKPlaz5B27Qnsnrd9O2+WnmO7if+HUNp0ipyUmT/LvsIMLMlN7
         e5FABgWRCUIEBDFZRiValwSEwIRme0dJdTP/v7VN8TxfBcbr7Q/Bb/eLGgzl5hohMZ3S
         efwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Yi0H/DT0iolgmo7NG/qMiO64up+Qc265jwkA+xu3tVM=;
        b=t6+tETpjgtXBu8dSxU1bJquc7LSZpWsiPD43Aym8FmePsq/5vTC75HL11BZSM7WaB2
         6igbrCzy/BnGn/wxFgtMXR/C7NjBQsxI+iQTV9QdpJ/4x1koYs1kj9QnyzfTRVqN1JJC
         i77NP9PjUkP+HKfsedpXeJuKAS+yaFdFSSnCIPYPXGUvRD3NJI6ZmMOcjohNwbTZuwqC
         iFZeJQDjd7N305tlOQXEnZOWgHArlINrop4Qq++xJwi0dphqbcwJyLd3StWQwvyyUzPg
         BfrfwycUCcno3cUqeBuT1w3oYE7IFfGESOODuuxfEeYhoqeW7XBOMOVHTH+0ZDSjLdtd
         BsIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JaBlZxu7;
       spf=pass (google.com: domain of 3xqavxwokcziw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xQavXwoKCZIw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e2si832064pjm.2.2020.11.13.14.20.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xqavxwokcziw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e22so6604095qte.22
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fdcb:: with SMTP id
 g11mr4476840qvs.58.1605306053723; Fri, 13 Nov 2020 14:20:53 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:06 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <ef974bf9a5cbab8fbf5d8fdf7c4468b04659d980.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 16/19] kasan: clarify comment in __kasan_kfree_large
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
 header.i=@google.com header.s=20161025 header.b=JaBlZxu7;       spf=pass
 (google.com: domain of 3xqavxwokcziw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xQavXwoKCZIw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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

Currently it says that the memory gets poisoned by page_alloc code.
Clarify this by mentioning the specific callback that poisons the
memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 821678a58ac6..42ba64fce8a3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -453,5 +453,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by page_alloc. */
+	/* The object will be poisoned by kasan_free_pages(). */
 }
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ef974bf9a5cbab8fbf5d8fdf7c4468b04659d980.1605305978.git.andreyknvl%40google.com.
