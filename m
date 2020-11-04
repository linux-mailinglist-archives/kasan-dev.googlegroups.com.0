Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4HNRT6QKGQER547SVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 51A872A7110
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:13 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id h14sf48736ljj.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531952; cv=pass;
        d=google.com; s=arc-20160816;
        b=KEuY8Tr6oczS/xxvCAgWWYlb0JqI4BcJxmOOE5xijX2Q+uykBVqFoVCtAA1MNN6em8
         YBDs5shADeGiCqO5ncuTGVFs0WmgZ9tH1hnjgUD1E+waVJJOKgLvLhOzJr7iOwZ5LAms
         6+N1XxtsD6q3WowOMqwT4m7KGt7RAsmai8ykKvlQ9sr5un1gKde47TWp4DyrmaF6fvJs
         u/ffKb0d3mwr8ec6ocsodVRRuosPLFcfXfnO3ukP2YOFrp2fmSpWpKqLi4XCiJ9R3MaV
         yNNfnCGsZSyIG3sOQMS3dH9ktwg/6F9cJwlQpSla+dhYf3bgI+MikArV5aHGbmXGMqOK
         Xn8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=agQg497Gt4HBlBYGZg3optXwMQQ9jyX7upOsxTJ4OKw=;
        b=ZfHBhxF5Kv63PZXaTK7mgwBeqHG9A/5sQtH3JquBvAGSxv9z+u8k4Gjz+9SPVHiV8B
         K/1inY8dbC52+8tCG6QjzPjIXExhd/LX1teexX3oJJdsFvtoZtyBdN5rUbW5c4eIegOu
         eTdmqS93sEW0PN8SOxuLWfIVLGvj8OJm/6NdMFJy8m6Gq3uoTUo//kmP/cNYJfm57C4J
         5rE8etqw684ViX5edQe//o27hys455ySm/uYXEVPY8ky7fmJ5hfGoAi63MT7xhIJDgvG
         NWR/mnlNy6nufQmkIGTReIhVvPF0J1WnrE0C/1miQ/v+OEWgUKhtnRBinV2LtAlOsWyf
         J/gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bHVBEntx;
       spf=pass (google.com: domain of 37jajxwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37jajXwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=agQg497Gt4HBlBYGZg3optXwMQQ9jyX7upOsxTJ4OKw=;
        b=BSgRUIBsXCM8235Cdiit08w3qQ9Q13jDyBmqxgEf6kMmwE69TnsNI5UqYx7fAjJCdL
         a0nbblVZC9wMvq8TB+qyT6B7bn1PXiLgjf+gfE/qZuPof8o5JW5Xxm+8FXfO0DcdsS3k
         N/+xzNF0ef/EwlP8hfF6178pwRaQbe6GfMvEAhj8toz88A785mrqszBJGfSqgwP7C0Po
         Pk4bPbF5XqiOwNqAvKMATtZkdPPikVYzXu2MNfASIC0dj1Fa8txUBmPBjlqfEeo/DDqn
         CNflimKoe5aAsXPRHolkkNGz5kv7pWIYE1MvjXZfVgyXKyx57RUmZtyf43TXdgfjag9B
         yN+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=agQg497Gt4HBlBYGZg3optXwMQQ9jyX7upOsxTJ4OKw=;
        b=qmEO686Wlucaj3u4a6sKjuoe0UY09vMluONdsAEbXbUXNjkN+VA6eO8ccCf+1JtPSm
         Tb8ifKa/OPuSdu7p4qx2dVT3WxqFm6OWqI3MB1ThLnNC0yLOc/Bmvqn1FMBCkT/vshIt
         Z1RgAZtN3ePZ/xkat4rCV0g9E9yf8D+P1NZNeKoiKPS7DXJWOJM+QlZVxtA1Q5wEI1Jg
         Dbrkn9Suhy3VZeNT+h3bc/qH3pUEJNwMYbQqf6zT6Qg0yFWN3cpqN26Y9AnFwZoLDHG7
         JPqCvgTjp37Nnkb86llFjkY7z9E4+ieDbsEFfrSqFfSe7MaCiMcTl8CmNcEUQwkDIoKG
         p1Lg==
X-Gm-Message-State: AOAM530DuG16ZdWIPo3Lqht9j0wysrHDUalQxkYDC3rN2jysQn2pfD9V
	ph9MvPk15Y8tdJ7PUo6VcCE=
X-Google-Smtp-Source: ABdhPJyeRvOwghhBgjcAm2D/9hgnvpPj/AbGZXcNJ+k77M+F0Od5/XLOpVnVSPeB2cNAuPh5A1YTKw==
X-Received: by 2002:a2e:9148:: with SMTP id q8mr123380ljg.182.1604531952857;
        Wed, 04 Nov 2020 15:19:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8848:: with SMTP id z8ls675405ljj.5.gmail; Wed, 04 Nov
 2020 15:19:11 -0800 (PST)
X-Received: by 2002:a2e:8143:: with SMTP id t3mr116450ljg.29.1604531951772;
        Wed, 04 Nov 2020 15:19:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531951; cv=none;
        d=google.com; s=arc-20160816;
        b=UJrDBVqJGQKeouqRL8T6v4jtpQK4zIFkn0z5sumBD4D8JBDRo/PKgdsjwAQvzo87zP
         Q9DgDcoj0zSLCyfkimzbKiqoGqGiawKzL/5dhGA/YH9Sm2qXGTt1+WE9UgSZ0O/PtONh
         XmlMrd+8ro4DYaJcJphgeZSaZO/bl6q7ZB5ljbaE+lXOxv1BvA9nJ5wZIMkT5lsLuD4m
         dyWISYxRU9u7/ImNm5oY5b0JZxoNf4aKlyDHUhgGHcq1n+c08Y35lQ7hRkAk/TQIk7Mn
         QwovKzFMyA0zs5HF6VX6ty13TdO9E4aduEji/UfPuBCHEWipMwjl2OynjiX9mjb1tuoV
         TjMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LIY2nrONxUEpI3abKUGgXLbsvOzrU8dATPLwmTEHaeU=;
        b=hg6IO0p6QtWz5Pco9YOhLyxL9SyLatOmLgLTKIWNGPtCXHmMqBS63U5gKpFZ24VKeT
         QErzC1hWe0MePot525ZrHQFShl54WILx6GPUNk3OWLzh0fZyNH/QNWMsQP0lBq0U2AtU
         VUjkCRyZGnfryT6mR5U2zjfiKrN8btgxM6sMm9dhhJBL930ZClgZqkRCF9rPvmz6nmrW
         afXFbW8vIYxyGmlmmETeA7m/M7EU3HGLRBtJPfjMSgta2aDOupxcEuyNyVnSTmt/rpss
         NGGIZR6MVH6Ho2SnHTN1vLub/j0SkF3KKtrzb/MaUZFwISifvXShxppfnXEv1wVMylcr
         jmQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bHVBEntx;
       spf=pass (google.com: domain of 37jajxwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37jajXwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id w28si101833lfq.3.2020.11.04.15.19.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 37jajxwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u207so23411wmu.4
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:11 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:309:: with SMTP id
 9mr83135wmd.80.1604531950904; Wed, 04 Nov 2020 15:19:10 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:17 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <f6161319e205bf6aff30ad4d46c93e66e60bb7ed.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 02/43] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bHVBEntx;       spf=pass
 (google.com: domain of 37jajxwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37jajXwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 542a9c18398e..8f0742a0f23e 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -155,7 +155,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f6161319e205bf6aff30ad4d46c93e66e60bb7ed.1604531793.git.andreyknvl%40google.com.
