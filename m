Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVW4QD6QKGQEV5BKEWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id C4C6D2A2F25
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:43 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id e142sf5942267oob.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333142; cv=pass;
        d=google.com; s=arc-20160816;
        b=LPtzYRAWafTnFcCC8QzmnKO394pU5j56RqKAlmkSMWb4x9LGme4IfSfhwWsSqmOAKN
         oatQSCDb2O4jaEecQqrU65qO4U8R8TFs7DvUaRbwjblnZnQaqn9uU5x7YQmGhnh7uf7o
         qbGdV05t40c8VZP8S8/bTWRzguG5YSrAKgtr16xQsOxGyKmYeRqahHYHB0lrrjWlwvnk
         eQzsWQowqWRz3NwA8idauelXmh2ojyOJ5tAJfNdIZeui2PfeQAeseC+eHHNmn4mAvQCr
         CWFhsYYqNV22FgWfDsd56l5Qtas/YxMHqwhOYT47oJ61gWw6oWR2Y88NjCpAreB0MN5r
         tmXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Krxiarbiscg/eR7dgJqP2B7zJ0f8uSPC8UdoTCNV83I=;
        b=SMQhp1F72mnlWqV2blOzaRAAJKg8rQKYySb3knKlZOhqVpVId6vgyfz4J8fQB3tw2s
         IeFgAkr884nvuylkOZ5+4KhWYgUKeZuaOuNbwXOqJCRkEBzHCKGLuHVRleZdXmcqU8zE
         q8bDHB91GFSejbcw+Eei/COaJduiFxAqPckbs1+dl+/bri3VNoygsKZJND6OwIGt8puJ
         2BClcw8z48AwWF7rI0drhvgfR6wqQ/lepMyVOf0gRw9BiZH4yij33ho20LLOGpVVy4Jt
         nVNPjJJcusP08PQvnLJBsTvWMMTyc/334JE/839A263c4qSx1xWmuGsE4KRRGe4/YMoP
         UALw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Iwa/zJ6O";
       spf=pass (google.com: domain of 3vs6gxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3VS6gXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Krxiarbiscg/eR7dgJqP2B7zJ0f8uSPC8UdoTCNV83I=;
        b=exEiWDzRc4bnF3uHjLwPcTw34KplBHWitWkq5pZrMyHFBzF87+xZ9Dr+i5eF7AgRTF
         pVRsIKjlUvs1VeOc4C2g/lHad3eG3svCM2i3glwALL6EEC877nQrsOQRfAyD0bs8zU5W
         mPHJSByzfybcDtiffBTX4ZE9jdHOM1TnaJGDRDjzF02o09FZoJS2XeIka+NoCxTgp3Cz
         eeKfZP32NsqdHnqXboFkE1XS9yOfzIV2X8WiOUUXFjc3tXPrNlMhumctrMxo4zjEwsdW
         HOHC2EOI7U8PcH/0vLFWbl4GdQ9C/+F0rx7gguAzmA2AHDEyqaIA2a8cONQkeR7shwnf
         mTbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Krxiarbiscg/eR7dgJqP2B7zJ0f8uSPC8UdoTCNV83I=;
        b=Wg0CfiezLC4Tnsc1p0z4IG5Ai5FKFPuQW2KYJgIr0cCmdRu9faNu8eXSvSjV6NnuJy
         u9azrBhl6inub+yvqPiHs8z8F0oetiRe5YHNcE02eKxtssdZprLyOip6XImYj0tBSm6V
         jJl1pxy2NEHuHqX/27lp/6x+3guELKAaY5IEp98ovRRM+msfoVwAD6M+a04mxmSE04l8
         FwKhtGD0emFq5fBg5nlxj1JbWxDSkUpPbj/ka+awwYLvfNqHeP/DVMP4BWzi8jK8OcED
         upmlksN665v0dJZPbG1aFwesZ9bjjNL4STbKimT1Q0XjQp6eZLr0ducLL4IEluUDC3hx
         RtmA==
X-Gm-Message-State: AOAM5307UmAwNrSHFkgMetNDnZyLkqEwmSLS1xijdQ5q1Cioj7Q8tP0C
	tcsoaiUb5mjIWvJd0E3Wj3A=
X-Google-Smtp-Source: ABdhPJxVt8rO5QiStv1pz2CqtNaVfdsjHMdvO8OU23HXa8NRMzFmVvsQkEZh5WdmjSl6uBZ0h9tAnQ==
X-Received: by 2002:a9d:4c91:: with SMTP id m17mr12841726otf.92.1604333142618;
        Mon, 02 Nov 2020 08:05:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls1263181oib.5.gmail; Mon, 02
 Nov 2020 08:05:42 -0800 (PST)
X-Received: by 2002:aca:bad4:: with SMTP id k203mr10890625oif.16.1604333142241;
        Mon, 02 Nov 2020 08:05:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333142; cv=none;
        d=google.com; s=arc-20160816;
        b=NuXKrwQN62MVW2AGMdWI2njl1Wz1HmF0SXAIkpgzoM0G/tTrE/OUb8oGVzNvUP1TPu
         55YEj87QwHjzPAxzwIPCUpsHz/VnGJ60gPurj+xWyOvRZoj9zpz59QUa3TdXgZZklVP0
         SCKYUZytleHjDsxjYuEesdzP8iMgVjYCCY1sYYuHlGOAxAuJ2ETcW0tNuMTYAvSO3vUv
         v5dtJl5gSDOxaJu9F5nHn5UsE3+4nEsN3mm0AQVJLzxT7vDlqvanqevKC2GL4Ex3IXtG
         jHyEvgP2+7whp92NTzHcLh8DozigOBFpC5zZz7aX0AprqY7rI25Qu+KzB+f7PIFmpYSH
         e33w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JhJQu0u6kYZyiKQdNOdQHHgHHQ9cOF6OLpbU2DNOxmQ=;
        b=Ro9cEiA0ytHdeS07q03FjV1jheD1qSFdWYF/kzoQR4hYw/W2jPdCfzap09fMjEfem4
         OfAXYBC1xJz4ex2iQy1nfVmX+FSz7z2wDiG3/ec9mA2Hm7pstdUXvCcz2dUWcQZhk2UT
         lYcslzsXbdRcbIQiHwCmWYPVmNBflq+55PP3F5BK4PxVTrLVIicuw7vZazJUirPg0CNJ
         fAHmtx4Qx3BOhq7dfNhc7gEpnoeGYOIvYL9VqRYIWgGIc9xEOH5dKNoUGjy7HajtWdwJ
         K+6AI0R4J7m6aRiruqHd5GDpJ2Ii0nmLgANLatp7vogoHVQVhoIQJI9T85Yl7AcFEaiQ
         xuvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Iwa/zJ6O";
       spf=pass (google.com: domain of 3vs6gxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3VS6gXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id f17si674478oot.2.2020.11.02.08.05.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vs6gxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id w189so8949343qkd.6
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:45b4:: with SMTP id
 y20mr1778243qvu.46.1604333141655; Mon, 02 Nov 2020 08:05:41 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:11 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <939e8bc7da624a0923d5f3346b4ef5a9b5e7b208.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 31/41] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Iwa/zJ6O";       spf=pass
 (google.com: domain of 3vs6gxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3VS6gXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index fddb48d35f0f..cebbd07ba27c 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -134,7 +134,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/939e8bc7da624a0923d5f3346b4ef5a9b5e7b208.1604333009.git.andreyknvl%40google.com.
