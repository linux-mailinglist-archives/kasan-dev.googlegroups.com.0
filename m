Return-Path: <kasan-dev+bncBAABBOP3QOHAMGQENUTLIYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B4FF47B5B7
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:03:38 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id w10-20020a50d78a000000b003f82342a95asf6566980edi.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:03:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037818; cv=pass;
        d=google.com; s=arc-20160816;
        b=bybSmnjRIqLso8iVJh7X0GkJEDRyHB1l2zUrGDvw6toBxslzkcZ+MY3jaapmgVVfpG
         GLhzxx5owEVvn8eDJ5AWK8vb5jM3ZgeJg4ytfOkqmAIuEmNqmgCiAn5GkyOSlbfoBEiY
         8IfuRRvxumHWKdPgnMIuV52L8HjoigljxCwpK041YrZZtUH5skj7LAUByxTcJm6t29Wn
         1CiAf5zaOP+tHFm4k36maorrwZbnoF4LVDQYffhOAFVVTr4+pvwW+7BWhq9dhTrCgie0
         7WEkSgJIiE0oQ4FboiBG4tLs3GayMYIPoakpTk9LkRDBGle+7m9Cw1xKxESQddpLdsed
         5lIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CH9v1diJ7Y5cZFvUVc3IUo4T2kjXGcOOPCHnVE/XHnQ=;
        b=FqbMoEvzwnHdudV+dvtGkO2/WdenZH/E2jhfnlWPgDIa3ylA2ynbTunHLz00VWJDRl
         9Rcl13luaLP0q0FEHRI/TdD2gUluTKIcczR7macBplLxL6uX0lldXtyjdj/eGHh8/VMT
         HC/hWOb46hueLaSjkqmmx2NkmgkOZ8/CPWby8urBxg/FzfOBXakrCQayNWoJQcoNhWLU
         Ic8jhGq8oFRumNoC+lw7xRJ4HqJPrjnNPqkz3BXp+B8eYIxfWc3e6jN9K+AzlZWpKA7L
         TfAaJ77hT6LAn50eeB0Oy2Mnpd6XXSm5FV5dlr6slCGk0kdlvXEUexzgmxH/acQCI138
         wKWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=E3LCMDVF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CH9v1diJ7Y5cZFvUVc3IUo4T2kjXGcOOPCHnVE/XHnQ=;
        b=AettveTu9RzWS103DyPD8FLa35OezAvNX1HXZY+VnUd02Tzv0S1snM+hwE5b7Z4XlC
         YT4MmBVHmkYyDaY5Q5rlQrLvqFxQmfWJaY++hzP05GHjCOpc8/0EpgHDQzetuUXD3Qon
         U+DqFqyrnOmNdw8hJ15K/9QANO++PV0tPPDf5+lyA8KdGLF+I3+kEvJmU0tMYTxNWSW6
         /MzEHaUFrJDyCd+3AYj0XpA8GYcmauUoC/YRhuoSc5BIfDHFE5XCGZeZBfKI1assCBai
         T+3MhV1PrmTszhMFkTekAUbg2+Czsjv17HfncPWU8G0973dXiT43klWbW919L86zcl07
         9enw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CH9v1diJ7Y5cZFvUVc3IUo4T2kjXGcOOPCHnVE/XHnQ=;
        b=Jr7ww2IXyhTKsbJz6CeBxGagCyE84NrOXSMfDKzWENSKj6nfhvQATgbQyFytYyxJ40
         UrxLm6zHKsJM7ti0qUTTDRj4SJGLUYja+zlPfsWnLZROAGVAdop+WutvycIUNTe6JMyG
         jRzjp63LGGrtqmTMqWdAITDZAyCkKNCn+XP7NtqWS4aLtHx5tYvqU6lSi3AjYhvZ+pbU
         rAVNC0JooUuazod5+eSrzdGWHN6eYyfea7rStdVfgwNwkPCYAN6EcgAG0nARRqIeKafj
         18nEdetEV0Q9WSzsaDbVHC3dtSajDbGg4NRe35WM/ue45Z8A5ONxLrU3Ovj52FGHgwr/
         0VyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532344u8ez95JZCJb+SFurEQlmUMu+ApFXNUC9ECHm/LnvsJbEG4
	OJeB72Eh5y1+pAekkvRW/FQ=
X-Google-Smtp-Source: ABdhPJxT0vwJTq92OG6JhYWkJ7k+8mmx2YpwiGxOXb8X86g8XzA0VxcwNFMFxo8k4nUzxUoFurfyiQ==
X-Received: by 2002:a17:906:9746:: with SMTP id o6mr156336ejy.714.1640037817984;
        Mon, 20 Dec 2021 14:03:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4246:: with SMTP id g6ls927094edb.1.gmail; Mon, 20
 Dec 2021 14:03:37 -0800 (PST)
X-Received: by 2002:aa7:cd4d:: with SMTP id v13mr148185edw.55.1640037817267;
        Mon, 20 Dec 2021 14:03:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037817; cv=none;
        d=google.com; s=arc-20160816;
        b=N5QY6wYmraaZlSbxUsdnwKVH7O8w+iC6uP+7N/Cv9VB6hsFMtauPH9s/Su4GkBiQdn
         Td/wgfcNvRnqQ2m7HzfNwZvtaa8TkLZEi3S4FzCoC96AmdQGJLkHsp/ED3E61/kayS07
         Ahcui6Tr+WUcN4HVEP6RE0zARCRANzJYq/zf0g9A9gYvOPAqnzcMyihdTqLYvQuS49c1
         idX26eVP4wmjTOdHNScMtncgRAaErrne2D6TZb9vaVd0BEAKB61D+HBIQF/usyZSfSnn
         GGwO1wNVPN0WehM/qILshzIANCWiRRaSU4rXHzEMN5txFOPV12He6mqGSC1z47uJLsUm
         F/+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0eXVYJ52EHc8HK0ZSN9sLRNZTeyGfQSxFg+mIo8E7jc=;
        b=tTQIwEJ4MxUCBkjqcg6J+fVcy/BGozPWyXFbKkMLaoleFWAewrL/4868Jnroq8aFhK
         xsTRZcr51W0pcZZbKrWvj8VwRmRLlVSuWjrNswC9YCpi+NKJLTg08ZWzqGVhDbc02InS
         mVmb0jsgcS04CFxyOPCjn7aEBkYpBtSgyuHEUi7VT2h3cTm/9UdrxSGv/qEU3wfNw4ay
         i64bLDkQvLFYY4FSHIUuycrhG2ywMS4gntPDXNa3WdqZENx5KkPO2chpQ267kEZaIKQ5
         9Pb3JCTi418PBVrpWHzqoQqAHiNpx+8r7s7HZ5nBZI5nG5e8molwpk4L89qs2YoGrRwe
         QX+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=E3LCMDVF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id bs25si526191ejb.2.2021.12.20.14.03.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:03:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 37/39] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
Date: Mon, 20 Dec 2021 23:03:31 +0100
Message-Id: <88439ce8afa1e794c561a098e7e1bcd735bdcdcf.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=E3LCMDVF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Generic KASAN already selects KASAN_VMALLOC to allow VMAP_STACK to be
selected unconditionally, see commit acc3042d62cb9 ("arm64: Kconfig:
select KASAN_VMALLOC if KANSAN_GENERIC is enabled").

The same change is needed for SW_TAGS KASAN.

HW_TAGS KASAN does not require enabling KASAN_VMALLOC for VMAP_STACK,
they already work together as is. Still, selecting KASAN_VMALLOC still
makes sense to make vmalloc() always protected. In case any bugs in
KASAN's vmalloc() support are discovered, the command line kasan.vmalloc
flag can be used to disable vmalloc() checking.

Select KASAN_VMALLOC for all KASAN modes for arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v2->v3:
- Update patch description.

Changes v1->v2:
- Split out this patch.
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 508769fe5be5..0833b3e87724 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -205,7 +205,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
-	select KASAN_VMALLOC if KASAN_GENERIC
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88439ce8afa1e794c561a098e7e1bcd735bdcdcf.1640036051.git.andreyknvl%40google.com.
