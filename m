Return-Path: <kasan-dev+bncBC5JXFXXVEGRBHOQYGLQMGQECCCLYJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id DF78258BEEF
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:34:22 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-31f56f635a9sf65723907b3.4
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:34:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922461; cv=pass;
        d=google.com; s=arc-20160816;
        b=uECRQGHgoW40E9i9ueiFwpcXM6VzXkIGxA6qC9N9TS+qogDsXRe6s+7C+RebP1H6Q/
         ofEOypd++0O5RziGtJ/8Npba2Yb9JlYyk2q9peBvTMAs+5fE2fRJWG4NF+Liac5XALwh
         KwiwZpjtA31ZqQFSY4zM/DDyuC6fu7u9M8JTG++T8epndI5rLEn4nQhtWXyPZaJJ2Zfr
         o66wBRHT+GioPu9KQU/KGPYWFW5XnB9t7TPgK60uASJ6eYT6K1lUahSj69X6XDDmNceJ
         tiSNGd0tZ8Jw+hEXEqcQnnNIPW2Cj6qGxfpLb4ygfcv38oyQKFF2cfeNzuIZAEaULtqd
         7YUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZM3dKf1d6pMbqo31IpBSrF3WPTdenWzOxdUsdUycYes=;
        b=Id00/AjsOOTsIHCSx5/7gTWPBxCJs4BZIVq7jmLpJ62aFkBf1UhI1xcawlM8Z/6Zq6
         oVgnaPufRwmZwACntg6uoxo3NBDLUfqQTbbpZTz+k6wlEOoFo/j0SRHdqtG2vjBSBuEd
         bJp0szKrPbAQUUwCXbfwJlXdJtr+iHfnVsB0hhsMgzsDTzPfEMtoEAPbXpE1uOo88tYK
         ADLVk955dFB3I80mx6tMEB/hIbSOdCeUdtWbFkUL7cdibY39C56+6jvlc+XIqYKPGwYp
         riSZrB6Nwq13ZqluxVbG7GAEpDyWrl2MIXoiXhkD2IBMFHSDb5zuI/7F2S9coZYJZF1w
         LXTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qIyQ06DE;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=ZM3dKf1d6pMbqo31IpBSrF3WPTdenWzOxdUsdUycYes=;
        b=Nw5paoByN6WuNQuReOZnXmkyqba/znG26i7efmNMX4ylXiv29XGIrN57X9+WXUaqlq
         JBDlNdPPUX0WBoGLZ+LOpjbA4xcbnyDhHRdIALz+gyngo0qYgg8tFMKD/qnuMQYBsNIS
         sC3ySC3c5eacCS/QuYwvKtRClFsApWG7LJNrdJG1kTHCFIBvSVu3ugPhsE9xG5p+qlcy
         JqOv3E1FgqZN9fwzuGE5b8Phy0gJTRmS8WSjFdah9UkZDSvbRj/PLhpyxY6wey6XnxYT
         7QRSJwU9+Rw2QojYgiB0UjcC5k//r+FJTGyBRP6w1y66//WfLpYZuzQ/T6WGrhqpPXZj
         i6GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=ZM3dKf1d6pMbqo31IpBSrF3WPTdenWzOxdUsdUycYes=;
        b=l3DfXj4K2tjijpfweYHegH7fE7+rYtpKqQyo1JxhOCkDW9p6SIPZj/Fj7PiGca4s1K
         T9t+PgTpmS0ngIQxy3ggvUvb5pvrBYQL/YGAQZbGac4PaR6bAoKfniQLI/NLRLSdIdME
         3hHXXnYTfup1+VXeISank6n0vNpioVQgIZz2UX0t0XRoO3cHG9FpC4cMJShYKX9oOIdS
         NDwjnVgPYj6lVisiCxlbaAC8Od8dpyEsFsjeLC0P7E9gxYCzKH0V4vhFxxtborceoHoA
         Yaeot8WLc9r/mhMo7plOhzGZ0K0LVjkEtJ80Osc+ODd8ltkuJgSsVJmfig7ZD7r3M8hl
         dX7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3BAC+e9pkF56s1SaEsjmf7upKJ6wkOgQ15lPA/JXBAuTmxp2Wu
	u2+2WO4Kqdn2J0XiSS8qOoY=
X-Google-Smtp-Source: AA6agR6G0zD7PTU4nGLHy3B+mi2KjR6r/vdL7VvWIvjnC/L+Hh4OhSRt4qVTOCvSwYA0hWEWytquew==
X-Received: by 2002:a25:b8cb:0:b0:66f:5517:47ce with SMTP id g11-20020a25b8cb000000b0066f551747cemr13764614ybm.342.1659922461482;
        Sun, 07 Aug 2022 18:34:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:293:b0:31c:8442:94bf with SMTP id
 bf19-20020a05690c029300b0031c844294bfls4735558ywb.6.-pod-prod-gmail; Sun, 07
 Aug 2022 18:34:20 -0700 (PDT)
X-Received: by 2002:a81:36c3:0:b0:31e:6899:dd7b with SMTP id d186-20020a8136c3000000b0031e6899dd7bmr16195305ywa.205.1659922460899;
        Sun, 07 Aug 2022 18:34:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922460; cv=none;
        d=google.com; s=arc-20160816;
        b=ym25WA05GhTb2k20wnk+wo6ueedyRYArREXzrIBgGB5ZEEgGKz85suHnjNmbud8kng
         VWf3f1P0LAcMSlfB4h8MFd9mmpw8mOj7RFge1RzA+70jjPsy4Qz+90kRTtE4T0jUc5OQ
         hXhFHzNV3b764VlM3NSq1RiEI6qCtrmfW/IBCcRksXG4qXEn4n9XHinC7j5j8OaS7EnH
         oQiIKoNMInzN3noY3RSnGFgE/zjpdj2yPT0a8otjsddWMromguozo+0JRvpf/5ybp9Xk
         7tK3z9JucKhqaF7itvaM1zYLl26flUpAyUCI2TeHg+8dqmB2sr8YOZtmpQdCdFr04Pkh
         NFhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4VOGKjNvxfdZgBDKksD0XWodTGLWtey/jHGu5uBXZZ4=;
        b=tp8xjcZqA4pMU8imW+aR92xNe6o4dQDmz0LmI2Bu5Rs804Dg4juiGWjhW/hlvrWVPn
         6L5Fa/qd6aqILZluMAET3hESWv5mv54S8L6h+JuPBohFk4d4VGb5+rbs5iAWxYr8bwF3
         H+p/tauoUkkNnIy1ePmGAq1Ok9byuZJT9UTn3VHs/DCuBt7CjnvlYu18didKL53FoYc6
         PRmCPO/7CwV6dir7gxOm18S4wJCDq5bZUNQkM8UizMoOcOoh/a51waE7nvAXf2SfZJzj
         K/hqU2vCLhhNU4JUTy2dlm6zuY2XYFqxUn8PII/Q8xSEL7rrzCPEFpODYvO8w3GNqGgk
         d/Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qIyQ06DE;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id r198-20020a0de8cf000000b00326d475396csi1036339ywe.0.2022.08.07.18.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:34:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 8993E60CF6;
	Mon,  8 Aug 2022 01:34:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5FBD6C433D6;
	Mon,  8 Aug 2022 01:34:19 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH AUTOSEL 5.18 08/53] mm: kasan: Ensure the tags are visible before the tag in page->flags
Date: Sun,  7 Aug 2022 21:33:03 -0400
Message-Id: <20220808013350.314757-8-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013350.314757-1-sashal@kernel.org>
References: <20220808013350.314757-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qIyQ06DE;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Catalin Marinas <catalin.marinas@arm.com>

[ Upstream commit ed0a6d1d973e9763989b44913ae1bd2a5d5d5777 ]

__kasan_unpoison_pages() colours the memory with a random tag and stores
it in page->flags in order to re-create the tagged pointer via
page_to_virt() later. When the tag from the page->flags is read, ensure
that the in-memory tags are already visible by re-ordering the
page_kasan_tag_set() after kasan_unpoison(). The former already has
barriers in place through try_cmpxchg(). On the reader side, the order
is ensured by the address dependency between page->flags and the memory
access.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Link: https://lore.kernel.org/r/20220610152141.2148929-2-catalin.marinas@arm.com
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 mm/kasan/common.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f31..f6b8dc4f354b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 		return;
 
 	tag = kasan_random_tag();
+	kasan_unpoison(set_tag(page_address(page), tag),
+		       PAGE_SIZE << order, init);
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
 void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013350.314757-8-sashal%40kernel.org.
