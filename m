Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD4OY36AKGQEWTFFZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D66DE295FC4
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:16 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id s6sf296237vkg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372816; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vj5MgaNZYrDnNjyiVCe4CRbWZQoQPHr5fHNc0AxBwgt7dfoGwrGGbiENIK9ejuYhNd
         DUN0r13uoL55Kj9DmSuzKTP/8lYVXxT95oWLXwn3SiZ8X1Wnvq0qCINXdneT5Ck69BBi
         G6NkX+EzlvMsfJtSvIB7sFij6BGd7T2chuJ1CPYNUy7LdYYQGdRQOzBXmMv5pilC/K0I
         neCZ5gpGpHgVV9v8EktNG5QXvJm0Alj5DYXSegxU3dD0kRmE9eoyP7tsXeobhV8sOKLZ
         UsHtylNpCYR83C6KlQqlr6MG0wiq/KAIdcYMDM4YnxZYyAg6mpPEf9YEcz4Cu9TFatUZ
         GF4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4Q8hBNBkDGPMZYojn3+fMu1JfJgfFaCAjNJPjAUTC44=;
        b=oBf8ItZodnLXM3ByG5ulmwxfVxP+msMPZt0Sfe5vcJaeLsYnWLkFdk39kE0AvXyta3
         0+e9bDZEXQBylmnZHT6QxKKsl0Fzx1+mQMExQLZ6DSZZTTKOVgNZXB+gWVOvVt3b0pzj
         /dk2sm5LWzxeUXCLYj+Jwtj7OWtH07bx1eRCOPr7xmjyXrki9WZ1lrJyTuMu0MoMIVPJ
         kIP0G/rH0nnxS5hHWkRrLNIClH1m2gRyZQVCChFHFw68kzFhOTEZO6xC0FGs5ss6smft
         UEM8DKPH+TjZQCGbdq1xIAX8E+akLs/lffx3M71CFUBMYiwZ2Kg+WcpXOgwcNbCLsfa0
         PqEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="tYUeZ/yu";
       spf=pass (google.com: domain of 3doerxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3DoeRXwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4Q8hBNBkDGPMZYojn3+fMu1JfJgfFaCAjNJPjAUTC44=;
        b=Tyfpvar9nzs3Qg+B77TpK/E1DfxL8i3FsBZuNqRk5FU/QQZL3Cs+ZTAUfYOuKfU5y7
         QiN8si0X5Gz97X8K9Sg2eMpX7/AJquthiov2e9QrZJ7L9daBNboeIsCXnQ8iKqmeR65E
         iyQZzHQbuctIbUF9IwzSv5o2i4ZJLBQqURRqKWnDFV258mU7XDt9VD2334HLrp/GIxwH
         Z8TmIW0UszevLT1MTWjFpXSkFKzdpjMTZ5qpB0YvzsgslA+daoPWYR97mO9cIBYrCPHY
         MRw3jv5ZA8bhx9G8AkoQNsfGHOlKvAhG6hfPc/4KqCfolejPkqO8DJNpk4UdDxMIsJ3u
         5chg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Q8hBNBkDGPMZYojn3+fMu1JfJgfFaCAjNJPjAUTC44=;
        b=MNLaXgH0UcaTIuYe4q7/PPT3pCIv7McShqjA83YhbWT7G0D3rW2jAZOdqbE0Qid6m0
         VPOj0iGV9Dpg0pzanvrzuiSqQOYZMVj3CymPO5n+5hruTjl7Kp3zru/5dHAuL9v7MaOI
         ZMAOarWFtx7NUkqGQeesGbA7HIFuGUrCmlb3647krbuKabqq9z7lJZtctEV5Iy0m9DXi
         ywFM0jA18KaY29ux235pq8ovwWU78W8ddOQXmXr3hJzdT0UDVPXYiwgJq+nYDHIaaStJ
         1SayDN87IcgGEtJ+Sc4KTLUm6JS/hPSZdOkOG/uZrF5WKtOcfSxp3un0P1S8Ihej1L32
         dGjA==
X-Gm-Message-State: AOAM531P0OSQxvielwfHrRKSPnOjA+vcyguaq6e1RBJHHJDn7BLA87ru
	s1waPUkV27Q3XFvUhFP1RFM=
X-Google-Smtp-Source: ABdhPJztlUjGQESpIqDDu5JbYjH0IuNCC7vcC3rpqWsA0WysNC6YtMR9i5rG0xHTkLRffsW1XW7I3A==
X-Received: by 2002:a1f:a2cc:: with SMTP id l195mr1548644vke.15.1603372815665;
        Thu, 22 Oct 2020 06:20:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e29a:: with SMTP id g26ls187544vsf.6.gmail; Thu, 22 Oct
 2020 06:20:15 -0700 (PDT)
X-Received: by 2002:a67:f954:: with SMTP id u20mr1561264vsq.5.1603372815083;
        Thu, 22 Oct 2020 06:20:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372815; cv=none;
        d=google.com; s=arc-20160816;
        b=iyq5eItA3WlmugojIFFzkKb0ZHDIf7YsPqw6sd1RUJN2rLzrZnO1st11/kTsrme3su
         r6rg9bHMG2REOwJbL6NbDBzeG0ENhaHa5Ppbs1PyX/dpSGZRlItFOikMxvVwpLrAEGTN
         lhJ2Ecb8LiLANqBRHN3BfEZC8zqzEuQu/nQWqAAQAZol0Wj91CBl//GhswnJWtOaiJkz
         5rSi+6NYIClJjlhNmpa1a5SBATG+kYOeWrfs+t4Ymacemq+S7q17lvlzWN21j0QGH7U5
         BDi7VJFBgX9E7y7XUNxWYa7kJkvn8m168QRly7+xzxGi6Aq37ouTeA7Bj/RRjW5Dlmyu
         lhKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mqqQQdM8JUr2kVRXhQOSR7CrNIaI2iWXdt/tai4LwbA=;
        b=tphkzqZ6dnt/XQdHytrBHqwGtDf5tNcNoz1Jo1pure1FigFle0K6IfZMowjo2WGQs/
         FZp5eiUUMg5qVREuaXHF2yvQKYjGD3u3G696kI1/2gGEWLrGitjzia8/E8K44hNvOaVy
         ORvEbQQOUP65t5pxn4K3uO8Wr459LsMXjXNe1seeLfrbs4P1RpiOQj1VU9MFYRHoQHGK
         BE/SfHytaNL3p2cKkatyYdNRiq8o2C/ONefQOY6zv8IME5Z/Vr0aeugT0xhVnzHYFtXr
         iRrSWdgKHJA6jRq+cFAUzpQAEztXUOWScIaARBAhgARKd42jxz2cnqmRqHV3HQ8jBNta
         y/wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="tYUeZ/yu";
       spf=pass (google.com: domain of 3doerxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3DoeRXwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v3si66444vkb.2.2020.10.22.06.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3doerxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 2so1032680qtb.5
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:15 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a261:: with SMTP id
 f88mr2273549qva.56.1603372814622; Thu, 22 Oct 2020 06:20:14 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:13 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <6ed65cca58736301a1cacb539a6e672aecd7859d.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 21/21] kasan: clarify comment in __kasan_kfree_large
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="tYUeZ/yu";       spf=pass
 (google.com: domain of 3doerxwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3DoeRXwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 3cd56861eb11..54af79aa8d3f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -445,5 +445,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by page_alloc. */
+	/* The object will be poisoned by kasan_free_pages(). */
 }
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ed65cca58736301a1cacb539a6e672aecd7859d.1603372719.git.andreyknvl%40google.com.
