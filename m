Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCNPUX4QKGQE4AX7DVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id EC35323BA8B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:46 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id l18sf29095750ion.9
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544906; cv=pass;
        d=google.com; s=arc-20160816;
        b=VsqK1V2h1rup4yNojrPnBjDI7VH/uOBaZxCLpRTQLe9+VLi/n4VKJfDAbgrT4+nRkj
         JMfUOZBp2KnwN22t9kk4J1vwC/R3G9h5frF2OjJsKmNnR1mbLXWnX6+xmT6wCYy+9DOM
         Dove+WwqlHUqN8VF60bfLRNaFx4JwWzGSRH6a9hgK66nF7cvZYAhYzvY1EvyZu82oI/A
         RUoKuHPPwY2eWh3kK1fiRxZzh7mM6pNkZA6ALJr+2qzrmlyK8DCkXAQCZaswXhExkJwR
         FkxchI230nCmEChik/u7jSDbmcsCu4UP3ziy+Wq5J4Il8C1GyyE35WUi4bu9vuxGI4BP
         JeAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=MUfWOvIE6lxuLidH0GCUTW/5FuX+epSc5xI+U96CQZU=;
        b=PGYa4GKNj7vGap5jLsBaIEMgIrg6Bjgw/sU+RfJMLBMCjpPES4TygbXfYrJmFLTKCm
         IM/9yRi5zzlTBQ0B2UoHJbYRkxbPViEBOqiAI13KR7pOhwZR521iTzvztDYw2koTMvov
         OQxzffFTeauhbQ9kt1o2X/cBmc3O4seSmmb90VhT9vlh6K9LhrqyrzQXZAlUj8mS9FFv
         ETKb2WzroRD7FT3duYFUSjyfAYqSGkgm7/cLC1UsCF6+0aRN8veSOOcwxGuby6aumVTX
         RXSST1390FKfPMCKLka8LFlDYh1j41SCAQgeEtMCNY9z/51TKTYyBDG4E83KWgOXdMqH
         iBqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ea5YjJ7o;
       spf=pass (google.com: domain of 3ifcpxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3iFcpXwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUfWOvIE6lxuLidH0GCUTW/5FuX+epSc5xI+U96CQZU=;
        b=H9NePD6kRSjfV8N8K9rBonASBbp7VONGnKUgNKzrxj9U4rLW+EQ317X9r9vHyj/uxf
         kf6wBKEA6OAol5fR/ZkQ9w5Z5OJnxAialjhR83+Yg2MBl7qR2sbQBTOkTC4R/RiWjikG
         FFqzfUJP7u/S37ATTmbLM71yEjrSUDGUWWqRkafnXZn0o4gnttSYm6UuIQ6M00IoGZIq
         /Zm/0evDOKZnOOecmAzHo3eIs6nfnNGqEpONpR7ruWc4ekz0+bbRsxZAucq3xYBgSqxi
         wwfPQcC9ncvRD+DGOf3i1FRGSWMRUX/AvQ6pHD8VWKsiUUXrLlcJfmHvzGKLU+ih3lC+
         mFdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUfWOvIE6lxuLidH0GCUTW/5FuX+epSc5xI+U96CQZU=;
        b=r13iBDraPpCPiZelThyPUy+BoXBqaFKDaqalNzATL8D1U2ZlIVv+S+eWLRf3YeqN9B
         HUCDnbSOUJIjuGvT2iGDfuMG5c8C/i3n9XUe2VpbI4m86EZM++CtG3yDttrUeqch+F6h
         vqJ2pGh/70fqVjcI04RcAsOOrcri4YixfO2duU6HA2PBjY0U8YbZxNx3cKH0SILudQVT
         GPYG/NvMGbflH+8VzlkqU3D+y8qA7ERQ9S3VFS0jw7SEC43bX7PTWdRLD8/Bxx7PFxCV
         OteKPhkhTm/2Bd6L4lvbtID7e0qBa9LSMiPJj+H8ZYDaTrzBHSoPL/kP811Yu/9ESAm1
         kTxA==
X-Gm-Message-State: AOAM530L2doF5DGB4yiYOK6Q8RhNhmhhRoB0aBHl2h044QI2H807eZOt
	C0qxMN6+eLQSNgaBEZFxRyU=
X-Google-Smtp-Source: ABdhPJywJu+rzFQYnyAIg2+WTeTDsgLZRt6N+tjGgFw9nyt84aUeR450FRiOIhHH2x36L1VnEG2Esg==
X-Received: by 2002:a05:6e02:52a:: with SMTP id h10mr4892360ils.259.1596544905890;
        Tue, 04 Aug 2020 05:41:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3aa:: with SMTP id z10ls3007335jap.1.gmail; Tue, 04
 Aug 2020 05:41:45 -0700 (PDT)
X-Received: by 2002:a05:6638:13c5:: with SMTP id i5mr5442591jaj.29.1596544905619;
        Tue, 04 Aug 2020 05:41:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544905; cv=none;
        d=google.com; s=arc-20160816;
        b=SdfcxPHtOWAAUC05sCMMCAYnKm3HZ9gvppwO2m2KvNVs9rG4mCoFpmK+ItOngWlfZK
         XvB/CGvhrI9cGGaplHl1eyORjag+9x5gk/3uy1K9q9fmHnmRp1eQmrdAI16KGSe4NiMf
         kxWaXDcrLCHmWdy8/WKf1QnroFw+ogmYp1rmIKi4KmBnZxL8pGnhiCzMXu5ZABHpKY0A
         dkDa0oCyShoDYwWD0MQtpBMf4BKaSZIS6QUn6Rc58osSkT8H784kNdSXENikSF0KnZf1
         QuBK+DBWA76Dm3z8cJ2TZl79QSDe4sGmfWIPHzbpLX3nUIV5ciNE2fh5PtYMQ6lwYuYd
         PVYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=OJV+wFsSuBAEdua9Kpud4j6ZGzVdRXqmU9/PZhjVLdc=;
        b=FyVdVlEkn4m1B7uj8TsYq7NdpIlIL8fc7ugE24zOy3ITNd/pec/TjhE7hU15Nm+l1V
         hmArqcPWaRwhWky/4VLIKBtDID+VbMQMKUawFHig5SdvMouLLv0yeSA0nmHjJTIdRO3+
         WAqY+CbC4wKD82Ovs60QbWzDk1nRyfIHPGlLxbdtfUcCDP9/DnTVEgssF+MWHzzu89mX
         hF/dyyrFvtGNsSNZ75dKZ8AuS70nc1zu0JswxmQNATdQd43MPa2Q9WXh+mIMzWDofIXq
         ivvD+qbuan+zRwu0OLumdXnys5XXRpNagG0iGVpfbJcqUV9GMviQJ9FKxd5MtAxDoOE6
         6Azw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ea5YjJ7o;
       spf=pass (google.com: domain of 3ifcpxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3iFcpXwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id f4si626824ilh.4.2020.08.04.05.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ifcpxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id j8so25899521qvu.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:45 -0700 (PDT)
X-Received: by 2002:a0c:b604:: with SMTP id f4mr15297001qve.68.1596544904936;
 Tue, 04 Aug 2020 05:41:44 -0700 (PDT)
Date: Tue,  4 Aug 2020 14:41:28 +0200
In-Reply-To: <cover.1596544734.git.andreyknvl@google.com>
Message-Id: <3063ab1411e92bce36061a96e25b651212e70ba6.1596544734.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v2 5/5] kasan: adjust kasan_stack_oob for tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ea5YjJ7o;       spf=pass
 (google.com: domain of 3ifcpxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3iFcpXwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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

Use OOB_TAG_OFF as access offset to land the access into the next granule.

Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7674616d0c37..5d3f496893ef 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -488,7 +488,7 @@ static noinline void __init kasan_global_oob(void)
 static noinline void __init kasan_stack_oob(void)
 {
 	char stack_array[10];
-	volatile int i = 0;
+	volatile int i = OOB_TAG_OFF;
 	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
 
 	pr_info("out-of-bounds on stack\n");
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3063ab1411e92bce36061a96e25b651212e70ba6.1596544734.git.andreyknvl%40google.com.
