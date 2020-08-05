Return-Path: <kasan-dev+bncBC6OLHHDVUOBBPXLVD4QKGQE6TLVQ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CFAB423C490
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 06:29:51 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id a12sf30832288ioo.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 21:29:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596601790; cv=pass;
        d=google.com; s=arc-20160816;
        b=UmuNtSWAwgftbWHO8B/T//mC6YWtU+eraavp2mm5rMgWG/93tysVKctpfxhbb5tLNp
         TQ/ppN7KGmbrAGoi38AJz6cGAKIEYnnelj17t12q4ZcFk8yZHy4kju5V/hv7yXSfmxbx
         bWaUMCBjL8IeOwJz/9zj0Ym4Wd6pp7P+LBx+u1AzamGBN9NUa9B/wwalpQtIEbQWFYNa
         qyG/kOfNREffu9p7C664kQZOtCqJ+qkUGD/oaTG4xVD9XLf6ZIJ7+4bwq82N+/PIJIZ4
         IzTMiwjfcFVn8s4Z6ypdv2/I/Q1LnfHq7iCHkWhbxWCDXwGXdEXvWIHievDhrJoquGGc
         OOdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=N8knBC13n8w8DPcyzxjDYCW7EY8Xz/smnfmjR34nSC4=;
        b=Df3F9KVbHGFcs0xagOXphgLzkrRzDeOd8e3OOOyBoomVUGf5m8yI/Y/rESmUg3aDpi
         MJxQYz0iRum52O2RHoR/bxBB0kV29IjDsblDaFkkqUIjfaO6xc7gs/DptFD7/UTUV6+e
         S6tuHHvtK5wt7qP8EkCeXCvM4OOs2/8p76IIRf8btI7AqCeUlnZPOX9Fzwm8KE7ZTYXq
         LYFmrWviBSJjLwbaD21oKLqehTS5JQfRZUAs9EcC9dr/y5UuWY/NIWyOBf46g3Slt4wc
         HDQ5dRgstwMbjk2jYenbV5+w7G4U0EsKtdmQqxdPMFTPHToLRId21WIIAmmZ6DR/8AHj
         S86w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KH87wYJU;
       spf=pass (google.com: domain of 3vtuqxwgkcdazwh4z2ai2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3vTUqXwgKCdAzwH4z2AI2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N8knBC13n8w8DPcyzxjDYCW7EY8Xz/smnfmjR34nSC4=;
        b=Io4Lzzm57GKJvbl7we5yZ4/RmkPZzjX3hrNmciN6hpfJ7NdheyIUt66ypxJEYEx+GA
         72cZ7BC1MWJCOjJPfFazbcJ6yAgAuhjpVS/LWOTvhJe3BhPB+gg49vRipztaV/SRBzNQ
         +AZZ+1GzdQIECArzMy+uvnwAHCiUj2fU05x3tSVpvvg9EtjX+DCxwuQkaXnaBH+zfdRo
         jQXMKxsuYFNyM8iI8Nt6XhSAKhlwIeq+sOfqpztYsCAcv5DS+d/QZW2VTfmzmCwwGs2E
         02ZDlzgTrXztCgjKJymwHQYZTVYX2kyDb8fU8iXdkHHpcq/4ZEaKM+tn3QJquIfHr2nn
         x+bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N8knBC13n8w8DPcyzxjDYCW7EY8Xz/smnfmjR34nSC4=;
        b=s5Ot9vrVUb2TZFn4beCQH9livbzc834fRJr+e6VZeVI/dUcWVG3qb46nnBypi0j9rt
         lGha7FiPG77XdhncsQZzqwVtenDjzX4R6ZrZaOCN4wgqK3iD6i4rA9PMSftJlS8EpVQg
         2/LNnWimQaVxCG3zEPMC7B0aYbKB09qql09yHGYeKphaM0sEx4ccA0JTLS38b3niOad1
         vdCO46UCbY54XobeutvtdltlqLzlx5ot3yGLqeEE0TFk6SGvRCnZHstCjkTkDT6Opr9x
         zgh7wAM94NSUPU0U5AXeCzkUoUwqqCdS2qqod0QaLZumDYp/1HFbK6sUNYGi9nYOJpxx
         64Pg==
X-Gm-Message-State: AOAM532ik7RZ5hi2TioQOoCkXazJGK0oNJZvOliFXPQDvCyNzmU077To
	plF5uuwx1vqf5Z05bWTt9+g=
X-Google-Smtp-Source: ABdhPJy8nGBgLe+XEclopyEudQnAdW0nW5qTRUUUyU4Td2hqqMYcItgidsfbJD0e3owVE0gKyBaMgA==
X-Received: by 2002:a05:6e02:143:: with SMTP id j3mr1865891ilr.97.1596601790604;
        Tue, 04 Aug 2020 21:29:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2a9:: with SMTP id d9ls164744jaq.6.gmail; Tue, 04
 Aug 2020 21:29:50 -0700 (PDT)
X-Received: by 2002:a02:93ca:: with SMTP id z68mr1928418jah.3.1596601790190;
        Tue, 04 Aug 2020 21:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596601790; cv=none;
        d=google.com; s=arc-20160816;
        b=frsO+YISahoHyhsqEdqYraOKMVSotKwguRd4444QqIIuk4ghzgKXWrKliq9IV4gzUU
         RpiBA9UhLMHc1S71lYPzTgQu37fPRDU2hWWc+QIIJwOfedesjsYZ/hWCJjPfHIC7p8ii
         5pPwNk3PoSxL+Aa6VBA6ZPyctKC0c91OxYIvbR1NFpB6I91BXuCAoHIfEhIugdMrJp2l
         4Lz75V2KFlIHegquVus07rNoyR92pFeqvuHw6RGNJ4aw4FNfdIBOJ9iYT4XZPD55boLP
         XobrnLp9gT3Y3ArrogNwMqVE48euF54QDWThLr7+03a+/IrxdLpTtlltHy1RJt3ZYADA
         gzzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1s/fGj49wZAcV85LY6dM4ghB8ELbpKuQm5SC6WcoZ6s=;
        b=ZpJMCcYCYBczxWNKTKFJGLyJNm/VG4FHcbWda/+6iQP5bul8861n+xFm9bacwjHiXe
         v4tyuLjwNwTJ/WdlaeCh7aUKDf/TYRCleugQ8QKk2yBETt7xN0XMQ0NArtsLwT4gv327
         Z3jfb+Jo9zZTSbzjnj+R7iftj022T0GDklmtx6L/OyVmuhNHM8g4mi0OJXlll759Rspg
         14eCmDT29hCWouamvZDXOoJ/KAdX4m6xhhqKVdy78cX765S9GdnR/KXKwIa5ZCFiwl7N
         FvrMf7CKzLVSLQLDG5G/76eibIS6IuX4iJrtdN5KeIrIIFoGWWITKJBIDuwpQcpum4gF
         Mq2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KH87wYJU;
       spf=pass (google.com: domain of 3vtuqxwgkcdazwh4z2ai2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3vTUqXwgKCdAzwH4z2AI2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id p1si45210ioh.3.2020.08.04.21.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 21:29:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vtuqxwgkcdazwh4z2ai2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id q19so21368859qtp.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 21:29:50 -0700 (PDT)
X-Received: by 2002:a05:6214:1742:: with SMTP id dc2mr1836989qvb.90.1596601789643;
 Tue, 04 Aug 2020 21:29:49 -0700 (PDT)
Date: Tue,  4 Aug 2020 21:29:33 -0700
In-Reply-To: <20200805042938.2961494-1-davidgow@google.com>
Message-Id: <20200805042938.2961494-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v11 1/6] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-mm@kvack.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KH87wYJU;       spf=pass
 (google.com: domain of 3vtuqxwgkcdazwh4z2ai2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3vTUqXwgKCdAzwH4z2AI2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 27882a08163f..f3f990b82bde 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1196,6 +1196,10 @@ struct task_struct {
 	struct kcsan_ctx		kcsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805042938.2961494-2-davidgow%40google.com.
