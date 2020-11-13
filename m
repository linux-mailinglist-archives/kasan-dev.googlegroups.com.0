Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLUNXT6QKGQEE7UYFXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D3652B283D
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:31 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id t188sf4737035oot.9
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306030; cv=pass;
        d=google.com; s=arc-20160816;
        b=UrscFfbNFdcMqhKfuBePqhVFFM+Iz3PT+GQKoMqxLhD1Bjng9T3aWytMtIBsJM9rAS
         9mnPq9I3KAY8SKl4lOb9Cb6cv76byDRDFgXbW+VpnIwWClXkL1g5bmO67Cpz0o3rA/+c
         7eUv7hK1AZT2snGbv8MssBbMmI/SbInEokHKPNagA7CpK2SZ14pV/mrKRgDyZLFkGJOy
         uCUZ1Fhvub/v+KPphSYToQDyj+Bb+QzeqduwnBu1/OCSlVWbvflsdRqyFp/eYyvCT8kM
         0EwQ1r1Bcng5RvGyYb/VwfuH6djCfx/oBqixZevxr9z3WX9iRzxZP/fiqrLR/EuzNGb0
         SWEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tjo6ZvYmQLa0PqEfgPudXTcqZwubTxN6ugWjQ4odwhg=;
        b=cX0CVs4ifeN3Z6CGn2/PF/npcMIDxluRGR4BiqPr5KZK8Lv7i8B2VamKttK4kcSb2+
         V8coHy5H1RTnBsna7YBYssYu8eMOr306v4AceEYo1J9CcbOG+0pu3x7seAftwnkxc4zZ
         x3TWUDPVOyy2mmh04+dlQ1VLJntP1pi5EM/jIdqDeZDfIInXtPcT6jkebS+0hOfh+ENE
         0WuJHzttiKBoyhDFt6fUFvQ0j7A02LXigVkYUqP4amCid1Pvz3IHflbrd/B19WDGBQyY
         pGKm/9XT7UfCyrLxUEwUF4qlOtEVIVpHOmqKfWZ62LGhsM/8ESmr3MKP55JcINWsijCd
         F+6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mr40u2Na;
       spf=pass (google.com: domain of 3rqavxwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rQavXwoKCXoYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tjo6ZvYmQLa0PqEfgPudXTcqZwubTxN6ugWjQ4odwhg=;
        b=RVGrtHn4q5f7TMo3ToPFihV13DedLxseblnaNOHhtjeuXXiDPEioKva8uFH8db48jz
         qNljIIjvvBIimKJ+IiJq2/CAekjZ4IKm+H3pmhiswKTpH+Yp6FPrxEvGYZ6mbvYxSYI1
         RMxyDObuj8hls2az9uI4U0aBypLEJOlpDA0eBno5Z56EfrcY6Cc+ZJ9wOOZVbH8BeaFf
         nIxQB0VSId8QGXRP6qmRgjXQ4zWynbtOtmAfk8ZmGTlj+kDwqdIXdtfoqxxNM6+SzRVC
         ldqlaP1UpcB5GN34cPV5lHXW844psDLBWTfcPqI9hGuEzoau+8Yf8SaCu0XpZ/5roihX
         Y7EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tjo6ZvYmQLa0PqEfgPudXTcqZwubTxN6ugWjQ4odwhg=;
        b=PZrOvI2ly0HUG+XcSRLQGTFQ70B1YrK0L02ferFTm0b5VTI1rqzEbwzZtneg4VVqrH
         RnAh4qgnSfFTDWYG7/5Wg9I2mF65+54keDV5qdL1Rj80fTClxoKFMuOGJumJj7JhyqSq
         sNFRN02gUVzF6WShQqcUg/dUFCJG8R+AalCGh1hP/N4oBa/mIr5KLvffhoiiz/wB5Vj1
         OUTOp8dfAu4x7OyX+EWyGMl1KyZCijot/0Ld1ipvJnErBeLzjUiz5QBlBdaeMx4P+lXf
         Cdf70aohcCA5MRA5/YJeiQIz1lPr+4Gpd3VDLc1BR6KhUiqYPQbhizj8o7EFW0PQC7dy
         TRGw==
X-Gm-Message-State: AOAM530y6YVXDq9PmcQfrmsiIejC5JoghjJ1iAc2xPUJr9/xELhk9m7d
	DdZOAllTTGApM/pcBwfC8FQ=
X-Google-Smtp-Source: ABdhPJxLQQwd6PrASop7Ob7SbfdLD4RFAGiFPcoWOTL71xZ2w1tNYhlhWsPNUVNvZy8dyyF0QvcZ2g==
X-Received: by 2002:a9d:760c:: with SMTP id k12mr3165860otl.52.1605306030420;
        Fri, 13 Nov 2020 14:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls1920514otm.2.gmail; Fri, 13 Nov
 2020 14:20:30 -0800 (PST)
X-Received: by 2002:a9d:6a91:: with SMTP id l17mr3167959otq.187.1605306030042;
        Fri, 13 Nov 2020 14:20:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306030; cv=none;
        d=google.com; s=arc-20160816;
        b=tfqUzgJHOQJZpOcCT/Iba3kVvu3e5LC8A9LZ73wkaLn+iHgFIPVOkkqJBikuzRzlEn
         yf78tanOUCJU2Xu1JOYLe36w9+z+Yox7YNFuoGvChiPvmJ07lw3Emffmumi2pJuOXu5R
         MVROOK6FsPl00Akl2EJUs8/C0UKGny8s9rRa795lyIUw+0LWIOD/1TM0qimEbSZBKC2u
         XGfIMpGXzDPwDlRFXfLFJjJQUnGMeLbFIfLDqlu5kiXsHoxK6vYTNpI5mBiCKihpAuWk
         +vYQFSsAYJyMKOmRZE1r2UaPzbHNkPt6LrisrR+ITWB4EhUIxY4LzHbssefIn0rwhDz5
         7ZYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Jsr+yOOqZi2Nj6qjC5GqIPggpAtw8z6+rbSLs9IYMt8=;
        b=kwMbOhunfMjItqr2meZi4FQq7dme6YCUjKLjvfEQe2dgW/CCcJCOdl6QUGP7P8biqu
         YXtsTaj49ol14dHluWVcCSai4NQPzb4bKm9pVI9gCD6oPciEeeobztm3W9xUkQtru9+L
         gtm1mu07RUEe7JRHe/fRg2Rmr7o8gqrtxUQrho8tjTX/7DaHpy6mQvReDYOgGz5z9XSY
         1qxqM/dOjRQgnozYaQ8aKLzkSrGpADMUIoNJau8ef8n25EsuBxB2ypTyye9A2BQjmrHl
         +rU2f8uvTDqAwJlc2GTTtOJc+v6F8wDfZW4VwwNL89KI3BmkL3ZDP34hPHNupZ7qAG+n
         8vCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mr40u2Na;
       spf=pass (google.com: domain of 3rqavxwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rQavXwoKCXoYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p17si748757oot.0.2020.11.13.14.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rqavxwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 11so6606312qtx.10
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4633:: with SMTP id
 x19mr4837837qvv.11.1605306029294; Fri, 13 Nov 2020 14:20:29 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:56 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <157e9dfe43c5612ab028638c39ed5774b613449d.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 06/19] kasan: remove __kasan_unpoison_stack
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
 header.i=@google.com header.s=20161025 header.b=Mr40u2Na;       spf=pass
 (google.com: domain of 3rqavxwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rQavXwoKCXoYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

There's no need for __kasan_unpoison_stack() helper, as it's only
currently used in a single place. Removing it also removes unneeded
arithmetic.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ie5ba549d445292fe629b4a96735e4034957bcc50
---
 mm/kasan/common.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7648a2452a01..fabd843eff3d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -65,18 +65,12 @@ void kasan_unpoison_range(const void *address, size_t size)
 }
 
 #if CONFIG_KASAN_STACK
-static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
-{
-	void *base = task_stack_page(task);
-	size_t size = sp - base;
-
-	unpoison_range(base, size);
-}
-
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
-	__kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
+	void *base = task_stack_page(task);
+
+	unpoison_range(base, THREAD_SIZE);
 }
 
 /* Unpoison the stack for the current task beyond a watermark sp value. */
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157e9dfe43c5612ab028638c39ed5774b613449d.1605305978.git.andreyknvl%40google.com.
