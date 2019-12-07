Return-Path: <kasan-dev+bncBCT4XGV33UIBBIHJVPXQKGQE5JYF7IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 2873E115A5B
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Dec 2019 01:38:57 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id c188sf448936qkf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 16:38:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575679136; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0319lu3slDG9Lnmais7Uti5rL1mvxjb8HqT5PUKv6gHZTYRDAxSCu7WIOtmyH192q
         nEQUS5FXqBs2cLNcqBz8ma1LFx3dq80Wz5dY8zqfnAii20hKZ+d7WQzMjI0z5nit2A8O
         VqsLgIFpuHiQpPPe7pV1Dx2VqOXApOE2Nl/9eV6hYeLnC/KojjC6Ju3XrNEVN1zY1zhs
         4nSCs55D8rJHDdiMl2v/IyzUHz1So+PioMA78XI7h3WrS4IAlvI/aBKU7+vcDw8DPo5y
         4qjN8eIkYjKWBOdu7cVKyyencXnIWmo5W1eXTrIqTsZsKl7TGq1GtHHHxl4IawZ6Z5ZJ
         M9yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Pqk72llJ9/ZQ/1YRoctXFTU2xGQcz8qUEvFlQWFmaNc=;
        b=S6WrReJMFGfGzEXvdJk8EFqfJkbxq8mWI4/QhAKkmqoAjt5Y8pG/Y2duTFk8MnlGUs
         HTPkl5kA4s3OJTU/gLoRnLk0IHZ5Dd0K7kIg1O57Q90ZDaXo12W/m19AUjSmSCr8vnq8
         /yzheNbyzxNV/gKlUj8XJagtkd/kinsx3qmJVqOoFn7I/jI/t19HOkDr0ezUbN+Ghn7I
         M5DW79kjuPuBnToDjUC4dL/dDj3nkwcgxmDOEbFS+aGM2/MHHyQejwe6qSJJ0znbMm8/
         oVK24YAU2mumgpgksH4saoacVy6TF+WwSWFc7LVMGoqduSetiJ0SAaOrsV8VQeJJqq61
         cEVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gOYIIK+P;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pqk72llJ9/ZQ/1YRoctXFTU2xGQcz8qUEvFlQWFmaNc=;
        b=plYJYfOKTqJ6IS95J1O4JFkWT7AJFrbCUlGpYWRgP9mZiz9qWgJdB1B6SvWOjcI0H/
         rjWkp8Z02NhaSdfZkqHdpcu4NSCmQuJNbwxLTMPRf65d62a+t2nIypVepyqBtS1Ey+W7
         2LA09aHrwL82qkWhssglu46gG3ZcLMuN6/4Bz8rKru4CCfC70GJE0zCIHhu7+nnsgM0v
         Wn5o0dFivKTmhiyqqQCSRlYgL13Gq1pfwKsX4csj+pVJbgeEtUPkgZJYiuh82e4OJFGf
         s1fczAI5f5Hv4ahYjel3LNhPqSfqYLTQxZvdInGgiqI5Fm0yZzstmSA3SZPTHHYVaMz5
         VBYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pqk72llJ9/ZQ/1YRoctXFTU2xGQcz8qUEvFlQWFmaNc=;
        b=HxiYLT49N+omaZShge/KTK3RjXMjft81oAzzYJ3hwc/nbsPBMChAjxz7Ag/ZGCiX8R
         yRIsOz0TS8MuipX1lxwWGUSBCKDVp20Jx3OT6oYVKZeEZlhxe8978+DYCxlu6bNeVBaw
         0PVSd+g4CaspbYeCsPUHth6o95Al6Pi6dLO/PqNjkRxqwO5S2vOI0e8k5JA+Oog7+fOs
         0zv+KBOpXBL0IXrVcSX5duD+Ml9cZs5RvVXTpgcdSPAiUvPPHeB5efzXG1Eqvcog6JDE
         CdQ4yMB/VUDqOjdV/aIDPZzNq5SOdJCMSXIQpwyinjfHwbPr2DCtcwgF578g5BqFQp9f
         P+WA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWVLRzeLJlFYdM1miuTqCcxVGV7N7FoEnoLMcEozhYXkXJn6jwG
	LYRysULg96crx9iv71XqwLQ=
X-Google-Smtp-Source: APXvYqxOImsPBbM4F72U/v9FMNYwZFEqHUSkDIo54K3WDsnhWswlE8Z+sQ1SRRj3d1+foXqe0VxpTw==
X-Received: by 2002:a37:4792:: with SMTP id u140mr16345361qka.472.1575679136165;
        Fri, 06 Dec 2019 16:38:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:49b1:: with SMTP id u17ls1389195qvx.14.gmail; Fri, 06
 Dec 2019 16:38:55 -0800 (PST)
X-Received: by 2002:a0c:eed2:: with SMTP id h18mr15522797qvs.184.1575679135728;
        Fri, 06 Dec 2019 16:38:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575679135; cv=none;
        d=google.com; s=arc-20160816;
        b=RvGSgAOpx1O2iWM8CmzKlhTWmpBcgQcZhintSh5QZ5vIRoigkv/MWU0rQI7NPv/5Zp
         X/VIqrG7mtogaTZCz3GABnbq/qUedmmHHlxbTCk2aQ8yj6H6aYTrWLRrL7R6Dz6zMIQv
         1p+RMGo9037yHTKtHndDoUKYzMHzWZGIej/HJOENnBBjWHPfwcbc4XVYC6j6KSXmaOKE
         upOsgJte07jaHfa5SI2TCJVwDzfYBdK200lTQzO4F13Dl9n+za4XjeEUrhzFerCerMnZ
         Eoly9dDRB9UFGd4O7L+NQgjSe+qIG4NiPvexDzSnS3vTJlCgP6zR9Ff/kG90BlgmRCFJ
         LLeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KFPuf+Pz/ScKeXGkS2fIEbfT+VrM5gDgvXP706XhsIc=;
        b=bDhThIvrbS2VUUhlvjinO+gY8JdRho8QpGGADXD54CQn5Yv3+qBPzToypktm2J9E3n
         uCnLMsZQooYeK39W5TTjwXefZDDwtMK0ahlqwkGR2AB8mzISBnCPuIkk8IoC2T3U6P3n
         3Tm8xvaofIOIJpuXGFYRyjdSnYmXvllKVvV/wb/PlXJHNEmFmTW1LZGA/8wyLnOpQYaN
         axPrNzhYO9KxVsZKTC58w7yC/PKQ22lSiXNREFI0G7EpMvOEiTue/OnEHG6W8RYOl6nZ
         5MNJ+v30A8RPwszr1qTfDHsvSR1f7JkhNc2jmN9DRzLC/W+Biuy2jQfJhSADTw9NagEA
         9KQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gOYIIK+P;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b11si857998qtq.4.2019.12.06.16.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 16:38:55 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 555CC217F4;
	Sat,  7 Dec 2019 00:38:54 +0000 (UTC)
Date: Fri, 6 Dec 2019 16:38:53 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, aryabinin@virtuozzo.com,
 glider@google.com, linux-kernel@vger.kernel.org, dvyukov@google.com,
 daniel@iogearbox.net, cai@lca.pw
Subject: Re: [PATCH 1/3] mm: add apply_to_existing_pages helper
Message-Id: <20191206163853.cdeb5dc80a8622fb6323a8d2@linux-foundation.org>
In-Reply-To: <20191205140407.1874-1-dja@axtens.net>
References: <20191205140407.1874-1-dja@axtens.net>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gOYIIK+P;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri,  6 Dec 2019 01:04:05 +1100 Daniel Axtens <dja@axtens.net> wrote:

> apply_to_page_range takes an address range, and if any parts of it
> are not covered by the existing page table hierarchy, it allocates
> memory to fill them in.
> 
> In some use cases, this is not what we want - we want to be able to
> operate exclusively on PTEs that are already in the tables.
> 
> Add apply_to_existing_pages for this. Adjust the walker functions
> for apply_to_page_range to take 'create', which switches them between
> the old and new modes.

Wouldn't apply_to_existing_page_range() be a better name?

--- a/include/linux/mm.h~mm-add-apply_to_existing_pages-helper-fix-fix
+++ a/include/linux/mm.h
@@ -2621,9 +2621,9 @@ static inline int vm_fault_to_errno(vm_f
 typedef int (*pte_fn_t)(pte_t *pte, unsigned long addr, void *data);
 extern int apply_to_page_range(struct mm_struct *mm, unsigned long address,
 			       unsigned long size, pte_fn_t fn, void *data);
-extern int apply_to_existing_pages(struct mm_struct *mm, unsigned long address,
-				   unsigned long size, pte_fn_t fn,
-				   void *data);
+extern int apply_to_existing_page_range(struct mm_struct *mm,
+				   unsigned long address, unsigned long size,
+				   pte_fn_t fn, void *data);
 
 #ifdef CONFIG_PAGE_POISONING
 extern bool page_poisoning_enabled(void);
--- a/mm/memory.c~mm-add-apply_to_existing_pages-helper-fix-fix
+++ a/mm/memory.c
@@ -2184,12 +2184,12 @@ EXPORT_SYMBOL_GPL(apply_to_page_range);
  * Unlike apply_to_page_range, this does _not_ fill in page tables
  * where they are absent.
  */
-int apply_to_existing_pages(struct mm_struct *mm, unsigned long addr,
-			    unsigned long size, pte_fn_t fn, void *data)
+int apply_to_existing_page_range(struct mm_struct *mm, unsigned long addr,
+				 unsigned long size, pte_fn_t fn, void *data)
 {
 	return __apply_to_page_range(mm, addr, size, fn, data, false);
 }
-EXPORT_SYMBOL_GPL(apply_to_existing_pages);
+EXPORT_SYMBOL_GPL(apply_to_existing_page_range);
 
 /*
  * handle_pte_fault chooses page fault handler according to an entry which was
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191206163853.cdeb5dc80a8622fb6323a8d2%40linux-foundation.org.
