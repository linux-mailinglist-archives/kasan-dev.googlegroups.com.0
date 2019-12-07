Return-Path: <kasan-dev+bncBCT4XGV33UIBBNPIVPXQKGQEM3UTMJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C3D81115A59
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Dec 2019 01:37:10 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id a11sf4404409plp.21
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 16:37:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575679029; cv=pass;
        d=google.com; s=arc-20160816;
        b=LrHCR+DyyOwt0pbentDqdbb7aI94PaFOEI65ZMqvYFOYBkUI+6uRlPj/Uxbmto0x/K
         uzmaKGW2klEMGWQEOXS8m/e2ZQPVhy5etSCYYFCSLPhPy3xGIJbBUaKsIm3rZsgu+fWN
         gEy3OxcwKf2C5Yspn20LX9k5pPAYYbOsG6QU84y9cV0An8vtVQHbrikGi1cIv7mvSP8A
         0i9TDIA/TTr2zhpshV1p92Q6ban2U5l6OIc/bgL/yzq2YcK3vYVDIivQZ8YuQaqXEWkS
         foKcqLLL8UvGCqdSXZYihFSSNYIlzhug7UVntJgmOxJEXNElSKr9kLI9kEfHTM6y1Pej
         n58g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Sqk//T5rQIHnMyPmEHdaim1zW9Q+YekHUltJPZCyLno=;
        b=AflViH6sUi2MFEovnV/Pr0bQCtyf9PYmchf1A6cQ6/stSImduKtlWFUzj0K9hWs9ic
         goAtKk/xKIibVgjv/SHHh5wdDUVIilIT1GBcfEk43iMQL99DE/s3YoN3IouCSqNwauOu
         Ya1pgsKLyiwrmyHsGdoLrGtqlXaBSG73mu9TC+stGKQHDDaa9krGg7wRS9MiDoT53y8H
         nadMVF3/BK0mnP5TIJ5Jm0PlWriT6lyGXoU/wQhMW3YCA7Ibc3IhvIFj2Us1e/c9Ub/F
         GvpxI/ATh6UsPursYptyfF3MNkNouIN7lfcgVavQpWDJG/IOu28Fyt5waTfUj1F9j/Fg
         LwZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hCUwOrYR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sqk//T5rQIHnMyPmEHdaim1zW9Q+YekHUltJPZCyLno=;
        b=UHRKkNSAJOr+Gzehux8anktUQDZTDyvynpA3mA5bNC61A5rF7TFH9NOv+mARlN8f/T
         tpRYAJ25Z2HqUW3ut6ZHfHWXQ6axuLhrAb31wfKjOv4J1eEWQdWVGsW8pBA5tDcL3zQp
         qTpnyXtOLJlEavDj6LfaXuCDljDubNf1sbsPqGFYOGTc6j2YiMmyh9kKSlLjY42ywaxg
         RLy7u5oUSKocsgrpdcBCdIlxsocnb/WpL/9Fqtenm9h/cVs8v8gR1F6oYWdeWt4vll6z
         S6ybqdx3goCgrHXbPF4JlFNutwCID0CjahLv92b7IHfaSiIHKta5sOPcE+hbEYf4xV9F
         TYXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sqk//T5rQIHnMyPmEHdaim1zW9Q+YekHUltJPZCyLno=;
        b=CoEpGwmFX9JhCc3HSk5znTeJw9Y/8aonESRvD3rDEFpVGfh5bmmsNbjqgBvhcyzsPj
         J+vSw0lV0RhB3GlSwVAkT2eaVmVz5+6BAOzl26u3mTojB9/7UZmgv3GuWEbavhbmsR+l
         aPUrqcyUw6vNnZgehGMmfX2U9b27kNk2pIsCYsW4KHKqrFx08Wv4b9yk6ifAOqvF0LJ/
         MY5Q4uYmvbPuUoLo1Z/dTIzdXsg4p5P75jjh2vQ/+jWZLIb0BAyTDx2cfaYagoYtM3BO
         zg7sc2Dn/BhzEarefNYj9sYDFh1NneiuohmEUzS7x6IquuuRXhPhTL1jsMLP8Mj1jIGM
         6dww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWgi2BomU6gxHtWac0DOaOmsTmfo5KOFw5Np4e4E/pw4vHSX10d
	/4HCR7GjtyBGDXRYGANv4Ss=
X-Google-Smtp-Source: APXvYqzTSN/kaqY8o8Eoz/qx2V6UtR3Sz4gbQjrAF89p7buxi2ZxxDL4/0qYw6ToX7UvyVpkxiM5vA==
X-Received: by 2002:a17:902:a418:: with SMTP id p24mr17866629plq.46.1575679029289;
        Fri, 06 Dec 2019 16:37:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b416:: with SMTP id x22ls2064112plr.0.gmail; Fri, 06
 Dec 2019 16:37:08 -0800 (PST)
X-Received: by 2002:a17:902:a50a:: with SMTP id s10mr17115648plq.49.1575679028732;
        Fri, 06 Dec 2019 16:37:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575679028; cv=none;
        d=google.com; s=arc-20160816;
        b=XtzPqCFLqM/dixMAGMG9xdKuZ5Qm3SHBmYrYE9FzDzIQEEHKio9idZKb0efy4CjEkO
         IRMuhzw/2V68QsVGS7EnJq2KDtt5p0R96+qwbtwcIt/IvFIE8aRmlIYD+aSUnC+Zq065
         0MD7nXD++WT233YrmKtiM0ZxOMPfscM+BrilH4Kw+B15P83bwha1jC4gLITvav5aBnqL
         kiQn6cqwMLpV3AIGsowoapn54U3ZeakMutZKRgMR9N3ZlCUDYqsAe9jgfSJ+KFWnxE1f
         67YZfglKOXH0+LYZUeIt2XnoCu7z0AMnGZHwT9tRcxg9pfnsGRUCi34yC6w9MKZNzDz5
         RZGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=i8bg+PNEc7ez/w6mYCyf9BTc3G7TrE8VggSCL05v7vw=;
        b=PwcomcVsz8+AW5wu58j4e9Mnb2Fbf5Bn4C+52lYrdMnbusi+aY0Ng5vFJEdzXxxIdi
         GXK/g/kzqiZ2MZzSRpEIFA+za1wno9Hgswpcii2LIx0QKkjynhKs8uwKa3oQN5TAp1gx
         xN5bOW1n831a8CyVDJZDRZPju4XjhF7T/LK23lvRcJJG5usLDRfUnV5fQMJhEKR4G8ai
         iEbwfVsTXNK4B51sIXfKMaUnmfmZBjMxrOTnngwcsgt72pK/g0vpdOYpF7ReY3O2epBX
         gAbjiNV85ny+bx1jC3ySw98klWWBoZNXGrlI9ihDn9exyk171TVG/2XXS1ZCdNye+7RW
         xerg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hCUwOrYR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 102si673736plb.3.2019.12.06.16.37.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 16:37:08 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E51C6217F4;
	Sat,  7 Dec 2019 00:37:07 +0000 (UTC)
Date: Fri, 6 Dec 2019 16:37:07 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, aryabinin@virtuozzo.com,
 glider@google.com, linux-kernel@vger.kernel.org, dvyukov@google.com,
 daniel@iogearbox.net, cai@lca.pw
Subject: Re: [PATCH 1/3] mm: add apply_to_existing_pages helper
Message-Id: <20191206163707.17f627c502846bd636049ad4@linux-foundation.org>
In-Reply-To: <20191205140407.1874-1-dja@axtens.net>
References: <20191205140407.1874-1-dja@axtens.net>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hCUwOrYR;       spf=pass
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

> +/*
> + * Scan a region of virtual memory, calling a provided function on
> + * each leaf page table where it exists.
> + *
> + * Unlike apply_to_page_range, this does _not_ fill in page tables
> + * where they are absent.
> + */
> +int apply_to_existing_pages(struct mm_struct *mm, unsigned long addr,
> +			    unsigned long size, pte_fn_t fn, void *data)
> +{
> +	pgd_t *pgd;
> +	unsigned long next;
> +	unsigned long end = addr + size;
> +	int err = 0;
> +
> +	if (WARN_ON(addr >= end))
> +		return -EINVAL;
> +
> +	pgd = pgd_offset(mm, addr);
> +	do {
> +		next = pgd_addr_end(addr, end);
> +		if (pgd_none_or_clear_bad(pgd))
> +			continue;
> +		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data, false);
> +		if (err)
> +			break;
> +	} while (pgd++, addr = next, addr != end);
> +
> +	return err;
> +}
> +EXPORT_SYMBOL_GPL(apply_to_existing_pages);

This is almost identical to apply_to_page_range() and cries out for
some deduplication.  This?

--- a/mm/memory.c~mm-add-apply_to_existing_pages-helper-fix
+++ a/mm/memory.c
@@ -2141,12 +2141,9 @@ static int apply_to_p4d_range(struct mm_
 	return err;
 }
 
-/*
- * Scan a region of virtual memory, filling in page tables as necessary
- * and calling a provided function on each leaf page table.
- */
-int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
-			unsigned long size, pte_fn_t fn, void *data)
+static int __apply_to_page_range(struct mm_struct *mm, unsigned long addr,
+				 unsigned long size, pte_fn_t fn,
+				 void *data, bool create)
 {
 	pgd_t *pgd;
 	unsigned long next;
@@ -2159,13 +2156,25 @@ int apply_to_page_range(struct mm_struct
 	pgd = pgd_offset(mm, addr);
 	do {
 		next = pgd_addr_end(addr, end);
-		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data, true);
+		if (!create && pgd_none_or_clear_bad(pgd))
+			continue;
+		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data, create);
 		if (err)
 			break;
 	} while (pgd++, addr = next, addr != end);
 
 	return err;
 }
+
+/*
+ * Scan a region of virtual memory, filling in page tables as necessary
+ * and calling a provided function on each leaf page table.
+ */
+int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
+			unsigned long size, pte_fn_t fn, void *data)
+{
+	return __apply_to_page_range(mm, addr, size, fn, data, true);
+}
 EXPORT_SYMBOL_GPL(apply_to_page_range);
 
 /*
@@ -2178,25 +2187,7 @@ EXPORT_SYMBOL_GPL(apply_to_page_range);
 int apply_to_existing_pages(struct mm_struct *mm, unsigned long addr,
 			    unsigned long size, pte_fn_t fn, void *data)
 {
-	pgd_t *pgd;
-	unsigned long next;
-	unsigned long end = addr + size;
-	int err = 0;
-
-	if (WARN_ON(addr >= end))
-		return -EINVAL;
-
-	pgd = pgd_offset(mm, addr);
-	do {
-		next = pgd_addr_end(addr, end);
-		if (pgd_none_or_clear_bad(pgd))
-			continue;
-		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data, false);
-		if (err)
-			break;
-	} while (pgd++, addr = next, addr != end);
-
-	return err;
+	return __apply_to_page_range(mm, addr, size, fn, data, false);
 }
 EXPORT_SYMBOL_GPL(apply_to_existing_pages);
 
_


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191206163707.17f627c502846bd636049ad4%40linux-foundation.org.
