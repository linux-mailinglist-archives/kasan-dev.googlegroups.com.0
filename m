Return-Path: <kasan-dev+bncBCM2HQW3QYHRBJVB2OGQMGQEOATIU2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 86F684714B8
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 17:24:07 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id u20-20020a056512129400b0040373ffc60bsf5571968lfs.15
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 08:24:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639239847; cv=pass;
        d=google.com; s=arc-20160816;
        b=rVqTgBTEW4VrfhaCBv9m+Kbn7jgLnIndSXhtN+AzGAnnRMwlnyGy+k342K6RFiVISO
         fzTHbCzEHoUUE2OxDs/Vufc9ncRH6RVXx35fbFxIXMgYCnR5jFLncWiBJOQWuq1w7Wni
         h85pDQLFzvNWLHDx1u2nLYNQLdBdB7O7jofM/TDgEBrhiIp6Lt04xWu2ViBc97Y3ersK
         CRU4/cie2tCdRNPndkGD9TUyi5kdhVddfocwDimGnft0ghnpCt+Wdk5vryvkEmdIBL6L
         /kt+sLAHPJ6HBecBceXPU6lM75HHwclrjbOztHEunv9zxsDhgdL110qJpYvR76Dt9Gzt
         asZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6VsjNI2z0xREb4+UFQ3ncJrJS+vQlH7Qsv0dOMBsro0=;
        b=RI6KtXtZQ+GI0begbwH/nsU9YArdQeLN+DDbSG2FN5Ecd21jQlXrdAstps7oblztZM
         lI/p+nqARiIaR1r19j7WzJpRXW7KBqOFKmaJrqb5LfA43BEffhYtEFNBxt8dTb4RzZQC
         3CpM24X5uZjYURM6IiD8ZEXM4qQ3PtIjZ6KYmmj4td7zXGevSSQUtFPfFOfqUruDHAJA
         AJZgRvQjiX6Cz/ka3Tym+OGrcTNmvismZF50zIqQp5K6cjkFK/6VQWBMUfH8gaHdFbSg
         VUchBrbY12kJxMzoZL2omasYJ1cmmoNwDQUpXJX5njxq7kcv1+UkrHkJrckDArGZaHFu
         zl8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ZVCnBQ0U;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6VsjNI2z0xREb4+UFQ3ncJrJS+vQlH7Qsv0dOMBsro0=;
        b=LiRyiAk3nu2cv/V49S9L+eBoTfhOYbG9XjQbRSsnIGDLCTI0HRW9zDwN6v81QqSEgn
         qbi3U7QeNjsluGxpylgT5xwzu5otIt2U234tbRG27paaZ5MEnDcrwIW6q/TBQyIikgWx
         pA/N1c7CR8EvCsJULtUAc4C38n9F11UKIyPFhMN68I6m9t/ICRw3mcYlrZQeO4HQp43x
         JuWFl3YLJvCY6PWzo1iGrqshB0lApfnfVmGAkuai9zohZ8Uq9vkN8JMlVyXdyW/kYONw
         ZuAWJ954WJs8XjZ6fqk7UA45ULxF5Mnb653aO1LxpEBZ9L4OSZt7YIKpWex7kFNcb95z
         R4Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6VsjNI2z0xREb4+UFQ3ncJrJS+vQlH7Qsv0dOMBsro0=;
        b=vkSvA8gjBAwU8OJoPDceh1eqWa6Cbgdz0KIISf2IhqQMY6etC9rnTzE2nLB5yBk/yu
         OQR0L2cBQRn7fKxsL5XEJ309BsN1S/RwW9p951+B9IcZWnOe+y0on8HylC/O3eYw5bUW
         3pq+G5cvEldDqQjrRkt1OJ7gAbJbIsuklXf07PRpqZ+wpMiMvpwvFRt/2mWc+gW160Jx
         P3d1RO+pQT6JIxnIqf/BLxVWiyJXSg0UECjxdsu9eojyu0mlVMxb50QAgByzR0lUn10u
         TYTy181DJhU9pBOJxxDFykI8lwaPmgVAK5JXz7ErqSKfV0FwbDoRPr//ACazhdhV4Wh5
         4aeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Kx7M5AP5Bl48xMdiMbQx4ET11Ze6LaDbqi500bRE+kt0+RkIU
	umt5nl+GUj+j6Odosq+Pu/Y=
X-Google-Smtp-Source: ABdhPJz3H0BxKWp8r75xUTFOQ5QsiOzm1qGfWFUcxx3p+ZdvjKlNTgUhgG+y9Wg+mUnghkq0RM+8lg==
X-Received: by 2002:a05:6512:2202:: with SMTP id h2mr18082543lfu.576.1639239846865;
        Sat, 11 Dec 2021 08:24:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls56533lfu.2.gmail; Sat, 11
 Dec 2021 08:24:05 -0800 (PST)
X-Received: by 2002:a19:c757:: with SMTP id x84mr18219161lff.278.1639239845911;
        Sat, 11 Dec 2021 08:24:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639239845; cv=none;
        d=google.com; s=arc-20160816;
        b=T2QDL/SntJwQwK0bOeQkLxCwaqpMfewL3N3taZELy7b1dVxozLiodIX++69IhJRZh2
         WqrAsVbtnOz1AR5T9cud6TL8/miVyeNvg3qxigl1X2NGPY2wPfpKum49LJWeADSm80hy
         cWtLaXbyz+lT8bny9AqBVNlvU4s2y4WCCQCOQ54+WLDNszn0T9skVyuScMsAxmJB4HDK
         sAivDSV8K9Gc3w41YzvUtKLSWwgs31Jhgpfz04DRxygQXneo+8STJJPyvB5v17EcdOcc
         6N8H4znmuTWBSKFCFcKAY+1P78oKNstK3PQZh+bvUTwa7WBI2UvuPWa6RYQ9xUsesZqm
         MIoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=duqWjPgqnpdR2SAcoAzM6rFQ0Wy0jzMQfoUHoYd8x4E=;
        b=CfDUxEwd5LzYTGg6m3Q0Sx/CnACNeBtvTCmh6jorfwFhoLJ076qhyCOw6FpUxTDAbE
         JFaoySwKYJljiijLs39E6KfCa/qlIv7pe0tEDRzLFgfnAgEfSH7HEtVTr9xMcJNpO1Si
         YMDSxMFmpgKnox7xZpKB+25/NGysx5CUDE1zl925cLnxZ6nS1mKPqF7qr17Gyvu10iRj
         mt7SZ73kgBmA8BE+uqaFNWM9KcuII+cl92o3QY7Hd6OoL+9c+sL30PbnKOdLN8Amty6V
         h3Hvmjv40E6EVTgYT1+tQSHlL8krKwZVWUR2Vdi70vJ6uXECKw2AHcWlocZwQFNkx0O3
         yK2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ZVCnBQ0U;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id l13si297317lfg.1.2021.12.11.08.24.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Dec 2021 08:24:05 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mw5A3-00BJr3-8n; Sat, 11 Dec 2021 16:23:47 +0000
Date: Sat, 11 Dec 2021 16:23:47 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
Message-ID: <YbTQk9Dj+kUYAX09@casper.infradead.org>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz>
 <20211210163757.GA717823@odroid>
 <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ZVCnBQ0U;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Fri, Dec 10, 2021 at 07:26:11PM +0100, Vlastimil Babka wrote:
> > Because SLUB and SLAB sets slab->slab_cache = NULL (to set page->mapping = NULL),
> 
> Hm, now that you mention it, maybe it would be better to do a
> "folio->mapping = NULL" instead as we now have a more clearer view where we
> operate on struct slab, and where we transition between that and a plain
> folio. This is IMHO part of preparing the folio for freeing, not a struct
> slab cleanup as struct slab doesn't need this cleanup.

Yes, I did that as part of "mm/slub: Convert slab freeing to struct slab"
in my original series:

-       __ClearPageSlabPfmemalloc(page);
+       __slab_clear_pfmemalloc(slab);
        __ClearPageSlab(page);
-       /* In union with page->mapping where page allocator expects NULL */
-       page->slab_cache = NULL;
+       page->mapping = NULL;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbTQk9Dj%2BkUYAX09%40casper.infradead.org.
