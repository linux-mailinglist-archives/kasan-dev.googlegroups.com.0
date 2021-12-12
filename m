Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBQFY22GQMGQE7FTJDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B6B84718F1
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Dec 2021 07:52:50 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id d27-20020a25addb000000b005c2355d9052sf24557719ybe.3
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 22:52:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639291969; cv=pass;
        d=google.com; s=arc-20160816;
        b=NJ9UuknyP/P++cfOFG4GHktfEZKBTvvv/v44rb5rLjpNFopLwFgv5MMC+3t4qp4wh9
         qXg2rj+vjzU/Y2Xlja69Dmz2sJd95LlD8VoJywrCqiIIdEobw6GWWXKefwQACzGvOXcR
         eWS2JWyy/jujsV/dTu1lcy5IZVsjQSDL0Ya5d+991nvEMWdcD3F6Ao4qDLVIm8Vv252g
         frcLxA58LNmyOx/Vo61ZmZQvUbAiR00pybTbfM+C4V7eCKVc5/rVoc+OyrN5HEhcq07G
         Qo1DKh6CsUcOfFbbaiKZlHkjqOfLH8ciRjqTRzbCeYNVb67oAr1kt0jaaeYoOVUC4Uwn
         /lDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=wYIbfNQ+K05XXR6DU5X02bgEzQNCLB33cwFoZaIThA0=;
        b=m5xVoPZ8U8SNXIRnuta9M1dXZ4KelOuX/mb6ypD6/ZokfR8eX+x9ZyWAKzVXn0YtnJ
         f/IeNZlwT9isGWeQqPooeE0ktya3BBh7nulz8ABCOqeyhhnvUtVpZV6Zv6cpJvQlmgXL
         l58UVTJg+fCeC3MZK1e7mcWUhrfeOhdJE+KXupE/2KBVsVVt9b0WafV9ylsgz4NVMmXT
         4ioAgl0mFnwu0Rok4SmOjIC880F20oBWPtxItci5sUhP0uxzjwx2uNmGVim2qA+E+51W
         eXWxifDnaozGblIxbMxmECm5JrqoPN5P3aktS8g1oubmwgkNV3vpoiC4PCMOsrkHaw/9
         DUFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IBAImVNc;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wYIbfNQ+K05XXR6DU5X02bgEzQNCLB33cwFoZaIThA0=;
        b=a6q584aR7OGNlK/gCED/Oa62kIsQqGtd5SneKvCWGs77Syabs8Oivlk+TWOkfCNPdl
         uAJV8m+oH3+slwHgnSr28Jm/idEWaXJxd8tOsPHIHW7DY6RnOXXnfEOBwDu1vBGvXl6d
         wnTTzMoX0+WqegJNMFAXXQZRTHO3bK2u3RoNH6vy5PiHtoFcsnMREn+CK5T06AXQR+Xq
         fUAXLoElmRXoadO7b2TyihfvAPKo5T9viXsQLR0v8Z5jqI5U5wcMJGxkH8UYH+cI/v9D
         G61WmzK3fMcJTdiJ9KNw5nr4eshju+0fVg1dMfslqsXvUBKC+V9Sjw5hBBMocEz+I7fj
         GNXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wYIbfNQ+K05XXR6DU5X02bgEzQNCLB33cwFoZaIThA0=;
        b=m8OVW69dKy61g5hJqjMKzU7am1YCVZucMmPw7ccnkbcH4jNybbLCDYiH5dxHqEpcuE
         rkz2p3fkKDoKCx397yPVCRCGkvLwqVvPL8ObMRr/0SlP4LhsOaHq4D0V5jyKGH0A2tqB
         KJrb2pF5FOGCiP6TMXRtvXVZEosVNGSfLJ1niPUlawcxIDYq6Vw2iJ5W8Gu/enBM806C
         LJrlSxuDukfvX+XLkT/maw8THmMcNBD5nAX63bp68HcA9rsf7g0qNHPpMRGFtv+Wie4v
         z44u488JLhFvtEAJ4p6wbzRwYVW5pc0NQi+VDm5Z1YzcSsZMDNFSut2fBqasrK+9+ljE
         Pptw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wYIbfNQ+K05XXR6DU5X02bgEzQNCLB33cwFoZaIThA0=;
        b=a3TpPiqk5HFNW3vwz4RWgmXpcLvLz1xZQ+i3lPpfjt/Ft51RXpqPrWMvdrt///VULe
         ky/T7C1fwjhG8AkJCzQtE3Mv13nTOLzMKkELYjIb+KgSKR+/ZDLg2z6HLdLHuGWhlbPq
         3XVdkfmg1UIXaREJ+PGPDZLuTkFvlf1Id5CgLkFFKGyGAZlLr5V63FrZHEkdFpzLDHF9
         YnF+1agjVgalkbJIIx1fOmM/KAJ8UjQg87RDvtpyKu3y7hexyirLdpwAoIiHDO0AroBu
         ak1BMthb4PClndpytJrnnMp9+2/Fwp5XjV/kfdcDlYMvxFaz4u7HIFmrXhLtFqOy7/HH
         kcvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530S6AWDlyNGVD5WrkTKk79MSLQdZxQRBM3mwDbHlbqu1uXI8tVQ
	1fRSCDGRdfQ8swevCOCXmWE=
X-Google-Smtp-Source: ABdhPJxWk7tiRVyJTPQqWEA3LxnVwyoBj+ZrmTCymk3glkatR/DgBGwUIhqzv1R+m+/3vDxrs4SOqQ==
X-Received: by 2002:a25:7451:: with SMTP id p78mr26898943ybc.507.1639291969051;
        Sat, 11 Dec 2021 22:52:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8752:: with SMTP id e18ls663161ybn.11.gmail; Sat, 11 Dec
 2021 22:52:48 -0800 (PST)
X-Received: by 2002:a25:99c6:: with SMTP id q6mr26099130ybo.587.1639291968617;
        Sat, 11 Dec 2021 22:52:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639291968; cv=none;
        d=google.com; s=arc-20160816;
        b=EyRdCrb9kl0p31dQWk8AjG5ZGT8YJa4pssne6rxpK+XFCWkE0yMGt4iPCkZLiybVNt
         Iozyg4wpvWSeppz3iPxVJoNu7AWPQXM0/tuhr1sNqZVjKQPmo7it3UhgC21ezoS+ew9M
         cUOAghRiycO7nMJ+WZL5UEQyUzEBvFhYS1991GjUudzF8ywLHkQsxo5z+Kk2jNkUUvxp
         dEpV5qrMJLWd5zOH1o5Dgwfd4iiGWNevZu0zDgnc/yUdKPZfv8zDqqKwscgaaUeK+L6I
         lKp7qLcx2KuwbILloNHHNMdPEj2VcWWMmskqeOXNua4CYWRllRExEAGyDGreGMGdMP/i
         FlMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=u3a3vrzHqdA/cq7G0yrkkIe6WLWwASeC4ff5g3IY6r0=;
        b=R4wdtFcVCaqzjeEOKyCvn7M8Ym4uUS5p4abxCN/r4ZjKQvb9+4y8gwnLmwpR++FS8H
         9FTQzPu++MWoFOOwPmz6CtxmcGFWIlbNKgISTV2JrC8/yCtHmcAm+cuqlkvu8TtHLHDq
         41OPNoSpN4tr0JtyhzmikaUtN+B0MtgSNmohXK5D2uNuDJWmfDMU1q5ONoTJVn23hT0W
         F5YfhbFCtpUu+p/ZX+EJ5J1LYIAAySHHPrbWuqa02sF6sR9qJzbRHizormeMWLMw4XzW
         /RZShYP0y1+6TNWLkLVzSH37GgGZY7HLqyWRXQwzOwvgGqdyGEXzmZQT+XmoEdkP7D5D
         QtTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IBAImVNc;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id e33si460994ybi.2.2021.12.11.22.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Dec 2021 22:52:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id fv9-20020a17090b0e8900b001a6a5ab1392so10837876pjb.1
        for <kasan-dev@googlegroups.com>; Sat, 11 Dec 2021 22:52:48 -0800 (PST)
X-Received: by 2002:a17:90a:a504:: with SMTP id a4mr35694110pjq.17.1639291967953;
        Sat, 11 Dec 2021 22:52:47 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id ng9sm3613977pjb.4.2021.12.11.22.52.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Dec 2021 22:52:47 -0800 (PST)
Date: Sun, 12 Dec 2021 06:52:41 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>
Subject: [PATCH] mm/slob: Remove unnecessary page_mapcount_reset() function
 call
Message-ID: <20211212065241.GA886691@odroid>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211201181510.18784-32-vbabka@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=IBAImVNc;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

After commit f1ac9059ca34 ("mm/sl*b: Differentiate struct slab fields
by sl*b implementations"), we can reorder fields of struct slab
depending on slab allocator.

For now, page_mapcount_reset() is called because page->_mapcount and
slab->units have same offset. But this is not necessary for
struct slab. Use unused field for units instead.

Signed-off-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
---
 mm/slab.h | 4 ++--
 mm/slob.c | 1 -
 2 files changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 90d7fceba470..dd0480149d38 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -50,8 +50,8 @@ struct slab {
 	struct list_head slab_list;
 	void * __unused_1;
 	void *freelist;		/* first free block */
-	void * __unused_2;
-	int units;
+	long units;
+	unsigned int __unused_2;
 
 #else
 #error "Unexpected slab allocator configured"
diff --git a/mm/slob.c b/mm/slob.c
index 39b651b3e6e7..7b2d2c7d69cc 100644
--- a/mm/slob.c
+++ b/mm/slob.c
@@ -404,7 +404,6 @@ static void slob_free(void *block, int size)
 			clear_slob_page_free(sp);
 		spin_unlock_irqrestore(&slob_lock, flags);
 		__ClearPageSlab(slab_page(sp));
-		page_mapcount_reset(slab_page(sp));
 		slob_free_pages(b, 0);
 		return;
 	}
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211212065241.GA886691%40odroid.
