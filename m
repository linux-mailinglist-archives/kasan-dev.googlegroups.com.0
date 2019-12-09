Return-Path: <kasan-dev+bncBCK2XL5R4APRBJ7SW7XQKGQEJNDEOQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C4D8116790
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 08:35:04 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id l76sf11023729ybf.10
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2019 23:35:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575876903; cv=pass;
        d=google.com; s=arc-20160816;
        b=GwFNNxB6chp9QFHAEAr+Xf/KsbFPxr+XIxThNXUolryBndFjWgVF2LbcLuZ+6lObjI
         uCD1G1qxRENiomnkJVAPtbDUNni3ILtxc8DZVuCmAofZdbAU/vT57WMtBFWZeGQK/LwS
         mkQxZwe373AVgSEbAAsxNlh0lVo7w4UavMC10OPn9O3mBxUd24jSaiUMuby+O9jGWFmJ
         5LUWH26/EBhT0kvJUq7eTmVYrFSs7anisYQlyV6Yy0LpGVIhrkDP4jKFC/GEtllLHQV4
         2Hkgk6fSpmwWqRfLalCjqP+6XriWFwjDheMjIaAYRLCOzb8o/uCTxc/kwHHXIB8c5kSA
         7O0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=coRQWlEIkWP37OP5hTZ8O/jHOuplAKRucam6nwp1FSQ=;
        b=GWyH5vsFzIlqN7mnOHfrfKmms025amwjGUqUbiSl4mOAu2AfbvdJFNXKZi4C+qzJfI
         YxEi91Cv0oNkETiv2fPfK/hFmzv9tLrOZcfZon7+OkO+BT1IgU93d4f/ZuwspgQCWWB+
         8DPmSzKMfMrUn0d+aRiKvnrb7w9AAUJTnLNG+q9wpevcNbL2q1aMqM+irtvd8FOixrtJ
         HDKNqTUQ6QRSjtpmrX+/0W/Moev4jJ8kHr0FisI6qmhMgV4Sy+zc4k2Qd50hV6EGIZvr
         kSRywWacdZCwKZBVXHyx9LfjKX+EAWwHU3CTXdejUS2tutgXBmgWeoXiC9JgbQCuYSvg
         rCzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=n37WqACQ;
       spf=pass (google.com: best guess record for domain of batv+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=coRQWlEIkWP37OP5hTZ8O/jHOuplAKRucam6nwp1FSQ=;
        b=KsV97EEXIZ5tthpGzWQfsCRKt3MvxhQd9OifzpASxaAseXP15S07j+YhUqwldECsKv
         U4/r/HoEwZb52/IPZDxSY7nHROnG7YPn5Xh4hpbzvJ3iFYShdx19DS2zOR8SRhi+PxjP
         DyIOnCbbtoMm77ARVGmkCW1lYpHbqyAxeO7DpNPnanvrbvFlwP6UX5/pTNCppt/JkxNJ
         Q4YMYeplKWbi4doSCNy8Z5N7gEULgLvXnyjSO4SUU3SG1NUb5i5XYtVaJzoVmn1qYNnb
         digiBDq7jam1B9HZyWEzko7B3B+vcYWrQNVV+x9KiglQHfOjlwohrz+LFElIPTzgWfa/
         es8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=coRQWlEIkWP37OP5hTZ8O/jHOuplAKRucam6nwp1FSQ=;
        b=VrTmTzw/Cl5RV/qgQbfwbxPRlkiT/IG/d1YQfS70P1RbaqbP5/ny2bnnfv/u/bxhNV
         cwRWRml7wSCLcH879KE5vPJwBmYnwDz93jPyALWV6SqtgoypOy8j/gwKGG1ym9+eA7Eh
         tEmMC0UDkpTt4iIbl9M7JrZaxKfLLp+0GQzdcR71+kyccrCEbZejhiP47aHa1Aq2lmp1
         YdrE2UuZ/SXGcP5DMn1dB6KDv7a1FJMIYsTsm8y5Q6uKYj80lN6tdEvh0f0BARrwlwdw
         cHjp+MAWNLX6zyY/FlEA4KOipbdEQ+5LnNPI/Aq0XpvDb02s7sGK8fph3cLSsDRY/zr5
         L+pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXZGcmeKUDXyIVGhXikQl9l/SyC6vjJT7gglfy/KkM8bt9m3cUd
	uP1l4GtFD2I2/bqnjI39yx0=
X-Google-Smtp-Source: APXvYqzWK42Kh4aNiCKPc2PKpmTFpzAftzlXBYFJae3DRLwbl00pChhQFgEvDQcncwCsYY76bWnzVw==
X-Received: by 2002:a81:9c4e:: with SMTP id n14mr19047051ywa.237.1575876903627;
        Sun, 08 Dec 2019 23:35:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:844f:: with SMTP id u76ls1855713ywf.15.gmail; Sun, 08
 Dec 2019 23:35:03 -0800 (PST)
X-Received: by 2002:a81:6641:: with SMTP id a62mr20412738ywc.249.1575876903202;
        Sun, 08 Dec 2019 23:35:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575876903; cv=none;
        d=google.com; s=arc-20160816;
        b=juQVrTpv/ORZlXcQoGjDBpEixhn7AxAYFb/Jlft5rC6bIW6VQfUjCsw9SfJv3qz5/+
         HH5sBrtqpAFZ12Nj3Mvd1UC+J78yr+eg376e0xL4nAcistVqBLYadSk5WANVJ0kma3KB
         i5nBn9plWT3cGal9v3lNRmxI9HzMTMJjpU4xDx9Z2Nb/NNKOQYjWCt/hG2s+TLi29p2H
         G3nDOrX2qP6sOQ/D6QHQUAM32AmcCtJ3c8SpPYSGgjmutzTu28hw4JifVTYJlWWgXr9F
         Byw34M5LjgnjW594BiiqwwDkd9GP3ZBEjI1GHSbsr8ld594AmZSnzeemwdk7BR7z8pmM
         TvPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AUVlsLdi8fdsPbY65zgNJOz3dj9sUmyYrS3GRJDCmW4=;
        b=q7g0QSCHN+S4YrWE0UJ0GgObU6kPuAkvC81gSMGoeJ6LO7Zs/P4ktwxf1uZjCrTt//
         0Ba3GobfLLX5j4VK2I3jeAAjYgPqk2xg1gVDxWVsoJ3E51V1pQEvCvFj/XIjTJo8BEQy
         /4CLM9vZAJFQC1IlR1r5VRWp/iBzJiRrI7upW8MuuF4CCCQYTKsB6cCiqaP7ucWKHDXd
         qOXA381w9R4R6cgox0IaAYvPFKdZzMOQ+jA50SO1RzR2fxqTKi3lcxPCEAVfbbo+i2uu
         XA+gItjkRdMfWOQFFCVMQgqIesuu+XzyqM1OG8o0qSxqnwCVUvrrg+x322CEdPdG5XUq
         wLvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=n37WqACQ;
       spf=pass (google.com: best guess record for domain of batv+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id r1si147323ybr.3.2019.12.08.23.35.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 08 Dec 2019 23:35:03 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of batv+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1ieDZK-0001GA-8U; Mon, 09 Dec 2019 07:34:58 +0000
Date: Sun, 8 Dec 2019 23:34:58 -0800
From: Christoph Hellwig <hch@infradead.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, aryabinin@virtuozzo.com, glider@google.com,
	linux-kernel@vger.kernel.org, dvyukov@google.com,
	daniel@iogearbox.net, cai@lca.pw
Subject: Re: [PATCH 1/3] mm: add apply_to_existing_pages helper
Message-ID: <20191209073458.GA3852@infradead.org>
References: <20191205140407.1874-1-dja@axtens.net>
 <20191206163853.cdeb5dc80a8622fb6323a8d2@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191206163853.cdeb5dc80a8622fb6323a8d2@linux-foundation.org>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=n37WqACQ;
       spf=pass (google.com: best guess record for domain of
 batv+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org
 designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+1f50caf4061583552184+5951+infradead.org+hch@bombadil.srs.infradead.org
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

Or a flags argument with descriptive flags to the existing function?
These magic bool arguments don't scale..

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191209073458.GA3852%40infradead.org.
